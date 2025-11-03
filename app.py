import os
import yaml
import json
import time
import threading
import subprocess
import re
import logging
from flask import Flask, Response
from flask_httpauth import HTTPBasicAuth
from kubernetes import client, config
from kubernetes.client.rest import ApiException
import requests
from jsonpath_ng import parse

# Configure logging
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(level=LOG_LEVEL, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
auth = HTTPBasicAuth()

# Load K8s config (in-cluster)
config.load_incluster_config()
v1 = client.CoreV1Api()
apps_v1 = client.AppsV1Api()

# Load config from mounted volume
try:
    with open('/config/config.yaml', 'r') as f:
        CONFIG = yaml.safe_load(f)['checks']
    logging.debug("Configuration loaded successfully: %s", CONFIG)
except Exception as e:
    logging.error("Failed to load configuration: %s", str(e))
    raise

# Global cache: {check_name: {'status': str, 'output': str, 'perfdata': str, 'timestamp': float}}
CACHE = {}
CACHE_LOCK = threading.Lock()

# Default globals (override in config if needed)
DEFAULT_TTL = 60
DEFAULT_REFRESH = 30
NAMESPACE = os.getenv('NAMESPACE', 'default')

def get_status_color(value, warn_threshold, crit_threshold):
    """Map numeric value to OK/WARN/CRIT based on thresholds (higher better)."""
    if crit_threshold is not None and value < crit_threshold:
        return 'CRITICAL'
    if warn_threshold is not None and value < warn_threshold:
        return 'WARNING'
    return 'OK'

@auth.verify_password
def verify_password(username, password):
    return (username == os.getenv('USERNAME') and
            password == os.getenv('PASSWORD'))

def run_check(check):
    """Run a single check and return dict with status, output, perfdata."""
    check_name = check['name']
    ns = check.get('namespace', NAMESPACE)
    logging.debug("Running check: %s in namespace %s", check_name, ns)
    try:
        if check['type'] == 'deployment':
            result = deployment_check(check, ns)
        elif check['type'] == 'service':
            result = service_check(check, ns)
        elif check['type'] == 'json':
            result = json_check(check)
        elif check['type'] == 'exec':
            result = exec_check(check)
        else:
            result = {'status': 'CRITICAL', 'output': f'Unknown check type {check["type"]}', 'perfdata': ''}
        logging.debug("Check %s completed with result: %s", check_name, result)
        return result
    except Exception as e:
        logging.error("Check %s failed: %s", check_name, str(e))
        return {'status': 'CRITICAL', 'output': f'Check failed: {str(e)}', 'perfdata': ''}

def deployment_check(check, ns):
    selector = check['label_selector']
    deployments = apps_v1.list_namespaced_deployment(namespace=ns, label_selector=selector)
    total = len(deployments.items)
    ready_total = sum(dep.status.ready_replicas or 0 for dep in deployments.items)
    desired_total = sum(dep.spec.replicas or 0 for dep in deployments.items)
    
    warn_th = check.get('warn_threshold')
    crit_th = check.get('crit_threshold')
    status = get_status_color(ready_total, warn_th, crit_th)
    
    failed = []
    for dep in deployments.items:
        ready = dep.status.ready_replicas or 0
        desired = dep.spec.replicas or 0
        if ready < desired:
            failed.append(f'{dep.metadata.name}: {ready}/{desired}')
    
    if status == 'OK':
        output = f'All {total} deployments healthy'
    else:
        output = f'{len(failed)}/{total} deployments unhealthy: {" - ".join(failed)}'
    
    perfdata = f"'deployments_ready'={ready_total};;0 'deployments_count'={total};;0"
    
    logging.debug("Deployment check result: %s", result)
    return {'status': status, 'output': output, 'perfdata': perfdata}

def service_check(check, ns):
    selector = check['label_selector']
    services = v1.list_namespaced_service(namespace=ns, label_selector=selector)
    total = len(services.items)
    healthy = 0
    failed = []
    for svc in services.items:
        eps = v1.list_namespaced_endpoints(namespace=ns, label_selector=f'app={svc.metadata.name}')
        if eps.items and any(e.subsets for e in eps.items):
            healthy += 1
        else:
            failed.append(svc.metadata.name)
    
    value = healthy
    warn_th = check.get('warn_threshold', total - 1)
    crit_th = check.get('crit_threshold', 0)
    status = get_status_color(value, warn_th, crit_th)
    
    if status == 'OK':
        output = f'All {total} services available'
    else:
        output = f'{len(failed)}/{total} services unavailable: {" - ".join(failed)}'
    
    perfdata = f"'services_healthy'={value};;0"
    
    logging.debug("Service check result: %s", result)
    return {'status': status, 'output': output, 'perfdata': perfdata}

def json_check(check):
    url = check['url']
    path = check['path']
    condition = check.get('condition', 'eq')
    value = check.get('value')
    warn_th = check.get('warn_threshold')
    crit_th = check.get('crit_threshold')
    headers = check.get('headers', {})
    metric_name = check.get('metric_name', 'json_value')

    # Ensure headers are a dictionary
    if isinstance(headers, list):
        headers_dict = {}
        for header in headers:
            key, val = header.split(': ', 1)
            headers_dict[key] = val
        headers = headers_dict
    
    logging.debug("Making GET request to %s with headers %s", url, headers)
    resp = requests.get(url, headers=headers, timeout=10)
    logging.debug("Received response from %s: %s", url, resp.status_code)
    # Log the first and last 5 lines of the response content
    response_lines = resp.text.split('\n')
    first_5_lines = '\n'.join(response_lines[:5])
    last_5_lines = '\n'.join(response_lines[-5:])
    
    if len(response_lines) <= 5:
        response_log = first_5_lines
    else:
        response_log = f"{first_5_lines}\n...skipped...\n{last_5_lines}"
    logging.debug("Response content: %s", response_log)

    if resp.status_code != 200:
        logging.error("HTTP %s from %s", resp.status_code, url)
        return {'status': 'CRITICAL', 'output': f'HTTP {resp.status_code} from {url}', 'perfdata': ''}
    
    try:
        data = resp.json()
        logging.debug("Parsed JSON data: %s", data)
    except json.JSONDecodeError:
        logging.error("Invalid JSON from %s", url)
        return {'status': 'CRITICAL', 'output': f'Invalid JSON from {url}', 'perfdata': ''}
    
    try:
        jsonpath_expr = parse(path)
        match = [match.value for match in jsonpath_expr.find(data)]
        logging.debug("JSONPath match: %s", match)
    except Exception as e:
        logging.error("Invalid JSONPath %s: %s", path, str(e))
        return {'status': 'CRITICAL', 'output': f'Invalid JSONPath {path}: {str(e)}', 'perfdata': ''}
    
    if not match:
        logging.error("No match for path %s", path)
        return {'status': 'CRITICAL', 'output': f'No match for path {path}', 'perfdata': ''}
    
    extracted = match[0] if len(match) == 1 else match
    logging.debug("Extracted value: %s", extracted)
    
    numeric_value = None
    perfdata = ''
    if condition == 'eq':
        if isinstance(extracted, list):
            status = 'OK' if all(item == value for item in extracted) else 'CRITICAL'
            output = f'All values match {value}' if status == 'OK' else f'Not all values match {value}, found {extracted}'
        else:
            status = 'OK' if extracted == value else 'CRITICAL'
            output = f'Value matches {value}' if status == 'OK' else f'Expected {value}, got {extracted}'
    elif condition == 'contains':
        if isinstance(extracted, list):
            status = 'OK' if any(value in str(item) for item in extracted) else 'CRITICAL'
            output = f'Contains {value}' if status == 'OK' else f'Missing {value} in {extracted}'
        else:
            status = 'OK' if value in str(extracted) else 'CRITICAL'
            output = f'Contains {value}' if status == 'OK' else f'Missing {value} in {extracted}'
    elif condition == 'count':
        # For count, if value provided, count matches (e.g., containing value)
        if value:
            count = sum(1 for item in extracted if str(value) in str(item))
        else:
            count = len(extracted)
        warn_str = str(warn_th) if warn_th is not None else ''
        crit_str = str(crit_th) if crit_th is not None else ''
        status = get_status_color(count, warn_th, crit_th)
        output = f'{count} items {"matching " + str(value) if value else "found"}' if status == 'OK' else f'{count} items (thresholds: warn={warn_str}, crit={crit_str})'
        numeric_value = count
        perfdata = f"'{metric_name}'={count};{warn_str};{crit_str}"
    else:
        logging.error("Unknown condition %s", condition)
        return {'status': 'CRITICAL', 'output': f'Unknown condition {condition}', 'perfdata': ''}
    
    if numeric_value is not None and not perfdata:
        warn_str = str(warn_th) if warn_th is not None else ''
        crit_str = str(crit_th) if crit_th is not None else ''
        perfdata = f"'{metric_name}'={numeric_value};{warn_str};{crit_str}"
    
    logging.debug("JSON check result: %s", {'status': status, 'output': output, 'perfdata': perfdata})
    return {'status': status, 'output': output, 'perfdata': perfdata}

def exec_check(check):
    command = check['command']
    expected_rc = check.get('expected_rc', {0: 'OK', 1: 'WARNING', 2: 'CRITICAL', 3: 'CRITICAL'})
    parse_expr = check.get('parse_output', '')  # JSONPath or regex like r'(\d+)'
    warn_th = check.get('warn_threshold')
    crit_th = check.get('crit_threshold')
    
    logging.debug("Executing command: %s", command)
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        rc = result.returncode
        output = result.stdout.strip() or result.stderr.strip() or f'Return code {rc}'
        logging.debug("Command output: %s", output)
        
        status_map = {0: 'OK', 1: 'WARNING', 2: 'CRITICAL', 3: 'CRITICAL'}
        status = status_map.get(rc, 'CRITICAL')
        
        numeric_value = None
        perfdata = ''
        if parse_expr:
            val = None
            if parse_expr.startswith('$.'):  # JSONPath
                try:
                    data = json.loads(output)
                    expr = parse(parse_expr)
                    matches = [m.value for m in expr.find(data)]
                    if matches:
                        val = matches[0] if len(matches) == 1 else len(matches)
                except:
                    pass
            else:  # Regex
                match = re.search(parse_expr, output)
                if match:
                    try:
                        val = int(match.group(1))
                    except:
                        val = match.group(1)
            
            if isinstance(val, (int, float)):
                numeric_value = val
                # Override status with thresholds if provided
                if warn_th is not None or crit_th is not None:
                    status = get_status_color(numeric_value, warn_th, crit_th)
                warn_str = str(warn_th) if warn_th is not None else ''
                crit_str = str(crit_th) if crit_th is not None else ''
                perfdata = f"'exec_value'={numeric_value};{warn_str};{crit_str}"
            else:
                perfdata = f"'exec_value'={repr(val)};;;0"
        
        output = output[:100] + '...' if len(output) > 100 else output
        logging.debug("Exec check result: %s", {'status': status, 'output': output, 'perfdata': perfdata})
        return {'status': status, 'output': output, 'perfdata': perfdata}
    except Exception as e:
        logging.error("Exec failed: %s", str(e))
        return {'status': 'CRITICAL', 'output': f'Exec failed: {str(e)}', 'perfdata': ''}

def refresh_cache():
    """Background refresh all checks."""
    while True:
        with CACHE_LOCK:
            for check in CONFIG:
                cached = CACHE.get(check['name'], {})
                if time.time() - (cached.get('timestamp', 0) or 0) > DEFAULT_REFRESH:
                    logging.debug("Refreshing check: %s", check['name'])
                    result = run_check(check)
                    CACHE[check['name']] = {
                        'status': result['status'],
                        'output': result['output'],
                        'perfdata': result['perfdata'],
                        'timestamp': time.time()
                    }
                    logging.debug("Refreshed check %s: %s", check['name'], result)
        time.sleep(DEFAULT_REFRESH)

# Start background refresher
threading.Thread(target=refresh_cache, daemon=True).start()

# Initial cache populate
for check in CONFIG:
    result = run_check(check)
    CACHE[check['name']] = {
        'status': result['status'],
        'output': result['output'],
        'perfdata': result['perfdata'],
        'timestamp': time.time()
    }

@app.route('/check/<check_name>')
@auth.login_required
def perform_check(check_name):
    with CACHE_LOCK:
        cached = CACHE.get(check_name, {})
        ttl = next((c.get('ttl', DEFAULT_TTL) for c in CONFIG if c['name'] == check_name), DEFAULT_TTL)
        if time.time() - cached.get('timestamp', 0) > ttl:
            # Stale, refresh
            check = next(c for c in CONFIG if c['name'] == check_name)
            logging.debug("Refreshing stale check: %s", check_name)
            result = run_check(check)
            cached = {
                'status': result['status'],
                'output': result['output'],
                'perfdata': result['perfdata'],
                'timestamp': time.time()
            }
            CACHE[check_name] = cached
            logging.debug("Refreshed stale check %s: %s", check_name, result)
        
        if not cached:
            logging.warning("Check not found: %s", check_name)
            return Response('CRITICAL - Check not found', mimetype='text/plain')
        
        body = f"{cached['status']} - {cached['output']}"
        if cached['perfdata']:
            body += f" | {cached['perfdata']}"
        
        if cached['status'] == 'WARNING':
            logging.warning("Check %s returned WARNING: %s", check_name, cached['output'])
        elif cached['status'] == 'CRITICAL':
            logging.critical("Check %s returned CRITICAL: %s", check_name, cached['output'])
        
        return Response(body, mimetype='text/plain')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)