# Kubernetes-Nagios/Icinga Integration: Check API

A lightweight, Kubernetes-native HTTP API for Nagios/Icinga monitoring - **no agents required**.  
Run health checks directly against your K8s cluster using native APIs and return Nagios-compatible output.

✅ **Nagios/Icinga Compatible**

✅ **In-cluster Deployment**

✅ **Zero Dependencies**

✅ **Check Deployments & Services via k8s API**

✅ **Check your App in-Cluster with JSON parsing**

✅ **Check in-Cluster Apps with native Nagios Check-Plugins**

✅ **Performance Data (perfdata)**

✅ **HTTP Basic Auth**

✅ **Non-Blocking checks with cached results**

---

## 🚀 Why This Tool?

If you're using **Nagios, Icinga, or similar monitoring systems** and need to monitor **Kubernetes resources** without installing agents, this is your solution.

This app exposes endpoints like `/check/deployment-healthy` that return Nagios-compatible output:

```
OK - All 3 deployments healthy | 'deployments_ready'=3;;0 'deployments_count'=3;;0
```

Use `check_http` or `check_url` plugins in Nagios/Icinga or a simple wrapper for `curl`.

---

## 📦 Features

| Check Type     | Description |
|----------------|-------------|
| `deployment`   | Checks replica availability by label selector |
| `service`      | Validates endpoints are ready for services |
| `json`         | Fetches JSON from URL, validates with JSONPath + conditions (`eq`, `contains`, `count`) |
| `exec`         | Runs shell commands, parses output via regex or JSONPath |

All checks support:
- `warn_threshold` / `crit_threshold`
- Custom `perfdata` for graphs
- TTL-based caching to reduce API load

---

## 🛠️ Installation (Kubernetes)

Example to deploy this in your cluster:

### 1. Create Namespace & ConfigMap with Checks

```bash
kubectl create ns k8s-icinga-bridge
```

```yaml
# config.yaml
checks:
  - name: nginx-deployments
    type: deployment
    label_selector: app=nginx
    warn_threshold: 2
    crit_threshold: 1
    ttl: 120

  - name: api-service-ready
    type: service
    label_selector: app=api
    warn_threshold: 1
    crit_threshold: 0

  - name: api-gateway-status
    type: "json"
    url: http://gateway.api.svc:4000/health
    path: $.status
    condition: eq
    value: ok
    headers:
      - "Authorization: Bearer xxx"

  - name: models-loaded
    type: json
    url: http://litellm.litellm.svc:4000/v1/models
    headers:
    - "Content-Type: application/json"
    - "Authorization: Bearer xxx"
    path: $.data[*].object
    condition: count
    value: model
    warn_threshold: 5
    crit_threshold: 3
    ttl: 60
    metric_name: model_count

  - name: redis-queue
    type: exec
    command:
    - "redis-cli"
    - "-h"
    - "redis.app.svc"
    - "LLEN"
    - "inference_queue"
    expected_rc: 0
    parse_output: 'r"(\d+)"'
    warn_threshold: 100
    crit_threshold: 500
    ttl: 30
```

Apply it:

```bash
kubectl -n k8s-icinga-bridge create configmap nagios-checks --from-file=config.yaml
```

### 2. Deploy the App

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: check-service
  namespace: k8s-icinga-bridge
spec:
  replicas: 1
  selector:
    matchLabels:
      app: check-service
  template:
    metadata:
      labels:
        app: check-service
    spec:
      serviceAccountName: check-sa
      volumes:
      - name: config-volume
        configMap:
          name: check-cm
      containers:
      - name: checker
        image: ghcr.io/mono-of-pg/k8s-icinga-bridge:main
        ports:
        - containerPort: 8080
        volumeMounts:
        - name: config-volume
          mountPath: /config
        env:
        - name: LOG_LEVEL
          value: DEBUG
        - name: USERNAME
          valueFrom:
            secretKeyRef:
              name: check-secret
              key: username
        - name: PASSWORD
          valueFrom:
            secretKeyRef:
              name: check-secret
              key: password
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 200m
            memory: 256Mi
---
apiVersion: v1
kind: Service
metadata:
  name: check-service
spec:
  selector:
    app: check-service
  ports:
  - port: 8080
    targetPort: 8080
  type: ClusterIP
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: check-sa
  namespace: k8s-icinga-bridge
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: check-clusterrole
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["services", "endpoints", "pods"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: check-clusterrolebinding
subjects:
- kind: ServiceAccount
  name: check-sa
  namespace: k8s-icinga-bridge
roleRef:
  kind: ClusterRole
  name: check-clusterrole
  apiGroup: rbac.authorization.k8s.io
```

> 💡 **Note**: RBAC is required to check Deployments and Services in other Namespaces

### 3. Create Secrets for Auth

```bash
kubectl create secret generic check-secret \
  --from-literal=username=nagios \
  --from-literal=password=yourstrongpassword
```

### 4. Apply Everything

```bash
kubectl apply -f deployment.yaml
```

---

## 🔍 Usage (Nagios/Icinga Integration)

Configure your Nagios/Icinga `check_http` or `check_url` to hit:

```
http://nagios-checks.default.svc.cluster.local/check/nginx-deployments
```

**Example Nagios Command Definition:**

```ini
define command {
    command_name    check_k8s_deployment
    command_line    $USER1$/check_http -H $HOSTADDRESS$ -u /check/$ARG1$ -t 10 -s "OK"
}
```

**Usage in service definition:**

```ini
define service {
    host_name               k8s-cluster
    service_description     Nginx Deployments
    check_command           check_k8s_deployment!nginx-deployments
    use                     generic-service
}
```

---

## 🔧 Configuration Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | ✅ | Unique check name (used in URL path) |
| `type` | string | ✅ | `deployment`, `service`, `json`, `exec` |
| `namespace` | string | ❌ | Override default namespace (`default`) |
| `ttl` | int | ❌ | Cache TTL in seconds (default: 60) |
| `label_selector` | string | ✅ (deployment/service) | K8s label selector (e.g., `app=myapp`) |
| `url` | string | ✅ (json) | Endpoint to GET |
| `path` | string | ✅ (json) | JSONPath to extract value (e.g., `$.data.status`) |
| `condition` | string | ❌ (json) | `eq`, `contains`, `count` (default: `eq`) |
| `value` | any | ❌ (json) | Expected value for `eq`/`contains` |
| `metric_name` | string | ❌ (json) | Custom perfdata metric name (default: `json_value`) |
| `headers` | list | ❌ (json) | HTTP headers as list of `"Key: Value"` strings |
| `command` | list | ✅ (exec) | Shell command as array (e.g., `["/bin/sh", "-c", "uptime"]`) |
| `parse_output` | string | ❌ (exec) | Regex (e.g., `r'([0-9]+)'`) or JSONPath (`$.value`) |
| `expected_rc` | dict | ❌ (exec) | Map return codes to status (default: `{0: 'OK', 1: 'WARNING', 2: 'CRITICAL'}`) |
| `warn_threshold` | number | ❌ | Threshold for WARNING (higher = better for numeric) |
| `crit_threshold` | number | ❌ | Threshold for CRITICAL |

> 💡 **Numeric thresholds**: Higher values = better. E.g., `warn_threshold: 5` means: `value < 5 → WARNING`.

---

## 🔐 Security

- Uses **HTTP Basic Auth** (set via `USERNAME`/`PASSWORD` env vars)
- Runs as non-root, read-only filesystem
- Minimal RBAC permissions (only list/get on needed resources)
- No external network access unless explicitly configured (e.g., `json` checks)

---

## 📈 Monitoring & Alerts

- **Performance data** enables graphing in Grafana, PNP4Nagios, etc.
- **Caching** reduces K8s API load - checks refresh every 30s by default
- Logs to stdout - compatible with Kubernetes log collectors (Fluentd, Loki)

---

## 🌐 Keywords for Search Engines

> ✅ **Optimized for discovery** - use these keywords when searching:

`nagios kubernetes monitoring`  
`icinga k8s checks`  
`kubernetes health check api`  
`nagios check_http k8s`  
`k8s no agent monitoring`  
`kubernetes service endpoint check`  
`jsonpath nagios check`  
`kubernetes deployment health check`  
`exec command nagios k8s`  
`nagios plugin kubernetes api`

---

> Built for DevOps teams who need **simple, reliable, agentless** k8s monitoring.
> Star this repo if it helped you!