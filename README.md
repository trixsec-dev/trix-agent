<div align="center">
  <h1>kijo-agent</h1>
  <p><strong>Continuous Security Monitoring Agent for Kubernetes</strong></p>

  <p>
    Long-running service that monitors your cluster's security posture<br>
    and sends notifications when vulnerabilities are discovered or fixed.
  </p>

  <p>
    <a href="https://go.dev/"><img src="https://img.shields.io/github/go-mod/go-version/kijosec/agent" alt="Go Version"></a>
    <a href="LICENSE"><img src="https://img.shields.io/github/license/kijosec/agent" alt="License"></a>
    <a href="https://goreportcard.com/report/github.com/kijosec/agent"><img src="https://goreportcard.com/badge/github.com/kijosec/agent" alt="Go Report Card"></a>
    <a href="https://github.com/kijosec/agent/releases"><img src="https://img.shields.io/github/v/release/kijosec/agent?include_prereleases" alt="Release"></a>
  </p>

  <p>
    <a href="#features"><strong>Features</strong></a> |
    <a href="#installation"><strong>Installation</strong></a> |
    <a href="#configuration"><strong>Configuration</strong></a> |
    <a href="#deployment"><strong>Deployment</strong></a> |
    <a href="#notifications"><strong>Notifications</strong></a>
  </p>
</div>

---

## Features

- **Continuous Monitoring** - Polls Trivy Operator CRDs at configurable intervals
- **Vulnerability Lifecycle Tracking** - Tracks new and fixed vulnerabilities in PostgreSQL
- **Multi-Channel Notifications** - Slack, generic webhooks, and Kijo SaaS integration
- **Health Endpoints** - Kubernetes-ready health checks for monitoring
- **Namespace Filtering** - Monitor specific namespaces or entire cluster
- **Configurable Severity** - Choose which severity levels trigger notifications
- **Structured Logging** - JSON or text logging with configurable levels

## How it Works

kijo-agent runs as a service in your Kubernetes cluster and continuously:

1. **Polls** Trivy Operator CRDs for security findings
2. **Tracks** vulnerability state changes in PostgreSQL database
3. **Detects** new vulnerabilities and when vulnerabilities are fixed
4. **Notifies** through configured channels when changes occur

The agent maintains a history of findings, allowing it to distinguish between:
- **New vulnerabilities** - Never seen before
- **Fixed vulnerabilities** - Previously detected but now resolved
- **Persistent vulnerabilities** - Ongoing issues that need attention

## Installation

### Prerequisites

- Kubernetes cluster with [Trivy Operator](https://aquasecurity.github.io/trivy-operator/) installed
- PostgreSQL database (for vulnerability state tracking)

### Quick Install with Helm

```bash
# Add the Helm repository
helm repo add kijo https://kijosec.github.io/kijo
helm repo update

# Install the agent
helm install kijo-agent kijo/kijo-agent \
  --namespace kijo-system \
  --create-namespace \
  --set databaseUrl=postgresql://user:pass@host:5432/dbname
```

### Manual Installation

**Create namespace and secrets:**

```bash
kubectl create namespace kijo-system

# Create database secret
kubectl create secret generic kijo-agent-db \
  --namespace kijo-system \
  --from-literal=database-url="postgresql://user:pass@host:5432/dbname"

# Optional: Slack webhook secret
kubectl create secret generic kijo-agent-notifications \
  --namespace kijo-system \
  --from-literal=slack-webhook="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
```

**Deploy the agent:**

```bash
kubectl apply -f https://raw.githubusercontent.com/kijosec/agent/main/deploy/kubernetes/deployment.yaml
```

### Build from Source

```bash
git clone https://github.com/kijosec/agent.git
cd agent
go build -o kijo-agent ./cmd/...
```

## Configuration

kijo-agent is configured via environment variables:

### Database

| Variable | Description | Required |
|----------|-------------|----------|
| `KIJO_DATABASE_URL` | PostgreSQL connection string | ✅ |

### Polling & Filtering

| Variable | Description | Default |
|----------|-------------|---------|
| `KIJO_POLL_INTERVAL` | How often to poll Trivy Operator | `5m` |
| `KIJO_NAMESPACES` | Namespaces to watch (comma-separated) | all |
| `KIJO_CLUSTER_NAME` | Human-readable cluster name | hostname |

### Notifications

| Variable | Description | Default |
|----------|-------------|---------|
| `KIJO_NOTIFY_SLACK` | Slack incoming webhook URL | - |
| `KIJO_NOTIFY_WEBHOOK` | Generic webhook URL | - |
| `KIJO_NOTIFY_SEVERITY` | Minimum severity to notify | `CRITICAL` |

### SaaS Integration

| Variable | Description | Default |
|----------|-------------|---------|
| `KIJO_SAAS_ENDPOINT` | Kijo SaaS API endpoint | - |
| `KIJO_SAAS_API_KEY` | API key for SaaS authentication | - |

### Logging & Health

| Variable | Description | Default |
|----------|-------------|---------|
| `KIJO_LOG_FORMAT` | Log format (`json` or `text`) | `json` |
| `KIJO_LOG_LEVEL` | Log level (`debug`, `info`, `warn`, `error`) | `info` |
| `KIJO_HEALTH_ADDR` | Health check server address | `:8080` |

## Deployment

### Kubernetes Deployment

The recommended way to deploy kijo-agent is using the provided Kubernetes manifests:

```bash
# Deploy with default configuration
kubectl apply -f deploy/kubernetes/

# Deploy with custom values
kubectl apply -f deploy/kubernetes/patches/
```

**Key deployment components:**

- **Deployment** - Runs the agent with replicas for high availability
- **Service** - Exposes health endpoints for Kubernetes probes
- **ServiceAccount** - Minimal RBAC permissions for Trivy Operator access
- **ConfigMap** - Default configuration
- **Secrets** - Database URL and notification webhooks

### Helm Chart

For more advanced deployments, use the Helm chart:

```bash
# Install with custom values
helm install kijo-agent kijo/kijo-agent \
  --namespace kijo-system \
  --create-namespace \
  --values values.yaml

# Example values.yaml
databaseUrl: "postgresql://user:pass@postgres:5432/kijo"
clusterName: "production-eu"
notifications:
  slack:
    webhookUrl: "https://hooks.slack.com/services/..."
  severity: "HIGH"
resources:
  limits:
    memory: "256Mi"
    cpu: "200m"
  requests:
    memory: "128Mi"
    cpu: "100m"
```

## Notifications

### Slack Notifications

Configure Slack integration to receive notifications about security changes:

```bash
# Create Slack incoming webhook
export KIJO_NOTIFY_SLACK="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
```

**Slack message format:**
```
🚨 New Critical Vulnerabilities in production

Cluster: production-eu
Namespace: default

Workloads affected:
• web-app: CVE-2024-45337 (golang.org/x/crypto)
• api-server: CVE-2024-3817 (nginx)

View details: https://kijo.example.com/clusters/production-eu
```

### Generic Webhooks

Send notifications to any webhook endpoint:

```bash
export KIJO_NOTIFY_WEBHOOK="https://your-webhook.example.com/security"
```

**Webhook payload:**
```json
{
  "cluster": "production-eu",
  "event": "vulnerabilities_fixed",
  "severity": "CRITICAL",
  "count": 3,
  "workloads": ["web-app", "api-server"],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Kijo SaaS Integration

Connect to the Kijo SaaS platform for centralized vulnerability management:

```bash
export KIJO_SAAS_ENDPOINT="https://api.kijo.io"
export KIJO_SAAS_API_KEY="your-api-key-here"
```

## Health Checks

kijo-agent provides HTTP endpoints for Kubernetes health probes:

- **`GET /health/live`** - Liveness probe (always returns 200 if service is running)
- **`GET /health/ready`** - Readiness probe (checks database connectivity)
- **`GET /metrics`** - Prometheus metrics (if enabled)

**Example probe configuration:**
```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /health/ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
```

## Monitoring and Observability

### Logs

kijo-agent uses structured logging with contextual information:

```json
{
  "level": "info",
  "msg": "vulnerabilities detected",
  "cluster": "production-eu",
  "namespace": "default",
  "new_count": 3,
  "fixed_count": 1,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Database Schema

The agent creates the necessary tables in PostgreSQL:

```sql
-- Track vulnerability lifecycle
CREATE TABLE vulnerability_history (
  id SERIAL PRIMARY KEY,
  cluster_name VARCHAR(255),
  namespace VARCHAR(255),
  workload VARCHAR(255),
  cve_id VARCHAR(50),
  severity VARCHAR(20),
  first_seen TIMESTAMP,
  last_seen TIMESTAMP,
  fixed_at TIMESTAMP
);
```

## Security Considerations

- **Minimal RBAC** - Agent requires only read access to Trivy Operator resources
- **Non-root Container** - Runs as user `65534:65534` in scratch image
- **Secret Management** - All sensitive data stored in Kubernetes secrets
- **Network Policies** - Can be restricted to database and outbound webhook access only

## Troubleshooting

### Common Issues

**Agent not finding vulnerabilities:**
```bash
# Check Trivy Operator is running
kubectl get pods -n trivy-system

# Verify agent can access CRDs
kubectl get vulnerabilityreports --all-namespaces
```

**Database connection errors:**
```bash
# Check database connectivity
kubectl exec -n kijo-system deployment/kijo-agent -- \
  /kijo-agent --database-url=$KIJO_DATABASE_URL --dry-run
```

**Notification failures:**
```bash
# Test webhook manually
curl -X POST "$KIJO_NOTIFY_WEBHOOK" \
  -H "Content-Type: application/json" \
  -d '{"test": true}'
```

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
# Update ConfigMap or set environment variable
KIJO_LOG_LEVEL=debug
KIJO_LOG_FORMAT=text
```

## Development

### Local Development

```bash
# Install dependencies
go mod download

# Run tests
go test -v ./...

# Build
go build -o kijo-agent ./cmd/...

# Run locally (requires kubeconfig)
export KIJO_DATABASE_URL="postgres://..."
./kijo-agent
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run `go test ./...` and `go fmt ./...`
6. Submit a pull request

## License

Distributed under the Apache 2.0 License. See [LICENSE](LICENSE) for more information.
