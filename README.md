# EKS Sage Enterprise

> **62 MCP tools that turn 3-hour EKS incidents into 10-second diagnoses.**

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.11+-yellow.svg)
![Tools](https://img.shields.io/badge/tools-62-purple.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

---

## How It Works

eks-sage runs **locally on your machine** and connects to **your own AWS account** using your existing AWS credentials. You keep full control — no data leaves your machine except your own AWS API calls.

```
Your Machine
├── ~/.aws/credentials     ← your AWS keys (already configured)
├── ~/.kube/config         ← your cluster config (updated by eks-sage)
└── eks-sage-enterprise    ← reads credentials, talks to YOUR AWS
        ↓
YOUR AWS Account
        ↓
YOUR EKS Cluster
```

---

## Prerequisites

Before installing, make sure you have these on your machine:

**1 — AWS CLI + profiles configured**
```bash
# Install AWS CLI
brew install awscli

# Check your existing profiles
cat ~/.aws/config

# You should have profiles like:
# [profile dev]
# [profile nonprod]
# [profile prod]

# Verify a profile works
aws sts get-caller-identity --profile dev
aws sts get-caller-identity --profile nonprod
aws sts get-caller-identity --profile prod
```

Your `~/.aws/config` typically looks like:
```ini
[profile dev]
region = us-east-1
role_arn = arn:aws:iam::111111111111:role/DevRole
source_profile = default

[profile nonprod]
region = us-east-1
role_arn = arn:aws:iam::222222222222:role/NonProdRole
source_profile = default

[profile prod]
region = us-east-1
role_arn = arn:aws:iam::333333333333:role/ProdRole
source_profile = default
```

Then tell eks-sage which profile to use:
```bash
# For dev cluster
AWS_PROFILE=dev claude mcp add eks-sage -s user -- python -m eks_sage_enterprise.server

# Or set it in your environment
export AWS_PROFILE=nonprod
```

Or just ask Claude:
```
select profile nonprod
connect to cluster my-nonprod-cluster in us-east-1
```

**2 — kubectl**
```bash
brew install kubectl
```

**3 — Python 3.11+**
```bash
python3 --version
# Should show 3.11 or higher
```

**4 — A Claude MCP client**

Works with: Claude Desktop · Claude Code · Cursor · Windsurf · Cline · Zed

---

## Install

```bash
pip install eks-sage-enterprise
claude mcp add eks-sage -s user -- python -m eks_sage_enterprise.server
```

Verify it connected:
```bash
claude mcp list
# Should show: eks-sage ✅ Connected
```

---

## Quick Start

```
# Connect to your cluster first
connect to cluster my-cluster in us-east-1

# Then ask anything
give me a full cluster health check
investigate NLB service my-api user_ip 203.0.113.45
investigate IRSA for service account my-sa in namespace production
check compliance profile cis
```

---

## Your Data stays on Your Machine

```
eks-sage ONLY makes calls to:
  → AWS APIs (*.amazonaws.com) using YOUR credentials
  → Your kubectl (~/.kube/config)
  → CloudWatch logs in YOUR account

eks-sage NEVER:
  → Sends data to any third party
  → Stores your credentials
  → Shares anything outside your machine
```

## 62 Tools · 12 Categories

| Category | Tools | Description |
|---|---|---|
| Guardrails | 5 | Safety mode, confirmation gate, audit log |
| Cluster | 5 | List, describe, connect, addons, upgrade insights |
| Nodes | 5 | Nodegroups, nodes, usage, events, cordon |
| Workloads | 8 | Pods, logs, deployments, daemonsets, statefulsets, jobs, cronjobs |
| Security | 7 | IRSA, RBAC audit, pod security, secrets, IAM mapping, service accounts |
| Networking | 7 | Services, ingresses, namespaces, DNS check, NLB investigation |
| Troubleshooting | 8 | Investigate pod/daemonset/statefulset/cronjob, health check, incident summary |
| Storage | 3 | PVs, PVCs, storage investigation |
| Scaling | 4 | HPA, quotas, PDBs, cost by namespace |
| Observability | 3 | CloudWatch, Container Insights, log aggregation |
| Multi-Cluster | 3 | Fleet view, compare, switch context |
| Compliance | 4 | CIS benchmark, drift, deprecations, audit trail |

---

## What to Ask — All 12 Categories

### 🛡️ Guardrails
```
set safety mode to standard
get safety status
confirm A1B2C3D4
show me the audit log
```

### 🏗️ Cluster Management
```
list my EKS clusters in us-east-1
connect to cluster my-cluster in us-east-1
what addons are installed on my cluster
is my cluster ready to upgrade
describe cluster my-cluster
```

### 🖥️ Node Management
```
show all nodes and their status
show CPU and memory usage per node
list my node groups
get events for node i-0abc123
```

### 📦 Workload Operations
```
show all pods across namespaces
get logs from pod my-app-xyz in namespace production
list all deployments
show all daemonsets
list statefulsets in namespace data
show CPU usage per pod
show jobs and cronjobs
```

### 🔐 Security & RBAC
```
investigate IRSA for service account my-sa in namespace production
audit RBAC permissions
check pod security across all namespaces
scan for secrets exposed as env vars
who has access to my cluster
show IAM to Kubernetes permission mapping
```

### 🌐 Networking & NLB
```
show all services and load balancers
investigate NLB service my-api namespace production user_ip 1.2.3.4
investigate NLB service my-api user_domain app.example.com
list all ingresses
check DNS resolution for my-service in namespace production
show network policies
list configmaps and secrets in namespace production
```

### 🔍 Troubleshooting & Incidents ← Most Used
```
give me a full cluster health check
something is broken — give me a full incident report
investigate pod my-app-xyz in namespace production
check for node pressure and OOM evictions
show all warning events in the cluster
investigate daemonset aws-node in kube-system
investigate statefulset my-db in namespace data
investigate cronjob my-backup in namespace ops
```

### 💾 Storage
```
show all PVs and PVCs
investigate stuck PVC my-data-pvc in namespace production
list storage classes
```

### 📈 Scaling & Cost
```
show horizontal pod autoscalers
show resource quotas per namespace
show pod disruption budgets
get cost breakdown by namespace
```

### 👁️ Observability
```
get CloudWatch metrics for my cluster
search Container Insights for ERROR logs last 2 hours
get logs from all pods with label app=my-api filter ERROR
show cost breakdown by namespace
```

### 🌍 Multi-Cluster
```
list all my EKS clusters across us-east-1 and eu-west-1
compare cluster staging to cluster production
switch to production cluster in us-west-2
```

### ✅ Compliance & Drift
```
check compliance profile cis
detect drift in my cluster last 24 hours
check for deprecated APIs before upgrading
show all cluster changes in last 24 hours
```

---

## 5-Layer Guardrail System

```
Layer 1 — Operation Classification  (READ/CONFIG/WRITE/DESTRUCTIVE)
Layer 2 — Safety Mode               (read_only / standard / unrestricted)
Layer 3 — Denylist                  (74 permanently blocked operations)
Layer 4 — Confirmation Gate         (writes require explicit approval)
Layer 5 — Audit Log                 (/tmp/eks-sage-audit.log)
```

## License

MIT — free for everyone. Commercial use welcome.
