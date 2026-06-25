# Changelog

## [2.0.0] — 2025-06-23

### Added
- 62 MCP tools across 12 categories (up from 29)
- 5-layer guardrail system (safety modes, denylist, confirmation gate, audit log)
- Category 4: Security & RBAC (investigate_irsa, audit_rbac, check_pod_security, scan_secrets_exposure, get_iam_to_k8s_mapping)
- Category 6: Extended troubleshooting (investigate_daemonset, investigate_statefulset, investigate_cronjob, get_incident_summary)
- Category 7: Storage investigation (investigate_storage for stuck PVCs)
- Category 10: Observability (CloudWatch metrics, Container Insights, log aggregation, cost by namespace)
- Category 11: Multi-cluster (list_all_clusters, compare_clusters, switch_cluster_context)
- Category 12: Compliance & Drift (check_compliance CIS, detect_drift, check_deprecations, audit_cluster_changes)
- NLB tool: 8-step investigation including Route53, controller health, target type, NLB scheme
- NLB tool: user_ip validation against annotation source ranges AND security group rules
- NLB tool: user_domain Route53 DNS record validation

### Fixed
- CoreDNS detection now supports EKS Auto Mode labels
- annotations variable scope bug in NLB tool Step 7
- FastMCP description parameter removed (API change)

## [1.0.0] — 2025-04-10

### Added
- Initial release
- 29 MCP tools across 9 categories
- Basic kubectl and boto3 integration
- NLB service investigation (5 steps)
- Cluster health check
- Pod investigation
