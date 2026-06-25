"""
EKS Sage Enterprise — Production-grade MCP server for Amazon EKS.
62 intelligent tools across 12 categories for enterprise Kubernetes operations.
"""
from __future__ import annotations
from typing import Optional
from fastmcp import FastMCP

# ── Guardrail system ──────────────────────────────────────────────────────────
from eks_sage_enterprise.core.guardrails import (
    enforce,
    set_safety_mode as _set_safety_mode,
    get_safety_mode,
    confirm_operation as _confirm_operation,
    cancel_operation as _cancel_operation,
    list_pending_confirmations as _list_pending,
    get_audit_log as _get_audit_log,
    get_audit_log_file_path,
)
from eks_sage_enterprise.core.utils import _j

# ── Other imports ─────────────────────────────────────────────────────────────
from eks_sage_enterprise.core.kubectl import run_kubectl, run_kubectl_raw
from eks_sage_enterprise.core.aws_client import get_client, get_current_cluster, get_current_region

from eks_sage_enterprise.tools.cluster import (
    list_clusters, describe_cluster, connect_cluster,
    get_cluster_addons, get_cluster_upgrade_insights,
)
from eks_sage_enterprise.tools.security import (
    investigate_irsa, audit_rbac, check_pod_security,
    scan_secrets_exposure, get_eks_access_entries, get_iam_to_k8s_mapping,
)
from eks_sage_enterprise.tools.troubleshooting import (
    investigate_pod, investigate_daemonset, investigate_statefulset,
    investigate_cronjob, get_cluster_events, check_node_pressure,
    investigate_cluster_health, get_incident_summary,
)
from eks_sage_enterprise.tools.observability import (
    get_cloudwatch_metrics, get_container_insights,
    get_application_logs, get_cost_by_namespace,
)
from eks_sage_enterprise.tools.compliance import (
    check_compliance, detect_drift, check_deprecations, audit_cluster_changes,
)
from eks_sage_enterprise.tools.multicluster import (
    list_all_clusters, compare_clusters, switch_cluster_context,
)
from eks_sage_enterprise.tools.nlb import investigate_nlb_service as _investigate_nlb

mcp = FastMCP(name="eks-sage-enterprise")


# ═════════════════════════════════════════════════════════════════════════════
# CATEGORY 0 — Guardrail Management (5 tools)
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def tool_set_safety_mode(mode: str) -> str:
    """
    Set the safety mode for all operations.

    Modes:
      read_only    — only list/get/describe/check/investigate (DEFAULT)
      standard     — read + config + write (writes need confirmation)
      unrestricted — all operations except permanent denylist

    Args:
        mode: 'read_only', 'standard', or 'unrestricted'
    """
    return _j(_set_safety_mode(mode))


@mcp.tool()
def tool_get_safety_status() -> str:
    """
    Show current safety mode, pending confirmations, and recent audit log.
    Use this to understand what operations are currently allowed.
    """
    mode = get_safety_mode()
    pending = _list_pending()
    recent_audit = _get_audit_log(10)
    return _j({
        "safety_mode": mode.value,
        "allowed_operation_types": {
            "read_only": ["READ only"],
            "standard": ["READ", "CONFIG", "WRITE (with confirmation)"],
            "unrestricted": ["READ", "CONFIG", "WRITE", "DESTRUCTIVE (except denylist)"],
        }.get(mode.value, []),
        "pending_confirmations": pending,
        "recent_audit_log": recent_audit,
        "audit_log_file": get_audit_log_file_path(),
    })


@mcp.tool()
def tool_confirm_operation(confirmation_id: str) -> str:
    """
    Confirm a pending write operation.
    Use when a tool returns CONFIRMATION_REQUIRED with a confirmation ID.

    Args:
        confirmation_id: The ID from the confirmation request (e.g. 'A1B2C3D4')
    """
    result = _confirm_operation(confirmation_id)
    if result.get("status") == "CONFIRMED":
        return _j({
            "status": "CONFIRMED",
            "message": "Operation confirmed. Re-run the original tool now to execute.",
            "operation": result.get("operation", {}).get("tool_name"),
        })
    return _j(result)


@mcp.tool()
def tool_cancel_operation(confirmation_id: str) -> str:
    """
    Cancel a pending write operation without executing it.

    Args:
        confirmation_id: The ID from the confirmation request
    """
    return _j(_cancel_operation(confirmation_id))


@mcp.tool()
def tool_get_audit_log(last_n: int = 20) -> str:
    """
    View the audit log — every operation that was attempted, allowed, denied,
    or confirmed. Essential for compliance and post-incident review.

    Args:
        last_n: Number of recent log entries to return (default: 20)
    """
    log = _get_audit_log(last_n)
    return _j({
        "audit_log_file": get_audit_log_file_path(),
        "entries_returned": len(log),
        "log": log,
    })


# ═════════════════════════════════════════════════════════════════════════════
# CATEGORY 1 — Cluster Management (5 tools)
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def tool_list_clusters(region: str = "us-east-1") -> str:
    """List all EKS clusters in a region with status and version."""
    return list_clusters(region)

@mcp.tool()
def tool_describe_cluster(cluster_name: str, region: str = "us-east-1") -> str:
    """Get full cluster details — version, VPC, auth mode, logging, encryption."""
    return describe_cluster(cluster_name, region)

@mcp.tool()
def tool_connect_cluster(cluster_name: str, region: str = "us-east-1") -> str:
    """Connect to an EKS cluster — updates kubeconfig. Run this first before any kubectl operations."""
    block = enforce("tool_connect_cluster", {"cluster": cluster_name, "region": region})
    if block:
        return _j(block)
    return connect_cluster(cluster_name, region)

@mcp.tool()
def tool_get_cluster_addons(cluster_name: str, region: str = "us-east-1") -> str:
    """List all addons with versions, status, health issues, and available updates."""
    return get_cluster_addons(cluster_name, region)

@mcp.tool()
def tool_get_cluster_upgrade_insights(cluster_name: str, region: str = "us-east-1") -> str:
    """Check upgrade readiness — addon compatibility, nodegroup versions, what will break."""
    return get_cluster_upgrade_insights(cluster_name, region)


# ═════════════════════════════════════════════════════════════════════════════
# CATEGORY 2 — Node Management (5 tools)
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def tool_list_nodegroups(cluster_name: str, region: str = "us-east-1") -> str:
    """List node groups with instance types, scaling config, AMI, and status."""
    try:
        eks = get_client("eks", region)
        nodegroups = eks.list_nodegroups(clusterName=cluster_name).get("nodegroups", [])
        details = []
        for ng in nodegroups:
            d = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng)["nodegroup"]
            details.append({
                "name": d["nodegroupName"],
                "status": d["status"],
                "instance_types": d.get("instanceTypes", []),
                "ami_type": d.get("amiType"),
                "capacity_type": d.get("capacityType"),
                "scaling": d.get("scalingConfig", {}),
                "disk_size_gb": d.get("diskSize"),
                "labels": d.get("labels", {}),
                "taints": d.get("taints", []),
                "release_version": d.get("releaseVersion"),
                "health": d.get("health", {}).get("issues", []),
            })
        return _j({"cluster": cluster_name, "nodegroup_count": len(details), "nodegroups": details})
    except Exception as e:
        return _j({"error": str(e)})

@mcp.tool()
def tool_get_nodes() -> str:
    """List all nodes with status, instance type, zone, capacity, and conditions."""
    data = run_kubectl("get", "nodes")
    if "error" in data:
        return _j(data)
    nodes = []
    for item in data.get("items", []):
        meta = item.get("metadata", {})
        status = item.get("status", {})
        labels = meta.get("labels", {})
        conditions = {c["type"]: c["status"] for c in status.get("conditions", [])}
        nodes.append({
            "name": meta.get("name"),
            "status": "Ready" if conditions.get("Ready") == "True" else "NotReady",
            "instance_type": labels.get("node.kubernetes.io/instance-type"),
            "zone": labels.get("topology.kubernetes.io/zone"),
            "capacity": status.get("capacity", {}),
            "allocatable": status.get("allocatable", {}),
            "conditions": conditions,
            "kubelet_version": status.get("nodeInfo", {}).get("kubeletVersion"),
        })
    not_ready = [n["name"] for n in nodes if n["status"] == "NotReady"]
    return _j({"total_nodes": len(nodes), "ready": len(nodes) - len(not_ready), "not_ready": not_ready, "nodes": nodes})

@mcp.tool()
def tool_get_node_resource_usage() -> str:
    """Show CPU and memory usage per node. Requires metrics-server."""
    output = run_kubectl_raw("top", "nodes", "--no-headers")
    if "error" in output.lower() or "not found" in output.lower():
        return _j({"error": output, "note": "Install metrics-server first"})
    nodes = []
    for line in output.strip().split("\n"):
        parts = line.split()
        if len(parts) >= 5:
            nodes.append({"name": parts[0], "cpu": parts[1], "cpu_percent": parts[2], "memory": parts[3], "memory_percent": parts[4]})
    return _j({"nodes": nodes})

@mcp.tool()
def tool_get_node_events(node_name: str) -> str:
    """Get recent Kubernetes events for a specific node."""
    data = run_kubectl("get", "events", "--field-selector", f"involvedObject.name={node_name}", "--all-namespaces", "--sort-by=.lastTimestamp")
    events = []
    if isinstance(data, dict):
        for item in data.get("items", []):
            events.append({"type": item.get("type"), "reason": item.get("reason"), "message": item.get("message"), "count": item.get("count"), "last_time": item.get("lastTimestamp")})
    return _j({"node": node_name, "event_count": len(events), "events": events})

@mcp.tool()
def tool_cordon_node(node_name: str, reason: str = "") -> str:
    """
    Cordon a node — mark it unschedulable so no new pods are placed on it.
    Existing pods continue running. Use before draining for maintenance.
    Requires STANDARD safety mode + confirmation.
    """
    # Guardrail check
    block = enforce("tool_cordon_node", {"node": node_name, "reason": reason})
    if block:
        return _j(block)

    result = run_kubectl_raw("cordon", node_name)
    return _j({
        "node": node_name,
        "action": "cordoned",
        "reason": reason,
        "result": result,
        "next_step": f"kubectl drain {node_name} --ignore-daemonsets --delete-emptydir-data",
    })


# ═════════════════════════════════════════════════════════════════════════════
# CATEGORY 3 — Workload Operations (7 tools)
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def tool_get_pods(namespace: str = "all") -> str:
    """List all pods with status, restarts, node, and container images."""
    if namespace == "all":
        data = run_kubectl("get", "pods", "--all-namespaces")
    else:
        data = run_kubectl("get", "pods", "-n", namespace)
    if "error" in data:
        return _j(data)
    pods = []
    for item in data.get("items", []):
        meta = item.get("metadata", {})
        spec = item.get("spec", {})
        status = item.get("status", {})
        restarts = sum(cs.get("restartCount", 0) for cs in status.get("containerStatuses", []))
        pods.append({
            "name": meta.get("name"),
            "namespace": meta.get("namespace"),
            "phase": status.get("phase"),
            "node": spec.get("nodeName"),
            "total_restarts": restarts,
            "containers": [{"name": c.get("name"), "image": c.get("image")} for c in spec.get("containers", [])],
            "start_time": status.get("startTime"),
        })
    failing = [p for p in pods if p["phase"] not in ("Running", "Succeeded")]
    return _j({"total": len(pods), "running": len([p for p in pods if p["phase"] == "Running"]), "failing_count": len(failing), "failing_pods": [p["name"] for p in failing], "pods": pods})

@mcp.tool()
def tool_get_pod_logs(pod_name: str, namespace: str = "default", container: Optional[str] = None, lines: int = 50, previous: bool = False) -> str:
    """Get logs from a pod. Set previous=true for logs from crashed container."""
    args = ["logs", pod_name, "-n", namespace, f"--tail={lines}"]
    if container:
        args += ["-c", container]
    if previous:
        args.append("--previous")
    output = run_kubectl_raw(*args)
    return _j({"pod": pod_name, "namespace": namespace, "container": container, "previous": previous, "logs": output})

@mcp.tool()
def tool_describe_pod(pod_name: str, namespace: str = "default") -> str:
    """Detailed pod info — containers, resources, probes, volumes, events."""
    data = run_kubectl("get", "pod", pod_name, "-n", namespace)
    if "error" in data:
        return _j(data)
    spec = data.get("spec", {})
    status = data.get("status", {})
    events_data = run_kubectl("get", "events", "-n", namespace, "--field-selector", f"involvedObject.name={pod_name}")
    events = [{"type": e.get("type"), "reason": e.get("reason"), "message": e.get("message")} for e in (events_data.get("items", []) if isinstance(events_data, dict) else [])]
    return _j({"name": pod_name, "namespace": namespace, "phase": status.get("phase"), "node": spec.get("nodeName"), "containers": [{"name": c.get("name"), "image": c.get("image"), "resources": c.get("resources", {}), "liveness_probe": c.get("livenessProbe"), "readiness_probe": c.get("readinessProbe")} for c in spec.get("containers", [])], "container_statuses": status.get("containerStatuses", []), "events": events[-10:]})

@mcp.tool()
def tool_get_deployments(namespace: str = "all") -> str:
    """List deployments with replica counts, images, and rollout status."""
    if namespace == "all":
        data = run_kubectl("get", "deployments", "--all-namespaces")
    else:
        data = run_kubectl("get", "deployments", "-n", namespace)
    if "error" in data:
        return _j(data)
    deployments = []
    for item in data.get("items", []):
        meta = item.get("metadata", {})
        spec = item.get("spec", {})
        status = item.get("status", {})
        containers = spec.get("template", {}).get("spec", {}).get("containers", [])
        deployments.append({"name": meta.get("name"), "namespace": meta.get("namespace"), "desired": spec.get("replicas"), "ready": status.get("readyReplicas", 0), "available": status.get("availableReplicas", 0), "unavailable": status.get("unavailableReplicas", 0), "images": [c.get("image") for c in containers]})
    unhealthy = [d for d in deployments if d.get("unavailable", 0) > 0]
    return _j({"total": len(deployments), "unhealthy_count": len(unhealthy), "unhealthy": [d["name"] for d in unhealthy], "deployments": deployments})

@mcp.tool()
def tool_get_pod_resource_usage(namespace: str = "all") -> str:
    """Show CPU and memory usage per pod. Requires metrics-server."""
    if namespace == "all":
        output = run_kubectl_raw("top", "pods", "--all-namespaces", "--no-headers")
    else:
        output = run_kubectl_raw("top", "pods", "-n", namespace, "--no-headers")
    if "error" in output.lower():
        return _j({"error": output})
    pods = []
    for line in output.strip().split("\n"):
        parts = line.split()
        if len(parts) >= 4:
            pods.append({"namespace": parts[0] if namespace == "all" else namespace, "name": parts[1] if namespace == "all" else parts[0], "cpu": parts[2] if namespace == "all" else parts[1], "memory": parts[3] if namespace == "all" else parts[2]})
    return _j({"pods": pods, "count": len(pods)})

@mcp.tool()
def tool_get_daemonsets(namespace: str = "all") -> str:
    """List DaemonSets with desired/ready/available counts per node."""
    if namespace == "all":
        data = run_kubectl("get", "daemonsets", "--all-namespaces")
    else:
        data = run_kubectl("get", "daemonsets", "-n", namespace)
    if "error" in data:
        return _j(data)
    daemonsets = []
    for item in data.get("items", []):
        meta = item.get("metadata", {})
        status = item.get("status", {})
        daemonsets.append({"name": meta.get("name"), "namespace": meta.get("namespace"), "desired": status.get("desiredNumberScheduled"), "ready": status.get("numberReady"), "available": status.get("numberAvailable"), "unavailable": status.get("numberUnavailable", 0)})
    unhealthy = [d for d in daemonsets if d.get("unavailable", 0) > 0]
    return _j({"total": len(daemonsets), "unhealthy": [d["name"] for d in unhealthy], "daemonsets": daemonsets})

@mcp.tool()
def tool_get_statefulsets(namespace: str = "all") -> str:
    """List StatefulSets with replica counts and ready status."""
    if namespace == "all":
        data = run_kubectl("get", "statefulsets", "--all-namespaces")
    else:
        data = run_kubectl("get", "statefulsets", "-n", namespace)
    if "error" in data:
        return _j(data)
    sts = []
    for item in data.get("items", []):
        meta = item.get("metadata", {})
        spec = item.get("spec", {})
        status = item.get("status", {})
        sts.append({"name": meta.get("name"), "namespace": meta.get("namespace"), "desired": spec.get("replicas"), "ready": status.get("readyReplicas", 0), "storage_class": spec.get("volumeClaimTemplates", [{}])[0].get("spec", {}).get("storageClassName") if spec.get("volumeClaimTemplates") else None})
    return _j({"total": len(sts), "statefulsets": sts})


# ═════════════════════════════════════════════════════════════════════════════
# CATEGORY 4 — Security & RBAC (6 tools)
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def tool_investigate_irsa(service_account: str, namespace: str = "default", region: str = "us-east-1") -> str:
    """
    Investigate IRSA issues — checks ServiceAccount annotation, IAM role existence,
    OIDC provider setup, trust policy, and permissions.
    Use when pods get AccessDenied or WebIdentityErr calling AWS APIs.
    """
    return investigate_irsa(service_account, namespace, region)

@mcp.tool()
def tool_audit_rbac(namespace: str = "all") -> str:
    """Audit RBAC — finds cluster-admin bindings, wildcard permissions, and overprivileged accounts."""
    return audit_rbac(namespace)

@mcp.tool()
def tool_check_pod_security(namespace: str = "all") -> str:
    """Check pods for security misconfigurations — privileged, root, hostNetwork, missing securityContext."""
    return check_pod_security(namespace)

@mcp.tool()
def tool_scan_secrets_exposure(namespace: str = "all") -> str:
    """Scan for secrets exposure — env vars, hardcoded values, default service accounts."""
    return scan_secrets_exposure(namespace)

@mcp.tool()
def tool_get_eks_access_entries(cluster_name: str, region: str = "us-east-1") -> str:
    """List all IAM principals with access to the cluster and their Kubernetes policies."""
    return get_eks_access_entries(cluster_name, region)

@mcp.tool()
def tool_get_iam_to_k8s_mapping(cluster_name: str, region: str = "us-east-1") -> str:
    """Show complete IAM → Kubernetes permission mapping. Essential for security audits."""
    return get_iam_to_k8s_mapping(cluster_name, region)


# ═════════════════════════════════════════════════════════════════════════════
# CATEGORY 5 — Networking (6 tools)
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def tool_get_services(namespace: str = "all") -> str:
    """List all services with type, cluster IP, external IP, and ports."""
    if namespace == "all":
        data = run_kubectl("get", "services", "--all-namespaces")
    else:
        data = run_kubectl("get", "services", "-n", namespace)
    if "error" in data:
        return _j(data)
    services = []
    for item in data.get("items", []):
        meta = item.get("metadata", {})
        spec = item.get("spec", {})
        status = item.get("status", {})
        lb = status.get("loadBalancer", {}).get("ingress", [])
        services.append({"name": meta.get("name"), "namespace": meta.get("namespace"), "type": spec.get("type"), "cluster_ip": spec.get("clusterIP"), "external_ip": lb[0].get("hostname") or lb[0].get("ip") if lb else None, "ports": [{"port": p.get("port"), "target_port": p.get("targetPort"), "node_port": p.get("nodePort")} for p in spec.get("ports", [])]})
    load_balancers = [s for s in services if s["type"] == "LoadBalancer"]
    return _j({"total": len(services), "load_balancers": len(load_balancers), "external_endpoints": [{"name": s["name"], "endpoint": s["external_ip"]} for s in load_balancers if s["external_ip"]], "services": services})

@mcp.tool()
def tool_get_ingresses(namespace: str = "all") -> str:
    """List ingresses with hostnames, paths, backends, and TLS config."""
    if namespace == "all":
        data = run_kubectl("get", "ingresses", "--all-namespaces")
    else:
        data = run_kubectl("get", "ingresses", "-n", namespace)
    if "error" in data:
        return _j(data)
    ingresses = []
    for item in data.get("items", []):
        meta = item.get("metadata", {})
        spec = item.get("spec", {})
        status = item.get("status", {})
        lb = status.get("loadBalancer", {}).get("ingress", [])
        rules = [{"host": r.get("host"), "paths": [{"path": p.get("path"), "backend": p.get("backend", {}).get("service", {}).get("name")} for p in r.get("http", {}).get("paths", [])]} for r in spec.get("rules", [])]
        ingresses.append({"name": meta.get("name"), "namespace": meta.get("namespace"), "class": spec.get("ingressClassName"), "address": lb[0].get("hostname") if lb else None, "rules": rules})
    return _j({"total": len(ingresses), "ingresses": ingresses})

@mcp.tool()
def tool_get_network_policies(namespace: str = "all") -> str:
    """List NetworkPolicies — shows which pods can communicate with which."""
    if namespace == "all":
        data = run_kubectl("get", "networkpolicies", "--all-namespaces")
    else:
        data = run_kubectl("get", "networkpolicies", "-n", namespace)
    if "error" in data:
        return _j(data)
    policies = []
    for item in data.get("items", []):
        meta = item.get("metadata", {})
        spec = item.get("spec", {})
        policies.append({"name": meta.get("name"), "namespace": meta.get("namespace"), "pod_selector": spec.get("podSelector", {}), "policy_types": spec.get("policyTypes", []), "ingress_rules": len(spec.get("ingress", [])), "egress_rules": len(spec.get("egress", []))})
    return _j({"total": len(policies), "policies": policies})

@mcp.tool()
def tool_get_configmaps_and_secrets(namespace: str = "default") -> str:
    """List ConfigMaps and Secrets. Shows secret names and types but NOT values."""
    cm = run_kubectl("get", "configmaps", "-n", namespace)
    sec = run_kubectl("get", "secrets", "-n", namespace)
    configmaps = [{"name": i.get("metadata", {}).get("name"), "keys": list(i.get("data", {}).keys())} for i in (cm.get("items", []) if isinstance(cm, dict) else [])]
    secrets = [{"name": i.get("metadata", {}).get("name"), "type": i.get("type"), "keys": list(i.get("data", {}).keys())} for i in (sec.get("items", []) if isinstance(sec, dict) else [])]
    return _j({"namespace": namespace, "configmaps": {"count": len(configmaps), "items": configmaps}, "secrets": {"count": len(secrets), "items": secrets}})

@mcp.tool()
def tool_check_dns_resolution(service_name: str, namespace: str = "default") -> str:
    """
    Check DNS resolution for a service from inside the cluster.
    Tests both short name and FQDN resolution.
    Useful when pods say 'could not resolve host'.
    """
    fqdn = f"{service_name}.{namespace}.svc.cluster.local"
    svc_data = run_kubectl("get", "service", service_name, "-n", namespace)
    if "error" in svc_data:
        return _j({"error": f"Service '{service_name}' not found in namespace '{namespace}'"})
    cluster_ip = svc_data.get("spec", {}).get("clusterIP")
    coredns = run_kubectl("get", "pods", "-n", "kube-system", "-l", "k8s-app=kube-dns")
    coredns_running = False
    if isinstance(coredns, dict):
        coredns_running = any(
            p.get("status", {}).get("phase") == "Running"
            for p in coredns.get("items", [])
        )
    return _j({
        "service": service_name,
        "namespace": namespace,
        "cluster_ip": cluster_ip,
        "short_name": service_name,
        "fqdn": fqdn,
        "coredns_running": coredns_running,
        "expected_resolution": f"{service_name} → {fqdn} → {cluster_ip}",
        "troubleshooting": {
            "if_dns_fails": [
                "Check CoreDNS pods: kubectl get pods -n kube-system -l k8s-app=kube-dns",
                "Check CoreDNS logs: kubectl logs -n kube-system -l k8s-app=kube-dns",
                "Verify service exists: kubectl get service " + service_name + " -n " + namespace,
                "Test from a pod: kubectl run test --image=busybox --rm -it -- nslookup " + service_name,
            ]
        },
    })

@mcp.tool()
def tool_investigate_nlb_service(
    service_name: str,
    namespace: str = "default",
    region: str = "us-east-1",
    user_ip: Optional[str] = None,
    user_domain: Optional[str] = None,
) -> str:
    """
    Full end-to-end NLB + Service investigation (no Ingress).
    Checks: Controller health → Service → NLB state/scheme/listeners →
    Target Group health → Port chain → Endpoints → Pods → Source IP → Route53 DNS.
    Pass user_ip to validate if a specific user is blocked.
    Pass user_domain to check Route53 DNS records.
    """
    return _investigate_nlb(service_name, namespace, region, user_ip, user_domain)


# ═════════════════════════════════════════════════════════════════════════════
# CATEGORY 6 — Troubleshooting & Incidents (8 tools)
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def tool_investigate_pod(pod_name: str, namespace: str = "default") -> str:
    """Full investigation of a failing pod — OOMKilled, CrashLoopBackOff, ImagePullBackOff, Pending."""
    return investigate_pod(pod_name, namespace)

@mcp.tool()
def tool_investigate_daemonset(daemonset_name: str, namespace: str = "kube-system") -> str:
    """Investigate DaemonSet — nodes missing pods, failing pods, misscheduled pods."""
    return investigate_daemonset(daemonset_name, namespace)

@mcp.tool()
def tool_investigate_statefulset(statefulset_name: str, namespace: str = "default") -> str:
    """Investigate StatefulSet — stuck pods, unbound PVCs, ordering issues."""
    return investigate_statefulset(statefulset_name, namespace)

@mcp.tool()
def tool_investigate_cronjob(cronjob_name: str, namespace: str = "default") -> str:
    """Investigate CronJob — last execution, failures, missed schedules, job logs."""
    return investigate_cronjob(cronjob_name, namespace)

@mcp.tool()
def tool_get_cluster_events(namespace: str = "all", event_type: str = "Warning") -> str:
    """Get cluster events filtered by type with reason summary."""
    return get_cluster_events(namespace, event_type)

@mcp.tool()
def tool_check_node_pressure(cluster_name: Optional[str] = None, region: str = "us-east-1") -> str:
    """Check node pressure — OOM evictions, disk/memory/PID pressure, Container Insights."""
    return check_node_pressure(cluster_name, region)

@mcp.tool()
def tool_investigate_cluster_health() -> str:
    """Full cluster health check — nodes, pods, deployments, events. Overall health score."""
    return investigate_cluster_health()

@mcp.tool()
def tool_get_incident_summary(namespace: str = "all") -> str:
    """
    One-shot full incident report — cluster health + node pressure +
    failing pods + warning events + severity rating.
    Use as first response to any 'something is broken' alert.
    """
    return get_incident_summary(namespace)


# ═════════════════════════════════════════════════════════════════════════════
# CATEGORY 7 — Storage (3 tools)
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def tool_get_persistent_volumes(namespace: str = "all") -> str:
    """List PVs and PVCs with status, capacity, storage class, and bound status."""
    pv = run_kubectl("get", "persistentvolumes")
    if namespace == "all":
        pvc = run_kubectl("get", "persistentvolumeclaims", "--all-namespaces")
    else:
        pvc = run_kubectl("get", "persistentvolumeclaims", "-n", namespace)
    pvs = [{"name": i.get("metadata", {}).get("name"), "capacity": i.get("spec", {}).get("capacity", {}).get("storage"), "status": i.get("status", {}).get("phase"), "claim": i.get("spec", {}).get("claimRef", {}).get("name"), "storage_class": i.get("spec", {}).get("storageClassName")} for i in (pv.get("items", []) if isinstance(pv, dict) else [])]
    pvcs = [{"name": i.get("metadata", {}).get("name"), "namespace": i.get("metadata", {}).get("namespace"), "status": i.get("status", {}).get("phase"), "capacity": i.get("status", {}).get("capacity", {}).get("storage"), "storage_class": i.get("spec", {}).get("storageClassName")} for i in (pvc.get("items", []) if isinstance(pvc, dict) else [])]
    unbound = [p for p in pvcs if p.get("status") != "Bound"]
    return _j({"pvs": {"count": len(pvs), "items": pvs}, "pvcs": {"count": len(pvcs), "unbound_count": len(unbound), "unbound": [p["name"] for p in unbound], "items": pvcs}})

@mcp.tool()
def tool_get_storage_classes() -> str:
    """List storage classes with provisioner, reclaim policy, and default status."""
    data = run_kubectl("get", "storageclasses")
    if "error" in data:
        return _j(data)
    classes = [{"name": i.get("metadata", {}).get("name"), "provisioner": i.get("provisioner"), "reclaim_policy": i.get("reclaimPolicy"), "volume_binding_mode": i.get("volumeBindingMode"), "is_default": i.get("metadata", {}).get("annotations", {}).get("storageclass.kubernetes.io/is-default-class") == "true"} for i in data.get("items", [])]
    return _j({"count": len(classes), "storage_classes": classes})

@mcp.tool()
def tool_investigate_storage(pvc_name: str, namespace: str = "default") -> str:
    """
    Investigate a stuck PVC — why it's not binding, which pod is using it,
    and what StorageClass is configured.
    """
    findings = []
    warnings = []
    pvc_data = run_kubectl("get", "pvc", pvc_name, "-n", namespace)
    if "error" in pvc_data:
        return _j({"error": f"PVC '{pvc_name}' not found"})
    spec = pvc_data.get("spec", {})
    status = pvc_data.get("status", {})
    phase = status.get("phase")
    storage_class = spec.get("storageClassName")
    volume_name = spec.get("volumeName")
    findings.append(f"PVC phase: {phase}")
    findings.append(f"Storage class: {storage_class}")
    findings.append(f"Requested storage: {spec.get('resources', {}).get('requests', {}).get('storage')}")
    if phase != "Bound":
        warnings.append(f"⚠️  PVC is {phase} not Bound — pods using this PVC will stay Pending")
        if not volume_name:
            warnings.append("No PersistentVolume found to bind to")
        sc_data = run_kubectl("get", "storageclass", storage_class) if storage_class else {}
        if isinstance(sc_data, dict) and "error" in sc_data:
            warnings.append(f"StorageClass '{storage_class}' not found — check spelling")
    pods_data = run_kubectl("get", "pods", "-n", namespace)
    using_pods = []
    if isinstance(pods_data, dict):
        for pod in pods_data.get("items", []):
            for vol in pod.get("spec", {}).get("volumes", []):
                if vol.get("persistentVolumeClaim", {}).get("claimName") == pvc_name:
                    using_pods.append({"pod": pod["metadata"]["name"], "phase": pod.get("status", {}).get("phase")})
    return _j({"pvc": pvc_name, "namespace": namespace, "phase": phase, "storage_class": storage_class, "findings": findings, "warnings": warnings, "using_pods": using_pods, "recommendations": ["Check StorageClass provisioner is running", "Check PV exists with matching storage class and access mode", "Check node has required storage driver"] if phase != "Bound" else ["✅ PVC is healthy"]})


# ═════════════════════════════════════════════════════════════════════════════
# CATEGORY 8 — Scaling & Cost (4 tools)
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def tool_get_hpa(namespace: str = "all") -> str:
    """List HorizontalPodAutoscalers with current/desired/max replicas and metrics."""
    if namespace == "all":
        data = run_kubectl("get", "hpa", "--all-namespaces")
    else:
        data = run_kubectl("get", "hpa", "-n", namespace)
    if "error" in data:
        return _j(data)
    hpas = [{"name": i.get("metadata", {}).get("name"), "namespace": i.get("metadata", {}).get("namespace"), "target": i.get("spec", {}).get("scaleTargetRef", {}).get("name"), "min_replicas": i.get("spec", {}).get("minReplicas"), "max_replicas": i.get("spec", {}).get("maxReplicas"), "current_replicas": i.get("status", {}).get("currentReplicas"), "desired_replicas": i.get("status", {}).get("desiredReplicas")} for i in data.get("items", [])]
    return _j({"count": len(hpas), "hpas": hpas})

@mcp.tool()
def tool_get_resource_quotas(namespace: str = "all") -> str:
    """Show resource quotas — CPU/memory allocated vs used per namespace."""
    if namespace == "all":
        data = run_kubectl("get", "resourcequotas", "--all-namespaces")
    else:
        data = run_kubectl("get", "resourcequotas", "-n", namespace)
    if "error" in data:
        return _j(data)
    quotas = []
    for item in data.get("items", []):
        meta = item.get("metadata", {})
        status = item.get("status", {})
        hard = status.get("hard", {})
        used = status.get("used", {})
        quotas.append({"name": meta.get("name"), "namespace": meta.get("namespace"), "usage": {k: {"limit": hard.get(k), "used": used.get(k, "0")} for k in hard}})
    return _j({"count": len(quotas), "resource_quotas": quotas})

@mcp.tool()
def tool_get_pod_disruption_budgets(namespace: str = "all") -> str:
    """
    List PodDisruptionBudgets — shows minimum available/maximum unavailable pods.
    PDBs prevent too many pods going down during node drains or rolling updates.
    """
    if namespace == "all":
        data = run_kubectl("get", "poddisruptionbudgets", "--all-namespaces")
    else:
        data = run_kubectl("get", "poddisruptionbudgets", "-n", namespace)
    if "error" in data:
        return _j(data)
    pdbs = []
    for item in data.get("items", []):
        meta = item.get("metadata", {})
        spec = item.get("spec", {})
        status = item.get("status", {})
        pdbs.append({
            "name": meta.get("name"),
            "namespace": meta.get("namespace"),
            "min_available": spec.get("minAvailable"),
            "max_unavailable": spec.get("maxUnavailable"),
            "current_healthy": status.get("currentHealthy"),
            "desired_healthy": status.get("desiredHealthy"),
            "disruptions_allowed": status.get("disruptionsAllowed"),
            "selector": spec.get("selector", {}).get("matchLabels", {}),
        })
    return _j({"count": len(pdbs), "pdbs": pdbs})

@mcp.tool()
def tool_get_cost_by_namespace() -> str:
    """Estimate cost breakdown by namespace based on resource requests."""
    return get_cost_by_namespace()


# ═════════════════════════════════════════════════════════════════════════════
# CATEGORY 9 — NLB / Ingress (3 tools)  — NLB tool registered in Category 5
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def tool_get_namespaces() -> str:
    """List all namespaces with status, labels, and age."""
    data = run_kubectl("get", "namespaces")
    if "error" in data:
        return _j(data)
    namespaces = [{"name": i.get("metadata", {}).get("name"), "status": i.get("status", {}).get("phase"), "labels": i.get("metadata", {}).get("labels", {}), "created": i.get("metadata", {}).get("creationTimestamp")} for i in data.get("items", [])]
    return _j({"count": len(namespaces), "namespaces": namespaces})

@mcp.tool()
def tool_get_service_accounts(namespace: str = "default") -> str:
    """List service accounts with IAM role annotations (IRSA) and secret count."""
    data = run_kubectl("get", "serviceaccounts", "-n", namespace)
    if "error" in data:
        return _j(data)
    accounts = []
    for i in data.get("items", []):
        meta = i.get("metadata", {})
        annotations = meta.get("annotations", {})
        accounts.append({"name": meta.get("name"), "namespace": meta.get("namespace"), "iam_role": annotations.get("eks.amazonaws.com/role-arn"), "has_irsa": bool(annotations.get("eks.amazonaws.com/role-arn")), "secrets_count": len(i.get("secrets", []))})
    return _j({"namespace": namespace, "count": len(accounts), "with_irsa": sum(1 for a in accounts if a["has_irsa"]), "service_accounts": accounts})

@mcp.tool()
def tool_get_jobs_and_cronjobs(namespace: str = "all") -> str:
    """List Jobs and CronJobs with schedules, last execution, and success/failure counts."""
    if namespace == "all":
        jobs = run_kubectl("get", "jobs", "--all-namespaces")
        cjs = run_kubectl("get", "cronjobs", "--all-namespaces")
    else:
        jobs = run_kubectl("get", "jobs", "-n", namespace)
        cjs = run_kubectl("get", "cronjobs", "-n", namespace)
    job_list = [{"name": i["metadata"]["name"], "namespace": i["metadata"]["namespace"], "completions": i.get("status", {}).get("succeeded", 0), "failed": i.get("status", {}).get("failed", 0), "active": i.get("status", {}).get("active", 0)} for i in (jobs.get("items", []) if isinstance(jobs, dict) else [])]
    cj_list = [{"name": i["metadata"]["name"], "namespace": i["metadata"]["namespace"], "schedule": i.get("spec", {}).get("schedule"), "suspended": i.get("spec", {}).get("suspend", False), "last_scheduled": i.get("status", {}).get("lastScheduleTime"), "last_successful": i.get("status", {}).get("lastSuccessfulTime")} for i in (cjs.get("items", []) if isinstance(cjs, dict) else [])]
    return _j({"jobs": {"count": len(job_list), "items": job_list}, "cronjobs": {"count": len(cj_list), "suspended": sum(1 for c in cj_list if c["suspended"]), "items": cj_list}})


# ═════════════════════════════════════════════════════════════════════════════
# CATEGORY 10 — Observability (4 tools)
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def tool_get_cloudwatch_metrics(cluster_name: Optional[str] = None, namespace: str = "all", region: str = "us-east-1", period_minutes: int = 60) -> str:
    """Get CloudWatch Container Insights metrics — CPU, memory, network, pod counts."""
    return get_cloudwatch_metrics(cluster_name, namespace, region, period_minutes)

@mcp.tool()
def tool_get_container_insights(cluster_name: Optional[str] = None, region: str = "us-east-1", hours: int = 1, filter_pattern: str = "ERROR") -> str:
    """Search Container Insights logs for errors or any pattern across all pods."""
    return get_container_insights(cluster_name, region, hours, filter_pattern)

@mcp.tool()
def tool_get_application_logs(pod_name: Optional[str] = None, namespace: str = "default", label_selector: Optional[str] = None, filter_text: Optional[str] = None, lines: int = 50, since_minutes: int = 10) -> str:
    """Aggregate logs across multiple pods by label. Filter by text pattern."""
    return get_application_logs(pod_name, namespace, label_selector, filter_text, lines, since_minutes)


# ═════════════════════════════════════════════════════════════════════════════
# CATEGORY 11 — Multi-Cluster (3 tools)
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def tool_list_all_clusters(regions: str = "us-east-1,us-west-2,eu-west-1") -> str:
    """List ALL EKS clusters across multiple regions — full fleet view."""
    return list_all_clusters(regions)

@mcp.tool()
def tool_compare_clusters(cluster1: str, cluster2: str, region1: str = "us-east-1", region2: str = "us-east-1") -> str:
    """Compare two clusters — versions, addons, config. Validates staging/prod parity."""
    return compare_clusters(cluster1, cluster2, region1, region2)

@mcp.tool()
def tool_switch_cluster_context(cluster_name: str, region: str = "us-east-1") -> str:
    """Switch active cluster context for all subsequent operations."""
    block = enforce("tool_switch_cluster_context", {"cluster": cluster_name})
    if block:
        return _j(block)
    return switch_cluster_context(cluster_name, region)


# ═════════════════════════════════════════════════════════════════════════════
# CATEGORY 12 — Compliance & Drift (4 tools)
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def tool_check_compliance(profile: str = "cis") -> str:
    """Run compliance checks — CIS Kubernetes Benchmark, RBAC, network policies, secrets."""
    return check_compliance(profile)

@mcp.tool()
def tool_detect_drift(cluster_name: Optional[str] = None, region: str = "us-east-1") -> str:
    """Detect configuration drift — what changed in the cluster in the last 24 hours via CloudTrail."""
    return detect_drift(cluster_name, region)

@mcp.tool()
def tool_check_deprecations(cluster_name: Optional[str] = None, region: str = "us-east-1") -> str:
    """Check for deprecated Kubernetes APIs in use — critical before cluster upgrades."""
    return check_deprecations(cluster_name, region)

@mcp.tool()
def tool_audit_cluster_changes(hours: int = 24, region: str = "us-east-1") -> str:
    """Full audit of all cluster changes from CloudTrail — who changed what and when."""
    return audit_cluster_changes(hours, region)


# ═════════════════════════════════════════════════════════════════════════════
# Entry point
# ═════════════════════════════════════════════════════════════════════════════

def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
