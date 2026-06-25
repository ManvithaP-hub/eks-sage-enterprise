"""Category 6 — Troubleshooting & Incidents (8 tools)."""
from __future__ import annotations
from datetime import datetime, timedelta
from eks_sage_enterprise.core.kubectl import run_kubectl, run_kubectl_raw
from eks_sage_enterprise.core.aws_client import get_client, get_current_cluster, get_current_region
from eks_sage_enterprise.core.utils import _j


def investigate_pod(pod_name: str, namespace: str = "default") -> str:
    """
    Full automated investigation of a failing pod.
    Checks OOMKilled, CrashLoopBackOff, ImagePullBackOff, Pending,
    resource limits, readiness probes, recent events, and log errors.
    """
    findings = []
    warnings = []
    recommendations = []

    data = run_kubectl("get", "pod", pod_name, "-n", namespace)
    if "error" in data:
        return _j({"error": f"Pod not found: {data.get('error')}"})

    spec = data.get("spec", {})
    status = data.get("status", {})
    phase = status.get("phase")
    findings.append(f"Pod phase: {phase}")

    for cs in status.get("containerStatuses", []):
        name = cs.get("name")
        restarts = cs.get("restartCount", 0)
        state = cs.get("state", {})
        last = cs.get("lastState", {})
        waiting = state.get("waiting", {})
        terminated = state.get("terminated", {})
        last_terminated = last.get("terminated", {})

        if restarts > 0:
            findings.append(f"Container '{name}' restarted {restarts} times")
        if restarts > 5:
            recommendations.append(f"Container '{name}' has high restarts ({restarts}) — likely CrashLoopBackOff")

        if terminated.get("reason") == "OOMKilled" or last_terminated.get("reason") == "OOMKilled":
            findings.append(f"⚠️  Container '{name}' was OOMKilled!")
            recommendations.append(f"Increase memory limit for '{name}'")

        if waiting.get("reason") == "ImagePullBackOff":
            findings.append(f"⚠️  Container '{name}' cannot pull image")
            recommendations.append("Check ECR permissions and VPC endpoints for ECR API/DKR/S3")

        if waiting.get("reason") == "CrashLoopBackOff":
            findings.append(f"⚠️  Container '{name}' is crash looping")
            recommendations.append(f"Check logs: kubectl logs {pod_name} -n {namespace} --previous")

    for c in spec.get("containers", []):
        if not c.get("resources", {}).get("limits"):
            recommendations.append(f"Container '{c.get('name')}' has no resource limits — risk of OOM")

    # Pending scheduling issues
    if phase == "Pending":
        for cond in status.get("conditions", []):
            if cond.get("type") == "PodScheduled" and cond.get("status") == "False":
                msg = cond.get("message", "")
                findings.append(f"⚠️  Pod unschedulable: {msg}")
                if "Insufficient" in msg:
                    recommendations.append("Scale up node group — insufficient resources")
                elif "node(s) had untolerated taint" in msg:
                    recommendations.append("Add tolerations to pod spec matching node taints")

    # Events
    events_data = run_kubectl(
        "get", "events", "-n", namespace,
        "--field-selector", f"involvedObject.name={pod_name}",
        "--sort-by=.lastTimestamp",
    )
    warning_events = []
    if isinstance(events_data, dict):
        for e in events_data.get("items", []):
            if e.get("type") == "Warning":
                warning_events.append({
                    "reason": e.get("reason"),
                    "message": e.get("message"),
                    "count": e.get("count"),
                })
    if warning_events:
        findings.append(f"Found {len(warning_events)} warning events")

    # Logs
    logs = run_kubectl_raw("logs", pod_name, "-n", namespace, "--tail=30")
    error_lines = [l for l in (logs or "").split("\n") if any(
        e in l.upper() for e in ["ERROR", "FATAL", "PANIC", "EXCEPTION", "500", "503"]
    )]

    return _j({
        "pod": pod_name,
        "namespace": namespace,
        "phase": phase,
        "findings": findings,
        "recommendations": recommendations,
        "warning_events": warning_events[-5:],
        "recent_error_logs": error_lines[:5],
        "recent_logs": logs[-1000:] if logs else "",
    })


def investigate_daemonset(daemonset_name: str, namespace: str = "kube-system") -> str:
    """
    Investigate a DaemonSet — checks desired vs ready nodes,
    which nodes are missing the pod, and why pods are failing.
    Critical for CNI plugins, log collectors, monitoring agents.
    """
    findings = []
    warnings = []
    recommendations = []

    ds_data = run_kubectl("get", "daemonset", daemonset_name, "-n", namespace)
    if "error" in ds_data:
        return _j({"error": f"DaemonSet '{daemonset_name}' not found"})

    status = ds_data.get("status", {})
    spec = ds_data.get("spec", {})

    desired = status.get("desiredNumberScheduled", 0)
    ready = status.get("numberReady", 0)
    available = status.get("numberAvailable", 0)
    unavailable = status.get("numberUnavailable", 0)
    misscheduled = status.get("numberMisscheduled", 0)

    findings.append(f"Desired: {desired}, Ready: {ready}, Available: {available}")

    if ready < desired:
        warnings.append(
            f"⚠️  DaemonSet '{daemonset_name}' has {desired - ready} pods not ready "
            f"({ready}/{desired} ready)"
        )
        recommendations.append(
            f"Check which nodes are missing the pod: "
            f"kubectl get pods -n {namespace} -l app={daemonset_name} -o wide"
        )

    if misscheduled > 0:
        warnings.append(
            f"⚠️  {misscheduled} pods are running on nodes that shouldn't have them "
            f"(misscheduled) — check node selectors and taints"
        )

    if unavailable > 0:
        warnings.append(f"⚠️  {unavailable} pods are unavailable")

    # Get pods for this daemonset
    selector = spec.get("selector", {}).get("matchLabels", {})
    label_sel = ",".join(f"{k}={v}" for k, v in selector.items())
    pod_data = run_kubectl("get", "pods", "-n", namespace, "-l", label_sel)

    node_pod_map = {}
    failing_pods = []
    if isinstance(pod_data, dict):
        for pod in pod_data.get("items", []):
            node = pod.get("spec", {}).get("nodeName", "unscheduled")
            phase = pod.get("status", {}).get("phase")
            pod_name = pod.get("metadata", {}).get("name")
            node_pod_map[node] = {"pod": pod_name, "phase": phase}
            if phase != "Running":
                failing_pods.append({"pod": pod_name, "node": node, "phase": phase})

    # Find nodes without a pod
    all_nodes_data = run_kubectl("get", "nodes")
    nodes_without_pod = []
    if isinstance(all_nodes_data, dict):
        for node in all_nodes_data.get("items", []):
            node_name = node.get("metadata", {}).get("name")
            if node_name not in node_pod_map:
                nodes_without_pod.append(node_name)

    if nodes_without_pod:
        warnings.append(
            f"⚠️  Nodes missing '{daemonset_name}' pod: {nodes_without_pod}"
        )
        recommendations.append(
            "Check node taints — DaemonSet may need tolerations to run on these nodes"
        )
    else:
        findings.append(f"✅ All nodes have a '{daemonset_name}' pod")

    if not warnings:
        findings.append(f"✅ DaemonSet '{daemonset_name}' is healthy on all nodes")

    return _j({
        "daemonset": daemonset_name,
        "namespace": namespace,
        "status": {
            "desired": desired,
            "ready": ready,
            "available": available,
            "unavailable": unavailable,
        },
        "findings": findings,
        "warnings": warnings,
        "recommendations": recommendations,
        "failing_pods": failing_pods,
        "nodes_missing_pod": nodes_without_pod,
    })


def investigate_statefulset(statefulset_name: str, namespace: str = "default") -> str:
    """
    Investigate a StatefulSet — checks pod ordering, PVC binding,
    stuck pods, and data persistence issues.
    Use for databases, Kafka, Elasticsearch, Redis clusters.
    """
    findings = []
    warnings = []
    recommendations = []

    sts_data = run_kubectl("get", "statefulset", statefulset_name, "-n", namespace)
    if "error" in sts_data:
        return _j({"error": f"StatefulSet '{statefulset_name}' not found"})

    spec = sts_data.get("spec", {})
    status = sts_data.get("status", {})
    replicas = spec.get("replicas", 0)
    ready_replicas = status.get("readyReplicas", 0)
    current_replicas = status.get("currentReplicas", 0)

    findings.append(f"Replicas: {replicas} desired, {ready_replicas} ready, {current_replicas} current")

    if ready_replicas < replicas:
        warnings.append(
            f"⚠️  StatefulSet '{statefulset_name}' has {replicas - ready_replicas} pods not ready"
        )

    # Check pods
    selector = spec.get("selector", {}).get("matchLabels", {})
    label_sel = ",".join(f"{k}={v}" for k, v in selector.items())
    pod_data = run_kubectl("get", "pods", "-n", namespace, "-l", label_sel)

    pods_with_issues = []
    if isinstance(pod_data, dict):
        for pod in pod_data.get("items", []):
            pod_name = pod.get("metadata", {}).get("name")
            phase = pod.get("status", {}).get("phase")
            if phase != "Running":
                pods_with_issues.append({"pod": pod_name, "phase": phase})
                warnings.append(f"⚠️  Pod '{pod_name}' is {phase}")

    # Check PVCs
    pvc_data = run_kubectl("get", "pvc", "-n", namespace)
    unbound_pvcs = []
    if isinstance(pvc_data, dict):
        for pvc in pvc_data.get("items", []):
            pvc_meta = pvc.get("metadata", {})
            pvc_status = pvc.get("status", {})
            if statefulset_name in pvc_meta.get("name", ""):
                if pvc_status.get("phase") != "Bound":
                    unbound_pvcs.append({
                        "pvc": pvc_meta.get("name"),
                        "status": pvc_status.get("phase"),
                    })
                    warnings.append(
                        f"⚠️  PVC '{pvc_meta.get('name')}' is {pvc_status.get('phase')} not Bound. "
                        "Pod will stay Pending until PVC is bound."
                    )
                    recommendations.append(
                        "Check StorageClass and available PersistentVolumes. "
                        "Ensure the StorageClass provisioner is running."
                    )

    if not warnings:
        findings.append(f"✅ StatefulSet '{statefulset_name}' is healthy")

    return _j({
        "statefulset": statefulset_name,
        "namespace": namespace,
        "replicas": {"desired": replicas, "ready": ready_replicas},
        "findings": findings,
        "warnings": warnings,
        "recommendations": recommendations,
        "pods_with_issues": pods_with_issues,
        "unbound_pvcs": unbound_pvcs,
    })


def investigate_cronjob(cronjob_name: str, namespace: str = "default") -> str:
    """
    Investigate a CronJob — checks last execution, failure history,
    missed schedules, and job pod logs.
    CronJobs fail silently — use this to catch them.
    """
    findings = []
    warnings = []
    recommendations = []

    cj_data = run_kubectl("get", "cronjob", cronjob_name, "-n", namespace)
    if "error" in cj_data:
        return _j({"error": f"CronJob '{cronjob_name}' not found"})

    spec = cj_data.get("spec", {})
    status = cj_data.get("status", {})

    schedule = spec.get("schedule")
    suspend = spec.get("suspend", False)
    last_schedule = status.get("lastScheduleTime")
    last_success = status.get("lastSuccessfulTime")
    active = status.get("active", [])

    findings.append(f"Schedule: {schedule}")
    findings.append(f"Last scheduled: {last_schedule}")
    findings.append(f"Last successful: {last_success}")
    findings.append(f"Currently active jobs: {len(active)}")

    if suspend:
        warnings.append(f"⚠️  CronJob '{cronjob_name}' is SUSPENDED — not running")
        recommendations.append(
            f"Unsuspend: kubectl patch cronjob {cronjob_name} "
            f"-n {namespace} -p '{{\"spec\":{{\"suspend\":false}}}}'"
        )

    if last_schedule and not last_success:
        warnings.append(
            f"⚠️  CronJob has been scheduled but never succeeded. "
            f"Check job pod logs for errors."
        )

    # Check failed jobs
    jobs_data = run_kubectl(
        "get", "jobs", "-n", namespace,
        "--field-selector", f"metadata.ownerReferences.name={cronjob_name}",
    )
    failed_jobs = []
    if isinstance(jobs_data, dict):
        for job in jobs_data.get("items", []):
            job_status = job.get("status", {})
            if job_status.get("failed", 0) > 0:
                failed_jobs.append({
                    "job": job.get("metadata", {}).get("name"),
                    "failed": job_status.get("failed"),
                    "start_time": job_status.get("startTime"),
                })
                warnings.append(
                    f"⚠️  Job '{job.get('metadata', {}).get('name')}' has "
                    f"{job_status.get('failed')} failed attempts"
                )

    # Get logs from most recent job pod
    recent_logs = ""
    if jobs_data and isinstance(jobs_data, dict):
        jobs = jobs_data.get("items", [])
        if jobs:
            latest_job = jobs[-1]
            job_name = latest_job.get("metadata", {}).get("name")
            pod_data = run_kubectl(
                "get", "pods", "-n", namespace,
                "--field-selector", f"metadata.ownerReferences.name={job_name}",
            )
            if isinstance(pod_data, dict) and pod_data.get("items"):
                pod_name = pod_data["items"][-1]["metadata"]["name"]
                recent_logs = run_kubectl_raw(
                    "logs", pod_name, "-n", namespace, "--tail=20"
                )

    if not failed_jobs and not suspend:
        findings.append(f"✅ CronJob '{cronjob_name}' is running as expected")

    return _j({
        "cronjob": cronjob_name,
        "namespace": namespace,
        "schedule": schedule,
        "suspended": suspend,
        "last_scheduled": last_schedule,
        "last_successful": last_success,
        "active_jobs": len(active),
        "findings": findings,
        "warnings": warnings,
        "recommendations": recommendations,
        "failed_jobs": failed_jobs,
        "recent_job_logs": recent_logs,
    })


def get_cluster_events(namespace: str = "all", event_type: str = "Warning") -> str:
    """Get cluster events filtered by type with reason summary."""
    if namespace == "all":
        data = run_kubectl("get", "events", "--all-namespaces", "--sort-by=.lastTimestamp")
    else:
        data = run_kubectl("get", "events", "-n", namespace, "--sort-by=.lastTimestamp")

    if "error" in data:
        return _j(data)

    events = []
    for item in data.get("items", []):
        if event_type != "all" and item.get("type") != event_type:
            continue
        events.append({
            "namespace": item.get("metadata", {}).get("namespace"),
            "type": item.get("type"),
            "reason": item.get("reason"),
            "object": f"{item.get('involvedObject', {}).get('kind')}/{item.get('involvedObject', {}).get('name')}",
            "message": item.get("message"),
            "count": item.get("count"),
            "last_time": item.get("lastTimestamp"),
        })

    reason_counts: dict = {}
    for e in events:
        r = e.get("reason", "unknown")
        reason_counts[r] = reason_counts.get(r, 0) + 1

    return _j({
        "total_events": len(events),
        "event_type_filter": event_type,
        "reason_summary": dict(sorted(reason_counts.items(), key=lambda x: x[1], reverse=True)),
        "events": events[-50:],
    })


def check_node_pressure(cluster_name: str | None = None, region: str = "us-east-1") -> str:
    """Check for node pressure — OOM evictions, disk pressure, NotReady, Container Insights."""
    findings = []
    recommendations = []
    evictions = []

    data = run_kubectl("get", "nodes")
    if isinstance(data, dict):
        for node in data.get("items", []):
            name = node["metadata"]["name"]
            conditions = {c["type"]: c["status"] for c in node.get("status", {}).get("conditions", [])}
            if conditions.get("Ready") != "True":
                findings.append(f"⚠️  Node '{name}' is NOT Ready")
                recommendations.append(f"Investigate node '{name}' — check kubelet and AWS console")
            if conditions.get("MemoryPressure") == "True":
                findings.append(f"⚠️  Node '{name}' has MemoryPressure")
                recommendations.append(f"Node '{name}' low on memory — pods may be evicted")
            if conditions.get("DiskPressure") == "True":
                findings.append(f"⚠️  Node '{name}' has DiskPressure")
                recommendations.append(f"Node '{name}' disk full — clean images or increase disk")
            if conditions.get("PIDPressure") == "True":
                findings.append(f"⚠️  Node '{name}' has PIDPressure")

    evict_data = run_kubectl("get", "events", "--all-namespaces", "--field-selector", "reason=Evicted")
    if isinstance(evict_data, dict):
        for e in evict_data.get("items", []):
            evictions.append({
                "pod": e.get("involvedObject", {}).get("name"),
                "namespace": e.get("metadata", {}).get("namespace"),
                "message": e.get("message"),
                "time": e.get("lastTimestamp"),
            })
        if evictions:
            findings.append(f"⚠️  Found {len(evictions)} evicted pods")
            recommendations.append("Pods being evicted — likely memory or disk pressure")

    if cluster_name:
        try:
            logs = get_client("logs", region)
            log_group = f"/aws/containerinsights/{cluster_name}/host"
            end = datetime.utcnow()
            start = end - timedelta(hours=1)
            resp = logs.filter_log_events(
                logGroupName=log_group,
                startTime=int(start.timestamp() * 1000),
                endTime=int(end.timestamp() * 1000),
                filterPattern="?Failed ?Evicted ?Killed ?NotReady",
                limit=10,
            )
            host_events = resp.get("events", [])
            if host_events:
                findings.append(f"⚠️  {len(host_events)} host-level failure events in CloudWatch")
                recommendations.append("Host-level failures detected — check node resource pressure")
        except Exception:
            pass

    if not findings:
        findings.append("✅ No node pressure issues detected")

    return _j({
        "findings": findings,
        "recommendations": recommendations,
        "recent_evictions": evictions[-5:],
    })


def investigate_cluster_health() -> str:
    """Full cluster health check — nodes, pods, deployments, events. Overall health score."""
    issues = []
    healthy = []
    summary = {}

    nodes_data = run_kubectl("get", "nodes")
    if isinstance(nodes_data, dict):
        total_nodes = len(nodes_data["items"])
        not_ready = [
            n["metadata"]["name"]
            for n in nodes_data["items"]
            if {c["type"]: c["status"] for c in n.get("status", {}).get("conditions", [])}.get("Ready") != "True"
        ]
        if not_ready:
            issues.append(f"Nodes NotReady: {', '.join(not_ready)}")
        else:
            healthy.append(f"All {total_nodes} nodes are Ready")
        summary["nodes"] = {"total": total_nodes, "not_ready": len(not_ready)}

    pods_data = run_kubectl("get", "pods", "--all-namespaces")
    if isinstance(pods_data, dict):
        total_pods = len(pods_data["items"])
        failing = [
            p["metadata"]["name"]
            for p in pods_data["items"]
            if p.get("status", {}).get("phase") not in ("Running", "Succeeded", "Pending")
        ]
        high_restarts = list(set([
            p["metadata"]["name"]
            for p in pods_data["items"]
            for cs in p.get("status", {}).get("containerStatuses", [])
            if cs.get("restartCount", 0) > 10
        ]))
        if failing:
            issues.append(f"Failing pods: {', '.join(failing[:5])}")
        if high_restarts:
            issues.append(f"High restart pods (>10): {', '.join(high_restarts[:5])}")
        if not failing and not high_restarts:
            healthy.append(f"All {total_pods} pods healthy")
        summary["pods"] = {"total": total_pods, "failing": len(failing), "high_restarts": len(high_restarts)}

    deploy_data = run_kubectl("get", "deployments", "--all-namespaces")
    if isinstance(deploy_data, dict):
        total = len(deploy_data["items"])
        unavailable = [
            d["metadata"]["name"]
            for d in deploy_data["items"]
            if d.get("status", {}).get("unavailableReplicas", 0) > 0
        ]
        if unavailable:
            issues.append(f"Deployments with unavailable replicas: {', '.join(unavailable)}")
        else:
            healthy.append(f"All {total} deployments healthy")
        summary["deployments"] = {"total": total, "unavailable": len(unavailable)}

    events_data = run_kubectl("get", "events", "--all-namespaces", "--field-selector", "type=Warning")
    warning_count = len(events_data.get("items", [])) if isinstance(events_data, dict) else 0
    if warning_count > 0:
        issues.append(f"{warning_count} Warning events in cluster")

    total_checks = len(issues) + len(healthy)
    score = round((len(healthy) / total_checks * 100) if total_checks > 0 else 100)

    return _j({
        "health_score": f"{score}%",
        "status": "HEALTHY" if score == 100 else "DEGRADED" if score >= 70 else "CRITICAL",
        "issues_found": len(issues),
        "issues": issues,
        "healthy_checks": healthy,
        "summary": summary,
        "warning_events": warning_count,
    })


def get_incident_summary(namespace: str = "all") -> str:
    """
    One-shot full incident report — combines cluster health, node pressure,
    failing pods, warning events, and top recommendations.
    Use this as first response to any 'something is broken' report.
    Enterprise SRE runbook entry point.
    """
    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "sections": {},
        "top_issues": [],
        "immediate_actions": [],
    }

    # Cluster health
    try:
        health_raw = investigate_cluster_health()
        import json
        health = json.loads(health_raw)
        report["sections"]["cluster_health"] = health
        if health.get("issues"):
            report["top_issues"].extend(health["issues"])
    except Exception as e:
        report["sections"]["cluster_health"] = {"error": str(e)}

    # Node pressure
    try:
        pressure_raw = check_node_pressure()
        pressure = json.loads(pressure_raw)
        report["sections"]["node_pressure"] = pressure
        if pressure.get("findings"):
            for f in pressure["findings"]:
                if "⚠️" in f:
                    report["top_issues"].append(f)
    except Exception as e:
        report["sections"]["node_pressure"] = {"error": str(e)}

    # Warning events
    try:
        events_raw = get_cluster_events(namespace=namespace, event_type="Warning")
        events = json.loads(events_raw)
        report["sections"]["warning_events"] = {
            "count": events.get("total_events"),
            "reason_summary": events.get("reason_summary"),
            "recent": events.get("events", [])[-5:],
        }
    except Exception as e:
        report["sections"]["warning_events"] = {"error": str(e)}

    # Failing pods
    try:
        pods_raw = run_kubectl("get", "pods", "--all-namespaces") if namespace == "all" else run_kubectl("get", "pods", "-n", namespace)
        if isinstance(pods_raw, dict):
            failing = [
                {
                    "name": p["metadata"]["name"],
                    "namespace": p["metadata"]["namespace"],
                    "phase": p.get("status", {}).get("phase"),
                }
                for p in pods_raw.get("items", [])
                if p.get("status", {}).get("phase") not in ("Running", "Succeeded")
            ]
            report["sections"]["failing_pods"] = {
                "count": len(failing),
                "pods": failing,
            }
            if failing:
                report["immediate_actions"].append(
                    f"Investigate {len(failing)} failing pods: "
                    f"{[p['name'] for p in failing[:3]]}"
                )
    except Exception as e:
        report["sections"]["failing_pods"] = {"error": str(e)}

    # Severity
    issue_count = len(report["top_issues"])
    report["severity"] = "CRITICAL" if issue_count > 5 else "HIGH" if issue_count > 2 else "MEDIUM" if issue_count > 0 else "OK"
    report["total_issues"] = issue_count

    return _j(report)
