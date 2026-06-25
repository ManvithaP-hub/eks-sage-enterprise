"""Category 10 — Observability (4 tools)."""
from __future__ import annotations
from datetime import datetime, timedelta
from eks_sage_enterprise.core.aws_client import get_client, get_current_cluster, get_current_region
from eks_sage_enterprise.core.kubectl import run_kubectl, run_kubectl_raw
from eks_sage_enterprise.core.utils import _j


def get_cloudwatch_metrics(
    cluster_name: str | None = None,
    namespace: str = "all",
    region: str | None = None,
    period_minutes: int = 60,
) -> str:
    """
    Get CloudWatch metrics for EKS cluster — CPU, memory, network,
    pod counts from Container Insights.
    Shows trends over the last N minutes.
    """
    cluster_name = cluster_name or get_current_cluster()
    region = region or get_current_region()

    if not cluster_name:
        return _j({"error": "No cluster connected. Run connect_cluster first."})

    try:
        cw = get_client("cloudwatch", region)
        end = datetime.utcnow()
        start = end - timedelta(minutes=period_minutes)
        metrics_to_fetch = [
            ("pod_cpu_utilization", "pod_cpu_utilization", "Percent"),
            ("pod_memory_utilization", "pod_memory_utilization", "Percent"),
            ("node_cpu_utilization", "node_cpu_utilization", "Percent"),
            ("node_memory_utilization", "node_memory_utilization", "Percent"),
            ("pod_number_of_running_containers", "pod_number_of_running_containers", "Count"),
        ]

        results = {}
        for metric_key, metric_name, unit in metrics_to_fetch:
            try:
                dims = [{"Name": "ClusterName", "Value": cluster_name}]
                if namespace != "all":
                    dims.append({"Name": "Namespace", "Value": namespace})

                resp = cw.get_metric_statistics(
                    Namespace="ContainerInsights",
                    MetricName=metric_name,
                    Dimensions=dims,
                    StartTime=start,
                    EndTime=end,
                    Period=period_minutes * 60,
                    Statistics=["Average", "Maximum"],
                )
                datapoints = resp.get("Datapoints", [])
                if datapoints:
                    latest = sorted(datapoints, key=lambda x: x["Timestamp"])[-1]
                    results[metric_key] = {
                        "average": round(latest.get("Average", 0), 2),
                        "maximum": round(latest.get("Maximum", 0), 2),
                        "unit": unit,
                        "timestamp": latest["Timestamp"],
                    }
            except Exception:
                pass

        # Add warnings for high utilization
        warnings = []
        if results.get("node_cpu_utilization", {}).get("average", 0) > 80:
            warnings.append("⚠️  Node CPU utilization > 80% — consider scaling")
        if results.get("node_memory_utilization", {}).get("average", 0) > 80:
            warnings.append("⚠️  Node memory utilization > 80% — risk of OOM evictions")

        return _j({
            "cluster": cluster_name,
            "namespace": namespace,
            "period_minutes": period_minutes,
            "metrics": results,
            "warnings": warnings,
            "note": "Requires Container Insights to be enabled on the cluster",
        })
    except Exception as e:
        return _j({"error": str(e)})


def get_container_insights(
    cluster_name: str | None = None,
    region: str | None = None,
    hours: int = 1,
    filter_pattern: str = "ERROR",
) -> str:
    """
    Search Container Insights logs in CloudWatch.
    Filter for errors, warnings, or any pattern across all pods.
    Requires Container Insights to be enabled.
    """
    cluster_name = cluster_name or get_current_cluster()
    region = region or get_current_region()

    if not cluster_name:
        return _j({"error": "No cluster connected. Run connect_cluster first."})

    try:
        logs = get_client("logs", region)
        end = datetime.utcnow()
        start = end - timedelta(hours=hours)

        log_groups = [
            f"/aws/containerinsights/{cluster_name}/application",
            f"/aws/containerinsights/{cluster_name}/host",
            f"/aws/containerinsights/{cluster_name}/dataplane",
        ]

        all_events = []
        for log_group in log_groups:
            try:
                resp = logs.filter_log_events(
                    logGroupName=log_group,
                    startTime=int(start.timestamp() * 1000),
                    endTime=int(end.timestamp() * 1000),
                    filterPattern=filter_pattern,
                    limit=20,
                )
                for event in resp.get("events", []):
                    all_events.append({
                        "log_group": log_group.split("/")[-1],
                        "message": event.get("message", "")[:300],
                        "timestamp": datetime.fromtimestamp(
                            event.get("timestamp", 0) / 1000
                        ).isoformat(),
                    })
            except Exception:
                pass

        return _j({
            "cluster": cluster_name,
            "filter_pattern": filter_pattern,
            "hours_searched": hours,
            "total_matches": len(all_events),
            "events": all_events,
            "log_groups_searched": log_groups,
        })
    except Exception as e:
        return _j({"error": str(e)})


def get_application_logs(
    pod_name: str | None = None,
    namespace: str = "default",
    label_selector: str | None = None,
    filter_text: str | None = None,
    lines: int = 50,
    since_minutes: int = 10,
) -> str:
    """
    Aggregate logs across multiple pods by label selector.
    Filter by text pattern. Essential for microservice debugging.
    e.g. Get all ERROR logs from all pods with label app=my-app.
    """
    results = []

    if pod_name:
        # Single pod
        args = ["logs", pod_name, "-n", namespace, f"--tail={lines}", f"--since={since_minutes}m"]
        logs = run_kubectl_raw(*args)
        lines_list = [l for l in (logs or "").split("\n") if not filter_text or filter_text.lower() in l.lower()]
        results.append({"pod": pod_name, "namespace": namespace, "lines": lines_list})

    elif label_selector:
        # Multiple pods by label
        pod_data = run_kubectl("get", "pods", "-n", namespace, "-l", label_selector)
        if isinstance(pod_data, dict):
            for pod in pod_data.get("items", []):
                p_name = pod.get("metadata", {}).get("name")
                args = ["logs", p_name, "-n", namespace, f"--tail={lines}", f"--since={since_minutes}m"]
                logs = run_kubectl_raw(*args)
                lines_list = [l for l in (logs or "").split("\n") if not filter_text or filter_text.lower() in l.lower()]
                if lines_list:
                    results.append({"pod": p_name, "namespace": namespace, "lines": lines_list})
    else:
        return _j({"error": "Provide either pod_name or label_selector"})

    total_lines = sum(len(r["lines"]) for r in results)
    return _j({
        "pods_searched": len(results),
        "total_matching_lines": total_lines,
        "filter": filter_text,
        "since_minutes": since_minutes,
        "results": results,
    })


def get_cost_by_namespace(region: str | None = None) -> str:
    """
    Estimate cost breakdown by Kubernetes namespace.
    Shows which teams/services are consuming the most resources and cost.
    Uses CPU/memory requests as cost proxy.
    """
    region = region or get_current_region()
    namespace_costs = {}

    pods_data = run_kubectl("get", "pods", "--all-namespaces")
    if not isinstance(pods_data, dict):
        return _j({"error": "Could not fetch pods"})

    # CPU cost: ~$0.04048/vCPU/hour (us-east-1 on-demand average)
    # Memory cost: ~$0.004445/GB/hour
    CPU_COST_PER_CORE_HOUR = 0.04048
    MEM_COST_PER_GB_HOUR = 0.004445

    for pod in pods_data.get("items", []):
        ns = pod.get("metadata", {}).get("namespace", "default")
        if ns not in namespace_costs:
            namespace_costs[ns] = {"cpu_millicores": 0, "memory_mb": 0, "pod_count": 0}

        namespace_costs[ns]["pod_count"] += 1
        for c in pod.get("spec", {}).get("containers", []):
            requests = c.get("resources", {}).get("requests", {})
            cpu = requests.get("cpu", "0m")
            mem = requests.get("memory", "0Mi")

            # Parse CPU
            if cpu.endswith("m"):
                namespace_costs[ns]["cpu_millicores"] += int(cpu[:-1])
            else:
                namespace_costs[ns]["cpu_millicores"] += int(float(cpu) * 1000)

            # Parse memory
            if mem.endswith("Mi"):
                namespace_costs[ns]["memory_mb"] += int(mem[:-2])
            elif mem.endswith("Gi"):
                namespace_costs[ns]["memory_mb"] += int(mem[:-2]) * 1024
            elif mem.endswith("Ki"):
                namespace_costs[ns]["memory_mb"] += int(mem[:-2]) // 1024

    # Calculate hourly and monthly costs
    breakdown = []
    for ns, data in namespace_costs.items():
        cpu_cores = data["cpu_millicores"] / 1000
        mem_gb = data["memory_mb"] / 1024
        hourly = (cpu_cores * CPU_COST_PER_CORE_HOUR) + (mem_gb * MEM_COST_PER_GB_HOUR)
        monthly = hourly * 730
        breakdown.append({
            "namespace": ns,
            "pod_count": data["pod_count"],
            "cpu_requested_cores": round(cpu_cores, 3),
            "memory_requested_gb": round(mem_gb, 3),
            "estimated_hourly_usd": round(hourly, 4),
            "estimated_monthly_usd": round(monthly, 2),
        })

    breakdown.sort(key=lambda x: x["estimated_monthly_usd"], reverse=True)
    total_monthly = sum(b["estimated_monthly_usd"] for b in breakdown)

    return _j({
        "total_estimated_monthly_usd": round(total_monthly, 2),
        "disclaimer": "Estimates based on resource requests and avg on-demand pricing (us-east-1). Actual cost varies.",
        "by_namespace": breakdown,
    })
