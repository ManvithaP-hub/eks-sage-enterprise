"""Category 11 — Multi-Cluster Management (3 tools)."""
from __future__ import annotations
import json
from eks_sage_enterprise.core.aws_client import get_client, set_cluster, get_current_cluster
from eks_sage_enterprise.core.kubectl import run_kubectl
from eks_sage_enterprise.core.utils import _j

ALL_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-central-1",
    "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
]


def list_all_clusters(regions: str = "us-east-1,us-west-2,eu-west-1") -> str:
    """
    List ALL EKS clusters across multiple AWS regions.
    Gives a single view of your entire EKS fleet.
    Args:
        regions: Comma-separated list of regions to scan
    """
    region_list = [r.strip() for r in regions.split(",")]
    all_clusters = []
    errors = []

    for region in region_list:
        try:
            eks = get_client("eks", region)
            cluster_names = []
            paginator = eks.get_paginator("list_clusters")
            for page in paginator.paginate():
                cluster_names.extend(page.get("clusters", []))

            for name in cluster_names:
                try:
                    detail = eks.describe_cluster(name=name)["cluster"]
                    all_clusters.append({
                        "name": name,
                        "region": region,
                        "status": detail.get("status"),
                        "version": detail.get("version"),
                        "platform_version": detail.get("platformVersion"),
                        "created_at": detail.get("createdAt"),
                    })
                except Exception:
                    all_clusters.append({"name": name, "region": region})
        except Exception as e:
            errors.append({"region": region, "error": str(e)})

    return _j({
        "total_clusters": len(all_clusters),
        "regions_scanned": region_list,
        "clusters": all_clusters,
        "errors": errors,
    })


def compare_clusters(
    cluster1: str,
    cluster2: str,
    region1: str = "us-east-1",
    region2: str = "us-east-1",
) -> str:
    """
    Compare two EKS clusters — versions, addons, node counts, config.
    Use for validating staging vs production parity.
    """
    results: dict = {"cluster1": cluster1, "cluster2": cluster2, "differences": [], "matches": []}

    def get_cluster_snapshot(name: str, region: str) -> dict:
        try:
            eks = get_client("eks", region)
            c = eks.describe_cluster(name=name)["cluster"]
            addons = eks.list_addons(clusterName=name).get("addons", [])
            nodegroups = eks.list_nodegroups(clusterName=name).get("nodegroups", [])
            return {
                "version": c.get("version"),
                "platform_version": c.get("platformVersion"),
                "auth_mode": c.get("accessConfig", {}).get("authenticationMode"),
                "logging_enabled": list(c.get("logging", {}).get("clusterLogging", [{}])[0].get("types", [])),
                "addon_count": len(addons),
                "addons": sorted(addons),
                "nodegroup_count": len(nodegroups),
                "public_access": c.get("resourcesVpcConfig", {}).get("endpointPublicAccess"),
                "private_access": c.get("resourcesVpcConfig", {}).get("endpointPrivateAccess"),
            }
        except Exception as e:
            return {"error": str(e)}

    snap1 = get_cluster_snapshot(cluster1, region1)
    snap2 = get_cluster_snapshot(cluster2, region2)
    results["cluster1_snapshot"] = snap1
    results["cluster2_snapshot"] = snap2

    # Compare each field
    for key in set(list(snap1.keys()) + list(snap2.keys())):
        if key == "error":
            continue
        v1 = snap1.get(key)
        v2 = snap2.get(key)
        if v1 == v2:
            results["matches"].append(f"✅ {key}: {v1}")
        else:
            results["differences"].append({
                "field": key,
                cluster1: v1,
                cluster2: v2,
            })

    results["parity_score"] = (
        f"{len(results['matches'])}/{len(results['matches']) + len(results['differences'])} fields match"
    )
    results["production_ready"] = len(results["differences"]) == 0

    return _j(results)


def switch_cluster_context(cluster_name: str, region: str = "us-east-1") -> str:
    """
    Switch active cluster context for all subsequent kubectl commands.
    Shows before/after context for confirmation.
    """
    previous = get_current_cluster()
    result = set_cluster(cluster_name, region)

    if "error" in result:
        return _j(result)

    return _j({
        "switched_from": previous or "none",
        "switched_to": cluster_name,
        "region": region,
        "status": "success",
        "message": f"All subsequent kubectl operations will target '{cluster_name}'",
        "kubeconfig_updated": result.get("message"),
    })
