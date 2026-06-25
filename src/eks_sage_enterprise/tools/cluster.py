"""Category 1 — Cluster Management (5 tools)."""
from __future__ import annotations
from eks_sage_enterprise.core.aws_client import get_client, set_cluster, get_current_cluster, get_current_region
from eks_sage_enterprise.core.utils import _j


def list_clusters(region: str = "us-east-1") -> str:
    """List all EKS clusters in a region with their status and version."""
    try:
        eks = get_client("eks", region)
        clusters = []
        paginator = eks.get_paginator("list_clusters")
        for page in paginator.paginate():
            for name in page.get("clusters", []):
                try:
                    detail = eks.describe_cluster(name=name)["cluster"]
                    clusters.append({
                        "name": name,
                        "status": detail.get("status"),
                        "version": detail.get("version"),
                        "platform_version": detail.get("platformVersion"),
                        "created_at": detail.get("createdAt"),
                        "tags": detail.get("tags", {}),
                    })
                except Exception:
                    clusters.append({"name": name})
        return _j({"region": region, "count": len(clusters), "clusters": clusters})
    except Exception as e:
        return _j({"error": str(e)})


def describe_cluster(cluster_name: str, region: str = "us-east-1") -> str:
    """Get full cluster details — version, VPC, auth mode, logging, addons count."""
    try:
        eks = get_client("eks", region)
        c = eks.describe_cluster(name=cluster_name)["cluster"]
        # Get addon count
        addon_count = len(eks.list_addons(clusterName=cluster_name).get("addons", []))
        return _j({
            "name": c["name"],
            "status": c["status"],
            "version": c["version"],
            "platform_version": c.get("platformVersion"),
            "endpoint": c.get("endpoint"),
            "role_arn": c.get("roleArn"),
            "kubernetes_network": c.get("kubernetesNetworkConfig", {}),
            "vpc_config": c.get("resourcesVpcConfig", {}),
            "logging": c.get("logging", {}),
            "auth_mode": c.get("accessConfig", {}).get("authenticationMode"),
            "created_at": c.get("createdAt"),
            "tags": c.get("tags", {}),
            "addon_count": addon_count,
            "encryption": c.get("encryptionConfig", []),
            "connector_config": c.get("connectorConfig", {}),
        })
    except Exception as e:
        return _j({"error": str(e)})


def connect_cluster(cluster_name: str, region: str = "us-east-1") -> str:
    """Connect to an EKS cluster — updates kubeconfig. Run this first."""
    return _j(set_cluster(cluster_name, region))


def get_cluster_addons(cluster_name: str, region: str = "us-east-1") -> str:
    """List all addons with versions, status, and available updates."""
    try:
        eks = get_client("eks", region)
        addons = eks.list_addons(clusterName=cluster_name).get("addons", [])
        details = []
        for addon in addons:
            d = eks.describe_addon(clusterName=cluster_name, addonName=addon)["addon"]
            # Check for updates
            try:
                updates = eks.describe_addon_versions(
                    addonName=addon,
                    kubernetesVersion=eks.describe_cluster(name=cluster_name)["cluster"]["version"]
                ).get("addons", [{}])[0].get("addonVersions", [])
                latest = updates[0].get("addonVersion") if updates else None
            except Exception:
                latest = None

            details.append({
                "name": d["addonName"],
                "current_version": d["addonVersion"],
                "latest_version": latest,
                "update_available": latest and latest != d["addonVersion"],
                "status": d["status"],
                "service_account_role": d.get("serviceAccountRoleArn"),
                "health": d.get("health", {}).get("issues", []),
                "created_at": d.get("createdAt"),
            })
        return _j({
            "cluster": cluster_name,
            "addon_count": len(details),
            "updates_available": sum(1 for d in details if d.get("update_available")),
            "addons": details,
        })
    except Exception as e:
        return _j({"error": str(e)})


def get_cluster_upgrade_insights(cluster_name: str, region: str = "us-east-1") -> str:
    """
    Check cluster upgrade readiness — deprecated APIs, addon compatibility,
    and what will break if you upgrade the Kubernetes version.
    Enterprise feature for planned upgrades.
    """
    try:
        eks = get_client("eks", region)
        cluster = eks.describe_cluster(name=cluster_name)["cluster"]
        current_version = cluster["version"]

        findings = []
        warnings = []
        recommendations = []

        # Check addon versions against next k8s version
        addons = eks.list_addons(clusterName=cluster_name).get("addons", [])
        incompatible_addons = []
        for addon in addons:
            d = eks.describe_addon(clusterName=cluster_name, addonName=addon)["addon"]
            try:
                # Check next minor version compatibility
                parts = current_version.split(".")
                next_version = f"{parts[0]}.{int(parts[1]) + 1}"
                versions = eks.describe_addon_versions(
                    addonName=addon,
                    kubernetesVersion=next_version
                ).get("addons", [{}])[0].get("addonVersions", [])
                if not versions:
                    incompatible_addons.append({
                        "addon": addon,
                        "current_version": d["addonVersion"],
                        "issue": f"No compatible version found for k8s {next_version}",
                    })
            except Exception:
                pass

        if incompatible_addons:
            warnings.append(
                f"{len(incompatible_addons)} addons may not be compatible with next k8s version"
            )
            recommendations.append(
                "Update addons before upgrading cluster version"
            )
        else:
            findings.append("✅ All addons appear compatible with next version")

        # Check nodegroup AMI versions
        try:
            nodegroups = eks.list_nodegroups(clusterName=cluster_name).get("nodegroups", [])
            outdated_ngs = []
            for ng in nodegroups:
                d = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng)["nodegroup"]
                ng_version = d.get("version", "")
                if ng_version != current_version:
                    outdated_ngs.append({
                        "nodegroup": ng,
                        "version": ng_version,
                        "cluster_version": current_version,
                    })
            if outdated_ngs:
                warnings.append(f"{len(outdated_ngs)} nodegroups are on older versions")
                recommendations.append("Update nodegroups to match cluster version before upgrading")
            else:
                findings.append("✅ All nodegroups match cluster version")
        except Exception:
            pass

        return _j({
            "cluster": cluster_name,
            "current_version": current_version,
            "upgrade_ready": len(warnings) == 0,
            "findings": findings,
            "warnings": warnings,
            "recommendations": recommendations,
            "incompatible_addons": incompatible_addons,
        })
    except Exception as e:
        return _j({"error": str(e)})
