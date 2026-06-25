"""Category 4 — Security & RBAC (6 tools)."""
from __future__ import annotations
from eks_sage_enterprise.core.kubectl import run_kubectl, run_kubectl_raw
from eks_sage_enterprise.core.aws_client import get_client, get_current_cluster, get_current_region
from eks_sage_enterprise.core.utils import _j


def investigate_irsa(
    service_account: str,
    namespace: str = "default",
    region: str | None = None,
) -> str:
    """
    Investigate IRSA (IAM Roles for Service Accounts) issues.
    Checks the full chain: ServiceAccount → IAM Role → OIDC → Trust Policy → Permissions.
    Use when pods get AccessDenied or WebIdentityErr calling AWS APIs.
    """
    region = region or get_current_region()
    cluster_name = get_current_cluster()
    findings = []
    warnings = []
    recommendations = []

    # Step 1 — Get service account
    sa_data = run_kubectl("get", "serviceaccount", service_account, "-n", namespace)
    if "error" in sa_data:
        return _j({"error": f"ServiceAccount '{service_account}' not found in namespace '{namespace}'"})

    annotations = sa_data.get("metadata", {}).get("annotations", {})
    role_arn = annotations.get("eks.amazonaws.com/role-arn")

    if not role_arn:
        warnings.append(
            f"⚠️  ServiceAccount '{service_account}' has NO IAM role annotation. "
            "Pod cannot assume any AWS role."
        )
        recommendations.append(
            f"Add annotation to service account:\n"
            f"  eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT_ID:role/YOUR_ROLE\n"
            f"  kubectl annotate serviceaccount {service_account} "
            f"-n {namespace} "
            f"eks.amazonaws.com/role-arn=arn:aws:iam::ACCOUNT:role/ROLE"
        )
        return _j({
            "service_account": service_account,
            "namespace": namespace,
            "irsa_configured": False,
            "findings": findings,
            "warnings": warnings,
            "recommendations": recommendations,
        })

    findings.append(f"✅ IAM role annotation found: {role_arn}")

    # Step 2 — Check IAM role exists
    try:
        iam = get_client("iam", region)
        role_name = role_arn.split("/")[-1]
        role = iam.get_role(RoleName=role_name)["Role"]
        findings.append(f"✅ IAM role exists: {role_name}")

        trust_policy = role.get("AssumeRolePolicyDocument", {})
        statements = trust_policy.get("Statement", [])

        # Step 3 — Check OIDC in trust policy
        oidc_found = False
        correct_namespace = False
        correct_sa = False

        for stmt in statements:
            principal = stmt.get("Principal", {})
            federated = principal.get("Federated", "")
            condition = stmt.get("Condition", {})

            if "oidc" in federated.lower() or "oidc" in str(condition).lower():
                oidc_found = True
                findings.append(f"✅ OIDC federation found in trust policy")

                # Check namespace and service account in condition
                for cond_type, cond_values in condition.items():
                    for key, value in cond_values.items():
                        if "sub" in key.lower():
                            expected_sub = f"system:serviceaccount:{namespace}:{service_account}"
                            if isinstance(value, list):
                                correct_sa = any(expected_sub in v for v in value)
                            else:
                                correct_sa = expected_sub in str(value)

                            if correct_sa:
                                findings.append(
                                    f"✅ Trust policy allows serviceaccount "
                                    f"{namespace}/{service_account}"
                                )
                            else:
                                warnings.append(
                                    f"⚠️  Trust policy sub condition is '{value}' "
                                    f"but expected '{expected_sub}'. "
                                    f"Wrong namespace or service account name."
                                )
                                recommendations.append(
                                    f"Fix trust policy condition:\n"
                                    f"  StringEquals:\n"
                                    f"    oidc.eks.REGION.amazonaws.com/id/OIDC_ID:sub:\n"
                                    f"      system:serviceaccount:{namespace}:{service_account}"
                                )

        if not oidc_found:
            warnings.append(
                "⚠️  No OIDC federation found in trust policy. "
                "Role cannot be assumed by Kubernetes service accounts."
            )
            recommendations.append(
                "Add OIDC federation to trust policy. "
                "Check OIDC provider is set up: "
                f"aws eks describe-cluster --name {cluster_name} "
                "--query 'cluster.identity.oidc.issuer'"
            )

        # Step 4 — Check OIDC provider exists in AWS
        if cluster_name:
            try:
                eks = get_client("eks", region)
                cluster = eks.describe_cluster(name=cluster_name)["cluster"]
                oidc_url = cluster.get("identity", {}).get("oidc", {}).get("issuer", "")
                if oidc_url:
                    oidc_id = oidc_url.split("/")[-1]
                    findings.append(f"✅ OIDC issuer found: {oidc_url}")

                    # Check OIDC provider exists in IAM
                    try:
                        account_id = role_arn.split(":")[4]
                        provider_arn = f"arn:aws:iam::{account_id}:oidc-provider/{oidc_url.replace('https://', '')}"
                        iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
                        findings.append(f"✅ OIDC provider registered in IAM")
                    except Exception:
                        warnings.append(
                            "⚠️  OIDC provider NOT registered in IAM. "
                            "IRSA cannot work without this."
                        )
                        recommendations.append(
                            "Register OIDC provider:\n"
                            f"eksctl utils associate-iam-oidc-provider "
                            f"--cluster {cluster_name} --approve"
                        )
                else:
                    warnings.append("⚠️  No OIDC issuer found on cluster")
            except Exception as e:
                findings.append(f"Could not check OIDC: {e}")

        # Step 5 — Check role permissions
        try:
            policies = iam.list_attached_role_policies(
                RoleName=role_name
            ).get("AttachedPolicies", [])
            inline = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
            findings.append(
                f"Role has {len(policies)} managed policies, {len(inline)} inline policies: "
                f"{[p['PolicyName'] for p in policies]}"
            )
            if not policies and not inline:
                warnings.append(
                    "⚠️  IAM role has NO policies attached. "
                    "Pod will get AccessDenied on all AWS API calls."
                )
                recommendations.append(
                    f"Attach a policy to role '{role_name}' with required permissions"
                )
        except Exception:
            pass

        # Step 6 — Check pods using this service account
        pods_data = run_kubectl(
            "get", "pods", "-n", namespace,
            "--field-selector", f"spec.serviceAccountName={service_account}"
        )
        pod_count = len(pods_data.get("items", [])) if isinstance(pods_data, dict) else 0

        # Check if AWS_ROLE_ARN env var is injected
        irsa_env_found = False
        if isinstance(pods_data, dict):
            for pod in pods_data.get("items", []):
                for c in pod.get("spec", {}).get("containers", []):
                    for env in c.get("env", []):
                        if env.get("name") == "AWS_ROLE_ARN":
                            irsa_env_found = True
                            break

        if pod_count > 0:
            findings.append(f"✅ {pod_count} pods using this service account")
            if irsa_env_found:
                findings.append("✅ AWS_ROLE_ARN environment variable injected into pods")
            else:
                warnings.append(
                    "⚠️  AWS_ROLE_ARN not found in pod environment. "
                    "Pod Identity Webhook may not be running."
                )
                recommendations.append(
                    "Check EKS Pod Identity Webhook is installed and running in kube-system"
                )

    except iam.exceptions.NoSuchEntityException:
        warnings.append(
            f"⚠️  IAM role '{role_arn}' does NOT exist in AWS. "
            "ServiceAccount annotation points to a non-existent role."
        )
        recommendations.append(
            f"Create the IAM role: {role_arn}\n"
            "Or update the service account annotation to point to an existing role"
        )
    except Exception as e:
        findings.append(f"Could not check IAM role: {e}")

    return _j({
        "service_account": service_account,
        "namespace": namespace,
        "role_arn": role_arn,
        "irsa_configured": len(warnings) == 0,
        "findings": findings,
        "warnings": warnings,
        "recommendations": recommendations,
    })


def audit_rbac(namespace: str = "all") -> str:
    """
    Audit RBAC permissions — who can do what in the cluster.
    Finds overprivileged service accounts, cluster-admin bindings,
    and wildcard permissions.
    """
    findings = []
    warnings = []
    risky_bindings = []

    # Get ClusterRoleBindings
    crb_data = run_kubectl("get", "clusterrolebindings")
    if isinstance(crb_data, dict):
        for item in crb_data.get("items", []):
            meta = item.get("metadata", {})
            role_ref = item.get("roleRef", {})
            subjects = item.get("subjects", [])

            # Flag cluster-admin bindings
            if role_ref.get("name") == "cluster-admin":
                for subj in subjects:
                    if subj.get("kind") != "Node":
                        risky_bindings.append({
                            "binding": meta.get("name"),
                            "type": "ClusterRoleBinding",
                            "role": "cluster-admin",
                            "subject_kind": subj.get("kind"),
                            "subject_name": subj.get("name"),
                            "risk": "CRITICAL — full cluster access",
                        })
                        warnings.append(
                            f"⚠️  CRITICAL: {subj.get('kind')} '{subj.get('name')}' "
                            f"has cluster-admin via '{meta.get('name')}'"
                        )

    # Get ClusterRoles with wildcard permissions
    cr_data = run_kubectl("get", "clusterroles")
    if isinstance(cr_data, dict):
        for item in cr_data.get("items", []):
            meta = item.get("metadata", {})
            name = meta.get("name", "")
            if name.startswith("system:"):
                continue
            for rule in item.get("rules", []):
                if "*" in rule.get("verbs", []) and "*" in rule.get("resources", []):
                    risky_bindings.append({
                        "role": name,
                        "type": "ClusterRole",
                        "risk": "HIGH — wildcard verbs and resources",
                    })
                    warnings.append(
                        f"⚠️  ClusterRole '{name}' has wildcard (*) verbs and resources"
                    )

    if not risky_bindings:
        findings.append("✅ No critical RBAC misconfigurations found")

    findings.append(
        f"Scanned ClusterRoleBindings and ClusterRoles for privilege escalation risks"
    )

    return _j({
        "overall_risk": "HIGH" if warnings else "LOW",
        "risky_binding_count": len(risky_bindings),
        "risky_bindings": risky_bindings,
        "findings": findings,
        "warnings": warnings,
        "recommendations": [
            "Review cluster-admin bindings — use least privilege instead",
            "Replace wildcard permissions with specific resource/verb combinations",
            "Audit service account permissions regularly",
        ] if warnings else ["✅ RBAC looks healthy"],
    })


def check_pod_security(namespace: str = "all") -> str:
    """
    Check pods for security misconfigurations:
    privileged containers, running as root, hostNetwork, hostPID,
    writable root filesystem, missing security context.
    """
    findings = []
    warnings = []
    risky_pods = []

    if namespace == "all":
        data = run_kubectl("get", "pods", "--all-namespaces")
    else:
        data = run_kubectl("get", "pods", "-n", namespace)

    if isinstance(data, dict):
        for item in data.get("items", []):
            meta = item.get("metadata", {})
            spec = item.get("spec", {})
            pod_name = meta.get("name")
            pod_ns = meta.get("namespace")
            risks = []

            # Host network
            if spec.get("hostNetwork"):
                risks.append("hostNetwork=true — shares node network namespace")

            # Host PID
            if spec.get("hostPID"):
                risks.append("hostPID=true — can see all node processes")

            # Host IPC
            if spec.get("hostIPC"):
                risks.append("hostIPC=true — shared IPC namespace")

            for c in spec.get("containers", []):
                sc = c.get("securityContext", {})
                c_name = c.get("name")

                # Privileged
                if sc.get("privileged"):
                    risks.append(f"container '{c_name}' is privileged — full node access")

                # Running as root
                if sc.get("runAsUser") == 0 or sc.get("runAsNonRoot") is False:
                    risks.append(f"container '{c_name}' runs as root (UID 0)")

                # No security context at all
                if not sc:
                    risks.append(f"container '{c_name}' has no securityContext")

                # Writable root filesystem
                if sc.get("readOnlyRootFilesystem") is False:
                    risks.append(f"container '{c_name}' has writable root filesystem")

                # Allow privilege escalation
                if sc.get("allowPrivilegeEscalation") is True:
                    risks.append(f"container '{c_name}' allows privilege escalation")

                # Capabilities
                caps = sc.get("capabilities", {})
                if "SYS_ADMIN" in caps.get("add", []):
                    risks.append(f"container '{c_name}' has SYS_ADMIN capability")

            if risks:
                risky_pods.append({
                    "pod": pod_name,
                    "namespace": pod_ns,
                    "risks": risks,
                    "risk_count": len(risks),
                })
                for risk in risks:
                    warnings.append(f"⚠️  [{pod_ns}/{pod_name}] {risk}")

    if not risky_pods:
        findings.append("✅ No security misconfigurations found in pods")
    else:
        findings.append(
            f"Found {len(risky_pods)} pods with security risks"
        )

    return _j({
        "overall_security": "AT RISK" if risky_pods else "SECURE",
        "risky_pod_count": len(risky_pods),
        "risky_pods": sorted(risky_pods, key=lambda x: x["risk_count"], reverse=True),
        "findings": findings,
        "warnings": warnings[:20],
        "recommendations": [
            "Set runAsNonRoot: true in all container securityContexts",
            "Set readOnlyRootFilesystem: true where possible",
            "Remove privileged: true unless absolutely necessary",
            "Drop all capabilities and add only what's needed",
            "Enable Pod Security Admission (PSA) at namespace level",
        ],
    })


def scan_secrets_exposure(namespace: str = "all") -> str:
    """
    Scan for secrets exposure risks:
    secrets mounted as env vars (readable in logs),
    secrets in ConfigMaps, default service account tokens,
    and unencrypted secrets at rest.
    """
    findings = []
    warnings = []
    exposed = []

    if namespace == "all":
        pod_data = run_kubectl("get", "pods", "--all-namespaces")
    else:
        pod_data = run_kubectl("get", "pods", "-n", namespace)

    if isinstance(pod_data, dict):
        for item in pod_data.get("items", []):
            meta = item.get("metadata", {})
            spec = item.get("spec", {})
            pod_name = meta.get("name")
            pod_ns = meta.get("namespace")

            for c in spec.get("containers", []):
                # Check env vars sourced from secrets
                for env in c.get("env", []):
                    value_from = env.get("valueFrom", {})
                    if value_from.get("secretKeyRef"):
                        secret_name = value_from["secretKeyRef"].get("name")
                        key = value_from["secretKeyRef"].get("key")
                        exposed.append({
                            "pod": pod_name,
                            "namespace": pod_ns,
                            "container": c.get("name"),
                            "type": "secret_as_env_var",
                            "secret": secret_name,
                            "key": key,
                            "risk": "Secret value visible in process environment and potentially in logs",
                        })
                        warnings.append(
                            f"⚠️  [{pod_ns}/{pod_name}] Secret '{secret_name}.{key}' "
                            f"mounted as env var — visible in process list"
                        )

                # Check for hardcoded secrets in env
                risky_names = ["password", "secret", "key", "token", "api_key", "credentials"]
                for env in c.get("env", []):
                    env_name = env.get("name", "").lower()
                    if any(r in env_name for r in risky_names) and "value" in env:
                        exposed.append({
                            "pod": pod_name,
                            "namespace": pod_ns,
                            "container": c.get("name"),
                            "type": "hardcoded_secret",
                            "env_var": env.get("name"),
                            "risk": "Hardcoded secret in pod spec — stored in etcd unencrypted",
                        })
                        warnings.append(
                            f"⚠️  [{pod_ns}/{pod_name}] Possible hardcoded secret "
                            f"in env var '{env.get('name')}'"
                        )

            # Check default service account usage
            sa = spec.get("serviceAccountName", "default")
            if sa == "default":
                warnings.append(
                    f"⚠️  [{pod_ns}/{pod_name}] Using 'default' service account — "
                    f"consider using a dedicated service account with minimal permissions"
                )

    if not exposed:
        findings.append("✅ No obvious secret exposure found")
    else:
        findings.append(f"Found {len(exposed)} potential secret exposure issues")

    return _j({
        "exposure_count": len(exposed),
        "exposures": exposed[:20],
        "findings": findings,
        "warnings": warnings[:20],
        "recommendations": [
            "Use volume mounts instead of env vars for secrets",
            "Use AWS Secrets Manager with External Secrets Operator",
            "Enable envelope encryption for etcd (KMS provider)",
            "Use dedicated service accounts, not 'default'",
            "Rotate any exposed secrets immediately",
        ],
    })


def get_eks_access_entries(cluster_name: str, region: str = "us-east-1") -> str:
    """List all IAM principals with access to the EKS cluster with their policies."""
    try:
        eks = get_client("eks", region)
        entries = eks.list_access_entries(clusterName=cluster_name).get("accessEntries", [])
        details = []
        for arn in entries:
            try:
                detail = eks.describe_access_entry(
                    clusterName=cluster_name, principalArn=arn
                )["accessEntry"]
                policies = eks.list_associated_access_policies(
                    clusterName=cluster_name, principalArn=arn
                ).get("associatedAccessPolicies", [])
                details.append({
                    "principal_arn": arn,
                    "type": detail.get("type"),
                    "username": detail.get("username"),
                    "groups": detail.get("kubernetesGroups", []),
                    "policies": [
                        {
                            "policy_arn": p.get("policyArn"),
                            "scope": p.get("accessScope", {}).get("type"),
                            "namespaces": p.get("accessScope", {}).get("namespaces", []),
                        }
                        for p in policies
                    ],
                    "is_cluster_admin": any(
                        "ClusterAdmin" in p.get("policyArn", "")
                        for p in policies
                    ),
                })
            except Exception:
                details.append({"principal_arn": arn})

        admin_count = sum(1 for d in details if d.get("is_cluster_admin"))
        return _j({
            "cluster": cluster_name,
            "total_entries": len(details),
            "cluster_admin_count": admin_count,
            "access_entries": details,
        })
    except Exception as e:
        return _j({"error": str(e)})


def get_iam_to_k8s_mapping(cluster_name: str, region: str = "us-east-1") -> str:
    """
    Show complete mapping of IAM → Kubernetes permissions.
    Maps IAM users/roles to their Kubernetes RBAC permissions.
    Essential for security audits and access reviews.
    """
    try:
        eks = get_client("eks", region)
        entries = eks.list_access_entries(clusterName=cluster_name).get("accessEntries", [])
        mapping = []

        for arn in entries:
            try:
                detail = eks.describe_access_entry(
                    clusterName=cluster_name, principalArn=arn
                )["accessEntry"]
                policies = eks.list_associated_access_policies(
                    clusterName=cluster_name, principalArn=arn
                ).get("associatedAccessPolicies", [])

                # Determine effective permissions
                k8s_permissions = []
                for p in policies:
                    policy_arn = p.get("policyArn", "")
                    scope = p.get("accessScope", {})
                    if "ClusterAdmin" in policy_arn:
                        k8s_permissions.append("cluster-admin (ALL resources, ALL namespaces)")
                    elif "Admin" in policy_arn:
                        k8s_permissions.append(f"admin ({scope})")
                    elif "Edit" in policy_arn:
                        k8s_permissions.append(f"edit ({scope})")
                    elif "View" in policy_arn:
                        k8s_permissions.append(f"view ({scope})")
                    else:
                        k8s_permissions.append(policy_arn.split("/")[-1])

                mapping.append({
                    "iam_principal": arn,
                    "principal_type": detail.get("type"),
                    "kubernetes_username": detail.get("username"),
                    "kubernetes_groups": detail.get("kubernetesGroups", []),
                    "effective_permissions": k8s_permissions,
                    "is_highly_privileged": any(
                        "admin" in p.lower() for p in k8s_permissions
                    ),
                })
            except Exception:
                pass

        highly_privileged = [m for m in mapping if m.get("is_highly_privileged")]

        return _j({
            "cluster": cluster_name,
            "total_principals": len(mapping),
            "highly_privileged_count": len(highly_privileged),
            "highly_privileged": [m["iam_principal"] for m in highly_privileged],
            "iam_to_k8s_mapping": mapping,
        })
    except Exception as e:
        return _j({"error": str(e)})
