"""NLB / Service investigation tool."""
from __future__ import annotations
import ipaddress
import boto3
from datetime import datetime, timedelta
from typing import Optional
from eks_sage_enterprise.core.kubectl import run_kubectl, run_kubectl_raw
from eks_sage_enterprise.core.aws_client import get_client
from eks_sage_enterprise.core.utils import _j


def investigate_nlb_service(
    service_name: str,
    namespace: str = "default",
    region: str = "us-east-1",
    user_ip: Optional[str] = None,
    user_domain: Optional[str] = None,
) -> str:
    """Full end-to-end NLB + Service investigation. See tool docstring."""
    Full end-to-end investigation of an NLB + Service (no Ingress) setup.

    Checks the COMPLETE traffic path:
    User URL → Route53 DNS → NLB → Target Group → NodePort → Service → Pods

    Checks:
    Step 0 → Controller pods health (aws-load-balancer-controller, coredns)
    Step 1 → Service type + port mapping
    Step 2 → NLB hostname assigned
    Step 3 → Endpoints health
    Step 4 → Pod + containerPort match
    Step 5 → Port chain validation (golden rule)
    Step 6 → Target Group health in AWS
    Step 7 → Source IP annotation + user IP validation
    Step 8 → Route53 hosted zone + DNS record + TTL + health check

    Args:
        service_name: Kubernetes Service name
        namespace: Kubernetes namespace (default: default)
        region: AWS region (default: us-east-1)
        user_ip: Optional user IP to validate against annotation + security group
                 e.g. "203.0.113.45"
        user_domain: Optional domain name to check Route53 DNS record
                     e.g. "app.example.com"
    """
    findings = []
    warnings = []
    recommendations = []
    port_map = {}

    # ── Step 0: Check required controller pods ───────────────────────────────
    # Before checking the service, verify the controllers that make NLB work
    # are actually healthy. A failing controller = NLB never created/updated.

    CONTROLLERS = [
        {
            "name": "aws-load-balancer-controller",
            "label": "app.kubernetes.io/name=aws-load-balancer-controller",
            "namespace": "kube-system",
            "why": "Creates and manages NLB. If down, EXTERNAL-IP stays <pending>.",
        },
        {
            "name": "coredns",
            # EKS Auto Mode and standard EKS use different labels
            # Try both: k8s-app=kube-dns (standard) and eks.amazonaws.com/component=coredns (Auto Mode)
            "label": "k8s-app=kube-dns",
            "label_fallback": "eks.amazonaws.com/component=coredns",
            "namespace": "kube-system",
            "why": "DNS resolution. If down, service hostnames won't resolve.",
        },
    ]

    controller_issues = []

    for ctrl in CONTROLLERS:
        ctrl_pods = run_kubectl(
            "get", "pods",
            "-n", ctrl["namespace"],
            "-l", ctrl["label"],
        )

        # If no pods found and fallback label exists, try fallback
        if (isinstance(ctrl_pods, dict) and
                not ctrl_pods.get("items") and
                ctrl.get("label_fallback")):
            ctrl_pods = run_kubectl(
                "get", "pods",
                "-n", ctrl["namespace"],
                "-l", ctrl["label_fallback"],
            )
            if ctrl_pods.get("items"):
                findings.append(
                    f"Found '{ctrl['name']}' using fallback label "
                    f"'{ctrl['label_fallback']}' (EKS Auto Mode)"
                )

        if "error" in ctrl_pods:
            controller_issues.append(
                f"Could not check {ctrl['name']}: {ctrl_pods.get('error')}"
            )
            continue

        items = ctrl_pods.get("items", [])

        if not items:
            # Controller not installed at all
            if ctrl["name"] == "aws-load-balancer-controller":
                warnings.append(
                    f"⚠️  aws-load-balancer-controller is NOT installed. "
                    f"This is why EXTERNAL-IP is <pending>. "
                    f"Reason: {ctrl['why']}"
                )
                recommendations.append(
                    "Install AWS Load Balancer Controller via Helm or eksctl. "
                    "Without it no NLB can be created or updated."
                )
            else:
                findings.append(f"Controller '{ctrl['name']}' not found in kube-system")
            continue

        # Check each controller pod
        running = 0
        not_running = []
        for pod in items:
            meta = pod.get("metadata", {})
            status_p = pod.get("status", {})
            phase = status_p.get("phase")
            pod_name = meta.get("name")

            # Check container statuses for specific failure reasons
            container_statuses = status_p.get("containerStatuses", [])
            failure_reason = None
            for cs in container_statuses:
                state = cs.get("state", {})
                waiting = state.get("waiting", {})
                terminated = state.get("terminated", {})
                if waiting.get("reason"):
                    failure_reason = waiting.get("reason")
                if terminated.get("reason") == "OOMKilled":
                    failure_reason = "OOMKilled"

            if phase == "Running":
                running += 1
                findings.append(
                    f"✅ Controller '{ctrl['name']}' pod '{pod_name}' is Running"
                )
            else:
                not_running.append(pod_name)
                reason_str = f" ({failure_reason})" if failure_reason else ""
                warnings.append(
                    f"⚠️  Controller '{ctrl['name']}' pod '{pod_name}' "
                    f"is {phase}{reason_str}. "
                    f"Impact: {ctrl['why']}"
                )
                # Give specific recommendation based on failure reason
                if failure_reason == "ImagePullBackOff":
                    recommendations.append(
                        f"Controller '{ctrl['name']}' cannot pull its image. "
                        f"Check ECR/registry access and VPC endpoints."
                    )
                elif failure_reason == "OOMKilled":
                    recommendations.append(
                        f"Controller '{ctrl['name']}' ran out of memory. "
                        f"Increase memory limits in the controller deployment."
                    )
                elif failure_reason == "CrashLoopBackOff":
                    recommendations.append(
                        f"Controller '{ctrl['name']}' is crash looping. "
                        f"Check logs: kubectl logs {pod_name} -n {ctrl['namespace']}"
                    )
                else:
                    recommendations.append(
                        f"Investigate '{ctrl['name']}' pod '{pod_name}'. "
                        f"Check logs: kubectl logs {pod_name} -n {ctrl['namespace']}"
                    )

        if running == 0 and items:
            warnings.append(
                f"🚫 ALL '{ctrl['name']}' pods are down ({len(not_running)} pods). "
                f"NLB operations are completely broken."
            )

    if controller_issues:
        findings.append(f"Controller check errors: {controller_issues}")

    # ── Step 1: Get the Kubernetes Service ──────────────────────────────────
    svc_data = run_kubectl("get", "service", service_name, "-n", namespace)
    if "error" in svc_data:
        return _j({"error": f"Service '{service_name}' not found: {svc_data.get('error')}"})

    spec = svc_data.get("spec", {})
    status = svc_data.get("status", {})
    svc_type = spec.get("type")
    # Define annotations early so all steps can access it
    annotations = svc_data.get("metadata", {}).get("annotations", {})
    selector = spec.get("selector", {})

    # Extract port mapping
    ports = spec.get("ports", [])
    for p in ports:
        port_map = {
            "service_port": p.get("port"),
            "node_port": p.get("nodePort"),
            "target_port": p.get("targetPort"),
            "protocol": p.get("protocol"),
        }

    findings.append(f"Service type: {svc_type}")
    findings.append(f"Service port mapping: port={port_map.get('service_port')} → targetPort={port_map.get('target_port')} → nodePort={port_map.get('node_port')}")

    if svc_type != "LoadBalancer":
        warnings.append(
            f"Service type is '{svc_type}' not 'LoadBalancer'. "
            "NLB is only created for LoadBalancer type services."
        )

    # ── Step 2: Get NLB hostname from service status ─────────────────────────
    lb_ingress = status.get("loadBalancer", {}).get("ingress", [])
    nlb_hostname = None
    if lb_ingress:
        nlb_hostname = lb_ingress[0].get("hostname") or lb_ingress[0].get("ip")
        findings.append(f"NLB hostname: {nlb_hostname}")
    else:
        warnings.append(
            "No NLB hostname assigned yet. "
            "Either the service was just created or the AWS Load Balancer Controller is not running."
        )
        recommendations.append(
            "Check AWS Load Balancer Controller is installed: "
            "kubectl get pods -n kube-system | grep aws-load-balancer"
        )

    # ── Step 3: Check Endpoints ──────────────────────────────────────────────
    ep_data = run_kubectl("get", "endpoints", service_name, "-n", namespace)
    endpoint_ips = []
    if isinstance(ep_data, dict):
        for subset in ep_data.get("subsets", []):
            for addr in subset.get("addresses", []):
                endpoint_ips.append(addr.get("ip"))
            not_ready = subset.get("notReadyAddresses", [])
            if not_ready:
                warnings.append(
                    f"{len(not_ready)} endpoints are NOT ready: "
                    f"{[a.get('ip') for a in not_ready]}"
                )
                recommendations.append(
                    "Not-ready endpoints mean pods are failing health checks. "
                    "Check pod readiness probes and application health."
                )

    if endpoint_ips:
        findings.append(f"Healthy endpoints: {len(endpoint_ips)} → {endpoint_ips}")
    else:
        warnings.append("No healthy endpoints found!")
        recommendations.append(
            f"No pods matching selector {selector} are ready. "
            "Check pod status and readiness probes."
        )

    # ── Step 4: Check Pods matching the Service selector ────────────────────
    if selector:
        label_selector = ",".join(f"{k}={v}" for k, v in selector.items())
        pod_data = run_kubectl(
            "get", "pods",
            "-n", namespace,
            "-l", label_selector,
        )
        pods = []
        if isinstance(pod_data, dict):
            items = pod_data.get("items", [])

            # Check if selector matches NO pods at all
            if not items:
                warnings.append(
                    f"⚠️  No pods found matching selector {selector}. "
                    f"Service has no pods to route traffic to."
                )
                recommendations.append(
                    f"Check deployment exists and selector labels match: "
                    f"kubectl get pods -n {namespace} -l {label_selector}"
                )

            for item in items:
                meta = item.get("metadata", {})
                status_p = item.get("status", {})
                spec_p = item.get("spec", {})
                containers = spec_p.get("containers", [])
                pod_name = meta.get("name")
                phase = status_p.get("phase")

                # ── Check containerPort matches targetPort ───────────────
                container_ports = []
                for c in containers:
                    for cp in c.get("ports", []):
                        container_ports.append(cp.get("containerPort"))

                target_port = port_map.get("target_port")
                port_match = str(target_port) in [str(p) for p in container_ports]

                # ── Check all failure reasons ────────────────────────────
                for cs in status_p.get("containerStatuses", []):
                    c_name = cs.get("name")
                    restarts = cs.get("restartCount", 0)
                    state = cs.get("state", {})
                    last_state = cs.get("lastState", {})
                    waiting = state.get("waiting", {})
                    terminated = state.get("terminated", {})
                    last_terminated = last_state.get("terminated", {})

                    # CrashLoopBackOff
                    if waiting.get("reason") == "CrashLoopBackOff":
                        warnings.append(
                            f"⚠️  Pod '{pod_name}' container '{c_name}' "
                            f"is CrashLoopBackOff (restarts: {restarts}). "
                            f"Application keeps crashing."
                        )
                        recommendations.append(
                            f"Check logs: kubectl logs {pod_name} "
                            f"-n {namespace} -c {c_name} --previous"
                        )

                    # OOMKilled
                    if (terminated.get("reason") == "OOMKilled" or
                            last_terminated.get("reason") == "OOMKilled"):
                        warnings.append(
                            f"⚠️  Pod '{pod_name}' container '{c_name}' "
                            f"was OOMKilled — ran out of memory."
                        )
                        recommendations.append(
                            f"Increase memory limit for container '{c_name}'. "
                            f"Current limit may be too low."
                        )

                    # ImagePullBackOff
                    if waiting.get("reason") in ("ImagePullBackOff", "ErrImagePull"):
                        warnings.append(
                            f"⚠️  Pod '{pod_name}' cannot pull image: "
                            f"{waiting.get('message', 'unknown error')}. "
                            f"Check ECR permissions and VPC endpoints."
                        )
                        recommendations.append(
                            "Check VPC endpoints for ECR exist: "
                            "com.amazonaws.region.ecr.api, "
                            "com.amazonaws.region.ecr.dkr, "
                            "com.amazonaws.region.s3"
                        )

                    # Pending — no node available
                    if phase == "Pending":
                        # Check if it's a scheduling issue
                        conditions = status_p.get("conditions", [])
                        for cond in conditions:
                            if (cond.get("type") == "PodScheduled" and
                                    cond.get("status") == "False"):
                                reason = cond.get("reason", "")
                                message = cond.get("message", "")
                                if "Insufficient" in message:
                                    warnings.append(
                                        f"⚠️  Pod '{pod_name}' is Pending — "
                                        f"insufficient resources on nodes. "
                                        f"Message: {message}"
                                    )
                                    recommendations.append(
                                        "Scale up your node group or reduce "
                                        "pod resource requests."
                                    )
                                elif "Unschedulable" in reason:
                                    warnings.append(
                                        f"⚠️  Pod '{pod_name}' is Unschedulable. "
                                        f"Message: {message}"
                                    )
                                    recommendations.append(
                                        "Check node taints and pod tolerations. "
                                        "Check node selectors match available nodes."
                                    )
                                else:
                                    warnings.append(
                                        f"⚠️  Pod '{pod_name}' not scheduled: "
                                        f"{reason} — {message}"
                                    )

                    # High restarts
                    if restarts > 5:
                        warnings.append(
                            f"⚠️  Pod '{pod_name}' container '{c_name}' "
                            f"has restarted {restarts} times. "
                            f"Likely unstable application."
                        )
                        recommendations.append(
                            f"Check application logs for crash reason: "
                            f"kubectl logs {pod_name} -n {namespace} --previous"
                        )

                    # No resource limits
                    for c in containers:
                        resources = c.get("resources", {})
                        if not resources.get("limits"):
                            warnings.append(
                                f"⚠️  Container '{c.get('name')}' in pod "
                                f"'{pod_name}' has NO resource limits. "
                                f"Risk of OOMKill and node pressure."
                            )
                            recommendations.append(
                                f"Add resource limits to container '{c.get('name')}' "
                                f"to prevent OOMKill and protect other pods."
                            )

                # ── Check app health via logs ─────────────────────────────
                # Look for 5xx errors in recent logs
                if phase == "Running":
                    recent_logs = run_kubectl_raw(
                        "logs", pod_name,
                        "-n", namespace,
                        "--tail=20",
                        "--since=5m",
                    )
                    if recent_logs and not isinstance(recent_logs, dict):
                        error_lines = [
                            line for line in recent_logs.split("\n")
                            if any(err in line.upper() for err in [
                                "ERROR", "FATAL", "PANIC",
                                "500", "502", "503", "504",
                                "EXCEPTION", "TRACEBACK",
                                "CONNECTION REFUSED", "TIMEOUT"
                            ])
                        ]
                        if error_lines:
                            warnings.append(
                                f"⚠️  Pod '{pod_name}' has recent error logs "
                                f"({len(error_lines)} error lines in last 5 min). "
                                f"App may be returning 5xx errors."
                            )
                            findings.append(
                                f"Recent errors in '{pod_name}': "
                                f"{error_lines[:3]}"
                            )
                            recommendations.append(
                                f"Check full logs: kubectl logs {pod_name} "
                                f"-n {namespace} --since=10m"
                            )

                pods.append({
                    "name": pod_name,
                    "phase": phase,
                    "pod_ip": status_p.get("podIP"),
                    "container_ports": container_ports,
                    "target_port_match": port_match,
                    "node": spec_p.get("nodeName"),
                })

                if not port_match:
                    warnings.append(
                        f"⚠️  Pod '{pod_name}' container ports {container_ports} "
                        f"do NOT match service targetPort {target_port}. "
                        "Traffic will fail!"
                    )
                    recommendations.append(
                        f"Fix: Set containerPort in pod spec to match "
                        f"service targetPort ({target_port})"
                    )

        findings.append(f"Pods matching selector: {len(pods)}")

        # Check if service has NO selector at all
    elif not selector:
        warnings.append(
            "⚠️  Service has NO selector defined. "
            "Service will not route to any pods automatically. "
            "You must manually create Endpoints."
        )
        recommendations.append(
            "Add a selector to the service matching your pod labels. "
            "e.g. selector: app: my-app"
        )

    # ── Step 5: Validate Port Chain ──────────────────────────────────────────
    port_chain = {
        "nlb_listener": "443 (HTTPS) or 80 (HTTP)",
        "target_group_port": port_map.get("node_port"),
        "service_node_port": port_map.get("node_port"),
        "service_target_port": port_map.get("target_port"),
        "pod_container_port": port_map.get("target_port"),
    }

    # The golden rule from your notes:
    # NLB Target Group port = NodePort
    node_port = port_map.get("node_port")
    if node_port:
        findings.append(
            f"✅ Rule check: NLB Target Group port should equal NodePort ({node_port})"
        )
        if 30000 <= int(node_port) <= 32767:
            findings.append(
                f"✅ NodePort {node_port} is in valid Kubernetes range (30000-32767)"
            )
        else:
            warnings.append(
                f"NodePort {node_port} is outside normal range 30000-32767"
            )

    # ── Step 6: Check AWS NLB Target Group health via boto3 ─────────────────
    if nlb_hostname:
        try:
            import boto3
            lb_client = boto3.client("elbv2", region_name=region)
            ec2_client = boto3.client("ec2", region_name=region)

            # Find the NLB by hostname
            lbs = lb_client.describe_load_balancers().get("LoadBalancers", [])
            nlb = next(
                (lb for lb in lbs
                 if lb.get("DNSName", "").lower() == nlb_hostname.lower()),
                None,
            )

            if nlb:
                nlb_arn = nlb["LoadBalancerArn"]
                nlb_state = nlb.get("State", {}).get("Code")
                nlb_scheme = nlb.get("Scheme")
                nlb_vpc = nlb.get("VpcId")
                nlb_azs = nlb.get("AvailabilityZones", [])
                nlb_type = nlb.get("Type")

                findings.append(f"NLB ARN: {nlb_arn}")
                findings.append(f"NLB state: {nlb_state}")
                findings.append(f"NLB scheme: {nlb_scheme}")
                findings.append(f"NLB VPC: {nlb_vpc}")
                findings.append(
                    f"NLB subnets: {[az.get('SubnetId') for az in nlb_azs]}"
                )

                # ── Check 6a: NLB State ──────────────────────────────────
                if nlb_state != "active":
                    warnings.append(
                        f"⚠️  NLB is in state '{nlb_state}' not 'active'. "
                        f"Traffic cannot be routed until NLB is active."
                    )
                    recommendations.append(
                        "Wait for NLB to become active or check AWS console "
                        "for provisioning errors."
                    )
                else:
                    findings.append("✅ NLB state is active")

                # ── Check 6b: NLB Scheme ─────────────────────────────────
                if nlb_scheme == "internal":
                    warnings.append(
                        "⚠️  NLB scheme is 'internal' — only reachable from "
                        "within the VPC. External users cannot reach this service."
                    )
                    recommendations.append(
                        "If external access is needed change annotation to: "
                        "service.beta.kubernetes.io/aws-load-balancer-scheme: internet-facing"
                    )
                else:
                    findings.append(f"✅ NLB scheme is '{nlb_scheme}' — publicly reachable")

                # ── Check 6c: NLB has listeners ──────────────────────────
                listeners = lb_client.describe_listeners(
                    LoadBalancerArn=nlb_arn
                ).get("Listeners", [])

                if not listeners:
                    warnings.append(
                        "⚠️  NLB has NO listeners configured. "
                        "Traffic cannot enter the NLB without a listener."
                    )
                    recommendations.append(
                        f"Add a listener to the NLB on port 80 (or 443) "
                        f"forwarding to the target group."
                    )
                else:
                    for listener in listeners:
                        l_port = listener.get("Port")
                        l_protocol = listener.get("Protocol")
                        findings.append(
                            f"✅ NLB Listener: {l_protocol}:{l_port}"
                        )

                # ── Check 6d: NLB subnets have routes ───────────────────
                subnet_ids = [az.get("SubnetId") for az in nlb_azs]
                if len(subnet_ids) < 2:
                    warnings.append(
                        f"⚠️  NLB is only in {len(subnet_ids)} subnet(s). "
                        "For high availability use at least 2 subnets "
                        "in different availability zones."
                    )
                    recommendations.append(
                        "Add NLB to subnets in multiple AZs for HA."
                    )
                else:
                    findings.append(
                        f"✅ NLB spans {len(subnet_ids)} subnets across multiple AZs"
                    )

                # ── Check 6e: Target Groups ──────────────────────────────
                tgs = lb_client.describe_target_groups(
                    LoadBalancerArn=nlb_arn
                ).get("TargetGroups", [])

                for tg in tgs:
                    tg_arn = tg["TargetGroupArn"]
                    tg_port = tg.get("Port")
                    tg_protocol = tg.get("Protocol")
                    tg_target_type = tg.get("TargetType")
                    tg_health_check = tg.get("HealthCheckProtocol")
                    tg_hc_path = tg.get("HealthCheckPath", "/")
                    tg_hc_interval = tg.get("HealthCheckIntervalSeconds")
                    tg_hc_threshold = tg.get("HealthyThresholdCount")

                    findings.append(
                        f"Target Group: {tg['TargetGroupName']} "
                        f"port={tg_port} type={tg_target_type} "
                        f"protocol={tg_protocol}"
                    )

                    # Target type check
                    annotation_target_type = annotations.get(
                        "service.beta.kubernetes.io/aws-load-balancer-nlb-target-type"
                    )
                    if annotation_target_type and tg_target_type:
                        if annotation_target_type != tg_target_type:
                            warnings.append(
                                f"⚠️  Target type mismatch: annotation says "
                                f"'{annotation_target_type}' but Target Group "
                                f"is using '{tg_target_type}'. "
                                f"This can cause traffic routing issues."
                            )
                            recommendations.append(
                                f"Fix: Ensure annotation "
                                f"'aws-load-balancer-nlb-target-type' matches "
                                f"the actual Target Group target type."
                            )
                        else:
                            findings.append(
                                f"✅ Target type '{tg_target_type}' matches annotation"
                            )

                    # Golden rule check
                    if node_port and str(tg_port) != str(node_port):
                        warnings.append(
                            f"⚠️  MISMATCH: Target Group port ({tg_port}) "
                            f"≠ Service NodePort ({node_port}). "
                            "Traffic WILL fail! NLB Target Group port must equal NodePort."
                        )
                        recommendations.append(
                            f"Fix: Update the NLB Target Group port to {node_port} "
                            f"OR update the Service to use nodePort: {tg_port}"
                        )
                    else:
                        findings.append(
                            f"✅ Target Group port ({tg_port}) matches NodePort ({node_port})"
                        )

                    # Health check settings
                    findings.append(
                        f"Health check: protocol={tg_health_check} "
                        f"interval={tg_hc_interval}s "
                        f"threshold={tg_hc_threshold}"
                    )

                    # Check target health
                    health = lb_client.describe_target_health(
                        TargetGroupArn=tg_arn
                    ).get("TargetHealthDescriptions", [])

                    healthy = [
                        t for t in health
                        if t.get("TargetHealth", {}).get("State") == "healthy"
                    ]
                    unhealthy = [
                        t for t in health
                        if t.get("TargetHealth", {}).get("State") != "healthy"
                    ]
                    initial = [
                        t for t in health
                        if t.get("TargetHealth", {}).get("State") == "initial"
                    ]

                    findings.append(
                        f"Target health: {len(healthy)} healthy, "
                        f"{len(unhealthy)} unhealthy, "
                        f"{len(initial)} initial"
                    )

                    if initial:
                        findings.append(
                            f"ℹ️  {len(initial)} targets in 'initial' state — "
                            f"still registering, wait 30-60 seconds."
                        )

                    if unhealthy:
                        for t in unhealthy:
                            reason = t.get("TargetHealth", {}).get("Reason")
                            desc = t.get("TargetHealth", {}).get("Description")
                            t_id = t.get("Target", {}).get("Id")
                            t_port = t.get("Target", {}).get("Port")
                            warnings.append(
                                f"⚠️  Unhealthy target {t_id}:{t_port} — "
                                f"{reason}: {desc}"
                            )
                        recommendations.append(
                            "Unhealthy targets: Check security group allows "
                            f"NodePort {node_port} traffic from NLB. "
                            "Check pods are passing health checks. "
                            "Check application is responding on the correct port."
                        )
                    else:
                        findings.append("✅ All targets are healthy")

                    # ── Check 6f: NLB Security Groups ────────────────────
                    node_sg = nlb.get("SecurityGroups", [])
                    if node_sg:
                        findings.append(f"NLB security groups: {node_sg}")

                        # Check if port 80/443 is open on NLB SG
                        sgs = ec2_client.describe_security_groups(
                            GroupIds=node_sg
                        ).get("SecurityGroups", [])

                        for sg in sgs:
                            inbound = sg.get("IpPermissions", [])
                            ports_open = []
                            for rule in inbound:
                                from_p = rule.get("FromPort", 0)
                                to_p = rule.get("ToPort", 65535)
                                for ip_r in rule.get("IpRanges", []):
                                    if ip_r.get("CidrIp") == "0.0.0.0/0":
                                        ports_open.append(f"{from_p}-{to_p}")

                            if ports_open:
                                findings.append(
                                    f"✅ NLB SG {sg['GroupId']} allows "
                                    f"public traffic on ports: {ports_open}"
                                )
                            else:
                                warnings.append(
                                    f"⚠️  NLB SG {sg['GroupId']} has no "
                                    f"inbound rules allowing public traffic. "
                                    f"Users cannot reach the NLB."
                                )
                                recommendations.append(
                                    f"Fix: Add inbound rule to NLB security "
                                    f"group {sg['GroupId']}:\n"
                                    f"  Port: 80 (and/or 443)\n"
                                    f"  Source: 0.0.0.0/0"
                                )
                    else:
                        findings.append(
                            "NLB has no security groups "
                            "(NLBs don't always require SGs — "
                            "traffic may be controlled at node level)"
                        )

            else:
                warnings.append(
                    f"⚠️  Could not find NLB with hostname {nlb_hostname} "
                    f"in AWS. It may have been deleted while service still "
                    f"shows the old hostname."
                )
                recommendations.append(
                    "Delete and recreate the service to provision a new NLB: "
                    f"kubectl delete service {service_name} -n {namespace} "
                    f"&& kubectl apply -f your-service.yaml"
                )

        except Exception as e:
            findings.append(f"Could not fetch NLB details from AWS: {e}")

    # ── Step 7: Check annotation source ranges + validate user IP ───────────
    # annotations already defined in Step 1
    source_ranges_raw = annotations.get(
        "service.beta.kubernetes.io/load-balancer-source-ranges"
    )

    ip_allowed_in_annotation = None
    ip_allowed_in_sg = None

    if source_ranges_raw:
        # Parse the CIDR ranges from annotation
        # e.g. "10.0.0.0/8, 203.0.113.0/24" → ["10.0.0.0/8", "203.0.113.0/24"]
        cidr_list = [c.strip() for c in source_ranges_raw.split(",")]
        findings.append(
            f"Annotation source ranges found: {cidr_list}"
        )

        # If user IP provided — check if it falls in any of the ranges
        if user_ip:
            try:
                import ipaddress
                user_addr = ipaddress.ip_address(user_ip)
                ip_allowed_in_annotation = False

                for cidr in cidr_list:
                    network = ipaddress.ip_network(cidr, strict=False)
                    if user_addr in network:
                        ip_allowed_in_annotation = True
                        findings.append(
                            f"✅ User IP {user_ip} IS in annotation "
                            f"source range {cidr}"
                        )
                        break

                if not ip_allowed_in_annotation:
                    warnings.append(
                        f"⚠️  User IP {user_ip} is NOT in any annotation "
                        f"source range: {cidr_list}"
                    )
                    recommendations.append(
                        f"Fix: Add {user_ip}/32 to the annotation "
                        f"'service.beta.kubernetes.io/load-balancer-source-ranges' "
                        f"Current value: {source_ranges_raw}"
                    )

            except ValueError as e:
                warnings.append(f"Could not parse IP address: {e}")
    else:
        # Annotation is missing entirely
        findings.append(
            "Annotation 'load-balancer-source-ranges' is NOT set — "
            "NLB is open to 0.0.0.0/0 (all IPs)"
        )
        if user_ip:
            findings.append(
                f"Since annotation is missing, user IP {user_ip} "
                f"is not restricted at annotation level — "
                f"check security group inbound rules instead"
            )
        else:
            recommendations.append(
                "Consider adding annotation "
                "'service.beta.kubernetes.io/load-balancer-source-ranges' "
                "to restrict which IPs can reach the NLB."
            )

    # ── Step 7b: Validate user IP against actual AWS Security Group rules ─────
    if user_ip and nlb_hostname:
        try:
            import boto3
            import ipaddress
            ec2_client = boto3.client("ec2", region_name=region)
            lb_client = boto3.client("elbv2", region_name=region)

            # Find NLB security groups
            lbs = lb_client.describe_load_balancers().get("LoadBalancers", [])
            nlb_obj = next(
                (lb for lb in lbs
                 if lb.get("DNSName", "").lower() == nlb_hostname.lower()),
                None,
            )

            if nlb_obj:
                sg_ids = nlb_obj.get("SecurityGroups", [])

                if not sg_ids:
                    findings.append(
                        "NLB has no security groups attached "
                        "(NLBs don't always use SGs — traffic may be controlled "
                        "by node security groups instead)"
                    )
                    recommendations.append(
                        f"Check the node/worker security group (your-node-security-group) "
                        f"inbound rules for port {port_map.get('node_port')} "
                        f"to confirm user IP {user_ip} is allowed."
                    )
                else:
                    for sg_id in sg_ids:
                        sg_resp = ec2_client.describe_security_groups(
                            GroupIds=[sg_id]
                        ).get("SecurityGroups", [])

                        for sg in sg_resp:
                            findings.append(
                                f"Security group: {sg_id} ({sg.get('GroupName')})"
                            )
                            inbound_rules = sg.get("IpPermissions", [])
                            ip_allowed_in_sg = False

                            for rule in inbound_rules:
                                from_port = rule.get("FromPort", 0)
                                to_port = rule.get("ToPort", 65535)
                                node_port_int = int(port_map.get("node_port", 0))

                                # Check if rule covers the NodePort
                                if from_port <= node_port_int <= to_port:
                                    # Check if user IP is in allowed ranges
                                    for ip_range in rule.get("IpRanges", []):
                                        cidr = ip_range.get("CidrIp", "")
                                        try:
                                            network = ipaddress.ip_network(
                                                cidr, strict=False
                                            )
                                            user_addr = ipaddress.ip_address(user_ip)
                                            if user_addr in network:
                                                ip_allowed_in_sg = True
                                                findings.append(
                                                    f"✅ User IP {user_ip} IS allowed "
                                                    f"in security group {sg_id} "
                                                    f"rule: {cidr} port {from_port}-{to_port}"
                                                )
                                        except ValueError:
                                            pass

                            if ip_allowed_in_sg is False:
                                warnings.append(
                                    f"⚠️  User IP {user_ip} is NOT allowed "
                                    f"in security group {sg_id} "
                                    f"for port {port_map.get('node_port')}"
                                )
                                recommendations.append(
                                    f"Fix: Add inbound rule to security group {sg_id}:\n"
                                    f"  Type: Custom TCP\n"
                                    f"  Port: {port_map.get('node_port')}\n"
                                    f"  Source: {user_ip}/32\n"
                                    f"  Description: Allow user {user_ip} to NLB"
                                )

            # ── Final verdict for the user IP ────────────────────────────────
            if user_ip:
                if ip_allowed_in_annotation is False and ip_allowed_in_sg is False:
                    warnings.append(
                        f"🚫 BLOCKED: User IP {user_ip} is blocked at BOTH "
                        f"annotation level AND security group level. "
                        f"This is why they cannot connect."
                    )
                elif ip_allowed_in_annotation is False:
                    warnings.append(
                        f"🚫 BLOCKED at annotation: User IP {user_ip} "
                        f"is not in source ranges annotation. "
                        f"AWS will block this IP at the NLB level."
                    )
                elif ip_allowed_in_sg is False:
                    warnings.append(
                        f"🚫 BLOCKED at security group: User IP {user_ip} "
                        f"passes annotation check but is blocked by "
                        f"security group inbound rules."
                    )
                elif ip_allowed_in_annotation and ip_allowed_in_sg:
                    findings.append(
                        f"✅ User IP {user_ip} is allowed at BOTH "
                        f"annotation AND security group level. "
                        f"Network access is not the issue — check application logs."
                    )

        except Exception as e:
            findings.append(f"Could not validate user IP against security groups: {e}")

    # ── Step 8: Route53 DNS Check ─────────────────────────────────────────────
    # Checks if a Route53 hosted zone exists and if a DNS record points
    # correctly to the NLB hostname. This is the first step in the
    # traffic path: User URL → Route53 → NLB
    if user_domain:
        try:
            import boto3
            r53 = boto3.client("route53", region_name=region)

            # Step 8a — List all hosted zones
            hosted_zones = r53.list_hosted_zones().get("HostedZones", [])

            if not hosted_zones:
                warnings.append(
                    "⚠️  No Route53 hosted zones found in this account. "
                    "Users cannot reach the service via a domain name."
                )
                recommendations.append(
                    f"Create a Route53 hosted zone for your domain "
                    f"and add an alias/CNAME record pointing to: {nlb_hostname}"
                )
            else:
                findings.append(
                    f"Found {len(hosted_zones)} hosted zone(s): "
                    f"{[z['Name'] for z in hosted_zones]}"
                )

                # Step 8b — Find zone matching the domain
                matching_zone = None
                for zone in hosted_zones:
                    zone_name = zone["Name"].rstrip(".")
                    domain_clean = user_domain.rstrip(".")
                    if domain_clean.endswith(zone_name) or zone_name.endswith(domain_clean):
                        matching_zone = zone
                        break

                if not matching_zone:
                    warnings.append(
                        f"⚠️  No hosted zone found matching domain '{user_domain}'. "
                        f"Available zones: {[z['Name'] for z in hosted_zones]}"
                    )
                    recommendations.append(
                        f"Create a hosted zone for '{user_domain}' in Route53 "
                        f"OR use the correct domain that matches an existing zone."
                    )
                else:
                    zone_id = matching_zone["Id"].split("/")[-1]
                    zone_name = matching_zone["Name"]
                    findings.append(
                        f"✅ Found matching hosted zone: {zone_name} (ID: {zone_id})"
                    )

                    # Step 8c — Check DNS records in that zone
                    records = r53.list_resource_record_sets(
                        HostedZoneId=zone_id
                    ).get("ResourceRecordSets", [])

                    # Find record matching the domain
                    domain_record = None
                    for record in records:
                        record_name = record["Name"].rstrip(".")
                        domain_clean = user_domain.rstrip(".")
                        if record_name == domain_clean:
                            domain_record = record
                            break

                    if not domain_record:
                        warnings.append(
                            f"⚠️  No DNS record found for '{user_domain}' "
                            f"in hosted zone '{zone_name}'. "
                            f"Users cannot reach the service."
                        )
                        recommendations.append(
                            f"Create a DNS record in hosted zone '{zone_name}':\n"
                            f"  Name:  {user_domain}\n"
                            f"  Type:  CNAME (or Alias A record)\n"
                            f"  Value: {nlb_hostname or 'your-nlb-hostname.elb.amazonaws.com'}\n"
                            f"  TTL:   300"
                        )
                    else:
                        record_type = domain_record.get("Type")
                        findings.append(
                            f"✅ DNS record found: {user_domain} "
                            f"Type={record_type}"
                        )

                        # Step 8d — Validate record points to correct NLB
                        # Check CNAME records
                        record_values = []
                        for rr in domain_record.get("ResourceRecords", []):
                            record_values.append(rr.get("Value", "").rstrip("."))

                        # Check Alias records (Route53 specific)
                        alias_target = domain_record.get(
                            "AliasTarget", {}
                        ).get("DNSName", "").rstrip(".")

                        if alias_target:
                            record_values.append(alias_target)

                        if nlb_hostname:
                            nlb_clean = nlb_hostname.rstrip(".")
                            record_matches = any(
                                nlb_clean.lower() in v.lower() or
                                v.lower() in nlb_clean.lower()
                                for v in record_values
                            )

                            if record_matches:
                                findings.append(
                                    f"✅ DNS record correctly points to NLB: "
                                    f"{record_values}"
                                )
                            else:
                                warnings.append(
                                    f"⚠️  DNS record for '{user_domain}' points to "
                                    f"{record_values} but NLB hostname is "
                                    f"{nlb_hostname}. MISMATCH — users will reach "
                                    f"wrong endpoint or get DNS failure."
                                )
                                recommendations.append(
                                    f"Fix: Update DNS record '{user_domain}' to point to:\n"
                                    f"  {nlb_hostname}\n"
                                    f"Current value: {record_values}"
                                )
                        else:
                            findings.append(
                                f"DNS record points to: {record_values} "
                                f"(cannot verify against NLB — hostname not assigned yet)"
                            )

                        # Step 8e — Check TTL
                        ttl = domain_record.get("TTL")
                        if ttl:
                            if int(ttl) > 300:
                                warnings.append(
                                    f"⚠️  DNS TTL is {ttl} seconds ({ttl//60} minutes). "
                                    f"High TTL means DNS changes take longer to propagate. "
                                    f"Users may be cached to old endpoint."
                                )
                                recommendations.append(
                                    f"Consider lowering TTL to 60-300 seconds "
                                    f"for faster failover during incidents."
                                )
                            else:
                                findings.append(
                                    f"✅ DNS TTL is {ttl} seconds — reasonable for fast propagation"
                                )

                        # Step 8f — Check Route53 health check if attached
                        health_check_id = domain_record.get("HealthCheckId")
                        if health_check_id:
                            try:
                                hc = r53.get_health_check(
                                    HealthCheckId=health_check_id
                                ).get("HealthCheck", {})
                                hc_status = r53.get_health_check_status(
                                    HealthCheckId=health_check_id
                                ).get("HealthCheckObservations", [])

                                unhealthy_obs = [
                                    o for o in hc_status
                                    if o.get("StatusReport", {}).get("Status", "").startswith("Failure")
                                ]

                                if unhealthy_obs:
                                    warnings.append(
                                        f"⚠️  Route53 health check {health_check_id} "
                                        f"is FAILING in {len(unhealthy_obs)} regions. "
                                        f"Route53 may be removing this endpoint from DNS."
                                    )
                                    recommendations.append(
                                        f"Check health check {health_check_id} — "
                                        f"if it keeps failing Route53 will stop routing "
                                        f"traffic to this endpoint entirely."
                                    )
                                else:
                                    findings.append(
                                        f"✅ Route53 health check {health_check_id} passing"
                                    )
                            except Exception:
                                pass
                        else:
                            findings.append(
                                "No Route53 health check attached to this DNS record. "
                                "Consider adding one for automatic failover."
                            )

        except Exception as e:
            findings.append(f"Could not check Route53: {e}")
    else:
        findings.append(
            "No domain provided — skipping Route53 check. "
            "Pass 'user_domain' parameter to check DNS records. "
            "e.g. user_domain='app.example.com'"
        )

    # ── Build final summary ──────────────────────────────────────────────────
    status_overall = "HEALTHY" if not warnings else "ISSUES FOUND"

    return _j({
        "service": service_name,
        "namespace": namespace,
        "overall_status": status_overall,
        "traffic_path": {
            "user_url": f"→ Route53 ({user_domain or 'no domain provided'})",
            "dns": f"→ NLB ({nlb_hostname or 'not assigned'})",
            "nlb": f"→ Target Group (port {port_map.get('node_port')})",
            "service": f"→ NodePort {port_map.get('node_port')} → targetPort {port_map.get('target_port')}",
            "pod": f"→ containerPort {port_map.get('target_port')}",
        },
        "port_chain": port_chain,
        "golden_rule": "NLB Target Group port MUST equal Service NodePort",
        "findings": findings,
        "warnings": warnings,
        "recommendations": recommendations,
        "endpoint_count": len(endpoint_ips),
        "endpoints": endpoint_ips,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

