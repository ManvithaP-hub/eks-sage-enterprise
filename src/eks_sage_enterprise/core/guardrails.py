"""
EKS Sage Enterprise — Guardrail System
5-layer protection for safe AWS/Kubernetes operations.

Layer 1 — Operation Classification (read/write/config/destructive)
Layer 2 — Safety Mode (read_only / standard / unrestricted)
Layer 3 — Denylist (operations that can NEVER run)
Layer 4 — Confirmation Gate (writes require explicit approval)
Layer 5 — Audit Log (every operation logged)
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Callable


# ─────────────────────────────────────────────────────────────────────────────
# Layer 1 — Operation Classification
# ─────────────────────────────────────────────────────────────────────────────

class OperationType(str, Enum):
    READ         = "read"          # get, list, describe, check, investigate
    CONFIG       = "config"        # connect, switch — low risk writes
    WRITE        = "write"         # cordon, scale, annotate — reversible
    DESTRUCTIVE  = "destructive"   # delete, drain — hard to reverse


# Map tool names to their operation type
TOOL_CLASSIFICATIONS: dict[str, OperationType] = {
    # GUARDRAIL MANAGEMENT — always allowed (read/config)
    "tool_set_safety_mode":            OperationType.CONFIG,
    "tool_get_safety_status":          OperationType.READ,
    "tool_confirm_operation":          OperationType.CONFIG,
    "tool_cancel_operation":           OperationType.CONFIG,
    "tool_get_audit_log":              OperationType.READ,

    # READ — safe, never blocked
    "tool_list_clusters":              OperationType.READ,
    "tool_describe_cluster":           OperationType.READ,
    "tool_get_cluster_addons":         OperationType.READ,
    "tool_get_cluster_upgrade_insights": OperationType.READ,
    "tool_list_nodegroups":            OperationType.READ,
    "tool_get_nodes":                  OperationType.READ,
    "tool_get_node_resource_usage":    OperationType.READ,
    "tool_get_node_events":            OperationType.READ,
    "tool_get_pods":                   OperationType.READ,
    "tool_get_pod_logs":               OperationType.READ,
    "tool_describe_pod":               OperationType.READ,
    "tool_get_deployments":            OperationType.READ,
    "tool_get_pod_resource_usage":     OperationType.READ,
    "tool_get_daemonsets":             OperationType.READ,
    "tool_get_statefulsets":           OperationType.READ,
    "tool_investigate_irsa":           OperationType.READ,
    "tool_audit_rbac":                 OperationType.READ,
    "tool_check_pod_security":         OperationType.READ,
    "tool_scan_secrets_exposure":      OperationType.READ,
    "tool_get_eks_access_entries":     OperationType.READ,
    "tool_get_iam_to_k8s_mapping":     OperationType.READ,
    "tool_get_services":               OperationType.READ,
    "tool_get_ingresses":              OperationType.READ,
    "tool_get_network_policies":       OperationType.READ,
    "tool_get_configmaps_and_secrets": OperationType.READ,
    "tool_check_dns_resolution":       OperationType.READ,
    "tool_investigate_nlb_service":    OperationType.READ,
    "tool_investigate_pod":            OperationType.READ,
    "tool_investigate_daemonset":      OperationType.READ,
    "tool_investigate_statefulset":    OperationType.READ,
    "tool_investigate_cronjob":        OperationType.READ,
    "tool_get_cluster_events":         OperationType.READ,
    "tool_check_node_pressure":        OperationType.READ,
    "tool_investigate_cluster_health": OperationType.READ,
    "tool_get_incident_summary":       OperationType.READ,
    "tool_get_persistent_volumes":     OperationType.READ,
    "tool_get_storage_classes":        OperationType.READ,
    "tool_investigate_storage":        OperationType.READ,
    "tool_get_hpa":                    OperationType.READ,
    "tool_get_resource_quotas":        OperationType.READ,
    "tool_get_pod_disruption_budgets": OperationType.READ,
    "tool_get_cost_by_namespace":      OperationType.READ,
    "tool_get_namespaces":             OperationType.READ,
    "tool_get_service_accounts":       OperationType.READ,
    "tool_get_jobs_and_cronjobs":      OperationType.READ,
    "tool_get_cloudwatch_metrics":     OperationType.READ,
    "tool_get_container_insights":     OperationType.READ,
    "tool_get_application_logs":       OperationType.READ,
    "tool_get_cost_by_namespace_obs":  OperationType.READ,
    "tool_list_all_clusters":          OperationType.READ,
    "tool_compare_clusters":           OperationType.READ,
    "tool_check_compliance":           OperationType.READ,
    "tool_detect_drift":               OperationType.READ,
    "tool_check_deprecations":         OperationType.READ,
    "tool_audit_cluster_changes":      OperationType.READ,

    # CONFIG — low risk, allowed in standard mode
    "tool_connect_cluster":            OperationType.CONFIG,
    "tool_switch_cluster_context":     OperationType.CONFIG,

    # WRITE — reversible, requires standard mode + confirmation
    "tool_cordon_node":                OperationType.WRITE,

    # Future write tools go here:
    # "tool_scale_deployment":         OperationType.WRITE,
    # "tool_restart_deployment":       OperationType.WRITE,
    # "tool_annotate_service":         OperationType.WRITE,
    # "tool_uncordon_node":            OperationType.WRITE,

    # Future destructive tools go here:
    # "tool_drain_node":               OperationType.DESTRUCTIVE,
    # "tool_delete_pod":               OperationType.DESTRUCTIVE,
    # "tool_delete_namespace":         OperationType.DESTRUCTIVE,
}


# ─────────────────────────────────────────────────────────────────────────────
# Layer 2 — Safety Mode
# ─────────────────────────────────────────────────────────────────────────────

class SafetyMode(str, Enum):
    READ_ONLY    = "read_only"    # only READ operations — default
    STANDARD     = "standard"    # READ + CONFIG + WRITE (with confirmation)
    UNRESTRICTED = "unrestricted" # all except NEVER_ALLOW denylist


# Global safety mode — defaults to READ_ONLY
_safety_mode: SafetyMode = SafetyMode(
    os.getenv("EKS_SAGE_SAFETY_MODE", "read_only")
)
# Pending confirmation state — tool waiting for user approval
_pending_confirmation: dict | None = None


def get_safety_mode() -> SafetyMode:
    return _safety_mode


def set_safety_mode(mode: str) -> dict:
    global _safety_mode
    try:
        _safety_mode = SafetyMode(mode.lower())
        return {
            "safety_mode": _safety_mode.value,
            "message": f"Safety mode set to '{_safety_mode.value}'",
            "allowed_operations": _describe_mode(_safety_mode),
        }
    except ValueError:
        return {
            "error": f"Invalid mode '{mode}'",
            "valid_modes": [m.value for m in SafetyMode],
        }


def _describe_mode(mode: SafetyMode) -> list[str]:
    if mode == SafetyMode.READ_ONLY:
        return ["list", "get", "describe", "check", "investigate", "audit"]
    elif mode == SafetyMode.STANDARD:
        return ["all read operations", "connect", "switch context", "cordon (with confirmation)"]
    else:
        return ["all operations except permanently blocked denylist"]


# ─────────────────────────────────────────────────────────────────────────────
# Layer 3 — Denylist (NEVER allowed regardless of safety mode)
# ─────────────────────────────────────────────────────────────────────────────

NEVER_ALLOW: frozenset[str] = frozenset([
    # Cluster destruction
    "delete_cluster",
    "delete_nodegroup",

    # Namespace destruction
    "delete_namespace",

    # Security system destruction
    "delete_network_policy",
    "delete_pod_security_policy",

    # RBAC destruction
    "delete_clusterrolebinding",
    "delete_clusterrole",

    # Data destruction
    "delete_persistentvolume",
    "delete_persistentvolumeclaim",

    # Secret destruction
    "delete_secret",

    # Workload destruction (require explicit tool, not raw kubectl)
    "delete_deployment",
    "delete_statefulset",
    "delete_daemonset",

    # Node destruction
    "drain_node",           # too dangerous without PDB check
    "delete_node",

    # AWS resource destruction
    "eks_delete_cluster",
    "ec2_terminate_instances",
    "iam_delete_role",
    "s3_delete_bucket",
])


def is_denied(operation: str) -> bool:
    """Check if an operation is permanently blocked."""
    return operation.lower() in NEVER_ALLOW


# ─────────────────────────────────────────────────────────────────────────────
# Layer 4 — Confirmation Gate
# ─────────────────────────────────────────────────────────────────────────────

_pending_confirmations: dict[str, dict] = {}


def request_confirmation(
    tool_name: str,
    operation_type: OperationType,
    details: dict,
) -> dict:
    """
    Store a pending operation and return a confirmation request.
    The user must call confirm_operation() to proceed.
    """
    import uuid
    confirmation_id = str(uuid.uuid4())[:8].upper()
    _pending_confirmations[confirmation_id] = {
        "tool_name": tool_name,
        "operation_type": operation_type.value,
        "details": details,
        "requested_at": datetime.utcnow().isoformat(),
        "expires_at": None,  # no expiry — user must confirm or deny
    }
    return {
        "status": "CONFIRMATION_REQUIRED",
        "confirmation_id": confirmation_id,
        "operation": tool_name,
        "operation_type": operation_type.value,
        "details": details,
        "message": (
            f"⚠️  This is a {operation_type.value.upper()} operation. "
            f"Type 'confirm {confirmation_id}' to proceed "
            f"or 'cancel {confirmation_id}' to abort."
        ),
        "risk_note": _get_risk_note(tool_name),
    }


def confirm_operation(confirmation_id: str) -> dict:
    """Confirm a pending operation. Returns the stored operation details."""
    if confirmation_id not in _pending_confirmations:
        return {
            "error": f"No pending operation with ID '{confirmation_id}'. "
                     "It may have already been confirmed or cancelled."
        }
    op = _pending_confirmations.pop(confirmation_id)
    audit_log(
        tool_name=op["tool_name"],
        operation_type=op["operation_type"],
        details=op["details"],
        status="CONFIRMED",
    )
    return {"status": "CONFIRMED", "proceed": True, "operation": op}


def cancel_operation(confirmation_id: str) -> dict:
    """Cancel a pending operation."""
    if confirmation_id not in _pending_confirmations:
        return {"error": f"No pending operation with ID '{confirmation_id}'"}
    op = _pending_confirmations.pop(confirmation_id)
    audit_log(
        tool_name=op["tool_name"],
        operation_type=op["operation_type"],
        details=op["details"],
        status="CANCELLED",
    )
    return {"status": "CANCELLED", "message": "Operation cancelled — no changes made"}


def list_pending_confirmations() -> dict:
    """List all operations waiting for confirmation."""
    return {
        "pending_count": len(_pending_confirmations),
        "pending": [
            {
                "id": cid,
                "tool": op["tool_name"],
                "type": op["operation_type"],
                "requested_at": op["requested_at"],
            }
            for cid, op in _pending_confirmations.items()
        ],
    }


def _get_risk_note(tool_name: str) -> str:
    notes = {
        "tool_cordon_node": "Cordoning a node prevents new pods from being scheduled on it. Existing pods continue running.",
    }
    return notes.get(tool_name, "This operation will modify cluster state.")


# ─────────────────────────────────────────────────────────────────────────────
# Layer 5 — Audit Log
# ─────────────────────────────────────────────────────────────────────────────

_audit_log: list[dict] = []
_audit_log_file: Path | None = None


def _get_log_file() -> Path:
    global _audit_log_file
    if _audit_log_file is None:
        log_dir = Path(os.getenv("EKS_SAGE_AUDIT_LOG_DIR", "/tmp"))
        log_dir.mkdir(parents=True, exist_ok=True)
        _audit_log_file = log_dir / "eks-sage-audit.log"
    return _audit_log_file


def audit_log(
    tool_name: str,
    operation_type: str,
    details: dict,
    status: str = "EXECUTED",
    error: str | None = None,
) -> None:
    """Write an audit log entry for every operation."""
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "tool": tool_name,
        "operation_type": operation_type,
        "details": details,
        "status": status,
        "safety_mode": _safety_mode.value,
        "error": error,
    }
    _audit_log.append(entry)

    # Also write to file
    try:
        log_file = _get_log_file()
        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass  # Never let audit logging crash the operation


def get_audit_log(last_n: int = 20) -> list[dict]:
    """Return the last N audit log entries."""
    return _audit_log[-last_n:]


def get_audit_log_file_path() -> str:
    return str(_get_log_file())


# ─────────────────────────────────────────────────────────────────────────────
# Main Guardrail Enforcer
# ─────────────────────────────────────────────────────────────────────────────

def enforce(
    tool_name: str,
    details: dict | None = None,
) -> dict | None:
    """
    Main guardrail check. Call this at the START of every tool.

    Returns:
        None if the operation is allowed (proceed normally)
        dict with error/confirmation_required if blocked
    """
    details = details or {}

    # Get operation type
    op_type = TOOL_CLASSIFICATIONS.get(tool_name, OperationType.READ)

    # Layer 3 — Denylist check (always first)
    if is_denied(tool_name):
        audit_log(tool_name, op_type.value, details, status="DENIED_DENYLIST")
        return {
            "error": f"🚫 Operation '{tool_name}' is permanently blocked.",
            "reason": "This operation is on the never-allow denylist for safety.",
            "safety_mode": _safety_mode.value,
        }

    # Layer 2 — Safety mode check
    mode = _safety_mode

    if mode == SafetyMode.READ_ONLY:
        if op_type not in (OperationType.READ,):
            audit_log(tool_name, op_type.value, details, status="DENIED_READ_ONLY")
            return {
                "error": f"🔒 Operation blocked — safety mode is READ_ONLY.",
                "operation_type": op_type.value,
                "tool": tool_name,
                "fix": "Use set_safety_mode('standard') to allow write operations.",
                "current_mode": mode.value,
            }

    if mode == SafetyMode.STANDARD:
        if op_type == OperationType.DESTRUCTIVE:
            audit_log(tool_name, op_type.value, details, status="DENIED_STANDARD")
            return {
                "error": f"🔒 Destructive operation blocked in STANDARD mode.",
                "operation_type": op_type.value,
                "tool": tool_name,
                "fix": "Use set_safety_mode('unrestricted') for destructive operations. Use with extreme caution.",
            }

        if op_type == OperationType.WRITE:
            # Layer 4 — Require confirmation for writes in standard mode
            audit_log(tool_name, op_type.value, details, status="CONFIRMATION_REQUESTED")
            return request_confirmation(tool_name, op_type, details)

    # Operation allowed — log it
    audit_log(tool_name, op_type.value, details, status="ALLOWED")
    return None  # None = proceed
