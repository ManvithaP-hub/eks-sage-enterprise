"""Unit tests for EKS Sage Enterprise — guardrails, classification, safety modes."""
from __future__ import annotations
import json
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from eks_sage_enterprise.core.guardrails import (
    SafetyMode,
    OperationType,
    TOOL_CLASSIFICATIONS,
    NEVER_ALLOW,
    is_denied,
    set_safety_mode,
    get_safety_mode,
    enforce,
    request_confirmation,
    confirm_operation,
    cancel_operation,
    audit_log,
    get_audit_log,
)


# ─────────────────────────────────────────────────────────────────────────────
# Denylist Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDenylist:
    def test_delete_cluster_always_blocked(self):
        assert is_denied("delete_cluster") is True

    def test_drain_node_always_blocked(self):
        assert is_denied("drain_node") is True

    def test_delete_namespace_always_blocked(self):
        assert is_denied("delete_namespace") is True

    def test_ec2_terminate_blocked(self):
        assert is_denied("ec2_terminate_instances") is True

    def test_iam_delete_role_blocked(self):
        assert is_denied("iam_delete_role") is True

    def test_safe_operation_not_blocked(self):
        assert is_denied("describe_cluster") is False

    def test_denylist_has_minimum_entries(self):
        assert len(NEVER_ALLOW) >= 15

    def test_case_insensitive(self):
        assert is_denied("DELETE_CLUSTER") is True
        assert is_denied("Delete_Cluster") is True


# ─────────────────────────────────────────────────────────────────────────────
# Tool Classification Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestClassification:
    def test_all_read_tools_classified(self):
        read_tools = [t for t, op in TOOL_CLASSIFICATIONS.items() if op == OperationType.READ]
        assert len(read_tools) >= 50

    def test_cordon_is_write(self):
        assert TOOL_CLASSIFICATIONS["tool_cordon_node"] == OperationType.WRITE

    def test_connect_is_config(self):
        assert TOOL_CLASSIFICATIONS["tool_connect_cluster"] == OperationType.CONFIG

    def test_get_pods_is_read(self):
        assert TOOL_CLASSIFICATIONS["tool_get_pods"] == OperationType.READ

    def test_investigate_pod_is_read(self):
        assert TOOL_CLASSIFICATIONS["tool_investigate_pod"] == OperationType.READ

    def test_security_tools_are_read(self):
        assert TOOL_CLASSIFICATIONS["tool_audit_rbac"] == OperationType.READ
        assert TOOL_CLASSIFICATIONS["tool_check_pod_security"] == OperationType.READ
        assert TOOL_CLASSIFICATIONS["tool_investigate_irsa"] == OperationType.READ

    def test_compliance_tools_are_read(self):
        assert TOOL_CLASSIFICATIONS["tool_check_compliance"] == OperationType.READ
        assert TOOL_CLASSIFICATIONS["tool_detect_drift"] == OperationType.READ

    def test_guardrail_tools_classified(self):
        assert TOOL_CLASSIFICATIONS["tool_get_safety_status"] == OperationType.READ
        assert TOOL_CLASSIFICATIONS["tool_set_safety_mode"] == OperationType.CONFIG
        assert TOOL_CLASSIFICATIONS["tool_get_audit_log"] == OperationType.READ


# ─────────────────────────────────────────────────────────────────────────────
# Safety Mode Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestSafetyMode:
    def setup_method(self):
        set_safety_mode("read_only")

    def test_default_is_read_only(self):
        assert get_safety_mode() == SafetyMode.READ_ONLY

    def test_set_standard(self):
        result = set_safety_mode("standard")
        assert result["safety_mode"] == "standard"
        assert get_safety_mode() == SafetyMode.STANDARD

    def test_set_unrestricted(self):
        result = set_safety_mode("unrestricted")
        assert result["safety_mode"] == "unrestricted"

    def test_invalid_mode_returns_error(self):
        result = set_safety_mode("destroy_everything")
        assert "error" in result

    def test_valid_modes_listed_in_error(self):
        result = set_safety_mode("bad_mode")
        assert "valid_modes" in result
        assert "read_only" in result["valid_modes"]


# ─────────────────────────────────────────────────────────────────────────────
# Enforce Tests (main guardrail)
# ─────────────────────────────────────────────────────────────────────────────

class TestEnforce:
    def setup_method(self):
        set_safety_mode("read_only")

    def test_read_allowed_in_read_only(self):
        result = enforce("tool_get_pods")
        assert result is None  # None = allowed

    def test_write_blocked_in_read_only(self):
        result = enforce("tool_cordon_node", {"node": "i-123"})
        assert result is not None
        assert "error" in result
        assert "READ_ONLY" in result["error"]

    def test_config_blocked_in_read_only(self):
        result = enforce("tool_connect_cluster", {"cluster": "my-cluster"})
        assert result is not None
        assert "error" in result

    def test_denylist_blocked_regardless_of_mode(self):
        set_safety_mode("unrestricted")
        result = enforce("delete_cluster")
        assert result is not None
        assert "permanently blocked" in result["error"]

    def test_write_requires_confirmation_in_standard(self):
        set_safety_mode("standard")
        result = enforce("tool_cordon_node", {"node": "i-123"})
        assert result is not None
        assert result.get("status") == "CONFIRMATION_REQUIRED"
        assert "confirmation_id" in result

    def test_read_allowed_in_standard(self):
        set_safety_mode("standard")
        result = enforce("tool_get_pods")
        assert result is None

    def test_read_allowed_in_unrestricted(self):
        set_safety_mode("unrestricted")
        result = enforce("tool_investigate_cluster_health")
        assert result is None

    def test_config_allowed_in_standard(self):
        set_safety_mode("standard")
        result = enforce("tool_connect_cluster")
        # CONFIG in standard mode should be allowed (no confirmation needed)
        assert result is None

    def test_unknown_tool_defaults_to_read(self):
        result = enforce("tool_unknown_future_tool")
        assert result is None  # defaults to READ, allowed


# ─────────────────────────────────────────────────────────────────────────────
# Confirmation Gate Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestConfirmationGate:
    def setup_method(self):
        set_safety_mode("standard")

    def test_write_returns_confirmation_request(self):
        result = enforce("tool_cordon_node", {"node": "i-test"})
        assert result["status"] == "CONFIRMATION_REQUIRED"
        assert len(result["confirmation_id"]) == 8

    def test_confirm_valid_id(self):
        result = enforce("tool_cordon_node", {"node": "i-test"})
        conf_id = result["confirmation_id"]
        confirmed = confirm_operation(conf_id)
        assert confirmed["status"] == "CONFIRMED"

    def test_confirm_invalid_id(self):
        result = confirm_operation("INVALID1")
        assert "error" in result

    def test_cancel_operation(self):
        result = enforce("tool_cordon_node", {"node": "i-test"})
        conf_id = result["confirmation_id"]
        cancelled = cancel_operation(conf_id)
        assert cancelled["status"] == "CANCELLED"

    def test_cannot_confirm_twice(self):
        result = enforce("tool_cordon_node", {"node": "i-test"})
        conf_id = result["confirmation_id"]
        confirm_operation(conf_id)
        # Second confirm should fail
        result2 = confirm_operation(conf_id)
        assert "error" in result2


# ─────────────────────────────────────────────────────────────────────────────
# Audit Log Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestAuditLog:
    def test_operations_are_logged(self):
        set_safety_mode("read_only")
        initial_count = len(get_audit_log(100))
        enforce("tool_get_pods")
        new_count = len(get_audit_log(100))
        assert new_count > initial_count

    def test_blocked_operations_are_logged(self):
        set_safety_mode("read_only")
        enforce("tool_cordon_node", {"node": "i-123"})
        log = get_audit_log(10)
        denied_entries = [e for e in log if e.get("status") == "DENIED_READ_ONLY"]
        assert len(denied_entries) > 0

    def test_audit_log_has_required_fields(self):
        enforce("tool_get_pods")
        log = get_audit_log(1)
        if log:
            entry = log[-1]
            assert "timestamp" in entry
            assert "tool" in entry
            assert "operation_type" in entry
            assert "status" in entry
            assert "safety_mode" in entry

    def test_last_n_entries_returned(self):
        for _ in range(5):
            enforce("tool_get_nodes")
        log = get_audit_log(3)
        assert len(log) <= 3


# ─────────────────────────────────────────────────────────────────────────────
# Coverage verification
# ─────────────────────────────────────────────────────────────────────────────

class TestCoverage:
    def test_all_tool_names_in_classification(self):
        """Every tool registered in server.py should be in TOOL_CLASSIFICATIONS."""
        import re
        server_path = os.path.join(
            os.path.dirname(__file__), '..', 'src',
            'eks_sage_enterprise', 'server.py'
        )
        with open(server_path) as f:
            content = f.read()
        tool_names = re.findall(r'^def (tool_\w+)\(', content, re.MULTILINE)

        missing = []
        for name in tool_names:
            if name not in TOOL_CLASSIFICATIONS:
                missing.append(name)

        assert missing == [], f"Tools not in TOOL_CLASSIFICATIONS: {missing}"

    def test_minimum_tool_count(self):
        """Ensure we have at least 60 tools registered."""
        import re
        server_path = os.path.join(
            os.path.dirname(__file__), '..', 'src',
            'eks_sage_enterprise', 'server.py'
        )
        with open(server_path) as f:
            content = f.read()
        tool_count = len(re.findall(r'^@mcp\.tool\(\)', content, re.MULTILINE))
        assert tool_count >= 60, f"Only {tool_count} tools — expected 60+"

    def test_denylist_minimum_coverage(self):
        """Denylist should have at least 15 critical operations."""
        assert len(NEVER_ALLOW) >= 15
