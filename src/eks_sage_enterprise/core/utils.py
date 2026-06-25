"""Shared utilities."""
from __future__ import annotations
import json
from datetime import datetime


def _j(data) -> str:
    def _default(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return str(obj)
    return json.dumps(data, indent=2, default=_default)
