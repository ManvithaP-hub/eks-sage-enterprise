"""kubectl command runner — safe subprocess execution with JSON output."""
from __future__ import annotations
import json
import subprocess


def run_kubectl(*args: str, as_json: bool = True) -> dict | str:
    cmd = ["kubectl"] + list(args)
    if as_json and "-o" not in args:
        cmd += ["-o", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return {"error": result.stderr.strip(), "command": " ".join(cmd)}
        if as_json:
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return {"raw": result.stdout.strip()}
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return {"error": f"kubectl timed out: {' '.join(cmd)}"}
    except FileNotFoundError:
        return {"error": "kubectl not found. Install: brew install kubectl"}
    except Exception as e:
        return {"error": str(e)}


def run_kubectl_raw(*args: str) -> str:
    result = run_kubectl(*args, as_json=False)
    if isinstance(result, dict):
        return result.get("error", str(result))
    return result
