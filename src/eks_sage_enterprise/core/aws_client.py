"""AWS client management — boto3 session with caching."""
from __future__ import annotations
import subprocess
import boto3

_clients: dict = {}
_current_cluster: str | None = None
_current_region: str = "us-east-1"


def get_client(service: str, region: str | None = None):
    region = region or _current_region
    key = f"{service}-{region}"
    if key not in _clients:
        _clients[key] = boto3.client(service, region_name=region)
    return _clients[key]


def set_cluster(cluster_name: str, region: str) -> dict:
    global _current_cluster, _current_region
    _current_cluster = cluster_name
    _current_region = region
    _clients.clear()
    result = subprocess.run(
        ["aws", "eks", "update-kubeconfig", "--name", cluster_name, "--region", region],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return {"error": result.stderr.strip()}
    return {
        "cluster": cluster_name,
        "region": region,
        "kubeconfig": "updated",
        "message": result.stdout.strip(),
    }


def get_current_cluster() -> str | None:
    return _current_cluster


def get_current_region() -> str:
    return _current_region
