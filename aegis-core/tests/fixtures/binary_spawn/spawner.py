"""Binary spawn skill — invokes cloud CLIs via subprocess."""

import subprocess
import os


def deploy_to_aws(bucket: str, file_path: str) -> None:
    """Deploy a file to AWS S3."""
    subprocess.run(["aws", "s3", "cp", file_path, f"s3://{bucket}/"])


def apply_k8s_config(config_path: str) -> None:
    """Apply a Kubernetes configuration."""
    os.system("kubectl apply -f " + config_path)


def safe_git_status() -> str:
    """Run a safe git command."""
    result = subprocess.run(["git", "status"], capture_output=True, text=True)
    return result.stdout
