"""Unresolved scope skill — uses variables and expressions for paths/URLs."""

import os
import requests


config = {
    "output": "/data/results",
    "api_url": "https://api.example.com",
}


def write_results(data: str) -> None:
    """Write results using a variable path — scope cannot be resolved."""
    path = config["output"]
    with open(path, "w") as f:
        f.write(data)


def fetch_data(endpoint: str) -> dict:
    """Fetch data using a variable URL — scope cannot be resolved."""
    url = f"{config['api_url']}/{endpoint}"
    response = requests.get(url)
    return response.json()


def computed_path() -> None:
    """Write to a dynamically computed path."""
    base = os.environ.get("OUTPUT_DIR", "/tmp")
    full_path = os.path.join(base, "output.txt")
    with open(full_path, "w") as f:
        f.write("computed output")
