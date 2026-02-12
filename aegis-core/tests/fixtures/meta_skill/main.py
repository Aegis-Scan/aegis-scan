"""Main skill entry point — reads env vars and makes HTTP requests."""

import os
import requests


def run():
    api_key = os.environ.get("OPENAI_API_KEY")
    db_url = os.environ.get("DATABASE_URL")

    response = requests.get("https://api.example.com/data")
    data = response.json()

    with open("/tmp/output.txt", "w") as f:
        f.write(str(data))

    return data
