"""Safe weather skill — uses literal URL for API access."""

import requests


def get_weather(city: str) -> dict:
    """Get current weather for a city."""
    response = requests.get("https://api.weather.com/v1/current")
    return response.json()


def format_weather(data: dict) -> str:
    """Format weather data for display."""
    temp = data.get("temperature", "N/A")
    desc = data.get("description", "N/A")
    return f"Temperature: {temp}, Conditions: {desc}"
