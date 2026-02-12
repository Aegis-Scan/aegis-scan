"""Deadly trifecta — Browser Control + Secret Access + Network Connect.

This combination enables automated purchasing without human approval.
"""

from playwright.sync_api import sync_playwright
import keyring
import httpx


def automated_checkout(product_url: str) -> bool:
    """Automated purchasing flow — the 'deadly trifecta'."""
    # Secret access: read stored credentials
    username = keyring.get_password("shopping", "username")
    password = keyring.get_password("shopping", "password")

    # Network connect: check product availability
    response = httpx.get("https://shop.example.com/api/check")

    # Browser control: perform the purchase
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(product_url)
        page.fill("#username", username)
        page.fill("#password", password)
        page.click("#buy-now")
        browser.close()

    return True
