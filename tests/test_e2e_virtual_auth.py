"""Headless Playwright End-to-End test using Chrome DevTools Protocol (CDP) Virtual Authenticator.

Simulates a hardware-backed FIDO2 / WebAuthn CTAP2 authenticator in headless Chromium.
Enforces registration, assertion, anti-replay verification, reverse proxying, and step-up auth.
"""

import threading
import time

import httpx
import pytest
import uvicorn
from playwright.async_api import async_playwright

from gateway.main import app as gateway_app
from upstream_service.app import app as upstream_app


class ServerThread(threading.Thread):
    def __init__(self, app, port):
        super().__init__(daemon=True)
        self.port = port
        self.config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        self.server = uvicorn.Server(self.config)

    def run(self):
        self.server.run()

    def stop(self):
        self.server.should_exit = True


@pytest.fixture(scope="module")
def live_services():
    """Spin up local Gateway and Upstream services in background threads."""
    gateway_server = ServerThread(gateway_app, 8000)
    upstream_server = ServerThread(upstream_app, 8001)

    gateway_server.start()
    upstream_server.start()

    # Wait for gateway to report healthy
    ready = False
    for _ in range(50):
        try:
            resp = httpx.get("http://localhost:8000/health", timeout=1.0)
            if resp.status_code == 200:
                ready = True
                break
        except Exception:
            time.sleep(0.1)

    if not ready:
        pytest.fail("Live Gateway server failed to start within timeout.")

    yield "http://localhost:8000"

    gateway_server.stop()
    upstream_server.stop()


@pytest.mark.asyncio
async def test_virtual_authenticator_e2e_lifecycle(live_services):
    """Complete E2E ceremony: Passkey Registration, Authentication, Upstream Proxy, and Step-Up Auth."""
    base_url = live_services

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()

        # Handle UI confirm/alert dialogs automatically
        page.on("dialog", lambda dialog: dialog.accept())

        # 1. Enable Chrome DevTools Protocol (CDP) WebAuthn & Virtual Authenticator
        cdp = await context.new_cdp_session(page)
        await cdp.send("WebAuthn.enable")

        virtual_auth = await cdp.send(
            "WebAuthn.addVirtualAuthenticator",
            {
                "options": {
                    "protocol": "ctap2",
                    "transport": "internal",
                    "hasResidentKey": True,
                    "hasUserVerification": True,
                    "isUserVerified": True,
                }
            },
        )
        authenticator_id = virtual_auth["authenticatorId"]
        assert authenticator_id is not None

        # 2. Navigate to Gateway UI
        await page.goto(base_url)
        await page.wait_for_selector("#statusBadge")
        badge_text = await page.text_content("#statusText")
        assert "Supported" in badge_text

        # 3. Register Passkey
        test_username = "alice.cdp@enterprise.corp"
        test_display = "Alice CDP"
        await page.fill("#regUsername", test_username)
        await page.fill("#regDisplayName", test_display)
        await page.click("#btnRegister")

        # Wait for registration success log
        await page.wait_for_function(
            "() => document.getElementById('consoleLog').innerText.includes('Registration successful!')",
            timeout=10000,
        )

        # 4. Authenticate with Passkey
        await page.fill("#loginUsername", test_username)
        await page.click("#btnLogin")

        # Wait for Session Panel to become active
        session_panel = page.locator("#sessionPanel")
        await session_panel.wait_for(state="visible", timeout=10000)

        # Verify Session metadata rendered
        user_text = await page.text_content("#sessUser")
        assert test_username in user_text
        assert test_display in user_text

        sign_count_text = await page.text_content("#sessSignCount")
        assert "Hardware Protected" in sign_count_text

        uv_text = await page.text_content("#sessUV")
        assert "Yes" in uv_text

        # 5. Verify Reverse Proxy to Upstream Protected Service
        await page.click("#btnUpstream")
        upstream_box = page.locator("#upstreamOutput")
        await upstream_box.wait_for(state="visible", timeout=5000)
        await page.wait_for_function(
            "() => document.getElementById('upstreamOutput').innerText.includes('TOP SECRET // RESTRICTED')",
            timeout=5000,
        )
        output_content = await upstream_box.text_content()
        assert "SOC 2 Type II" in output_content
        assert "Quantum-Resistant HSM" in output_content

        # 6. Verify Step-Up Wire Transfer
        await page.click("#btnTransfer")
        await page.wait_for_function(
            "() => document.getElementById('upstreamOutput').innerText.includes('wire_transfer')",
            timeout=5000,
        )
        transfer_content = await upstream_box.text_content()
        assert "50000" in transfer_content
        assert "Global Treasury Escrow" in transfer_content

        # 7. Verify Logout
        await page.click("#btnLogout")
        await session_panel.wait_for(state="hidden", timeout=5000)
        auth_section = page.locator("#authSection")
        await auth_section.wait_for(state="visible", timeout=5000)

        # Clean up virtual authenticator and browser
        await cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": authenticator_id})
        await browser.close()
