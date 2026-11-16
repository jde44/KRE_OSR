#!/usr/bin/env python3
"""Optional browser check for the local demo UI (developer tool; not part of the release suite).

Requires the Python Playwright package and a Chromium build it can launch. Neither is a runtime dependency of
Open Sovereign Router. The check starts the demo on a free loopback port, then verifies:

- the three preset scenarios render the expected outcome;
- synthetic input containing markup is displayed as text and never executed;
- the presets, Run, Approve and Reset controls work from the keyboard, with a visible focus outline;
- there is no horizontal overflow at desktop and tablet widths;
- the page makes no request to any host other than the loopback demo server.

Usage:  python3 scripts/demo_ui/e2e_check.py [--screenshots DIR]
Screenshots are written outside the repository by default; they are not committed (the release scanner rejects
binary files).
"""

import argparse
from pathlib import Path
import sys
import tempfile
import threading
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import server as demo  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover - optional tool
    raise SystemExit("Playwright for Python is not installed; this optional check was not run.")

XSS = '<img src=x onerror="window.__xss=1"><script>window.__xss=1</script>'
WIDTHS = ((1440, 900), (1024, 768), (820, 1180))


def capture(page, path):
    """Full-page screenshot from the top, with the pointer parked so no hover state or sticky offset is captured."""
    page.mouse.move(0, 0)
    page.evaluate("window.scrollTo(0, 0)")
    page.screenshot(path=str(path), full_page=True)


class Check:
    def __init__(self):
        self.failures = []

    def expect(self, condition, label):
        print(("PASS  " if condition else "FAIL  ") + label)
        if not condition:
            self.failures.append(label)


def run(shot_dir):
    app = demo.DemoApp()
    server = demo.build_demo_server(app, "127.0.0.1", 0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{port}/#t={app.ui_token}"
    check = Check()
    foreign = []
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page(viewport={"width": 1440, "height": 900}, device_scale_factor=2)
            page.on("request", lambda r: urlsplit(r.url).hostname not in ("127.0.0.1",) and foreign.append(r.url))
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.on("console", lambda m: m.type == "error" and errors.append(m.text))
            page.goto(url)
            page.wait_for_selector("#preset-list button.preset")
            check.expect("#t=" not in page.url, "UI token is removed from the address bar")

            # Scenario 1: public, simple -> smallest local model
            page.locator("button.preset").nth(0).click()
            page.wait_for_selector("#decision .outcome.routed")
            check.expect("local-small" in page.inner_text("#decision"), "public simple preset routes to local-small")
            capture(page, shot_dir / "1-public-local.png")

            # Scenario 2: public, advanced -> approval required, then approve with the keyboard
            page.locator("button.preset").nth(1).click()
            page.wait_for_selector("#decision .outcome.approval_required")
            check.expect("cloud-advanced" in page.inner_text("#approval"), "cloud route shows the approval request")
            capture(page, shot_dir / "2-cloud-approval-required.png")
            page.locator("button.approve").focus()
            page.keyboard.press("Enter")
            page.wait_for_selector("#decision .outcome.routed")
            check.expect("approved" in page.inner_text("#decision").lower(), "keyboard approval executes once")

            # Scenario 3: restricted -> blocked
            page.locator("button.preset").nth(2).click()
            page.wait_for_selector("#decision .outcome.blocked")
            check.expect("never" in page.inner_text("#decision").lower(), "restricted preset is blocked with an explanation")
            capture(page, shot_dir / "3-restricted-blocked.png")

            # Audit table is metadata only
            check.expect("Summarise this public" not in page.inner_text("#audit-rows"), "audit table shows no prompt text")

            # XSS-safe rendering
            page.fill("#message", XSS)
            page.click("#run-button")
            page.wait_for_selector("#decision .outcome")
            check.expect(page.evaluate("window.__xss") is None, "markup in synthetic input is never executed")
            check.expect(page.locator("#decision img, #approval img, #audit-rows img").count() == 0, "no injected elements")

            # Keyboard path: the skip link is first, then presets; focus outline is visible
            page.click("#reset-button")
            page.wait_for_selector("#audit-rows .placeholder")
            check.expect(page.locator("#audit-rows .placeholder").count() == 1, "reset clears the audit view")
            page.goto("about:blank")
            page.goto(url)  # fresh load so sequential focus starts at the top of the document
            page.wait_for_selector("#preset-list button.preset")
            page.keyboard.press("Tab")
            check.expect(page.evaluate("document.activeElement.className") == "skip-link", "first Tab reaches the skip link")
            page.keyboard.press("Tab")
            check.expect(page.evaluate("document.activeElement.className").startswith("preset"), "second Tab reaches the first preset")
            check.expect(page.evaluate("document.activeElement === document.querySelector('button.preset')"), "focus is on the first preset")
            outline = page.evaluate("getComputedStyle(document.activeElement).outlineStyle")
            check.expect(outline not in ("none", ""), "focused control has a visible outline")
            page.keyboard.press("Enter")
            page.wait_for_selector("#decision .outcome.routed")
            check.expect(True, "Enter on a focused preset runs it")

            for width, height in WIDTHS:
                page.set_viewport_size({"width": width, "height": height})
                overflow = page.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
                check.expect(overflow <= 0, f"no horizontal overflow at {width}px")

            check.expect(not errors, "no console or page errors" + (": " + "; ".join(errors) if errors else ""))
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        app.close()
    check.expect(not foreign, "no request left the loopback demo server" + (": " + ", ".join(foreign) if foreign else ""))
    print(f"Screenshots: {shot_dir}")
    return 1 if check.failures else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--screenshots", type=Path, default=None, help="directory for the three scenario screenshots")
    args = parser.parse_args()
    shot_dir = args.screenshots or Path(tempfile.mkdtemp(prefix="osr-demo-shots-"))
    shot_dir.mkdir(parents=True, exist_ok=True)
    return run(shot_dir)


if __name__ == "__main__":
    raise SystemExit(main())
