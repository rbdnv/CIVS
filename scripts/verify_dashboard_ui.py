#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys


VIEWPORTS = [
    ("desktop", {"width": 1440, "height": 900}),
    ("mobile", {"width": 390, "height": 844}),
]

NAV_ITEMS = [
    ("Contexts", "contexts"),
    ("Verification", "verification"),
    ("RAG ingest", "rag"),
    ("Audit", "audit"),
    ("Security events", "security"),
    ("Demo", "demo"),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Browser screenshot smoke test for the CIVS dashboard.")
    parser.add_argument("--url", default="http://localhost:8000/dashboard", help="Dashboard URL to open.")
    parser.add_argument(
        "--output-dir",
        default="/tmp/civs-dashboard-ui",
        help="Directory where screenshots will be written.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ModuleNotFoundError:
        print("Playwright is not installed. Install it with: pip install playwright && playwright install chromium")
        return 2

    console_errors: list[str] = []
    screenshots: list[Path] = []

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            for viewport_name, viewport in VIEWPORTS:
                page = browser.new_page(viewport=viewport, device_scale_factor=1)
                page.on(
                    "console",
                    lambda message: console_errors.append(message.text) if message.type == "error" else None,
                )
                response = page.goto(args.url, wait_until="networkidle")
                if response is None or response.status >= 400:
                    status = response.status if response else "no response"
                    raise RuntimeError(f"{args.url} returned {status}")

                page.locator(".app-shell").wait_for()
                for nav_label, panel_name in NAV_ITEMS:
                    page.get_by_role("button", name=nav_label).click()
                    page.locator(f'[data-panel="{panel_name}"].is-active').wait_for()
                    screenshot_path = output_dir / f"dashboard-{viewport_name}-{panel_name}.png"
                    page.screenshot(path=screenshot_path, full_page=True)
                    screenshots.append(screenshot_path)
                page.close()
            browser.close()
    except PlaywrightError as exc:
        print(f"Playwright failed: {exc}")
        return 1

    if console_errors:
        print("Browser console errors:")
        for error in console_errors:
            print(f"- {error}")
        return 1

    for screenshot in screenshots:
        print(f"wrote {screenshot}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
