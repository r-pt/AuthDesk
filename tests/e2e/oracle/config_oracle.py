"""Config and Architecture Specification Oracle.

Authoritative source for inspecting and validating Tauri v2 configuration (`tauri.conf.json`),
Cargo dependencies (`Cargo.toml`), and Webview security capabilities.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class ConfigOracle:
    """Validates project configurations against architectural specifications in PROJECT.md."""

    EXPECTED_PRODUCT_NAME = "AuthDesk"
    EXPECTED_IDENTIFIER = "com.rod.authdesk"
    EXPECTED_WINDOW_LABEL = "palette"
    EXPECTED_WINDOW_WIDTH = 420
    EXPECTED_WINDOW_HEIGHT = 560

    FORBIDDEN_NETWORK_CRATES = [
        "reqwest",
        "hyper",
        "curl",
        "ureq",
        "surf",
        "tokio-tungstenite",
        "sentry",
        "telemetry",
    ]

    REQUIRED_CRYPTO_CRATES = [
        "zeroize",
        "argon2",
        "chacha20poly1305",
        "sha1",
        "sha2",
        "hmac",
        "data-encoding",
    ]

    @classmethod
    def validate_tauri_conf(cls, conf_path: str | Path) -> Tuple[bool, List[str]]:
        """Validates `tauri.conf.json` for window dimensions, transparency, CSP, and security."""
        p = Path(conf_path)
        if not p.exists():
            return False, [f"tauri.conf.json not found at: {conf_path}"]

        errors = []
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            return False, [f"Failed to parse tauri.conf.json as JSON: {e}"]

        if data.get("productName") != cls.EXPECTED_PRODUCT_NAME:
            errors.append(f"productName: expected '{cls.EXPECTED_PRODUCT_NAME}', got '{data.get('productName')}'")

        if data.get("identifier") != cls.EXPECTED_IDENTIFIER:
            errors.append(f"identifier: expected '{cls.EXPECTED_IDENTIFIER}', got '{data.get('identifier')}'")

        # Window validation
        app = data.get("app", {})
        windows = app.get("windows", [])
        if not windows:
            errors.append("No windows configured under app.windows")
        else:
            palette = next((w for w in windows if w.get("label") == cls.EXPECTED_WINDOW_LABEL), None)
            if not palette:
                errors.append(f"Missing window with label '{cls.EXPECTED_WINDOW_LABEL}'")
            else:
                if palette.get("width") != cls.EXPECTED_WINDOW_WIDTH:
                    errors.append(f"palette width: expected {cls.EXPECTED_WINDOW_WIDTH}, got {palette.get('width')}")
                if palette.get("height") != cls.EXPECTED_WINDOW_HEIGHT:
                    errors.append(f"palette height: expected {cls.EXPECTED_WINDOW_HEIGHT}, got {palette.get('height')}")
                if palette.get("resizable") is not False:
                    errors.append("palette resizable: expected false")
                if palette.get("decorations") is not False:
                    errors.append("palette decorations: expected false")
                if palette.get("transparent") is not True:
                    errors.append("palette transparent: expected true")
                if palette.get("alwaysOnTop") is not True:
                    errors.append("palette alwaysOnTop: expected true")
                if palette.get("skipTaskbar") is not True:
                    errors.append("palette skipTaskbar: expected true")
                if palette.get("center") is not True:
                    errors.append("palette center: expected true")
                if palette.get("visible") is not False:
                    errors.append("palette visible at startup: expected false (summoned via shortcut/toggle)")

        # Security & CSP validation
        security = app.get("security", {})
        csp = security.get("csp", "")
        if "connect-src 'none'" not in csp:
            errors.append(f"Webview CSP violation: expected 'connect-src \\'none\\'', got: '{csp}'")

        return len(errors) == 0, errors

    @classmethod
    def validate_cargo_toml(cls, cargo_path: str | Path) -> Tuple[bool, List[str]]:
        """Validates `Cargo.toml` for zero-network enforcement and required crypto crates."""
        p = Path(cargo_path)
        if not p.exists():
            return False, [f"Cargo.toml not found at: {cargo_path}"]

        errors = []
        content = p.read_text(encoding="utf-8")

        # Check for forbidden network crates
        for crate in cls.FORBIDDEN_NETWORK_CRATES:
            pattern = rf"^\s*{re.escape(crate)}\s*="
            if re.search(pattern, content, re.MULTILINE):
                errors.append(f"Forbidden networking crate found in Cargo.toml: '{crate}'")

        # Check for required crypto crates
        for crate in cls.REQUIRED_CRYPTO_CRATES:
            pattern = rf"^\s*{re.escape(crate)}\s*="
            if not re.search(pattern, content, re.MULTILINE):
                errors.append(f"Required crypto crate missing from Cargo.toml: '{crate}'")

        return len(errors) == 0, errors
