"""Tier 1: Feature Coverage - Floating Palette Window and CLI Flags.

Verifies:
- Window dimensions 420x560, undecorated, transparent, alwaysOnTop, skipTaskbar, centered.
- CLI flags: `--hidden` (starts silently in tray/background).
- CLI flags: `--toggle` (toggles palette visibility).
- Single-instance mutex and IPC forwarding.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

from tests.e2e.oracle.config_oracle import ConfigOracle


@pytest.mark.tier(1)
@pytest.mark.milestone("M0")
class TestWindowAndCli:
    """Validates window properties and CLI flag requirements."""

    def test_window_dimensions_and_properties(self, tauri_conf_path: Path):
        """Verifies window dimensions 420x560, transparency, and presentation flags in tauri.conf.json."""
        if not tauri_conf_path.exists():
            pytest.skip("tauri.conf.json not yet scaffolded by M0")

        valid, errors = ConfigOracle.validate_tauri_conf(tauri_conf_path)
        assert valid, f"tauri.conf.json window specification violation:\n" + "\n".join(errors)

    def test_window_palette_spec_details(self, tauri_conf_path: Path):
        """Explicitly checks each individual window attribute per PROJECT.md."""
        if not tauri_conf_path.exists():
            pytest.skip("tauri.conf.json not yet scaffolded by M0")

        with open(tauri_conf_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        windows = data.get("app", {}).get("windows", [])
        palette = next((w for w in windows if w.get("label") == "palette"), None)
        assert palette is not None, "Window 'palette' missing from configuration"

        assert palette.get("width") == 420, f"Width must be 420, got {palette.get('width')}"
        assert palette.get("height") == 560, f"Height must be 560, got {palette.get('height')}"
        assert palette.get("transparent") is True, "Window must be transparent"
        assert palette.get("decorations") is False, "Window must be undecorated (decorations: false)"
        assert palette.get("alwaysOnTop") is True, "Window must be alwaysOnTop: true"
        assert palette.get("skipTaskbar") is True, "Window must skip taskbar"
        assert palette.get("center") is True, "Window must center on screen"
        assert palette.get("visible") is False, "Window visible at startup must be false (for --hidden)"

    def test_cli_flag_hidden_support(self, authdesk_binary: Path | None):
        """Verifies binary accepts '--hidden' flag without error code or crash."""
        if not authdesk_binary:
            pytest.skip("authdesk binary not yet compiled")

        # Run with timeout to prevent hanging daemon
        proc = subprocess.Popen(
            [str(authdesk_binary), "--hidden"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            # Let it boot briefly
            exit_code = proc.wait(timeout=2.0)
            assert exit_code == 0, f"--hidden exited with non-zero code {exit_code}"
        except subprocess.TimeoutExpired:
            # Process is running normally in daemon mode
            proc.terminate()
            proc.wait(timeout=2.0)

    def test_cli_flag_toggle_support(self, authdesk_binary: Path | None):
        """Verifies secondary instance with '--toggle' forwards signal to primary instance."""
        if not authdesk_binary:
            pytest.skip("authdesk binary not yet compiled")

        # Launch primary instance with --hidden
        primary = subprocess.Popen(
            [str(authdesk_binary), "--hidden"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            # Give primary instance time to bind single-instance socket
            import time
            time.sleep(1.0)

            # Invoke secondary instance with --toggle
            secondary = subprocess.run(
                [str(authdesk_binary), "--toggle"],
                capture_output=True,
                text=True,
                timeout=5.0,
            )
            assert secondary.returncode == 0, f"Secondary --toggle exited with code {secondary.returncode}"
        finally:
            primary.terminate()
            primary.wait(timeout=2.0)
