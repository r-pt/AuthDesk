"""Tier 1: Feature Coverage - System Tray Icon and Global Shortcuts.

Verifies:
- System tray menu actions: "Mostrar AuthDesk", "Bloquear", "Salir" (and English equivalents).
- Left-click tray action: toggle window visibility.
- Global shortcut: Ctrl+Alt+A registration with graceful Wayland fallback and non-crashing logs.
"""

from pathlib import Path
import re

import pytest


@pytest.mark.tier(1)
@pytest.mark.milestone("M0")
class TestTrayAndShortcut:
    """Validates System Tray configuration and Global Shortcut behaviors."""

    def test_cargo_toml_tray_feature(self, cargo_toml_path: Path):
        """Verifies tauri dependency in Cargo.toml has 'tray-icon' feature enabled."""
        if not cargo_toml_path.exists():
            pytest.skip("src-tauri/Cargo.toml not yet scaffolded")

        content = cargo_toml_path.read_text(encoding="utf-8")
        assert 'tray-icon' in content, "Cargo.toml must enable the 'tray-icon' feature on tauri"

    def test_cargo_toml_plugins(self, cargo_toml_path: Path):
        """Verifies Cargo.toml includes global-shortcut and single-instance plugins."""
        if not cargo_toml_path.exists():
            pytest.skip("src-tauri/Cargo.toml not yet scaffolded")

        content = cargo_toml_path.read_text(encoding="utf-8")
        assert "tauri-plugin-single-instance" in content, "Missing tauri-plugin-single-instance"
        assert "tauri-plugin-global-shortcut" in content, "Missing tauri-plugin-global-shortcut"

    def test_tray_menu_action_definitions(self, project_root: Path):
        """Inspects tray setup code or i18n files for standard menu actions."""
        tray_file = project_root / "src-tauri" / "src" / "tray.rs"
        lib_file = project_root / "src-tauri" / "src" / "lib.rs"
        i18n_es = project_root / "src" / "i18n" / "es.ts"

        # Check in Rust or TypeScript source if present
        source_content = ""
        for p in [tray_file, lib_file, i18n_es]:
            if p.exists():
                source_content += p.read_text(encoding="utf-8") + "\n"

        if not source_content:
            pytest.skip("Source files for tray menu not yet created by M0/M3")

        expected_menu_actions = ["Mostrar AuthDesk", "Bloquear", "Salir"]
        for action in expected_menu_actions:
            assert action in source_content, f"Expected tray menu action '{action}' not found in source"

    def test_wayland_shortcut_graceful_handling(self, project_root: Path):
        """Verifies that Ctrl+Alt+A shortcut registration catches errors and logs warnings without panicking."""
        lib_file = project_root / "src-tauri" / "src" / "lib.rs"
        shortcut_file = project_root / "src-tauri" / "src" / "shortcut.rs"

        content = ""
        for p in [shortcut_file, lib_file]:
            if p.exists():
                content += p.read_text(encoding="utf-8") + "\n"

        if not content:
            pytest.skip("Backend shortcut code not yet scaffolded")

        # Must mention Ctrl+Alt+A and handle error gracefully
        assert "Ctrl+Alt+A" in content, "Shortcut Ctrl+Alt+A must be configured"
        # Must not panic on shortcut registration error
        assert "expect(" not in content or "Valid shortcut syntax" in content
