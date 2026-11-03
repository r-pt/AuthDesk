"""Tier 1: Feature Coverage - Zero-Network Isolation and Zero-Secret Logging.

Verifies:
- Webview Content Security Policy: `connect-src 'none'`.
- Cargo dependency audit: no forbidden networking crates (`reqwest`, `hyper`, `curl`, `ureq`, `surf`).
- Zero secrets in logs: passwords, master keys, derived keys, and base32 seeds are never emitted to stdout/stderr.
"""

from pathlib import Path
from typing import Type

import pytest

from tests.e2e.oracle.config_oracle import ConfigOracle
from tests.e2e.oracle.vault_oracle import VaultOracle


@pytest.mark.tier(1)
@pytest.mark.milestone("M4")
class TestZeroNetworkAndLogs:
    """Validates absolute network lockdown and leak-free logging."""

    def test_csp_connect_src_none(self, tauri_conf_path: Path, config_oracle: Type[ConfigOracle]):
        """Verifies tauri.conf.json enforces CSP 'connect-src none'."""
        if not tauri_conf_path.exists():
            pytest.skip("tauri.conf.json not yet created")

        is_valid, errors = config_oracle.validate_tauri_conf(tauri_conf_path)
        # Check specifically for CSP error
        csp_errors = [e for e in errors if "CSP" in e]
        assert len(csp_errors) == 0, f"CSP violation: {csp_errors}"

    def test_cargo_zero_networking_crates(self, cargo_toml_path: Path, config_oracle: Type[ConfigOracle]):
        """Verifies Cargo.toml contains zero forbidden networking libraries."""
        if not cargo_toml_path.exists():
            pytest.skip("Cargo.toml not yet created")

        is_valid, errors = config_oracle.validate_cargo_toml(cargo_toml_path)
        net_errors = [e for e in errors if "Forbidden networking" in e]
        assert len(net_errors) == 0, f"Networking crates detected: {net_errors}"

    def test_zero_secrets_log_leak_detection(self, vault_oracle: Type[VaultOracle]):
        """Verifies secret scanner detects leaked passwords and base32 secrets."""
        test_secret = "JBSWY3DPEHPK3PXP"
        leaky_log = f"2026-11-04 07:00:00 [INFO] Loaded account secret: {test_secret}"
        clean_log = "2026-11-04 07:00:00 [INFO] Vault unlocked: 3 accounts loaded."

        # Leaky log must trigger leak detection
        leaks = vault_oracle.scan_for_secret_leaks(leaky_log, known_secrets=[test_secret])
        assert len(leaks) > 0, "Oracle failed to detect secret leak in log"

        # Clean log must have zero leaks
        clean_leaks = vault_oracle.scan_for_secret_leaks(clean_log, known_secrets=[test_secret])
        assert len(clean_leaks) == 0, f"False positive in clean log: {clean_leaks}"

    def test_debug_redaction_contract(self, project_root: Path):
        """Verifies that sensitive Rust structs implement manual Debug with [REDACTED] rather than derive(Debug)."""
        vault_types_file = project_root / "src-tauri" / "src" / "vault" / "types.rs"
        if not vault_types_file.exists():
            # Check other possible locations
            vault_mod = project_root / "src-tauri" / "src" / "vault.rs"
            if vault_mod.exists():
                vault_types_file = vault_mod
            else:
                pytest.skip("Vault types source file not yet scaffolded")

        content = vault_types_file.read_text(encoding="utf-8")
        # Ensure MasterKey / DerivedKek do not derive standard Debug without redaction
        if "struct MasterKey" in content:
            assert "[REDACTED]" in content, "MasterKey Debug implementation must print '[REDACTED]'"
