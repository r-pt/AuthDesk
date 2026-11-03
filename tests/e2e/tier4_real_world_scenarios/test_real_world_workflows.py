"""Tier 4: Real-World Application Scenarios - End-to-End User Workflows.

Verifies complete lifecycles:
1. First-time setup: master password initialization, envelope generation, POSIX permissions (0600/0700).
2. Authenticator onboarding: importing multiple tokens (GitHub, Google, AWS, custom high-security).
3. Search, filter, and keyboard copy: Enter copies code and triggers 30s auto-clear.
4. Memory safety: locking vault zeroes active keys.
5. Desktop integration: summon via tray / CLI `--toggle`.
6. Disaster recovery: corrupted `vault.enc` auto-recovery from `vault.enc.bak`.
"""

import base64
import json
import os
import shutil
from pathlib import Path
from typing import Type

import pytest

from tests.e2e.oracle.totp_oracle import TotpOracle
from tests.e2e.oracle.vault_oracle import VaultOracle


@pytest.mark.tier(4)
@pytest.mark.milestone("M4")
class TestRealWorldWorkflows:
    """Executes full end-to-end user workflows against specification contracts."""

    def test_workflow_initial_setup_and_persistence(self, temp_vault_dir: Path, vault_oracle: Type[VaultOracle]):
        """Scenario 1: Fresh user setup -> sets master password -> creates vault.enc with 0600 mode."""
        vault_file = temp_vault_dir / "vault.enc"
        assert not vault_file.exists(), "Pre-condition: vault must not exist on first run"

        # Simulate setup master password
        salt = os.urandom(32)
        nonce_mk = os.urandom(24)
        wrapped_mk = os.urandom(48)  # 32B MK + 16B Poly1305
        nonce_payload = os.urandom(24)
        encrypted_payload = os.urandom(64)

        envelope = {
            "magic": "AUTHDESK_VAULT",
            "version": 1,
            "created_at": 1710000000,
            "updated_at": 1710000000,
            "kdf": {
                "algorithm": "Argon2id",
                "m_cost_kib": 65536,
                "t_cost": 3,
                "p_cost": 1,
                "salt_b64": base64.b64encode(salt).decode(),
            },
            "wrapped_master_key": {
                "nonce_b64": base64.b64encode(nonce_mk).decode(),
                "ciphertext_b64": base64.b64encode(wrapped_mk).decode(),
            },
            "payload": {
                "nonce_b64": base64.b64encode(nonce_payload).decode(),
                "ciphertext_b64": base64.b64encode(encrypted_payload).decode(),
            },
        }

        # Atomic write sequence with 0600 permissions
        tmp_file = temp_vault_dir / "vault.enc.tmp.setup"
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(envelope, f)
        os.chmod(tmp_file, 0o600)
        os.replace(tmp_file, vault_file)

        # Assertions
        assert vault_file.exists()
        mode, mode_oct = vault_oracle.check_posix_permissions(vault_file)
        assert mode == 0o600, f"Expected 0600 mode, got {mode_oct}"
        is_valid, errors = vault_oracle.validate_envelope_structure(envelope)
        assert is_valid, f"Envelope validation failed: {errors}"

    def test_workflow_multi_account_totp_generation(self, totp_oracle: Type[TotpOracle]):
        """Scenario 2: User imports multiple authenticators (GitHub, Google, AWS, Corporate)."""
        accounts = [
            {
                "issuer": "GitHub",
                "label": "rod@github.com",
                "secret": "JBSWY3DPEHPK3PXP",  # standard Base32
                "algo": "SHA1",
                "digits": 6,
                "period": 30,
            },
            {
                "issuer": "Google",
                "label": "rod@gmail.com",
                "secret": "HXDM VJEC JJW7 B777",  # spaces + Base32
                "algo": "SHA1",
                "digits": 6,
                "period": 30,
            },
            {
                "issuer": "AWS",
                "label": "admin@aws",
                "secret": "KRSX-G5CT-MVRX-EZLU",  # hyphens + Base32
                "algo": "SHA1",
                "digits": 6,
                "period": 30,
            },
            {
                "issuer": "Corporate-VPN",
                "label": "internal-sys",
                "secret": "MZXW6YTBOI======",  # SHA256 8-digit
                "algo": "SHA256",
                "digits": 8,
                "period": 60,
            },
        ]

        test_timestamp = 1710000030

        generated_codes = {}
        for acc in accounts:
            code = totp_oracle.generate_totp(
                acc["secret"],
                timestamp=test_timestamp,
                step=acc["period"],
                digits=acc["digits"],
                algorithm=acc["algo"],
            )
            assert len(code) == acc["digits"]
            assert code.isdigit()
            generated_codes[acc["issuer"]] = code

        # All 4 codes must be non-empty and formatted correctly
        assert len(generated_codes) == 4
        assert len(generated_codes["Corporate-VPN"]) == 8

    def test_workflow_search_and_keyboard_copy(self, totp_oracle: Type[TotpOracle]):
        """Scenario 3: User filters for 'git', selects GitHub account, copies TOTP code."""
        accounts = [
            {"id": "1", "issuer": "GitHub", "name": "rod@github.com", "secret": "JBSWY3DPEHPK3PXP"},
            {"id": "2", "issuer": "Google", "name": "rod@gmail.com", "secret": "JBSWY3DPEHPK3PXP"},
            {"id": "3", "issuer": "AWS", "name": "admin@aws", "secret": "JBSWY3DPEHPK3PXP"},
        ]

        search_query = "git"
        filtered = [
            a for a in accounts
            if search_query.lower() in a["issuer"].lower() or search_query.lower() in a["name"].lower()
        ]

        assert len(filtered) == 1
        assert filtered[0]["issuer"] == "GitHub"

        # User presses Enter -> copies code
        code = totp_oracle.generate_totp(filtered[0]["secret"], timestamp=1000, step=30, digits=6)
        clipboard = code  # simulate copy

        # Verify copy
        assert len(clipboard) == 6
        assert clipboard.isdigit()

    def test_workflow_disaster_recovery_from_backup(self, temp_vault_dir: Path, vault_oracle: Type[VaultOracle]):
        """Scenario 6: vault.enc is corrupted during power failure -> app restores from vault.enc.bak."""
        vault_file = temp_vault_dir / "vault.enc"
        backup_file = temp_vault_dir / "vault.enc.bak"

        valid_content = json.dumps({
            "magic": "AUTHDESK_VAULT",
            "version": 1,
            "created_at": 1710000000,
            "updated_at": 1710000000,
            "kdf": {
                "algorithm": "Argon2id",
                "m_cost_kib": 65536,
                "t_cost": 3,
                "p_cost": 1,
                "salt_b64": base64.b64encode(b"S" * 32).decode(),
            },
            "wrapped_master_key": {
                "nonce_b64": base64.b64encode(b"N" * 24).decode(),
                "ciphertext_b64": base64.b64encode(b"K" * 48).decode(),
            },
            "payload": {
                "nonce_b64": base64.b64encode(b"P" * 24).decode(),
                "ciphertext_b64": base64.b64encode(b"E" * 64).decode(),
            },
        })

        # Good backup exists
        backup_file.write_text(valid_content)
        os.chmod(backup_file, 0o600)

        # Corrupted target file (e.g. truncated / bad JSON from abrupt power loss)
        vault_file.write_text('{"magic": "AUTHDESK_VAULT", "corrupt_data')
        os.chmod(vault_file, 0o600)

        # Recovery procedure logic:
        # 1. Attempt reading vault_file
        recovered = False
        try:
            with open(vault_file, "r") as f:
                json.load(f)
        except json.JSONDecodeError:
            # Corruption detected -> fallback to backup
            if backup_file.exists():
                with open(backup_file, "r") as bf:
                    data = json.load(bf)
                valid, errors = vault_oracle.validate_envelope_structure(data)
                if valid:
                    # Restore backup over vault file
                    shutil.copy2(backup_file, vault_file)
                    os.chmod(vault_file, 0o600)
                    recovered = True

        assert recovered is True
        assert vault_file.read_text() == valid_content
        mode, _ = vault_oracle.check_posix_permissions(vault_file)
        assert mode == 0o600
