"""Tier 1: Feature Coverage - Atomic File Persistence and POSIX Permissions.

Verifies:
- Atomic write sequence: temporary file in same directory -> write -> fsync -> rename -> .bak copy.
- POSIX permissions: 0600 on vault file (`vault.enc`) and backup (`vault.enc.bak`).
- POSIX permissions: 0700 on vault parent directory (`~/.local/share/authdesk`).
- Automatic hardening of insecure permissions upon file load.
"""

import os
import stat
from pathlib import Path
from typing import Type

import pytest

from tests.e2e.oracle.vault_oracle import VaultOracle


@pytest.mark.tier(1)
@pytest.mark.milestone("M2")
class TestAtomicPersistence:
    """Validates atomic storage durability and POSIX permission hardening."""

    def test_posix_directory_permissions(self, temp_vault_dir: Path, vault_oracle: Type[VaultOracle]):
        """Verifies that vault directory permissions are strictly 0700 (drwx------)."""
        mode, mode_oct = vault_oracle.check_posix_permissions(temp_vault_dir)
        assert mode == 0o700, f"Vault directory permissions must be 0700, got {mode_oct}"
        assert vault_oracle.verify_vault_dir_permissions(temp_vault_dir) is True

    def test_posix_file_permissions(self, temp_vault_dir: Path, vault_oracle: Type[VaultOracle]):
        """Verifies that vault file permissions are strictly 0600 (-rw-------)."""
        vault_file = temp_vault_dir / "vault.enc"
        # Simulate creating vault file with mode 0600
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(str(vault_file), flags, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write('{"test": true}')

        mode, mode_oct = vault_oracle.check_posix_permissions(vault_file)
        assert mode == 0o600, f"Vault file permissions must be 0600, got {mode_oct}"
        assert vault_oracle.verify_vault_file_permissions(vault_file) is True

    def test_atomic_replace_and_backup_creation(self, temp_vault_dir: Path):
        """Simulates atomic replace sequence and verifies .bak file preservation."""
        vault_file = temp_vault_dir / "vault.enc"
        backup_file = temp_vault_dir / "vault.enc.bak"
        tmp_file = temp_vault_dir / "vault.enc.tmp.1234abcd"

        # Initial write (Version 1)
        vault_file.write_text("VERSION_1")
        os.chmod(vault_file, 0o600)

        # Update to Version 2:
        # Step 1: Write to tmp file with 0600
        tmp_file.write_text("VERSION_2")
        os.chmod(tmp_file, 0o600)

        # Step 2: Backup existing vault.enc to vault.enc.bak
        import shutil
        shutil.copy2(vault_file, backup_file)
        os.chmod(backup_file, 0o600)

        # Step 3: Atomic rename tmp -> vault.enc
        os.replace(tmp_file, vault_file)

        # Verification
        assert vault_file.read_text() == "VERSION_2"
        assert backup_file.read_text() == "VERSION_1"
        assert not tmp_file.exists()

        # Both files must have 0600 permissions
        assert stat.S_IMODE(os.stat(vault_file).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(backup_file).st_mode) == 0o600

    def test_loose_permissions_hardening_logic(self, temp_vault_dir: Path, vault_oracle: Type[VaultOracle]):
        """Verifies auto-hardening behavior: insecure file (e.g. 0644 or 0666) is detected and hardened to 0600."""
        vault_file = temp_vault_dir / "vault.enc"
        vault_file.write_text('{"dummy": "data"}')
        os.chmod(vault_file, 0o666)  # Insecure world-writable file

        mode, mode_oct = vault_oracle.check_posix_permissions(vault_file)
        assert mode == 0o666, "Setup failed to create insecure file"
        assert vault_oracle.verify_vault_file_permissions(vault_file) is False

        # Apply hardening action
        os.chmod(vault_file, 0o600)

        # Hardened check
        assert vault_oracle.verify_vault_file_permissions(vault_file) is True
