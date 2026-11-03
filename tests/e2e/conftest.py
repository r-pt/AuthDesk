"""Pytest configuration and shared fixtures for AuthDesk E2E test suites."""

import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import Generator

# Ensure project root is in sys.path for test discovery and oracle imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

from tests.e2e.oracle.config_oracle import ConfigOracle
from tests.e2e.oracle.totp_oracle import TotpOracle
from tests.e2e.oracle.vault_oracle import VaultOracle


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Returns absolute path to the project root directory."""
    return Path(__file__).resolve().parent.parent.parent


@pytest.fixture(scope="session")
def tauri_conf_path(project_root: Path) -> Path:
    """Returns path to src-tauri/tauri.conf.json."""
    return project_root / "src-tauri" / "tauri.conf.json"


@pytest.fixture(scope="session")
def cargo_toml_path(project_root: Path) -> Path:
    """Returns path to src-tauri/Cargo.toml."""
    return project_root / "src-tauri" / "Cargo.toml"


@pytest.fixture(scope="session")
def capabilities_path(project_root: Path) -> Path:
    """Returns path to src-tauri/capabilities/default.json."""
    return project_root / "src-tauri" / "capabilities" / "default.json"


@pytest.fixture(scope="session")
def authdesk_binary(project_root: Path) -> Path | None:
    """Locates the built AuthDesk executable if compiled."""
    candidates = [
        project_root / "src-tauri" / "target" / "release" / "authdesk",
        project_root / "src-tauri" / "target" / "debug" / "authdesk",
    ]
    for c in candidates:
        if c.exists() and os.access(c, os.X_OK):
            return c
    return None


@pytest.fixture
def temp_vault_dir() -> Generator[Path, None, None]:
    """Provides an isolated temporary vault directory hardened to mode 0700."""
    temp_dir = tempfile.mkdtemp(prefix="authdesk_test_vault_")
    path = Path(temp_dir)
    os.chmod(path, 0o700)
    try:
        yield path
    finally:
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)


@pytest.fixture(scope="session")
def totp_oracle() -> type[TotpOracle]:
    return TotpOracle


@pytest.fixture(scope="session")
def vault_oracle() -> type[VaultOracle]:
    return VaultOracle


@pytest.fixture(scope="session")
def config_oracle() -> type[ConfigOracle]:
    return ConfigOracle


def pytest_configure(config):
    """Register custom markers for tiers and milestones."""
    config.addinivalue_line("markers", "tier(number): mark test as belonging to a specific tier (1, 2, 3, 4)")
    config.addinivalue_line("markers", "milestone(name): mark test as associated with a milestone (M0, M1, M2, M3, M4)")
