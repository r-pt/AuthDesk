"""Oracle package containing authoritative reference implementations for E2E tests."""

from tests.e2e.oracle.config_oracle import ConfigOracle
from tests.e2e.oracle.totp_oracle import TotpOracle
from tests.e2e.oracle.vault_oracle import VaultOracle

__all__ = ["TotpOracle", "VaultOracle", "ConfigOracle"]
