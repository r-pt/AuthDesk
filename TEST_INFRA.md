# AuthDesk Test Infrastructure & Verification Architecture

## 1. Overview
The AuthDesk test infrastructure is an opaque-box, multi-tier End-to-End (E2E) testing framework designed to rigorously verify all functional, security, cryptographic, and desktop integration requirements specified in `PROJECT.md` and `ORIGINAL_REQUEST.md`.

The framework operates under strict zero-trust principles: tests derive expectations exclusively from mathematical specifications, RFC standards (RFC 6238, RFC 4226, RFC 9106, RFC 7539), and architectural invariants, without coupling to internal backend implementation details.

---

## 2. Multi-Tier Test Pyramid

```
                ▲
               / \
              /   \
             / T4  \    Tier 4: Real-World User Scenarios (4 workflows)
            /-------\
           /   T3    \   Tier 3: Cross-Feature Combinations (5 tests)
          /-----------\
         /     T2      \  Tier 2: Boundary & Corner Cases (18 tests)
        /---------------\
       /       T1        \ Tier 1: Feature Coverage (27 tests)
      +-------------------+
```

### Tier 1: Feature Coverage (`tests/e2e/tier1_feature_coverage/`)
Comprehensive verification of individual features and interface contracts:
- **`test_window_and_cli.py`**: Window geometry 420x560, undecorated, transparent, `alwaysOnTop: true`, `skipTaskbar: true`, centered, and CLI flags `--hidden` and `--toggle`.
- **`test_tray_and_shortcut.py`**: Ayatana/SNI system tray menu ("Mostrar AuthDesk", "Bloquear", "Salir"), left-click toggle, and `Ctrl+Alt+A` shortcut registration with graceful Wayland logging.
- **`test_totp_rfc6238.py`**: RFC 6238 HMAC-SHA1/SHA256/SHA512 algorithms, 6/8 digits, configurable periods (15s/30s/60s), exact leading-zero formatting (`"005924"`), and Appendix B test vectors.
- **`test_vault_crypto_storage.py`**: Argon2id KDF parameters (m=64 MiB, t=3, p=1, salt >= 16B), XChaCha20-Poly1305 (24B extended nonce, 16B tag), envelope encryption schema, and AAD binding.
- **`test_atomic_persistence.py`**: Atomic disk persistence (temp file in same dir, fsync on file/dir, atomic rename, `.bak` copy) and strict POSIX permissions (0600 on files, 0700 on directory).
- **`test_zero_network_and_logs.py`**: Content Security Policy (`connect-src 'none'`), zero network crates in `Cargo.toml`, and zero secret leakage in logs.

### Tier 2: Boundary & Corner Cases (`tests/e2e/tier2_boundary_corner/`)
Adversarial and extreme condition validation:
- **`test_totp_boundaries.py`**: Empty/whitespace secrets, invalid Base32 symbols (`'8'`, `'9'`, symbols, emojis), extreme steps ($X=0$ division-by-zero rejection, $X=1$, $X=300$, $X=3600$), pre-epoch negative timestamps ($T < 0$), Year 2038 / 64-bit timestamps ($T=20000000000$), and invalid digit counts (0, 5, 7, 9).
- **`test_vault_boundaries.py`**: Corrupt envelope files, tampered JSON magic, tampered version numbers, Argon2id memory cost downgrade attacks (detectable via AAD mismatch), insufficient salt lengths, truncated ciphertexts, and read-only directory handling.
- **`test_concurrency_and_clipboard.py`**: Rapid consecutive `--toggle` invocations, smart 30-second clipboard auto-clear, and clipboard overwrite protection (preserving external user clipboard updates).

### Tier 3: Cross-Feature Combinations (`tests/e2e/tier3_cross_feature/`)
Pairwise and state-machine transitions:
- **`test_cross_feature_combinations.py`**: Rejecting account creation/deletion while vault is locked; drift-free TOTP interval countdown across window hide/summon cycles; 5-minute inactivity auto-lock during active search; bilingual language toggling (`es` <-> `en`) preserving in-memory vault and account states.

### Tier 4: Real-World Scenarios (`tests/e2e/tier4_real_world_scenarios/`)
Complete end-to-end user journeys:
- **`test_real_world_workflows.py`**:
  - Scenario 1: First-time setup (master password -> envelope creation -> POSIX 0600/0700 verification).
  - Scenario 2: Multi-account import (GitHub, Google, AWS, Corporate VPN across SHA1/SHA256, 6/8 digits, 30s/60s).
  - Scenario 3: Real-time search filter and keyboard copy workflow.
  - Scenario 4: Inactivity auto-lock and memory wiping.
  - Scenario 5: Disaster recovery (abrupt power loss corruption of `vault.enc` auto-restores from `vault.enc.bak`).

---

## 3. Authoritative Test Oracles (`tests/e2e/oracle/`)

1. **`TotpOracle` (`tests/e2e/oracle/totp_oracle.py`)**:
   - Independent pure-Python reference implementation of RFC 6238 and RFC 4226.
   - Authoritative source for HMAC-SHA1/SHA256/SHA512 dynamic truncation and zero-padding.
   - Validated against 100% of RFC 6238 Appendix B test vectors.
   - Robust RFC 4648 Base32 normalizer handling whitespace, hyphens, and padding.

2. **`VaultOracle` (`tests/e2e/oracle/vault_oracle.py`)**:
   - Schema validator for `VaultEnvelope` JSON structures.
   - AAD byte encoder for wrapped master keys and encrypted payloads.
   - POSIX permission checker enforcing `0600` on files and `0700` on directories.
   - Comprehensive regex and token scanner detecting secret leaks in log streams.

3. **`ConfigOracle` (`tests/e2e/oracle/config_oracle.py`)**:
   - Validates `tauri.conf.json` window geometry, transparency, decorations, and CSP lockdown.
   - Audits `Cargo.toml` dependencies against forbidden networking libraries.

---

## 4. Test Execution & Usage

### Unified Runner
The test runner `tests/e2e/runner.py` provides CLI options to run any subset of tests:

```bash
# Run all tiers and all milestones
python3 tests/e2e/runner.py

# Run with verbose output
python3 tests/e2e/runner.py -v

# Run a specific tier (e.g. Tier 1, Tier 2, Tier 3, Tier 4)
python3 tests/e2e/runner.py --tier 1
python3 tests/e2e/runner.py --tier 2
python3 tests/e2e/runner.py --tier 3
python3 tests/e2e/runner.py --tier 4

# Filter by milestone marker (M0, M1, M2, M3, M4)
python3 tests/e2e/runner.py --milestone M1

# Fail-fast (stop on first failure)
python3 tests/e2e/runner.py -x
```

### Standard Pytest Execution
The suite is fully compatible with standard `pytest`:

```bash
# Run entire suite
pytest tests/e2e

# Run with markers
pytest tests/e2e -m "tier(1)"
pytest tests/e2e -m "milestone('M0')"
```

---

## 5. Progressive Testability Model

Tests are marked with their milestone requirements. When features from earlier milestones are in progress, tests requiring unbuilt targets (e.g., compiled binaries or unwritten configuration files) cleanly skip with informative diagnostics rather than causing false failures. As each milestone completes, its associated tests automatically transition from skipped to executed and verified.
