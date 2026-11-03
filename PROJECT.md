# Project: AuthDesk

## Architecture
AuthDesk is an offline, security-hardened Linux desktop TOTP manager built with Tauri v2, React + TypeScript (Vite), and a Rust backend.
- **Backend (Rust)**:
  - Cryptographic Engine: RFC 6238 compliant TOTP generator (HMAC-SHA1/SHA256/SHA512).
  - Security & Storage: Envelope encryption with 32-byte Master Key (CSPRNG), Argon2id KDF (m=64 MiB, t=3, p=1), XChaCha20-Poly1305 AEAD (24-byte random nonce + AAD binding). Atomic persistence (temp + fsync + rename + .bak) with Linux permissions 0600 (file) / 0700 (directory). Memory zeroization via `zeroize`.
  - Window & Desktop Integration: Tauri v2 window manager (`palette` 420x560, transparent, undecorated, always-on-top, centered, skipTaskbar), AppIndicator/SNI system tray icon with menu, single-instance `--toggle` IPC listener, and Ctrl+Alt+A global shortcut with safe Wayland logging.
- **Frontend (React + TypeScript + Vite)**:
  - Floating palette UI matching 420x560 dimensions with transparent background.
  - Live search filter, full keyboard navigation (arrows, Enter to copy & hide, Esc to hide).
  - Visual circular/bar countdown timer for TOTP period expiration.
  - Bilingual interface (Spanish default, English toggle).
  - Smart 30-second clipboard auto-clear (conditional on code matching).
  - 5-minute inactivity auto-lock.
- **Strict Security Boundaries**:
  - Zero-network enforcement: Webview CSP `connect-src 'none'`, no networking crates.
  - Zero secret leakage: Passwords, Master Key, and raw secrets never sent across IPC to frontend, nor printed in logs/stdout/stderr.
  - Coding convention: Spanish code comments, English identifiers.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Toolchain & Environment Verification | Verify rustc, cargo, node, npm, webkit2gtk-4.1, ayatana-indicator | M0 | R1, Survey |
| 2 | Tauri v2 Project Initialization | Initialize Tauri v2 + React + TS (Vite) with `com.rod.authdesk` identifier | M0 | R1, Survey |
| 3 | Pinned Plugins & Cargo Features | Configure global-shortcut, single-instance, autostart, clipboard, dialog, and tray-icon feature | M0 | R1, Survey |
| 4 | Floating Palette Window | 420x560, undecorated, transparent, alwaysOnTop, skipTaskbar, centered, hidden at startup | M0 | R2, Survey |
| 5 | System Tray & Context Menu | Tray icon with menu ("Mostrar AuthDesk", "Bloquear", "Salir") and toggle on click | M0 | R2, Survey |
| 6 | Single-Instance & `--toggle` Flag | Intercept `--toggle` via secondary instance to show/hide and focus palette | M0 | R2, Survey |
| 7 | Global Shortcut Ctrl+Alt+A | Register Ctrl+Alt+A with graceful non-crashing diagnostic logging on Wayland | M0 | R2, Survey |
| 8 | RFC 6238 TOTP Engine | HMAC-SHA1, SHA256, SHA512, 6/8 digits, configurable period, leading zero formatting | M1 | R3, Survey |
| 9 | Base32 & Secret Sanitization | Parse and normalize Base32 keys, strip spaces/hyphens, validate inputs | M1 | R3, Survey |
| 10 | RFC 6238 Test Vectors | Unit tests validating RFC 6238 Appendix B test vectors via `cargo test` | M1 | R3, Survey |
| 11 | Argon2id Key Derivation | Argon2id KDF (m=64 MiB, t=3, p=1, salt >= 16 bytes) deriving KEK from password | M2 | R3, Survey |
| 12 | XChaCha20-Poly1305 Vault Encryption | 32-byte CSPRNG Master Key wrapped by KEK, payload encrypted with 24B nonce + AAD | M2 | R3, Survey |
| 13 | Atomic Disk Persistence | Temp file in same directory -> write -> fsync -> rename -> .bak copy | M2 | R3, Survey |
| 14 | Linux POSIX Permissions | Vault file 0600 permissions, parent directory 0700 permissions | M2 | R3, Survey |
| 15 | In-Memory Zeroize & Safety | Use `zeroize::ZeroizeOnDrop` for Master Key, KEK, plaintext passwords and buffers | M2 | R3, R4, Survey |
| 16 | React Floating Palette UI | Fast, sleek dark palette UI with transparent background fitting 420x560 window | M3 | R4, Survey |
| 17 | Live Search & Keyboard Navigation | Real-time filter, arrow navigation, Enter to copy & hide, Esc to hide | M3 | R4, Survey |
| 18 | Visual Countdown Timer | Visual progress indicator showing remaining seconds in current TOTP cycle | M3 | R4, Survey |
| 19 | Bilingual Localization | Complete Spanish (default) and English translations for all UI strings | M3 | R4, Survey |
| 20 | Smart Clipboard Auto-Clear | 30s timer clears clipboard only if it still contains the copied TOTP code | M3 | R4, Survey |
| 21 | Inactivity Auto-Lock | 5-minute inactivity timer triggers vault lock and purges keys from memory | M3 | R4, Survey |
| 22 | Zero-Network & CSP Enforcement | Webview CSP `connect-src 'none'`, offline-only operation | M4 | R5, Survey |
| 23 | Zero-Leak Logging & Error Handling | Redacted Debug traits, no secrets in logs/stdout/stderr | M4 | R5, Survey |
| 24 | E2E Integration & Verification | Pass 100% of E2E test suites (Tiers 1-4) and adversarial hardening (Tier 5) | M4 | AC, Survey |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M0 | Project Init & Palette Skeleton (Fase 0) | Toolchain verify, Tauri v2 init, palette window (420x560, transparent), tray icon, single-instance `--toggle`, Ctrl+Alt+A | none | DONE |
| M1 | TOTP Engine & RFC 6238 Logic (Fase 1) | RFC 6238 HMAC-SHA1/256/512, 6/8 digits, period, Base32 parser, Appendix B unit tests | none | PLANNED |
| M2 | Secure Vault & Crypto Storage (Fase 2) | Argon2id KDF, XChaCha20-Poly1305 envelope, atomic temp+fsync+rename+.bak, 0600/0700 perms, zeroize | M1 | PLANNED |
| M3 | React UI Palette & Security Flows (Fases 3-4) | Palette UI, live search, keyboard navigation, countdown, smart clipboard clear, 5-min auto-lock, bilingual | M0, M2 | PLANNED |
| M4 | E2E Testing & Hardening | Full E2E verification (Tiers 1-4), zero-network & zero-leak auditing, adversarial test hardening (Tier 5) | M0, M1, M2, M3 | PLANNED |

## Interface Contracts

### Frontend <-> Backend IPC Commands (Tauri Invoke)
1. `get_vault_status() -> VaultStatusDto`
   - Returns `{ initialized: bool, locked: bool, account_count: usize }`
2. `init_vault(password: String) -> Result<(), String>`
   - Initializes vault with new password, generates 32B MK, saves vault to disk.
3. `unlock_vault(password: String) -> Result<(), String>`
   - Derives KEK via Argon2id, decrypts MK, loads accounts into memory.
4. `lock_vault() -> Result<(), String>`
   - Wipes MK and account keys from memory using `zeroize`, sets locked state.
5. `list_accounts() -> Result<Vec<AccountSummaryDto>, String>`
   - Returns metadata only: `{ id: String, name: String, issuer: String, digits: u32, period: u32 }`
   - DOES NOT return secret keys.
6. `get_totp(account_id: String) -> Result<TotpCodeDto, String>`
   - Returns `{ code: String, remaining_seconds: u32, total_seconds: u32 }`
7. `add_account(req: AddAccountDto) -> Result<AccountSummaryDto, String>`
   - Adds account with name, issuer, secret (Base32), algo, digits, period.
8. `delete_account(account_id: String) -> Result<(), String>`
   - Removes account and re-encrypts vault atomically.
9. `toggle_window() -> Result<(), String>`
   - Toggles visibility of palette window.
10. `hide_window() -> Result<(), String>`
    - Hides palette window.

## Code Layout
- `src/` (React + TypeScript Frontend):
  - `src/App.tsx` - Main Palette container, search input, account list, keyboard listener
  - `src/components/AccountItem.tsx` - Individual TOTP item with countdown indicator and copy button
  - `src/components/CountdownPie.tsx` - Visual circular/bar countdown component
  - `src/components/LockScreen.tsx` - Unlock / setup master password screen
  - `src/i18n/` - Bilingual dictionaries (es.ts, en.ts)
  - `src/hooks/useAutoLock.ts` - 5-minute inactivity tracker
  - `src/hooks/useClipboard.ts` - 30-second conditional clipboard auto-clear
  - `src/styles/` - Global styles, transparency and dark theme CSS
- `src-tauri/` (Rust Backend):
  - `src-tauri/Cargo.toml` - Dependencies pinned: tauri, plugins, argon2, chacha20poly1305, zeroize, hmac, sha1, sha2, data-encoding, rand
  - `src-tauri/tauri.conf.json` - Tauri v2 config, palette window, permissions, CSP
  - `src-tauri/capabilities/default.json` - Plugin capabilities
  - `src-tauri/src/main.rs` - Entry point
  - `src-tauri/src/lib.rs` - Tauri builder, plugin registrations, tray setup, single-instance setup
  - `src-tauri/src/totp/` - RFC 6238 engine, Base32 parser, test vectors
  - `src-tauri/src/vault/` - Argon2id KDF, XChaCha20-Poly1305 envelope, atomic storage
  - `src-tauri/src/commands/` - Tauri IPC commands implementation
  - `src-tauri/src/tray/` - System tray menu and event handling
