# AuthDesk Technical Specification (`v0.2.0`)

## 1. System Overview & Trust Boundaries

AuthDesk (`com.rod.authdesk`) is an offline Linux desktop TOTP authenticator built with Tauri v2, React 18 + TypeScript (Vite 6), and a Rust backend (`authdesk_lib`).

- **Zero-Network Enforcement**:
  - WebView CSP (`src-tauri/tauri.conf.json`):
    `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'none';`
  - `src-tauri/Cargo.toml` contains no HTTP, TCP, or networking crates.
- **IPC Secret Boundary**:
  - Plaintext credentials (`password`, `pin`, export `credential`) and Base32 `secret` values cross IPC only on write/unlock/import/export-auth inputs from the React frontend to Rust (`init_vault`, `unlock_vault`, `set_pin`, `unlock_with_pin`, `add_account`, `update_account`, `set_master_password`, `remove_master_password`, `change_master_password`, `stage_import_uris`, `stage_import_qr_images`, `export_vault_qr_batches`).
  - The Rust backend **never returns** plaintext `secret` fields, Master Keys (`MasterKey`), Key Encryption Keys (`DerivedKek`), or `DeviceKey` values on vault/account/preview DTOs (`AccountCodeDto`, `AccountSummaryDto`, `ImportPreviewItemDto`, `ImportSkippedItemDto`, `ImportPreviewResultDto`, `ImportConfirmResultDto`). Staged import `Account` entries remain strictly inside `AppState.staged_import: RwLock<Vec<Account>>` until `confirm_staged_import`, `cancel_staged_import`, or `lock_vault` zeroizes and clears them.
  - Sensitive structs (`MasterKey`, `DerivedKek`, `DeviceKey`, `Account`, `AddAccountDto`, `UpdateAccountDto`, `QrImageInputDto`, `ExportQrBatchDto`, `MigrationOtpParameters`) implement custom `Debug` formatters redacting secrets/bytes/SVGs (`[REDACTED]` or `bytes_len`), and `Account`, `AddAccountDto`, `UpdateAccountDto`, `QrImageInputDto`, and `ExportQrBatchDto` implement `Drop` to zeroize buffers via `zeroize::Zeroize`.
  - Incoming `password`, `pin`, `uris_text`, and `credential` `String` arguments in Tauri command handlers (including both `current_password` and `new_password` in `set_master_password`) and `unlock_*`/`set_*` paths are wiped via `zeroize::Zeroize` (`zeroize` v1.8.1).
  - `export_vault_qr_batches` returns plaintext Google Authenticator `otpauth-migration://` QR SVGs (`<= 10` accounts/batch) only when the vault is unlocked, `confirmed_warning == true`, and caller re-authentication succeeds (Master Password when `!passwordless`, 6-digit PIN when `passwordless && pin_enabled` under the 5-attempt lockout, or warning-only when `passwordless && !pin_enabled`), rejecting empty vaults cleanly. The frontend renders SVGs via `<img src="data:image/svg+xml;utf8,..." />` (without `dangerouslySetInnerHTML`) and clears exported batches and credentials on close, `Escape`, tab switch, vault lock, or unmount.
- **State Persistence Split**:
  - **Backend (`AppState` + `vault.enc` + Secret Service)**: Owns encrypted accounts, cryptographic unlock state (`RwLock<Option<MasterKey>>`), ephemeral import staging (`staged_import: RwLock<Vec<Account>>`), PIN failed attempt counter (`AtomicU32`), and runtime window state (`RwLock<WindowSettingsDto>`, with `hide_on_copy` defaulting to `true`).
  - **Frontend (`localStorage`)**: Persists UI preferences (`authdesk_theme`, `authdesk_lang`, `authdesk_window_settings`, `authdesk_hide_on_copy`, `authdesk_autolock_ms`, `authdesk_clipboard_ms`, `authdesk_mask_codes`, `authdesk_global_shortcut`) and pushes stored window settings and `authdesk_global_shortcut` (`toggle_global_shortcut`) to Rust on startup (`src/App.tsx`).

---

## 2. Cryptography, Storage & Keyring Specification

### Vault Envelope & KDF (`VaultEnvelope` v1)

Defined in [`src-tauri/src/storage/vault_file.rs`](file:///home/rod/Desktop/Proyects/AuthDesk/src-tauri/src/storage/vault_file.rs):

- **Header**: `magic = "AUTHDESK_VAULT"`, `version = 1`, `created_at` (`i64`), `updated_at` (`i64`), `passwordless` (`bool`, `#[serde(default)]`).
- **KDF (`KdfConfig`)**:
  - `algorithm = "Argon2id"` (`Version::V0x13`)
  - `m_cost_kib = 65536` (`64 MiB`, validated `>= 65536`)
  - `t_cost = 3` (validated `>= 3`)
  - `p_cost = 1` (validated `== 1` in `kdf.rs` and `vault_file.rs`)
  - `salt_b64`: Base64-encoded random salt (`RECOMMENDED_SALT_LEN = 32` bytes, minimum `16` bytes)
- **Cipher (`src-tauri/src/crypto/aead.rs`)**:
  - **XChaCha20-Poly1305** with 24-byte `OsRng` nonces and 16-byte Poly1305 authentication tags.
  - `wrapped_master_key`: Encrypts the 32-byte `MasterKey` under the derived `DerivedKek` (`48`-byte ciphertext).
  - `payload`: Encrypts JSON-serialized `VaultPayload { version: 1, accounts: Vec<Account> }` under the 32-byte `MasterKey`.
- **Domain-Separated AADs**:
  - **Wrapped Master Key AAD**: `b"AUTHDESK_MK_V1:" || version.to_be_bytes() || m_cost.to_be_bytes() || t_cost.to_be_bytes() || p_cost.to_be_bytes() || salt`
  - **Payload AAD**: `b"AUTHDESK_PAYLOAD_V1:" || version.to_be_bytes() || updated_at.to_be_bytes()`
  - **PIN Wrapped Master Key AAD**: `b"AUTHDESK_PIN_MK_V1"` (`PIN_AAD`)

### Authentication Modes & Keyring (`src-tauri/src/crypto/keyring.rs`)

OS Keyring integration uses `keyring` v3 (`sync-secret-service`, `crypto-rust`) under `KEYRING_SERVICE = "authdesk"`:

| Keyring Entry Key | Value | Purpose |
| :--- | :--- | :--- |
| `"device-key"` | Base64 32-byte `DeviceKey` (`OsRng`) | Keyed secret passed to `Argon2::new_with_secret` in `derive_pin_kek` |
| `"pin-blob"` | JSON `PinBlob` (`version`, Argon2id costs, `salt_b64`, `nonce_b64`, `ciphertext_b64`) | `MasterKey` wrapped under `pin_kek` with `PIN_AAD` |
| `"passwordless-mk"` | Base64 32-byte `MasterKey` | Cached `MasterKey` for fast auto-unlock in passwordless mode |
| `"probe"` | Probed via `get_secret()` | Secret Service availability check in `is_available()` |

- **Master Password Mode**: Standard Argon2id KDF wraps/unwraps `MasterKey`. `set_master_password`, `change_master_password`, and `remove_master_password` decrypt/verify `VaultPayload`, rotate `MasterKey` via `generate_master_key()` (whenever no PIN is active during password setup/change, and unconditionally on `remove_master_password`), re-encrypt `VaultPayload` with a fresh timestamp AAD, and execute `atomic_write_file` twice so `vault.enc.bak` is overwritten with the new envelope and old passwords/keys are invalidated in `.bak`.
- **6-Digit PIN Mode**: Requires Secret Service availability (`pin_available == true`) and an unlocked vault to enable. Wrong PIN attempts increment `pin_failed_attempts: AtomicU32` (max `5`). In Master Password + PIN mode, reaching `5` failed attempts calls `delete_pin_blob()` and falls back to Master Password unlock. In Passwordless + PIN mode, reaching `5` failed attempts keeps `pin-blob` intact, disables numeric input in `PinKeypadView.tsx`, and blocks `auto_unlock_if_passwordless()` (and `get_vault_status()` auto-unlock) for the active session (`pin_failed_attempts > 0`).
- **Passwordless Mode**: Wraps `MasterKey` using `PASSWORDLESS_INTERNAL_KEY` (`"AUTHDESK_PASSWORDLESS_INTERNAL_KEY_V1"`) via Argon2id and caches `MasterKey` in `"passwordless-mk"`. When a PIN is enabled (`is_pin_enabled()`), `auto_unlock_if_passwordless()` returns `Ok(false)` and `get_vault_status()` skips auto-unlock.
- **Lock Capability Invariant (`can_lock_vault`)**:
  - `can_lock_vault() == vault_path.exists() && (!is_passwordless() || is_pin_enabled())`
  - System tray `"Bloquear"`, `PaletteView` lock icon button, `Ctrl+L`, and `useAutoLock` are enabled only when `can_lock_vault()` is `true`.

### Atomic Filesystem Storage (`src-tauri/src/storage/atomic.rs`)

- **Directory Resolution (`default_vault_dir`)**: `$XDG_DATA_HOME/authdesk` -> `$HOME/.local/share/authdesk` -> `/tmp/authdesk`.
- **Vault Paths**: `<dir>/vault.enc` and `<dir>/vault.enc.bak`.
- **POSIX Permissions**: Directory hardened to `0700`; temporary file (`vault.enc.tmp.<pid>_<rand>`), `vault.enc`, and `vault.enc.bak` hardened to `0600`.
- **Write Sequence**: Write temp file (`O_CREAT | O_EXCL`, `0600`) -> `flush()` + `sync_all()` -> copy existing `vault.enc` to `vault.enc.bak` -> `rename(tmp, vault.enc)` -> `sync_all()` on parent directory -> harden `0600`.
- **Corruption Recovery (`safe_read_file`)**: Automatically copies `vault.enc.bak` over `vault.enc` if `vault.enc` fails JSON deserialization or `VaultEnvelope::validate()`.

### Known Architectural & Security Caveats (Current Behavior)

- **Passwordless Static Fallback Key (No PIN)**: When no PIN is configured, `init_vault_passwordless`, `auto_unlock_if_passwordless`, and locked `set_master_password` (when `env.passwordless` is `true`) fall back to `PASSWORDLESS_INTERNAL_KEY`, so passwordless mode provides convenience rather than protection against local file readers.
- **Secret Service Session Isolation**: `device-key` and `pin-blob` reside together in the user's unlocked desktop Secret Service session (software-backed, not hardware/TPM-bound).
- **Plaintext Migration QR Export**: `export_vault_qr_batches` intentionally emits unencrypted `otpauth-migration://` QR SVGs for Google Authenticator compatibility; exposure is mitigated via explicit warning acknowledgment, Master Password/PIN re-authentication (when configured), and immediate state clearing in `SettingsModal.tsx`.
- **Frontend Watchdogs & Startup Shortcut Hook**:
  - Clipboard auto-clear (`src/hooks/useClipboard.ts`) keeps a module-scoped timer (`activeClipboardTimer`) that persists across `PaletteView` unmounts on lock, and inactivity auto-lock (`src/hooks/useAutoLock.ts`) runs on React timers; browser/WebKit JS timers may still throttle or pause when the window is hidden.
  - Runtime shortcut toggling (`toggle_global_shortcut` -> `shortcut.rs`) propagates OS registration/unregistration errors to the UI via `Result<(), String>`, while initial startup in `lib.rs` ignores `setup_global_shortcut` failure so Wayland compositors or conflicting system bindings do not prevent launch.

---

## 3. Window Management & Desktop Integration

- **Dual Window Modes (`WindowSettingsDto`)**:
  - `"popup"` (default; normalizes legacy `"floating"` and `"tray-popup"`): Undecorated (`decorations: false`), hidden from taskbar (`skipTaskbar: true`), fixed `420x560` logical dimensions (`set_resizable(false)`).
  - `"normal"` (normalizes `"taskbar"`): Undecorated (`decorations: false`), shown in taskbar (`skipTaskbar: false`), defaults to fixed `420x560` unless `resizable: true` is enabled in Settings (which preserves resized logical dimensions >= `420x560`).
- **Active-Monitor Positioning & Wayland Fallback**:
  - On X11, `position_popup_window` selects the monitor containing the click/cursor coordinates and places the window within `monitor.work_area()` (`top-right`, `bottom-right`, `center`, or anchored near tray click coordinates).
  - Wayland detection (`is_wayland` / `detect_wayland` via `WAYLAND_DISPLAY` and `XDG_SESSION_TYPE`) falls back to `win.center()` and displays a Wayland notice banner in Settings -> Window.
- **Startup, Single Instance & System Tray**:
  - Launching `authdesk` shows the palette window immediately unless `--hidden` is passed (configured on `tauri_plugin_autostart`).
  - `tauri_plugin_single_instance` handles secondary launches (`--toggle` calls `toggle_palette_window`; normal launch shows and focuses).
  - AppIndicator/SNI tray (`"Mostrar AuthDesk"`, `"Bloquear"`, `"Salir"`) syncs `"Bloquear"` enabled state with `can_lock_vault()`.
  - Global `Ctrl+Alt+A` shortcut (`src-tauri/src/shortcut.rs`) toggles the palette window and propagates OS shortcut errors through `toggle_global_shortcut`.

---

## 4. Interface Contracts (All 35 Tauri IPC Commands & DTOs)

Registered in `tauri::generate_handler!` ([`src-tauri/src/lib.rs#L729-L765`](file:///home/rod/Desktop/Proyects/AuthDesk/src-tauri/src/lib.rs#L729-L765)):

### Vault & Authentication Commands
1. `get_vault_status() -> VaultStatusDto`
2. `init_vault(password: String) -> Result<(), String>`
3. `unlock_vault(password: String) -> Result<(), String>`
4. `lock_vault() -> Result<(), String>`
5. `create_vault_passwordless() -> Result<(), String>`
6. `auto_unlock_if_passwordless() -> Result<bool, String>`
7. `set_master_password(current_password: Option<String>, new_password: String) -> Result<(), String>`
8. `remove_master_password(current_password: String) -> Result<(), String>`
9. `change_master_password(current_password: String, new_password: String) -> Result<(), String>`
10. `set_pin(pin: String) -> Result<(), String>`
11. `unlock_with_pin(pin: String) -> Result<(), String>`
12. `disable_pin() -> Result<(), String>`

### Account, TOTP & Migration Commands
13. `current_codes() -> Result<Vec<AccountCodeDto>, String>`
14. `list_accounts() -> Result<Vec<AccountSummaryDto>, String>`
15. `add_account(req: AddAccountDto) -> Result<AccountSummaryDto, String>`
16. `update_account(req: UpdateAccountDto) -> Result<AccountSummaryDto, String>`
17. `delete_account(account_id: String) -> Result<bool, String>`
18. `reorder_accounts(account_ids: Vec<String>) -> Result<(), String>`
19. `load_demo_accounts() -> Result<usize, String>`
20. `remove_demo_accounts() -> Result<usize, String>`
21. `stage_import_uris(uris_text: String) -> Result<ImportPreviewResultDto, String>`
22. `stage_import_qr_images(images: Vec<QrImageInputDto>) -> Result<ImportPreviewResultDto, String>`
23. `confirm_staged_import(selected_indices: Vec<usize>) -> Result<ImportConfirmResultDto, String>`
24. `cancel_staged_import() -> Result<(), String>`
25. `export_vault_qr_batches(credential: Option<String>, confirmed_warning: bool) -> Result<ExportQrResultDto, String>`

### Window & Desktop Commands
26. `get_window_settings() -> WindowSettingsDto`
27. `set_window_mode(mode: String) -> Result<(), String>`
28. `set_window_resizable(resizable: bool) -> Result<(), String>`
29. `set_popup_position(pos: String) -> Result<(), String>`
30. `set_always_on_top(enabled: bool) -> Result<(), String>`
31. `set_auto_hide_on_blur(enabled: bool) -> Result<(), String>`
32. `is_wayland() -> bool`
33. `toggle_global_shortcut(enabled: bool) -> Result<(), String>`
34. `start_window_drag() -> Result<(), String>`
35. `hide_window() -> Result<(), String>`

### Canonical DTO Schemas ([`src-tauri/src/models.rs`](file:///home/rod/Desktop/Proyects/AuthDesk/src-tauri/src/models.rs))

```rust
pub struct VaultStatusDto {
    pub initialized: bool,
    pub locked: bool,
    pub account_count: usize,
    pub pin_available: bool,
    pub pin_enabled: bool,
    pub pin_attempts_remaining: Option<u32>,
    pub passwordless: bool,
}

pub struct AccountCodeDto {
    pub id: String,
    pub issuer: String,
    pub account: String,
    pub code: String,
    pub seconds_remaining: u64,
    pub period: u64,
    pub digits: u32,
    pub algorithm: Algorithm, // "SHA1" | "SHA256" | "SHA512"
}

pub struct AccountSummaryDto {
    pub id: String,
    pub issuer: String,
    pub account: String,
    pub digits: u32,
    pub period: u64,
    pub algorithm: Algorithm,
    pub account_type: AccountType, // "TOTP" | "HOTP"
}

pub struct AddAccountDto {
    pub issuer: String,
    pub account: String,
    pub secret: String,
    pub algorithm: Option<Algorithm>,
    pub digits: Option<u32>,
    pub period: Option<u64>,
}

pub struct UpdateAccountDto {
    pub id: String,
    pub issuer: String,
    pub account: String,
    pub secret: Option<String>,
    pub algorithm: Option<Algorithm>,
    pub digits: Option<u32>,
    pub period: Option<u64>,
}

pub struct WindowSettingsDto {
    pub mode: String,           // "popup" | "normal"
    pub popup_position: String, // "top-right" | "bottom-right" | "center"
    pub always_on_top: bool,
    pub auto_hide_on_blur: bool,
    pub hide_on_copy: bool,     // defaults to true
    pub resizable: bool,
}

pub struct ImportPreviewItemDto {
    pub index: usize,
    pub issuer: String,
    pub account: String,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
    pub is_duplicate: bool,
}

pub struct ImportSkippedItemDto {
    pub source: String,
    pub reason: String,
}

pub struct ImportPreviewResultDto {
    pub items: Vec<ImportPreviewItemDto>,
    pub skipped: Vec<ImportSkippedItemDto>,
    pub total_found: usize,
    pub ready_count: usize,
    pub duplicate_count: usize,
    pub skipped_count: usize,
}

pub struct ImportConfirmResultDto {
    pub imported_count: usize,
    pub skipped_duplicates: usize,
}

pub struct QrImageInputDto {
    pub name: String,
    pub bytes: Vec<u8>,
}

pub struct ExportQrBatchDto {
    pub batch_index: usize,
    pub batch_size: usize,
    pub account_count: usize,
    pub svg: String,
}

pub struct ExportQrResultDto {
    pub batches: Vec<ExportQrBatchDto>,
    pub total_accounts: usize,
}
```

---

## 5. Code Layout

- **`src/` (React 18 + TypeScript + Vite 6 Frontend)**:
  - `src/App.tsx` — Root shell, themes (`dark`/`light`/`coffee`), language (`es`/`en`), vault polling, startup window settings & `authdesk_global_shortcut` sync
  - `src/main.tsx` — React DOM entry point
  - `src/assets/fonts/` — Offline bundled `.woff2` files (`Inter-{Regular,Medium,SemiBold,Bold}.woff2`, `JetBrainsMono-{Regular,Medium,SemiBold,Bold}.woff2`)
  - `src/assets/brand/` & `src/assets/logo.svg` — Vector brand assets
  - `src/components/PaletteView.tsx` — Search bar, keyboard navigation (`↑`/`↓`, `Alt+↑`/`Alt+↓`, `Ctrl+N`, `Ctrl+L`, `Enter`, `Escape`), top-bar actions, account list, and `showSettingsRef` focus guard so native OS file pickers inside Settings do not close the modal
  - `src/components/AccountItem.tsx` — Account card with continuous single-line TOTP code (`tabular-nums`), copy button, circular countdown, hover actions
  - `src/components/AccountFormModal.tsx` — Add/Edit account modal with Base32 validation, `parseOtpAuthUri` (`otpauth://totp/` URI paste auto-fill), duplicate check, and `"Importar lote / QR"` / `"Batch / QR import"` trigger in `add` mode
  - `src/components/DeleteConfirmModal.tsx` — Delete confirmation dialog
  - `src/components/SettingsModal.tsx` — Tabbed settings modal (`security`, `window`, `timers`, `appearance`, `import_export`, `demo`) with `initialTab`, QR image/URI batch import preview & confirmation, re-authenticated multi-batch QR SVG export viewer (`<img src="data:image/svg+xml;utf8,..." />`), immediate sensitive-state cleanup, and `Escape` closing
  - `src/components/LockScreen.tsx`, `SetupVaultView.tsx`, `UnlockVaultView.tsx`, `PinKeypadView.tsx` — Vault initialization, master password unlock, passwordless setup, and 6-digit PIN keypad views (disabling numeric digit entry on PIN lockout)
  - `src/components/DragBar.tsx`, `BrandLogo.tsx`, `ServiceIcon.tsx`, `CountdownRing.tsx`, `Icons.tsx` — Top window drag handle, brand emblem, service SVG icons, TOTP SVG ring, and `lucide-react` (`strokeWidth=1.75`) icon wrappers (including upload, download, QR, alert, and pagination chevron icons)
  - `src/hooks/` — `useTotpCodes.ts` (1s code polling), `useClipboard.ts` (module-scoped conditional clear timer persisting across `PaletteView` unmounts), `useAutoLock.ts` (inactivity lock timer)
  - `src/i18n/` — `es.ts` (default), `en.ts`, `index.ts`
  - `src/styles/global.css` — `@font-face` rules, typography tokens, 3 themes, 3-column settings tabs grid, import/export preview and QR viewer styles
  - `src/types/index.ts` — Shared TypeScript DTO interfaces (`SettingsTab`, import/export DTOs, `DEFAULT_WINDOW_SETTINGS.hide_on_copy = true`) and `localStorage` window settings parser/normalizer
  - `src/utils/base32.ts` — Client-side RFC 4648 Base32 format validator (`validateBase32`) and `parseOtpAuthUri` (`otpauth://totp/` URI parser)
- **`src-tauri/` (Rust Backend)**:
  - `src-tauri/Cargo.toml` & `Cargo.lock` — Dependencies (`tauri`, `tauri-plugin-{single-instance,global-shortcut,autostart,clipboard-manager,dialog}`, `argon2`, `chacha20poly1305`, `zeroize`, `keyring`, `hmac`, `sha1`, `sha2`, `data-encoding`, `rand`, `serde`, `serde_json`, `thiserror`, `parking_lot`, `log`, `qrcode`, `rqrr`, `image`, `protobuf`, `url`)
  - `src-tauri/tauri.conf.json` & `capabilities/default.json` — Tauri v2 window defaults, CSP, Linux packaging, and window ACL capabilities
  - `src-tauri/src/main.rs` — Binary entry point calling `authdesk_lib::run()`
  - `src-tauri/src/lib.rs` — Tauri builder, 35 IPC commands, X11/Wayland window placement & flags, system tray, and single-instance setup
  - `src-tauri/src/state.rs` — `AppState` orchestrating vault initialization, unlock, PIN lockout, passwordless transitions, account CRUD/reorder, demo accounts, zero-secret-leak import staging (`staged_import`), and re-authenticated QR batch export
  - `src-tauri/src/models.rs` — Domain models (`Algorithm`, `AccountType`, `Account`), DTO structs (including redacted/zeroizing migration DTOs), `WindowSettingsDto::default().hide_on_copy = true`, and `normalize_window_mode`
  - `src-tauri/src/error.rs` — `AuthDeskError` enum serialized cleanly across IPC
  - `src-tauri/src/shortcut.rs` — `Ctrl+Alt+A` global shortcut setup, toggle helpers, and `Result<(), String>` OS error propagation
  - `src-tauri/src/tray.rs` — Tray menu labels (`Mostrar AuthDesk`, `Bloquear`, `Salir`) and state struct
  - `src-tauri/src/crypto/` — `kdf.rs` (Argon2id + PIN KEK), `aead.rs` (`MasterKey`, XChaCha20-Poly1305, AAD builders), `keyring.rs` (Linux Secret Service wrapper & mock test store)
  - `src-tauri/src/otp/` — `base32.rs` (RFC 4648 Base32 decoder/normalizer), `totp.rs` (RFC 4226 HOTP / RFC 6238 TOTP generator + remaining seconds), `migration.rs` (Google Authenticator protobuf v1 wire codec, `otpauth-migration://` & `otpauth://totp/` parsers, `rqrr`+`image` PNG/JPEG/WebP QR decoding with input/dimension bounds & multi-grid detection, `qrcode` multi-batch SVG export `<= 10` accounts/batch), `mod.rs`
  - `src-tauri/src/storage/` — `vault_file.rs` (`VaultEnvelope`, `VaultPayload`, schema validator), `atomic.rs` (`default_vault_path`, temp+`fsync`+rename+`.bak`, `0600`/`0700` enforcement)
  - `src-tauri/src/vault/` — `mod.rs`, `types.rs` (public re-exports of `MasterKey` and `DerivedKek`)
  - `src-tauri/tests/` — Local Rust adversarial integration test suites (`adversarial_{account,empirical_challenge_m3,passwordless,pin,pin_bitflip,totp,vault}_challenge.rs`, `probe_keyring.rs`)
- **`.github/workflows/` (CI & Release Automation)**:
  - `.github/workflows/ci.yml` — Push (`main`, `master`) and PR checks on `ubuntu-24.04` (`npm ci`, `npx tsc --noEmit`, `npm run build`, `cargo test`, `cargo check --release`)
  - `.github/workflows/release.yml` — Tag push (`v*`) and `workflow_dispatch` Linux bundle builder (`.deb`, `.rpm`, `.AppImage`, standalone `authdesk` binary, `SHA256SUMS` attached to GitHub Release)

---

## 6. Roadmap Status (`M0`–`M8`)

- [x] **Milestone 0 — Native Shell & Platform Foundations**: Window management (`popup` / `normal`), tray menu, single-instance `--toggle` / `--hidden`, `Ctrl+Alt+A` shortcut.
- [x] **Milestone 1 — RFC 6238 TOTP Engine**: `SHA-1` / `SHA-256` / `SHA-512`, `6` / `8` digits, configurable time steps, Base32 validation/normalization, RFC test vectors.
- [x] **Milestone 2 — Authenticated Encrypted Vault**: Argon2id (`64 MiB`, `t=3`, `p=1`) + XChaCha20-Poly1305 AEAD, domain-separated AAD, atomic POSIX `0600`/`0700` storage, `.bak` fallback, master password lifecycle.
- [x] **Milestone 3 — OS-Keyring 6-Digit PIN & Passwordless Modes**: Linux Secret Service (`libsecret` / GNOME Keyring / KWallet), 256-bit `DeviceKey`, 5-attempt lockout, passwordless mode, inactivity auto-lock.
- [x] **Milestone 4 — Account Management & UI Polish**: Full CRUD, `otpauth://totp/` paste auto-fill, reordering, duplicate check, 3 themes (`Dark`, `Light`, `Coffee`), bilingual UI (`ES` / `EN`), bundled `.woff2` fonts, `lucide-react` icons.
- [x] **Milestone 5 — Google Authenticator Migration (Import & Export)**: `src-tauri/src/otp/migration.rs` (Google Auth protobuf v1, `otpauth://totp/`, `rqrr`+`image` QR decode, `qrcode` multi-batch SVG export <= `10`/batch), zero-secret-leak `AppState` preview/confirm/cancel staging, and re-authenticated export UI in `SettingsModal.tsx` with quick trigger in `AccountFormModal.tsx`.
- [x] **Milestone 6 — Desktop Integration & IPC Alignment**: System tray, `--hidden` autostart, global `Ctrl+Alt+A` shortcut, and synchronized 35-command IPC & DTO reference from `src-tauri/src/lib.rs` and `src-tauri/src/models.rs`.
- [x] **Milestone 7 — Hardening & CI/CD Release Packaging**: `WindowSettingsDto::default().hide_on_copy = true`, `env_logger` removed, dead Unix-socket legacy code/tests removed, OS global shortcut error propagation (`Result<(), String>`), and `.github/workflows/ci.yml` + `.github/workflows/release.yml`.
- [ ] **Milestone 8 — Windows Multiplatform & Extended Linux Packaging (Multiplataforma Windows y Empaquetado Linux Extendido)**:
  - Native Windows desktop support: WebView2 runtime, `.msi` / NSIS `.exe` installers, tray/autostart/global shortcut support, `%APPDATA%` vault path resolution, and `windows-latest` CI matrix.
  - Extended Linux packaging: Flatpak manifest (`org.authdesk.AuthDesk`), Snap (`snapcraft.yaml`), Arch Linux AUR (`PKGBUILD` / `authdesk-bin`), and Nix Flake (`flake.nix`).
