<div align="center">
  <img src="public/sinfondo.png" alt="AuthDesk Logo" width="96" height="96" />
  <h1>AuthDesk</h1>
  <p><strong>Offline Desktop TOTP Authenticator for Linux</strong></p>
  <p>
    <img src="https://img.shields.io/badge/version-0.2.0-FFC82C?style=flat-square&labelColor=2C2E33" alt="Version 0.2.0" />
    <img src="https://img.shields.io/badge/platform-Linux-FFC82C?style=flat-square&labelColor=2C2E33" alt="Platform Linux" />
    <img src="https://img.shields.io/badge/stack-Tauri_v2_%2B_Rust_%2B_React_%2B_TS-FFC82C?style=flat-square&labelColor=2C2E33" alt="Stack Tauri v2 + Rust + React + TS" />
    <img src="https://img.shields.io/badge/license-MIT-FFC82C?style=flat-square&labelColor=2C2E33" alt="License MIT" />
  </p>
</div>

---

**AuthDesk** is a command-palette style TOTP (RFC 6238) desktop authenticator built for Linux with **Tauri v2**, **Rust**, and **React + TypeScript**. It operates strictly offline via WebView CSP (`connect-src 'none'`) with zero networking crates in `Cargo.toml`, keeps cryptographic keys and Base32 secrets inside the Rust backend, and provides keyboard-driven access from the desktop.

## 1. Key Features

- **Offline & Zero-Network Architecture**: Enforced via WebView Content Security Policy (`connect-src 'none'`) and zero networking crates in `Cargo.toml`. TOTP secrets, Master Keys, and PIN keys are never returned from the Rust backend to the frontend over IPC and are wiped from memory on lock or drop via `zeroize`.
- **Authenticated Local Vault Encryption**: Vault encrypted at rest using **Argon2id** (`64 MiB` / `65536 KiB`, `3` iterations, `1` lane, 32-byte random salt) and **XChaCha20-Poly1305** (24-byte random nonce with domain-separated AAD), written atomically with POSIX `0600` (file) / `0700` (directory) permissions (`.tmp` + `fsync` + `.bak` rotation) and automatic `.bak` fallback if the primary vault envelope is unreadable or invalid.
- **Three Authentication Modes**:
  1. **Master Password**: Full Argon2id KDF protection (`init_vault` / `unlock_vault`), with support for adding, changing, or removing the master password in Settings.
  2. **OS-Keyring-Backed 6-Digit PIN**: Combines a 256-bit random `DeviceKey` stored in the Linux Secret Service (`libsecret` / GNOME Keyring / KDE Wallet) with Argon2id (`derive_pin_kek`) and an in-memory 5-attempt lockout (which deletes `pin-blob` when backed by a Master Password, or locks out PIN entry for the active session in Passwordless + PIN mode). *(Threat-model note: Secret Service access relies on your unlocked desktop login session rather than hardware/TPM isolation.)*
  3. **Passwordless Mode**: Convenience mode for single-user desktop sessions storing `passwordless-mk` in the OS Keyring with an internal key fallback. Vault locking is enabled only when a Master Password or 6-digit PIN is configured; in Passwordless + PIN mode, 5 failed PIN attempts lock out PIN entry for the active session without auto-unlocking the vault.
- **RFC 6238 TOTP Engine & Account Management**: Supports `SHA-1`, `SHA-256`, and `SHA-512`, `6` or `8` digits, configurable periods (`5s`–`300s` in `5s` steps via UI, default `30s`), single-line continuous tabular code display (`123456` / `12345678`), code masking toggle, live circular countdown rings, full account CRUD with `otpauth://totp/` URI paste auto-fill in the account modal and duplicate detection, and manual/keyboard reordering.
- **Google Authenticator Migration (Import & Export)**: Supports batch import from `otpauth-migration://offline?data=...` protobuf v1 payloads, newline-separated `otpauth://totp/` URIs, and PNG/JPEG/WebP QR image files (`rqrr` + `image`), backed by a secret-free staging preview (`AppState.staged_import`), duplicate filtering, and skipped-entry diagnostics. Supports multi-batch SVG QR export (`<= 10` accounts per batch via `qrcode`) gated by an explicit plaintext warning acknowledgment and Master Password or PIN re-authentication (when configured).
- **Dual Window Modes & Local Typography**:
  - **Popup Mode** (default, `skipTaskbar: true`, positioned on the active cursor monitor via `work_area()` on X11 or centered on Wayland) and **Normal Window Mode** (`skipTaskbar: false`, with an optional `resizable` toggle preserving logical sizes >= `420x560`). Both modes use `decorations: false` and `420x560` default geometry.
  - Bundled offline `.woff2` fonts (`Inter` for UI, `JetBrains Mono` for TOTP codes), `lucide-react` (`strokeWidth=1.75`) iconography, bilingual localization (`ES` default / `EN`), and three solid surface themes (`Dark`, `Light`, `Coffee`) inside a rounded window shell.
- **Timers, Desktop Integration & CI Packaging**: Configurable inactivity auto-lock (default `5m`; options `Never`, `1m`, `5m`, `15m`, `30m`), configurable conditional clipboard auto-clear (default `30s`; options `10s`, `30s`, `60s`, `Never`), `hide_on_copy` defaulting to `true`, single-instance `--toggle` / `--hidden` CLI flags, system tray integration (`Mostrar AuthDesk`, `Bloquear`, `Salir`), global `Ctrl+Alt+A` toggle with OS error propagation, and GitHub Actions CI + Linux release workflows (`.deb`, `.rpm`, `.AppImage`, standalone binary, and `SHA256SUMS`).

---

## 2. Roadmap

- [x] **Milestone 0 — Native Shell & Platform Foundations**: Window management (`popup` and `normal` modes), system tray menu, single-instance `--toggle` / `--hidden` handling, and `Ctrl+Alt+A` shortcut hook.
- [x] **Milestone 1 — RFC 6238 TOTP Engine**: `SHA-1` / `SHA-256` / `SHA-512`, `6` / `8` digits, configurable time steps, Base32 validation/normalization, RFC test vectors, and live circular countdown rings.
- [x] **Milestone 2 — Authenticated Encrypted Vault**: Argon2id KDF (`p=1`) + XChaCha20-Poly1305 AEAD, domain-separated AAD, atomic POSIX `0600`/`0700` persistence, `.bak` fallback on envelope corruption, and master password lifecycle.
- [x] **Milestone 3 — OS-Keyring 6-Digit PIN & Passwordless Modes**: Linux Secret Service (`libsecret` / GNOME Keyring / KWallet) integration with 256-bit `DeviceKey`, 5-attempt lockout, passwordless mode, and inactivity auto-lock.
- [x] **Milestone 4 — Account Management & UI Polish**: Full CRUD, `otpauth://totp/` URI paste auto-fill in the account modal, account reordering, duplicate detection, draggable undecorated shell, three themes (`Dark`, `Light`, `Coffee`), bilingual UI (`ES` / `EN`), bundled local `.woff2` fonts, and `lucide-react` iconography.
- [x] **Milestone 5 — Google Authenticator Migration (Import & Export)**: `src-tauri/src/otp/migration.rs` (Google Authenticator protobuf v1 wire codec, `otpauth://totp/` parser, `rqrr` + `image` PNG/JPEG/WebP QR decoding, `qrcode` multi-batch SVG export <= 10 accounts/batch), zero-secret-leak `AppState` preview/confirm/cancel staging, and re-authenticated export / import UI in `SettingsModal.tsx` with a quick trigger in `AccountFormModal.tsx`.
- [x] **Milestone 6 — Desktop Integration & IPC Alignment**: System tray (`Mostrar AuthDesk`, `Bloquear`, `Salir`), `--hidden` autostart, `Ctrl+Alt+A` global shortcut, and synchronized 35-command Tauri IPC & DTO contract across `lib.rs`, `models.rs`, and the frontend (see [PROJECT.md](PROJECT.md)).
- [x] **Milestone 7 — Hardening & CI/CD Release Packaging**: `WindowSettingsDto::default().hide_on_copy = true`, `env_logger` removed, dead legacy Unix-socket single-instance code/tests removed, global shortcut error propagation (`Result<(), String>`), and `.github/workflows/ci.yml` + `.github/workflows/release.yml` for automated `.deb`, `.rpm`, `.AppImage`, standalone binary, and `SHA256SUMS` releases.
- [ ] **Milestone 8 — Windows Multiplatform & Extended Linux Packaging (Multiplataforma Windows y Empaquetado Linux Extendido)**:
  - Native Windows desktop support: WebView2 runtime integration, `.msi` / NSIS `.exe` installers, tray/autostart/global shortcut support, `%APPDATA%` vault path resolution, and a `windows-latest` CI build matrix.
  - Extended Linux packaging: Flatpak manifest (`org.authdesk.AuthDesk`), Snap (`snapcraft.yaml`), Arch Linux AUR (`PKGBUILD` / `authdesk-bin`), and Nix Flake (`flake.nix`).

---

## 3. System Dependencies by Linux Distribution

Before building AuthDesk from source, install the required **WebKit2GTK 4.1**, **GTK 3 / System Tray**, **libsecret**, **Node.js**, and **Rust** packages for your distribution:

### Arch Linux / Manjaro / EndeavourOS (`pacman`)

```bash
sudo pacman -Syu --needed \
  webkit2gtk-4.1 \
  base-devel \
  curl \
  wget \
  file \
  openssl \
  appmenu-gtk-module \
  libappindicator-gtk3 \
  librsvg \
  libsecret \
  nodejs \
  npm \
  rust
```

### Ubuntu / Debian / Linux Mint / Pop!_OS (`apt`)

```bash
sudo apt update && sudo apt install -y \
  libwebkit2gtk-4.1-dev \
  build-essential \
  curl \
  wget \
  file \
  libxdo-dev \
  libssl-dev \
  libayatana-appindicator3-dev \
  librsvg2-dev \
  libdbus-1-dev \
  libsecret-1-dev \
  patchelf \
  pkg-config \
  nodejs \
  npm \
  rustc \
  cargo
```

> When building `.rpm` or `.AppImage` release bundles on Ubuntu/Debian (matching `.github/workflows/release.yml`), also install `rpm`, `xdg-utils`, and `libfuse2t64` (or `libfuse2` on older releases).

### Fedora / RHEL / Ultramarine (`dnf`)

```bash
sudo dnf install -y \
  webkit2gtk4.1-devel \
  openssl-devel \
  curl \
  wget \
  file \
  libappindicator-gtk3-devel \
  librsvg2-devel \
  libsecret-devel \
  nodejs \
  npm \
  cargo \
  rust \
  @development-tools
```

### openSUSE Tumbleweed / Leap (`zypper`)

```bash
sudo zypper install -y \
  webkit2gtk3-devel \
  libopenssl-devel \
  curl \
  wget \
  file \
  libappindicator3-1 \
  librsvg-devel \
  libsecret-devel \
  nodejs20 \
  npm20 \
  cargo \
  rust
```

> **Note on Rust toolchain**: If your distribution ships an older Rust version (< `1.77`) or lacks current `rustc`/`cargo` packages, install the latest stable toolchain via [rustup](https://rustup.rs/):
> ```bash
> curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
> ```

---

## 4. Build, Run & Verification

```bash
# 1. Clone the repository
git clone https://github.com/r-pt/AuthDesk.git
cd AuthDesk

# 2. Install exact frontend dependencies
npm ci

# 3. Run in development mode
npm run tauri dev
```

### Build Release Binary & Native Packages (`.deb`, `.rpm`, `AppImage`)

- **Standalone Binary Only (recommended for Arch Linux / manual install)**:
  ```bash
  npm run tauri build -- --no-bundle
  ```
- **All Linux Bundles (`.deb`, `.rpm`, `AppImage` + binary)**:
  ```bash
  # In containerized or FUSE-less environments, export APPIMAGE_EXTRACT_AND_RUN=1
  npm run tauri build
  ```

Generated artifacts are written to `src-tauri/target/release/` and `src-tauri/target/release/bundle/`:
- **Debian / Ubuntu**: `src-tauri/target/release/bundle/deb/AuthDesk_0.2.0_amd64.deb`
- **Fedora / openSUSE**: `src-tauri/target/release/bundle/rpm/AuthDesk-0.2.0-1.x86_64.rpm`
- **Universal Linux**: `src-tauri/target/release/bundle/appimage/AuthDesk_0.2.0_amd64.AppImage`
- **Standalone Binary**: `src-tauri/target/release/authdesk`

GitHub Actions (`.github/workflows/release.yml`) publishes all four artifacts alongside `SHA256SUMS` on `v*` tag pushes and manual `workflow_dispatch` triggers (`sha256sum -c SHA256SUMS`).

### Installing the Built Package

> Build first with `npm run tauri build -- --no-bundle` (standalone binary) or `npm run tauri build` (`.deb` / `.rpm` / `.AppImage`).

- **Debian / Ubuntu**:
  ```bash
  sudo apt install ./src-tauri/target/release/bundle/deb/AuthDesk_*.deb
  ```
- **Fedora / openSUSE**:
  ```bash
  sudo dnf install ./src-tauri/target/release/bundle/rpm/AuthDesk-*.rpm
  ```
- **AppImage (Any Linux Distro)**:
  ```bash
  chmod +x ./src-tauri/target/release/bundle/appimage/AuthDesk_*.AppImage
  ./src-tauri/target/release/bundle/appimage/AuthDesk_*.AppImage
  ```
- **Arch Linux / Standalone Binary**:
  ```bash
  npm run tauri build -- --no-bundle
  sudo install -Dm755 src-tauri/target/release/authdesk /usr/local/bin/authdesk
  ```

### Verification & Tests

```bash
# Frontend TypeScript check + Vite production bundle
npx tsc --noEmit
npm run build

# Backend Rust unit + integration test suites and release check
cargo test --manifest-path src-tauri/Cargo.toml
cargo check --release --manifest-path src-tauri/Cargo.toml
```

---

## 5. Keyboard Shortcuts & Wayland / X11 Setup

| Shortcut / Command | Action |
| :--- | :--- |
| `Ctrl+Alt+A` | Global toggle (show / hide AuthDesk window; can be enabled or disabled in Settings, with OS registration errors surfaced) |
| `Ctrl+N` | Open Add Account modal |
| `Ctrl+L` | Lock vault (when lockable via Master Password or PIN) |
| `↑` / `↓` | Navigate accounts in the list |
| `Alt+↑` / `Alt+↓` | Reorder selected account up or down (when search filter is empty) |
| `Enter` | Copy selected TOTP code to clipboard (auto-clears after 30s by default; hides window when `Hide on copy` is enabled) |
| `Escape` | Close Settings/Add/Edit/Delete modals (clearing staged imports and exported QR batches), or hide the palette window |

> **Wayland Global Shortcut Tip (GNOME / KDE / Hyprland / Sway)**: Wayland compositors restrict background applications from grabbing global hotkeys directly. Because AuthDesk enforces a single instance and exposes `--toggle`, bind `Ctrl+Alt+A` natively in your compositor or desktop settings to `authdesk --toggle` (for example in Hyprland `hyprland.conf`: `bind = CTRL ALT, A, exec, authdesk --toggle`).

---

## 6. Storage & Security Layout

- **Vault Path**: `$XDG_DATA_HOME/authdesk/vault.enc` or `~/.local/share/authdesk/vault.enc` (`0600` file permissions, `0700` directory permissions).
- **Backup Path**: `~/.local/share/authdesk/vault.enc.bak` (`0600` file permissions, rotated before every atomic write).
- **OS Keyring Service**: `authdesk` (entries: `device-key`, `pin-blob`, `passwordless-mk`).

See [PROJECT.md](PROJECT.md) for the complete technical architecture, envelope schema, IPC contracts, and security boundaries.

---

## 7. License

Licensed under the [MIT License](LICENSE).
