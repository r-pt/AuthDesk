<div align="center">
  <img src="public/logo.svg" alt="AuthDesk Logo" width="96" height="96" />
  <h1>AuthDesk</h1>
  <p><strong>Fast, Zero-Network Desktop TOTP Authenticator for Linux</strong></p>
  <p>
    <img src="https://img.shields.io/badge/version-0.1.0-FFC82C?style=flat-square&labelColor=2C2E33" alt="Version 0.1.0" />
    <img src="https://img.shields.io/badge/platform-Linux-FFC82C?style=flat-square&labelColor=2C2E33" alt="Platform Linux" />
    <img src="https://img.shields.io/badge/stack-Tauri_v2_%2B_Rust_%2B_React-FFC82C?style=flat-square&labelColor=2C2E33" alt="Stack" />
    <img src="https://img.shields.io/badge/license-MIT-FFC82C?style=flat-square&labelColor=2C2E33" alt="License MIT" />
  </p>
</div>

---

**AuthDesk** is a lightweight, command-palette style TOTP (RFC 6238 / RFC 4226) desktop authenticator built specifically for Linux with **Tauri v2**, **Rust**, and **React**. It operates strictly offline (`connect-src 'none'`), keeps all cryptographic material inside the Rust backend, and provides instant keyboard-driven access from anywhere on your desktop.

## Key Features

- **Zero-Network & Zero-Frontend-Secret Architecture**: Base32 secrets, master keys, and PIN keys never leave the Rust process and are wiped from memory on lock/drop via `zeroize`.
- **Authenticated Local Encryption**: Vault encrypted at rest using **Argon2id** (`64 MiB`, `3` iterations, `4` lanes) + **XChaCha20-Poly1305** with domain-separated AAD and atomic POSIX `0600`/`0700` file persistence (`.tmp` + `fsync` + `.bak` rotation).
- **Quick 6-Digit PIN Unlock**: Optional hardware/OS-bound quick unlock backed by the Linux **Secret Service** (`libsecret` / GNOME Keyring / KDE Wallet) using a 256-bit `DeviceKey` combined with Argon2id and automatic 5-attempt lockout protection.
- **RFC 6238 Compliant TOTP Engine**: Supports `SHA-1`, `SHA-256`, and `SHA-512`, `6` or `8` digits, and custom periods (`15s`, `30s`, `60s`) with live countdown rings.
- **Account Management**: Full CRUD (Add, Edit, Delete with secret zeroization, Reorder) plus live `otpauth://totp/...` URI paste parsing and duplicate detection.
- **Floating Movable Window**: Unlocked window dragging via native drag regions—not anchored to screen center.
- **Command-Palette Workflow**: Configurable global shortcut (`Ctrl+Alt+A`), CLI toggle (`authdesk --toggle`), system tray integration, instant search, keyboard navigation, and auto-clearing clipboard (`30s`).
- **Refined Solid UI**: 100% solid, non-transparent surfaces with modern typography (`Adwaita Sans` / `Inter`), crisp SVG iconography, and built-in `Dark`, `Light`, and `Coffee` themes.

---

## Roadmap & Milestones

- [x] **Milestone 0 — Native Shell & Platform Foundations**: Window toggle, system tray, single instance socket IPC, and `Ctrl+Alt+A` / `--toggle` hook.
- [x] **Milestone 1 — RFC 6238 TOTP Engine**: SHA-1 / SHA-256 / SHA-512, 6/8 digits, 15s/30s/60s time steps, RFC test vectors, and live countdown rings.
- [x] **Milestone 2 — Authenticated Encrypted Vault**: Argon2id KDF + XChaCha20-Poly1305 AEAD, domain-separated AAD, atomic POSIX `0600`/`0700` storage, `.bak` disaster recovery, and master password unlock.
- [x] **Milestone 3 — Hardware-Bound 6-Digit PIN**: Linux Secret Service (`libsecret` / GNOME Keyring / KWallet) integration with 256-bit `DeviceKey`, 5-attempt lockout security, and auto-lock on inactivity.
- [x] **Milestone 4 — Account Management & Brand Polish**: Full CRUD, account reordering, duplicate detection, live `otpauth://` parser, Recraft brand identity, movable window, solid UI, and optional global shortcut.
- [ ] **Milestone 5 — Google Authenticator Import**: Batch protobuf migration decoding (`otpauth-migration://` and `otpauth://`), camera/QR file scanner, and preview import modal.
- [ ] **Milestone 6 — Google Authenticator Export**: Batch protobuf migration encoding, high-density QR code rendering, and secure plaintext export warnings.
- [ ] **Milestone 7 — Hardening & Release Packaging**: Automated `.deb`, `.rpm`, and standalone Linux binary distribution.

---

## 1. System Dependencies by Linux Distribution

Before building or running AuthDesk from source, install the required **Tauri v2**, **WebKit2GTK 4.1**, **System Tray**, and **Libsecret (Keyring)** native packages for your distribution:

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
  libsecret-1-dev \
  nodejs \
  npm
```

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

> **Note on Rust toolchain**: If your distribution ships an older Rust version (< `1.77`), install the latest stable toolchain via [rustup](https://rustup.rs/):
> ```bash
> curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
> ```

---

## 2. Build & Run from Source

```bash
# 1. Clone the repository
git clone https://github.com/r-pt/AuthDeck.git
cd AuthDeck

# 2. Install exact frontend dependencies
npm ci

# 3. Run in development mode
npm run tauri dev
```

### Build Native Release Packages (`.deb`, `.rpm`, `AppImage`)

```bash
npm run tauri build
```

Generated artifacts will be located in `src-tauri/target/release/bundle/`:
- **Debian / Ubuntu**: `src-tauri/target/release/bundle/deb/authdesk_0.1.0_amd64.deb`
- **Fedora / openSUSE**: `src-tauri/target/release/bundle/rpm/authdesk-0.1.0-1.x86_64.rpm`
- **Universal Linux**: `src-tauri/target/release/bundle/appimage/authdesk_0.1.0_amd64.AppImage`
- **Standalone Binary**: `src-tauri/target/release/authdesk`

### Installing the Built Package

- **Debian / Ubuntu**:
  ```bash
  sudo apt install ./src-tauri/target/release/bundle/deb/authdesk_*.deb
  ```
- **Fedora**:
  ```bash
  sudo dnf install ./src-tauri/target/release/bundle/rpm/authdesk-*.rpm
  ```
- **Arch Linux (Direct Binary)**:
  ```bash
  sudo install -Dm755 src-tauri/target/release/authdesk /usr/local/bin/authdesk
  ```

---

## 3. Keyboard Shortcuts & Wayland / X11 Setup

| Shortcut / Command | Action |
| :--- | :--- |
| `Ctrl+Alt+A` | Global toggle (show / hide AuthDesk window) |
| `↑` / `↓` | Navigate accounts in the list |
| `Enter` | Copy selected TOTP code to clipboard (auto-clears after 30s) |
| `Ctrl+N` | Open **New Account** modal |
| `Ctrl+L` | Immediately lock vault and wipe keys from memory |
| `Escape` | Close active modal / clear search / hide window |

### Wayland Global Shortcut Tip (GNOME / KDE / Hyprland / Sway)
Some Wayland compositors restrict X11 global hotkeys for background windows. Because AuthDesk enforces a single instance and exposes a `--toggle` flag, you can bind `Ctrl+Alt+A` natively in your desktop environment or window manager to:

```bash
authdesk --toggle
```

*(Example in Hyprland `hyprland.conf`: `bind = CTRL ALT, A, exec, authdesk --toggle`)*

---

## 4. Storage & Security Layout

- **Vault Path**: `~/.local/share/com.rod.authdesk/vault.enc` (`0600` file permissions, `0700` directory permissions).
- **Backup Path**: `~/.local/share/com.rod.authdesk/vault.enc.bak` (automatically rotated before every atomic write).
- **OS Keyring Service**: `com.rod.authdesk` (entries: `device_key_v1`, `pin_wrapped_mk_v1`).

## License

Licensed under the [MIT License](LICENSE).
