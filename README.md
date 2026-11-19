# Voltes IIV

A 100% local, offline-first macOS password manager built with Python, native Cocoa (`AppKit` / `LocalAuthentication`), and `pywebview`. Zero cloud servers, zero telemetry, and hardware-backed Touch ID support.

## Security Architecture
- **Key Derivation:** Argon2id (`memory_cost=65536`, `iterations=3`, `lanes=4`)
- **Encryption:** AES-256-GCM authenticated encryption with fresh random 16-byte salt and 12-byte nonce on every save
- **Storage:** Single local encrypted file (`~/.local_vault/vault.enc`) with `0600` owner-only permissions
- **Biometrics:** Optional Touch ID / Apple Watch / macOS login authentication via `LocalAuthentication` + macOS Keychain

## Features
- Native Apple-inspired dark UI with password health indicators & custom password generator
- Built-in rotating 6-digit 2FA (TOTP) authenticator codes
- Menu Bar mini-vault (`🔒 IIV`) + global `⌘⇧L` Quick-Fill Spotlight overlay
- System-wide Auto-Type (`Username → Tab → Password`)
- Configurable inactivity auto-lock, automatic clipboard wiping, and encrypted `.enc` backups

## Run from Source (macOS)
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    python vault_app.py
