import os
import sys
import csv
import math
import time
import hmac
import base64
import struct
import hashlib
import shutil
import json
import secrets
import string
import subprocess
import threading
import webbrowser
from collections import Counter
from datetime import datetime
from pathlib import Path

import webview
from pynput import keyboard
from Foundation import NSBundle, NSObject
from AppKit import (
    NSApplication, NSImage, NSPasteboard, NSPasteboardTypeString,
    NSStatusBar, NSVariableStatusItemLength, NSMenu, NSMenuItem
)
from ApplicationServices import AXIsProcessTrusted
from LocalAuthentication import LAContext, LAPolicyDeviceOwnerAuthentication
from PyObjCTools import AppHelper
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NSBundle.mainBundle().infoDictionary()["CFBundleName"] = "Voltes IIV"

DEFAULT_VAULT_DIR = Path.home() / ".local_vault"
SETTINGS_FILE = DEFAULT_VAULT_DIR / "settings.json"
ICON_PATH = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)) / "icon.png"
APP_BUNDLE = Path("/Applications/Voltes IIV.app")
LAUNCH_AGENT = Path.home() / "Library/LaunchAgents/com.local.voltes-iiv.plist"
KEYCHAIN_SERVICE = "com.local.voltes-iiv.master"
KEYCHAIN_ACCOUNT = os.environ.get("USER", "voltes_user")

SALT_SIZE = 16
NONCE_SIZE = 12

DEFAULT_SETTINGS = {
    "auto_lock_seconds": 180,
    "auto_submit": False,
    "clear_clipboard_seconds": 20,
    "touch_id_enabled": False,
    "vault_dir": str(DEFAULT_VAULT_DIR),
}

WORDLIST = [
    "anchor", "anthem", "apricot", "arcade", "arctic", "arrow", "atlas", "aurora",
    "autumn", "avenue", "bamboo", "banjo", "beacon", "beetle", "bison", "blazer",
    "blossom", "boulder", "breeze", "bridge", "bronze", "brook", "cactus", "camera",
    "canopy", "canyon", "capsule", "caravan", "cascade", "castle", "cedar", "chalice",
    "chariot", "cheetah", "cipher", "citadel", "cobalt", "comet", "compass", "condor",
    "coral", "cosmos", "coyote", "crater", "crimson", "crystal", "cypress", "dagger",
    "delta", "desert", "diamond", "dolphin", "dragon", "drizzle", "dynamo", "eclipse",
    "emerald", "empire", "encore", "engine", "equinox", "falcon", "feather", "festival",
    "firefly", "flannel", "forest", "fortress", "fossil", "fountain", "frontier", "galaxy",
    "garnet", "gazelle", "geyser", "glacier", "granite", "gravity", "griffin", "harbor",
    "harvest", "hawk", "hazel", "helmet", "horizon", "hunter", "hybrid", "iceberg",
    "ignite", "impulse", "indigo", "island", "ivory", "jacket", "jaguar", "jasper",
    "javelin", "journey", "jungle", "jupiter", "kestrel", "kingdom", "kraken", "lagoon",
    "lantern", "legacy", "legend", "leopard", "liberty", "lightning", "lotus", "lunar",
    "magnet", "mammoth", "marble", "mariner", "meadow", "mercury", "meteor", "mirage",
    "monarch", "monsoon", "mountain", "mustang", "nebula", "nectar", "neptune", "nomad",
    "nova", "oasis", "obsidian", "ocean", "octave", "odyssey", "olive", "omega",
    "onyx", "oracle", "orbit", "orchid", "orion", "osprey", "outpost", "pacific",
    "paladin", "panther", "paradox", "pegasus", "pelican", "pendulum", "penguin", "phantom",
    "phoenix", "pioneer", "planet", "plasma", "platinum", "prism", "pulsar", "pyramid",
    "quantum", "quartz", "quasar", "quest", "quiver", "radar", "rainbow", "ranger",
    "raptor", "raven", "reactor", "redwood", "relic", "ripple", "river", "rocket",
    "saffron", "samurai", "sapphire", "saturn", "scarlet", "scepter", "scorpion", "scout",
    "sentinel", "sequoia", "shadow", "sherpa", "shogun", "sierra", "silver", "solstice",
    "sonar", "sparrow", "spectrum", "sphinx", "spiral", "spruce", "starlight", "stealth",
    "stellar", "storm", "stratos", "summit", "sunrise", "supernova", "swallow", "sycamore",
    "tempest", "terrain", "thistle", "thunder", "tiger", "timber", "titan", "topaz",
    "tornado", "torrent", "trident", "trilogy", "tundra", "turbine", "twilight", "typhoon",
    "unicorn", "universe", "valkyrie", "valley", "vanguard", "velocity", "velvet", "venture",
    "vertex", "viking", "viper", "volcano", "voltes", "vortex", "voyager", "walrus",
    "warden", "warrior", "waterfall", "whisper", "wildcat", "willow", "winter", "wizard",
    "wolverine", "wonder", "zenith", "zephyr", "zodiac"
]


def load_settings() -> dict:
    if SETTINGS_FILE.exists():
        try:
            data = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            merged = DEFAULT_SETTINGS.copy()
            merged.update(data)
            return merged
        except Exception:
            pass
    return DEFAULT_SETTINGS.copy()


def save_settings(settings: dict):
    DEFAULT_VAULT_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(DEFAULT_VAULT_DIR, 0o700)
    tmp = SETTINGS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, SETTINGS_FILE)


def get_active_vault_paths():
    settings = load_settings()
    vdir = Path(settings.get("vault_dir") or DEFAULT_VAULT_DIR).expanduser()
    return vdir, vdir / "vault.enc"


def keychain_store_master(password: str) -> bool:
    res = subprocess.run(
        ["security", "add-generic-password", "-U", "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w", password],
        capture_output=True
    )
    return res.returncode == 0


def keychain_get_master():
    res = subprocess.run(
        ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w"],
        capture_output=True, text=True
    )
    if res.returncode == 0:
        return res.stdout.strip()
    return None


def keychain_delete_master():
    subprocess.run(
        ["security", "delete-generic-password", "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT],
        capture_output=True
    )


def is_launch_at_login_enabled() -> bool:
    return LAUNCH_AGENT.exists()


def set_launch_at_login(enabled: bool) -> bool:
    if enabled:
        LAUNCH_AGENT.parent.mkdir(parents=True, exist_ok=True)
        target_app = APP_BUNDLE if APP_BUNDLE.exists() else (Path.home() / "Applications/Voltes IIV.app")
        plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.local.voltes-iiv</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/open</string>
        <string>-a</string>
        <string>{target_app}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"""
        LAUNCH_AGENT.write_text(plist, encoding="utf-8")
        return True
    else:
        if LAUNCH_AGENT.exists():
            LAUNCH_AGENT.unlink()
        return False


def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536)
    return kdf.derive(master_password.encode("utf-8"))


def save_encrypted_vault(data: list, master_password: str):
    vdir, vfile = get_active_vault_paths()
    vdir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(vdir, 0o700)
    except Exception:
        pass
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(master_password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps(data).encode("utf-8"), None)
    # Atomic write prevents partial/corrupted files during iCloud Drive or USB sync
    tmp_file = vfile.with_suffix(".enc.tmp")
    with open(tmp_file, "wb") as f:
        f.write(salt + nonce + ciphertext)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp_file, 0o600)
    os.replace(tmp_file, vfile)


def load_encrypted_vault(master_password: str) -> list:
    _, vfile = get_active_vault_paths()
    with open(vfile, "rb") as f:
        raw = f.read()
    salt = raw[:SALT_SIZE]
    nonce = raw[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = raw[SALT_SIZE + NONCE_SIZE:]
    key = derive_key(master_password, salt)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))


def evaluate_password_weakness(pw: str) -> bool:
    if len(pw) < 12:
        return True
    score = 0
    if any(c.islower() for c in pw) and any(c.isupper() for c in pw):
        score += 1
    if any(c.isdigit() for c in pw):
        score += 1
    if any(not c.isalnum() for c in pw):
        score += 1
    return score < 2


class VaultAPI:
    def __init__(self):
        self.master_password = None
        self.entries = []
        self.settings = load_settings()
        self.window = None
        self.kb = keyboard.Controller()

    def set_window(self, window):
        self.window = window

    def vault_exists(self):
        _, vfile = get_active_vault_paths()
        return vfile.exists()

    def can_use_touch_id(self):
        ctx = LAContext.alloc().init()
        can_eval, _ = ctx.canEvaluatePolicy_error_(LAPolicyDeviceOwnerAuthentication, None)
        has_key = keychain_get_master() is not None
        return bool(can_eval and self.settings.get("touch_id_enabled") and has_key)

    def unlock_with_touch_id(self):
        if not self.can_use_touch_id():
            return {"ok": False, "error": "Biometric unlock not enabled."}

        done = threading.Event()
        auth_result = {"success": False}
        ctx = LAContext.alloc().init()

        def reply_handler(success, error):
            auth_result["success"] = bool(success)
            done.set()

        ctx.evaluatePolicy_localizedReason_reply_(
            LAPolicyDeviceOwnerAuthentication,
            "Unlock Voltes IIV Vault",
            reply_handler
        )
        done.wait(timeout=45)

        if not auth_result["success"]:
            return {"ok": False, "error": "Authentication cancelled or failed."}

        stored_pw = keychain_get_master()
        if not stored_pw:
            return {"ok": False, "error": "Keychain credential missing. Enter Master Password once."}

        return self.unlock_vault(stored_pw)

    def toggle_touch_id(self, enabled: bool):
        if enabled:
            if not self.master_password:
                return {"ok": False, "error": "Unlock vault first."}
            if not keychain_store_master(self.master_password):
                return {"ok": False, "error": "Could not save credential to macOS Keychain."}
            self.settings["touch_id_enabled"] = True
            save_settings(self.settings)
            return {"ok": True, "enabled": True}
        else:
            keychain_delete_master()
            self.settings["touch_id_enabled"] = False
            save_settings(self.settings)
            return {"ok": True, "enabled": False}

    def toggle_launch_at_login(self, enabled: bool):
        state = set_launch_at_login(bool(enabled))
        return {"ok": True, "enabled": state}

    def get_settings(self):
        self.settings = load_settings()
        _, vfile = get_active_vault_paths()
        ctx = LAContext.alloc().init()
        hw_supported, _ = ctx.canEvaluatePolicy_error_(LAPolicyDeviceOwnerAuthentication, None)
        return {
            "settings": self.settings,
            "accessibility_granted": bool(AXIsProcessTrusted()),
            "biometrics_supported": bool(hw_supported),
            "launch_at_login": is_launch_at_login_enabled(),
            "python_binary": os.path.realpath(os.sys.executable),
            "vault_path": str(vfile),
            "vault_dir": str(vfile.parent),
        }

    def update_settings(self, new_settings: dict):
        self.settings.update(new_settings)
        save_settings(self.settings)
        return {"ok": True, "settings": self.settings}

    def choose_sync_folder(self):
        if self.master_password is None or self.window is None:
            return {"ok": False, "error": "Unlock vault first."}
        result = self.window.create_file_dialog(webview.FOLDER_DIALOG)
        if not result:
            return {"ok": False}
        chosen_dir = Path(result[0] if isinstance(result, (list, tuple)) else result).expanduser()
        target_file = chosen_dir / "vault.enc"

        # If target folder already has an existing vault.enc (e.g. from another Mac via iCloud Drive), load it
        if target_file.exists():
            try:
                old_dir = self.settings.get("vault_dir", str(DEFAULT_VAULT_DIR))
                self.settings["vault_dir"] = str(chosen_dir)
                save_settings(self.settings)
                loaded = load_encrypted_vault(self.master_password)
                self.entries = loaded
                return {
                    "ok": True,
                    "entries": self.entries,
                    "vault_path": str(target_file),
                    "vault_dir": str(chosen_dir),
                    "message": "Connected to existing encrypted vault in sync folder"
                }
            except Exception:
                self.settings["vault_dir"] = old_dir
                save_settings(self.settings)
                return {
                    "ok": False,
                    "error": "Existing vault.enc in that folder uses a different Master Password."
                }

        # Otherwise save current vault into the new sync folder
        self.settings["vault_dir"] = str(chosen_dir)
        save_settings(self.settings)
        save_encrypted_vault(self.entries, self.master_password)
        return {
            "ok": True,
            "entries": self.entries,
            "vault_path": str(target_file),
            "vault_dir": str(chosen_dir),
            "message": "Vault synced to new folder"
        }

    def reset_sync_folder(self):
        if self.master_password is None:
            return {"ok": False}
        self.settings["vault_dir"] = str(DEFAULT_VAULT_DIR)
        save_settings(self.settings)
        save_encrypted_vault(self.entries, self.master_password)
        _, vfile = get_active_vault_paths()
        return {
            "ok": True,
            "vault_path": str(vfile),
            "vault_dir": str(DEFAULT_VAULT_DIR),
            "message": "Reset to default local folder (~/.local_vault)"
        }

    def import_csv_file(self):
        if self.master_password is None or self.window is None:
            return {"ok": False, "error": "Unlock vault first."}
        result = self.window.create_file_dialog(
            webview.OPEN_DIALOG,
            allow_multiple=False,
            file_types=("CSV Files (*.csv)", "All files (*.*)")
        )
        if not result:
            return {"ok": False}
        csv_path = Path(result[0] if isinstance(result, (list, tuple)) else result)
        try:
            content = csv_path.read_text(encoding="utf-8-sig")
            reader = csv.DictReader(content.splitlines())
            if not reader.fieldnames:
                return {"ok": False, "error": "CSV file is empty or missing headers."}

            existing_sigs = {
                (e.get("title", "").lower(), e.get("username", "").lower(), e.get("password", ""))
                for e in self.entries
            }

            imported = 0
            skipped = 0
            for raw_row in reader:
                row = {(k or "").strip().lower(): (v or "").strip() for k, v in raw_row.items()}
                title = (
                    row.get("title")
                    or row.get("name")
                    or row.get("website")
                    or row.get("url")
                    or row.get("login_uri")
                    or ""
                )
                username = (
                    row.get("username")
                    or row.get("login_username")
                    or row.get("email")
                    or row.get("user")
                    or ""
                )
                password = (
                    row.get("password")
                    or row.get("login_password")
                    or row.get("pass")
                    or ""
                )
                url = (
                    row.get("url")
                    or row.get("website")
                    or row.get("login_uri")
                    or row.get("origin_url")
                    or ""
                )
                totp = (
                    row.get("otpauth")
                    or row.get("totp")
                    or row.get("login_totp")
                    or row.get("2fa")
                    or ""
                )
                notes = row.get("notes") or row.get("note") or row.get("extra") or ""

                if not password:
                    skipped += 1
                    continue
                if not title:
                    title = url or username or "Imported Login"

                sig = (title.lower(), username.lower(), password)
                if sig in existing_sigs:
                    skipped += 1
                    continue

                self.entries.append({
                    "title": title,
                    "username": username,
                    "password": password,
                    "url": url,
                    "totp": totp,
                    "notes": notes,
                    "favorite": False,
                    "history": [],
                })
                existing_sigs.add(sig)
                imported += 1

            if imported > 0:
                save_encrypted_vault(self.entries, self.master_password)
            return {
                "ok": True,
                "entries": self.entries,
                "imported": imported,
                "skipped": skipped,
            }
        except Exception as ex:
            return {"ok": False, "error": f"Import failed: {ex}"}

    def get_watchtower_report(self):
        pw_counts = Counter(e.get("password", "") for e in self.entries if e.get("password"))
        reused_indices = []
        weak_indices = []
        no_2fa_indices = []

        for idx, item in enumerate(self.entries):
            pw = item.get("password", "")
            if pw and pw_counts[pw] > 1:
                reused_indices.append(idx)
            if evaluate_password_weakness(pw):
                weak_indices.append(idx)
            if not (item.get("totp") or "").strip():
                no_2fa_indices.append(idx)

        total = len(self.entries)
        unique_compromised = len(set(reused_indices) | set(weak_indices))
        score = 100 if total == 0 else max(0, round(((total - unique_compromised) / total) * 100))

        return {
            "total": total,
            "score": score,
            "reused": reused_indices,
            "weak": weak_indices,
            "no_2fa": no_2fa_indices,
        }

    def open_accessibility_settings(self):
        subprocess.run(["open", "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"])
        return True

    def reveal_python_in_finder(self):
        real_bin = os.path.realpath(os.sys.executable)
        subprocess.run(["open", "-R", real_bin])
        return True

    def create_vault(self, password: str):
        if len(password) < 8:
            return {"ok": False, "error": "Use at least 8 characters for your Master Password."}
        self.master_password = password
        self.entries = []
        save_encrypted_vault(self.entries, self.master_password)
        return {"ok": True, "entries": self.entries, "settings": self.settings}

    def unlock_vault(self, password: str):
        try:
            self.entries = load_encrypted_vault(password)
            self.master_password = password
            self.settings = load_settings()
            if self.settings.get("touch_id_enabled"):
                keychain_store_master(password)
            return {"ok": True, "entries": self.entries, "settings": self.settings}
        except Exception:
            return {"ok": False, "error": "Incorrect Master Password."}

    def change_master_password(self, current_pw: str, new_pw: str):
        if self.master_password is None or current_pw != self.master_password:
            return {"ok": False, "error": "Current Master Password is incorrect."}
        if len(new_pw) < 8:
            return {"ok": False, "error": "New Master Password must be at least 8 characters."}
        self.master_password = new_pw
        save_encrypted_vault(self.entries, self.master_password)
        if self.settings.get("touch_id_enabled"):
            keychain_store_master(new_pw)
        return {"ok": True}

    def lock_vault(self):
        self.master_password = None
        self.entries = []
        return {"ok": True}

    def save_entry(self, index, record):
        if self.master_password is None:
            return {"ok": False, "error": "Vault locked"}
        if index is not None and 0 <= index < len(self.entries):
            existing = self.entries[index]
            history = list(existing.get("history", []))
            old_pw = existing.get("password", "")
            new_pw = record.get("password", "")
            # Record previous password in history whenever password changes
            if old_pw and new_pw and old_pw != new_pw:
                history.insert(0, {
                    "password": old_pw,
                    "changed_at": datetime.now().strftime("%Y-%m-%d %H:%M")
                })
                history = history[:15]
            record["history"] = history
            self.entries[index] = record
            active_idx = index
        else:
            record.setdefault("history", [])
            self.entries.append(record)
            active_idx = len(self.entries) - 1
        save_encrypted_vault(self.entries, self.master_password)
        return {"ok": True, "entries": self.entries, "activeIndex": active_idx}

    def clear_entry_history(self, index: int):
        if self.master_password is None or not (0 <= index < len(self.entries)):
            return {"ok": False}
        self.entries[index]["history"] = []
        save_encrypted_vault(self.entries, self.master_password)
        return {"ok": True, "entries": self.entries}

    def toggle_favorite(self, index: int):
        if self.master_password is None or not (0 <= index < len(self.entries)):
            return {"ok": False}
        self.entries[index]["favorite"] = not bool(self.entries[index].get("favorite", False))
        save_encrypted_vault(self.entries, self.master_password)
        return {"ok": True, "entries": self.entries}

    def delete_entry(self, index):
        if self.master_password is None:
            return {"ok": False}
        if 0 <= index < len(self.entries):
            self.entries.pop(index)
            save_encrypted_vault(self.entries, self.master_password)
        return {"ok": True, "entries": self.entries}

    def generate_password(self, options=None):
        opts = options or {}
        mode = opts.get("mode", "random")

        if mode == "memorable":
            word_count = max(3, min(12, int(opts.get("words", 4))))
            sep = str(opts.get("separator", "-"))
            capitalize = bool(opts.get("capitalize", True))
            include_num = bool(opts.get("include_number", True))

            chosen = [secrets.choice(WORDLIST) for _ in range(word_count)]
            if capitalize:
                chosen = [w.capitalize() for w in chosen]
            if include_num:
                num_idx = secrets.randbelow(word_count)
                chosen[num_idx] = f"{chosen[num_idx]}{secrets.randbelow(90) + 10}"

            pw = sep.join(chosen)
            bits = int(word_count * math.log2(len(WORDLIST)) + (7 if include_num else 0))
            return {"password": pw, "bits": bits}

        length = max(8, min(64, int(opts.get("length", 20))))
        use_numbers = bool(opts.get("numbers", True))
        use_symbols = bool(opts.get("symbols", True))
        avoid_ambiguous = bool(opts.get("avoid_ambiguous", False))

        letters = string.ascii_letters
        digits = string.digits
        symbols = "!@#$%^&*-_=+?"

        if avoid_ambiguous:
            for ch in "0O1lI":
                letters = letters.replace(ch, "")
                digits = digits.replace(ch, "")

        pools = [letters]
        if use_numbers:
            pools.append(digits)
        if use_symbols:
            pools.append(symbols)

        full_alphabet = "".join(pools)
        chars = [secrets.choice(p) for p in pools]
        while len(chars) < length:
            chars.append(secrets.choice(full_alphabet))
        secrets.SystemRandom().shuffle(chars)

        pw = "".join(chars[:length])
        bits = int(length * math.log2(len(full_alphabet)))
        return {"password": pw, "bits": bits}

    def get_totp(self, secret: str):
        cleaned = (secret or "").strip().replace(" ", "").upper()
        if not cleaned:
            return None
        try:
            padding = "=" * ((8 - len(cleaned) % 8) % 8)
            key = base64.b32decode(cleaned + padding, casefold=True)
            now = int(time.time())
            counter = now // 30
            remaining = 30 - (now % 30)
            msg = struct.pack(">Q", counter)
            digest = hmac.new(key, msg, hashlib.sha1).digest()
            offset = digest[-1] & 0x0F
            code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1000000
            return {"code": f"{code:06d}", "remaining": remaining}
        except Exception:
            return {"code": "INVALID", "remaining": 0}

    def copy_to_clipboard(self, text: str):
        val = str(text)
        pb = NSPasteboard.generalPasteboard()
        pb.clearContents()
        pb.setString_forType_(val, NSPasteboardTypeString)

        clear_sec = int(self.settings.get("clear_clipboard_seconds", 20))
        if clear_sec > 0:
            def _wipe():
                time.sleep(clear_sec)
                current = pb.stringForType_(NSPasteboardTypeString)
                if current == val:
                    pb.clearContents()
            threading.Thread(target=_wipe, daemon=True).start()
        return True

    def open_url(self, url: str):
        if not url:
            return False
        target = url if url.startswith(("http://", "https://")) else "https://" + url
        webbrowser.open(target)
        return True

    def auto_type_entry(self, index: int):
        if self.master_password is None or not (0 <= index < len(self.entries)):
            return {"ok": False}
        if not AXIsProcessTrusted():
            return {"ok": False, "need_accessibility": True}

        item = self.entries[index]
        username = item.get("username", "")
        password = item.get("password", "")
        auto_submit = bool(self.settings.get("auto_submit", False))

        def _perform_type():
            AppHelper.callAfter(lambda: NSApplication.sharedApplication().hide_(None))
            time.sleep(0.32)
            if username:
                self.kb.type(username)
                time.sleep(0.06)
                self.kb.press(keyboard.Key.tab)
                self.kb.release(keyboard.Key.tab)
                time.sleep(0.08)
            if password:
                self.kb.type(password)
                if auto_submit:
                    time.sleep(0.06)
                    self.kb.press(keyboard.Key.enter)
                    self.kb.release(keyboard.Key.enter)

        threading.Thread(target=_perform_type, daemon=True).start()
        return {"ok": True}

    def export_backup(self):
        _, vfile = get_active_vault_paths()
        if not vfile.exists() or self.window is None:
            return {"ok": False}
        stamp = datetime.now().strftime("%Y-%m-%d")
        result = self.window.create_file_dialog(
            webview.SAVE_DIALOG,
            save_filename=f"Voltes-IIV-Backup-{stamp}.enc"
        )
        if result:
            dest = result if isinstance(result, str) else result[0]
            shutil.copy2(vfile, dest)
            return {"ok": True, "path": dest}
        return {"ok": False}


HTML_UI = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Voltes IIV</title>
<style>
  :root {
    --bg-window: #161618;
    --bg-sidebar: #1e1e21;
    --bg-card: #242428;
    --bg-input: #2c2c31;
    --bg-hover: rgba(255, 255, 255, 0.06);
    --border: rgba(255, 255, 255, 0.08);
    --text-primary: #f5f5f7;
    --text-secondary: #98989f;
    --accent: #0a84ff;
    --accent-hover: #0071e3;
    --danger: #ff453a;
    --success: #30d158;
    --warning: #ffd60a;
    --symbol-orange: #ff9f0a;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; -webkit-user-select: none; }
  input, textarea, select { -webkit-user-select: text; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro Display", sans-serif;
    background: var(--bg-window);
    color: var(--text-primary);
    height: 100vh;
    overflow: hidden;
    display: flex;
  }

  /* LOCK SCREEN */
  #lock-screen {
    position: fixed; inset: 0;
    background: radial-gradient(circle at 50% 20%, #25262b 0%, #121214 100%);
    display: flex; align-items: center; justify-content: center;
    z-index: 50;
    -webkit-app-region: drag;
  }
  .lock-card {
    width: 380px;
    background: rgba(34, 34, 38, 0.85);
    backdrop-filter: blur(24px);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 36px 32px;
    text-align: center;
    box-shadow: 0 24px 60px rgba(0, 0, 0, 0.55);
    -webkit-app-region: no-drag;
  }
  .lock-badge {
    width: 64px; height: 64px;
    margin: 0 auto 18px;
    border-radius: 16px;
    background: linear-gradient(145deg, #2c2d33, #1a1b1f);
    border: 1px solid rgba(255,255,255,0.14);
    display: flex; align-items: center; justify-content: center;
    font-size: 28px;
    box-shadow: 0 8px 20px rgba(0,0,0,0.35);
  }
  .lock-card h1 { font-size: 21px; font-weight: 600; letter-spacing: -0.3px; margin-bottom: 6px; }
  .lock-card p { font-size: 13px; color: var(--text-secondary); line-height: 1.45; margin-bottom: 22px; }
  .apple-input, .apple-select {
    width: 100%; height: 38px;
    background: var(--bg-input);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 0 13px;
    color: var(--text-primary);
    font-size: 14px;
    outline: none;
    margin-bottom: 12px;
    transition: border-color 0.15s, box-shadow 0.15s;
  }
  .apple-select { width: auto; height: 32px; margin-bottom: 0; font-size: 13px; }
  .apple-input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(10, 132, 255, 0.25);
  }
  .btn-primary {
    width: 100%; height: 38px;
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 10px;
    font-size: 14px; font-weight: 500;
    cursor: pointer;
    transition: background 0.15s;
  }
  .btn-primary:hover { background: var(--accent-hover); }
  .btn-touchid {
    width: 100%; height: 38px;
    margin-top: 10px;
    background: rgba(255, 255, 255, 0.08);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 10px;
    font-size: 13.5px; font-weight: 500;
    cursor: pointer;
    transition: background 0.15s;
  }
  .btn-touchid:hover { background: rgba(255, 255, 255, 0.14); }
  .error-msg { color: var(--danger); font-size: 12px; margin-top: 10px; min-height: 16px; }

  /* QUICK-FILL SPOTLIGHT OVERLAY */
  #quick-overlay {
    position: fixed; inset: 0;
    background: rgba(10, 10, 12, 0.72);
    backdrop-filter: blur(18px);
    display: none;
    align-items: flex-start;
    justify-content: center;
    padding-top: 72px;
    z-index: 40;
  }
  .spotlight-box {
    width: 520px;
    background: #222226;
    border: 1px solid rgba(255,255,255,0.16);
    border-radius: 16px;
    box-shadow: 0 28px 70px rgba(0,0,0,0.7);
    overflow: hidden;
  }
  .spotlight-top {
    display: flex; align-items: center; padding: 14px 18px;
    border-bottom: 1px solid var(--border);
  }
  .spotlight-input {
    flex: 1; background: transparent; border: none; outline: none;
    color: var(--text-primary); font-size: 17px;
  }
  .spotlight-hint { font-size: 11px; color: var(--text-secondary); background: var(--bg-input); padding: 3px 8px; border-radius: 6px; }
  .spotlight-results { max-height: 300px; overflow-y: auto; padding: 8px; }
  .spot-row {
    display: flex; align-items: center; justify-content: space-between;
    padding: 10px 12px; border-radius: 10px; cursor: pointer;
  }
  .spot-row.selected { background: var(--accent); }
  .spot-left { display: flex; align-items: center; gap: 12px; }
  .spot-badge { font-size: 11px; opacity: 0.85; }
  .spotlight-footer {
    padding: 9px 16px; background: #1a1a1d; border-top: 1px solid var(--border);
    display: flex; justify-content: space-between; font-size: 11.5px; color: var(--text-secondary);
  }

  /* MAIN APP LAYOUT */
  #app-shell { display: none; width: 100%; height: 100vh; }

  /* SIDEBAR */
  .sidebar {
    width: 288px;
    background: var(--bg-sidebar);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    height: 100%;
  }
  .sidebar-header {
    padding: 42px 16px 10px;
    -webkit-app-region: drag;
  }
  .brand-row {
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 12px;
    -webkit-app-region: no-drag;
  }
  .brand-title { font-size: 17px; font-weight: 700; letter-spacing: -0.3px; }
  .pill-btn {
    background: var(--bg-input);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 5px 10px;
    font-size: 12px; font-weight: 500;
    cursor: pointer;
    transition: background 0.15s;
  }
  .pill-btn:hover { background: #38383e; }

  .search-wrap { position: relative; -webkit-app-region: no-drag; margin-bottom: 10px; }
  .search-input {
    width: 100%; height: 32px;
    background: var(--bg-input);
    border: 1px solid transparent;
    border-radius: 8px;
    padding: 0 12px 0 30px;
    color: var(--text-primary);
    font-size: 13px;
    outline: none;
  }
  .search-input:focus { border-color: var(--accent); }
  .search-icon {
    position: absolute; left: 10px; top: 8px;
    font-size: 12px; color: var(--text-secondary); pointer-events: none;
  }

  .nav-pills {
    display: flex; gap: 6px; -webkit-app-region: no-drag;
  }
  .nav-pill {
    flex: 1; padding: 6px 8px; border-radius: 8px;
    background: var(--bg-input); border: 1px solid var(--border);
    color: var(--text-secondary); font-size: 11.5px; font-weight: 600;
    cursor: pointer; text-align: center; transition: all 0.15s;
  }
  .nav-pill:hover { color: var(--text-primary); background: #34343a; }
  .nav-pill.active-nav { background: rgba(10, 132, 255, 0.18); color: var(--accent); border-color: rgba(10, 132, 255, 0.35); }

  .item-list {
    flex: 1;
    overflow-y: auto;
    padding: 6px 10px;
  }
  .item-list::-webkit-scrollbar { width: 6px; }
  .item-list::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.14); border-radius: 3px; }

  .vault-item {
    display: flex; align-items: center; gap: 11px;
    padding: 9px 10px;
    border-radius: 10px;
    cursor: pointer;
    margin-bottom: 2px;
    transition: background 0.12s;
  }
  .vault-item:hover { background: var(--bg-hover); }
  .vault-item.active { background: var(--accent); }
  .avatar {
    width: 34px; height: 34px;
    border-radius: 9px;
    display: flex; align-items: center; justify-content: center;
    font-weight: 600; font-size: 14px; color: #fff;
    flex-shrink: 0;
  }
  .item-meta { overflow: hidden; flex: 1; }
  .item-title { font-size: 13px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .item-sub { font-size: 11.5px; color: var(--text-secondary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .vault-item.active .item-sub { color: rgba(255,255,255,0.82); }
  .star-badge { font-size: 12px; color: var(--warning); flex-shrink: 0; }

  .sidebar-footer {
    padding: 12px 14px;
    border-top: 1px solid var(--border);
    display: flex; gap: 6px;
  }
  .btn-add {
    flex: 1; height: 32px;
    background: var(--accent);
    color: #fff; border: none; border-radius: 8px;
    font-size: 12.5px; font-weight: 500; cursor: pointer;
  }
  .btn-add:hover { background: var(--accent-hover); }

  /* DETAIL PANE */
  .main-pane {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow-y: auto;
    padding: 44px 42px 36px;
    -webkit-app-region: drag;
  }
  .main-content { max-width: 630px; width: 100%; margin: 0 auto; -webkit-app-region: no-drag; }

  .empty-state {
    height: 100%; display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    color: var(--text-secondary); text-align: center;
    -webkit-app-region: no-drag;
  }
  .empty-state .big-icon { font-size: 40px; margin-bottom: 12px; opacity: 0.5; }

  .detail-top {
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 24px;
  }
  .detail-header-left { display: flex; align-items: center; gap: 16px; }
  .detail-avatar {
    width: 52px; height: 52px; border-radius: 14px;
    display: flex; align-items: center; justify-content: center;
    font-size: 22px; font-weight: 700; color: #fff;
  }
  .detail-title { font-size: 24px; font-weight: 700; letter-spacing: -0.4px; }
  .section-heading {
    font-size: 12px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.5px; color: var(--text-secondary);
    margin: 20px 0 8px 4px;
  }
  .strength-pill, .status-pill {
    display: inline-block; font-size: 11px; font-weight: 600;
    padding: 3px 9px; border-radius: 99px;
    background: rgba(48, 209, 88, 0.15); color: var(--success);
  }
  .strength-pill { margin-top: 4px; }
  .strength-pill.weak, .status-pill.warn { background: rgba(255, 159, 10, 0.18); color: #ff9f0a; }
  .strength-pill.fair { background: rgba(255, 214, 10, 0.15); color: var(--warning); }

  .action-group { display: flex; gap: 8px; }
  .btn-autofill {
    background: rgba(10, 132, 255, 0.16);
    color: var(--accent);
    border: 1px solid rgba(10, 132, 255, 0.3);
    border-radius: 8px; padding: 6px 12px; font-size: 12.5px; font-weight: 600; cursor: pointer;
  }
  .btn-autofill:hover { background: rgba(10, 132, 255, 0.28); }
  .btn-danger {
    background: rgba(255, 69, 58, 0.14);
    color: var(--danger);
    border: 1px solid rgba(255, 69, 58, 0.25);
    border-radius: 8px; padding: 6px 12px; font-size: 12.5px; font-weight: 500; cursor: pointer;
  }
  .btn-danger:hover { background: rgba(255, 69, 58, 0.25); }

  /* GROUPED APPLE CARD */
  .group-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 14px;
    overflow: hidden;
    margin-bottom: 16px;
  }
  .field-row {
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px 18px;
    border-bottom: 1px solid var(--border);
  }
  .field-row:last-child { border-bottom: none; }
  .field-label { font-size: 13px; font-weight: 500; color: var(--text-primary); margin-bottom: 2px; }
  .field-sub { font-size: 11.5px; color: var(--text-secondary); line-height: 1.4; }
  .field-value { font-size: 14px; font-weight: 500; word-break: break-all; }
  .mono { font-family: "SF Mono", Menlo, monospace; letter-spacing: 0.4px; }
  .totp-code { font-family: "SF Mono", Menlo, monospace; font-size: 18px; font-weight: 700; color: var(--accent); }
  .field-actions { display: flex; gap: 6px; flex-shrink: 0; margin-left: 14px; align-items: center; }

  /* WATCHTOWER DASHBOARD */
  .wt-grid {
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 18px;
  }
  .wt-stat {
    background: var(--bg-card); border: 1px solid var(--border); border-radius: 14px;
    padding: 14px; text-align: center;
  }
  .wt-num { font-size: 24px; font-weight: 700; margin-bottom: 4px; }
  .wt-lbl { font-size: 11.5px; color: var(--text-secondary); }

  /* 1PASSWORD-STYLE GENERATOR */
  .seg-control {
    display: flex; background: var(--bg-input); padding: 3px; border-radius: 10px;
    border: 1px solid var(--border); margin-bottom: 16px;
  }
  .seg-btn {
    flex: 1; padding: 7px 12px; border: none; border-radius: 8px;
    background: transparent; color: var(--text-secondary);
    font-size: 13px; font-weight: 600; cursor: pointer; transition: all 0.15s;
  }
  .seg-btn.active { background: #3a3a40; color: var(--text-primary); box-shadow: 0 2px 6px rgba(0,0,0,0.25); }

  .gen-hero {
    background: #1a1a1d; border: 1px solid var(--border); border-radius: 14px;
    padding: 20px; margin-bottom: 16px;
  }
  .gen-display {
    font-family: "SF Mono", Menlo, monospace; font-size: 20px; font-weight: 600;
    line-height: 1.5; word-break: break-all; min-height: 62px;
    display: flex; align-items: center; flex-wrap: wrap;
    margin-bottom: 14px; -webkit-user-select: text;
  }
  .ch-num { color: #64d2ff; }
  .ch-sym { color: var(--symbol-orange); }
  .strength-bar-track {
    height: 5px; background: var(--bg-input); border-radius: 99px; overflow: hidden; margin-bottom: 14px;
  }
  .strength-bar-fill { height: 100%; width: 100%; background: var(--success); transition: width 0.2s, background 0.2s; }
  .gen-hero-footer { display: flex; align-items: center; justify-content: space-between; }

  /* APPLE TOGGLE SWITCH */
  .switch { position: relative; display: inline-block; width: 42px; height: 24px; }
  .switch input { opacity: 0; width: 0; height: 0; }
  .slider {
    position: absolute; cursor: pointer; inset: 0;
    background-color: #3a3a3f; transition: .2s; border-radius: 24px;
  }
  .slider:before {
    position: absolute; content: ""; height: 20px; width: 20px;
    left: 2px; bottom: 2px; background-color: white;
    transition: .2s; border-radius: 50%;
  }
  input:checked + .slider { background-color: var(--success); }
  input:checked + .slider:before { transform: translateX(18px); }

  /* FORM */
  .form-group { margin-bottom: 14px; }
  .form-group label { display: block; font-size: 12px; color: var(--text-secondary); margin-bottom: 6px; }
  .pw-gen-row { display: flex; gap: 8px; align-items: center; }
  .pw-gen-row .apple-input { margin-bottom: 0; }
  .gen-opts { display: flex; align-items: center; flex-wrap: wrap; gap: 12px; margin-top: 8px; font-size: 12px; color: var(--text-secondary); }
  textarea.apple-input { height: 84px; padding: 10px 13px; resize: vertical; font-family: inherit; }

  /* TOAST */
  .toast {
    position: fixed; bottom: 20px; right: 24px;
    background: rgba(44, 44, 48, 0.95);
    border: 1px solid var(--border);
    padding: 9px 16px; border-radius: 10px;
    font-size: 12.5px; font-weight: 500;
    box-shadow: 0 10px 25px rgba(0,0,0,0.4);
    opacity: 0; transform: translateY(8px);
    transition: opacity 0.2s, transform 0.2s;
    pointer-events: none;
    z-index: 60;
  }
  .toast.show { opacity: 1; transform: translateY(0); }
</style>
</head>
<body>

  <!-- LOCK / SETUP SCREEN -->
  <div id="lock-screen">
    <div class="lock-card">
      <div class="lock-badge">🔒</div>
      <h1 id="lock-title">Voltes IIV</h1>
      <p id="lock-subtitle">Enter your Master Password to unlock your local encrypted vault.</p>
      <input id="master-pw" type="password" class="apple-input" placeholder="Master Password" autofocus />
      <input id="confirm-pw" type="password" class="apple-input" placeholder="Confirm Master Password" style="display:none;" />
      <button id="unlock-btn" class="btn-primary">Unlock Vault</button>
      <button id="touchid-btn" class="btn-touchid" style="display:none;" onclick="handleTouchID()">􀟒 Unlock with Touch ID / Mac Password</button>
      <div id="lock-error" class="error-msg"></div>
    </div>
  </div>

  <!-- QUICK-FILL SPOTLIGHT OVERLAY -->
  <div id="quick-overlay" onclick="if(event.target===this) closeQuickFill()">
    <div class="spotlight-box">
      <div class="spotlight-top">
        <input id="spot-input" class="spotlight-input" placeholder="Type site or app name to Auto-Type..." />
        <span class="spotlight-hint">⌘⇧L</span>
      </div>
      <div id="spot-results" class="spotlight-results"></div>
      <div class="spotlight-footer">
        <span><b>↵ Enter</b> Auto-Type User + Pass</span>
        <span><b>⇧↵ Shift+Enter</b> Copy Pass &nbsp;|&nbsp; <b>Esc</b> Close</span>
      </div>
    </div>
  </div>

  <!-- MAIN APP -->
  <div id="app-shell">
    <aside class="sidebar">
      <div class="sidebar-header">
        <div class="brand-row">
          <span class="brand-title">Voltes IIV</span>
          <div style="display:flex; gap:6px;">
            <button class="pill-btn" onclick="openQuickFill()" title="Shortcut: Command + Shift + L">Quick Fill</button>
            <button class="pill-btn" onclick="lockVault()" title="Shortcut: Command + L">Lock</button>
          </div>
        </div>
        <div class="search-wrap">
          <span class="search-icon">🔍</span>
          <input id="search-input" class="search-input" type="text" placeholder="Search (⌘F)" oninput="renderSidebar()" />
        </div>
        <div class="nav-pills">
          <button id="nav-gen" class="nav-pill" onclick="openGenerator()" title="Shortcut: Command + G">Generator</button>
          <button id="nav-wt" class="nav-pill" onclick="openWatchtower()" title="Shortcut: Command + W">Watchtower</button>
        </div>
      </div>
      <div id="item-list" class="item-list"></div>
      <div class="sidebar-footer">
        <button class="btn-add" onclick="openForm()" title="Shortcut: Command + N">+ New Login</button>
        <button id="nav-set" class="pill-btn" onclick="openSettings()" title="Shortcut: Command + ,">Settings</button>
      </div>
    </aside>

    <main class="main-pane">
      <div id="main-content" class="main-content"></div>
    </main>
  </div>

  <div id="toast" class="toast">Copied to clipboard</div>

<script>
  let entries = [];
  let appSettings = { auto_lock_seconds: 180, auto_submit: false, clear_clipboard_seconds: 20, touch_id_enabled: false };
  let activeIndex = null;
  let currentView = "detail"; // detail | generator | watchtower | settings | form
  let revealPw = false;
  let showHistory = false;
  let isNewVault = false;
  let lastActivity = Date.now();
  let pendingQuickFill = false;
  let spotMatches = [];
  let spotSelected = 0;

  let genState = {
    mode: "random",
    length: 20,
    numbers: true,
    symbols: true,
    avoid_ambiguous: false,
    words: 4,
    separator: "-",
    capitalize: true,
    include_number: true,
    currentPassword: "",
    bits: 120
  };

  const colors = ["#0a84ff", "#30d158", "#bf5af2", "#ff9f0a", "#ff375f", "#5e5ce6", "#64d2ff"];
  function avatarColor(str) {
    let h = 0;
    for (let i = 0; i < str.length; i++) h = str.charCodeAt(i) + ((h << 5) - h);
    return colors[Math.abs(h) % colors.length];
  }

  function showToast(msg) {
    const t = document.getElementById("toast");
    t.textContent = msg;
    t.classList.add("show");
    setTimeout(() => t.classList.remove("show"), 2200);
  }

  function setNavHighlight(view) {
    currentView = view;
    document.getElementById("nav-gen").classList.toggle("active-nav", view === "generator");
    document.getElementById("nav-wt").classList.toggle("active-nav", view === "watchtower");
  }

  function touchActivity() { lastActivity = Date.now(); }
  document.addEventListener("mousemove", touchActivity);
  document.addEventListener("keydown", (e) => {
    touchActivity();
    if (document.getElementById("app-shell").style.display === "flex" && e.metaKey) {
      if (e.key.toLowerCase() === "n") { e.preventDefault(); openForm(); }
      else if (e.key.toLowerCase() === "g") { e.preventDefault(); openGenerator(); }
      else if (e.key.toLowerCase() === "w") { e.preventDefault(); openWatchtower(); }
      else if (e.key.toLowerCase() === "f") { e.preventDefault(); document.getElementById("search-input").focus(); }
      else if (e.key.toLowerCase() === "l" && !e.shiftKey) { e.preventDefault(); lockVault(); }
      else if (e.key === ",") { e.preventDefault(); openSettings(); }
    }
  });

  window.triggerQuickFillFromSystem = async function() {
    touchActivity();
    if (document.getElementById("app-shell").style.display === "flex") {
      openQuickFill();
    } else {
      pendingQuickFill = true;
      if (await pywebview.api.can_use_touch_id()) {
        handleTouchID();
      } else {
        document.getElementById("master-pw").focus();
      }
    }
  };

  window.openSettingsFromSystem = function() {
    touchActivity();
    if (document.getElementById("app-shell").style.display === "flex") {
      openSettings();
    }
  };

  setInterval(async () => {
    if (document.getElementById("app-shell").style.display === "flex") {
      const lockMs = (appSettings.auto_lock_seconds || 0) * 1000;
      if (lockMs > 0 && Date.now() - lastActivity > lockMs) {
        lockVault();
        return;
      }
      if (currentView === "detail" && activeIndex !== null && entries[activeIndex] && entries[activeIndex].totp) {
        const res = await pywebview.api.get_totp(entries[activeIndex].totp);
        const el = document.getElementById("live-totp");
        if (el && res) {
          const fmt = res.code.length === 6 ? res.code.slice(0,3) + " " + res.code.slice(3) : res.code;
          el.textContent = `${fmt}  (${res.remaining}s)`;
        }
      }
    }
  }, 1000);

  async function refreshLockScreenBiometrics() {
    const canTouch = await pywebview.api.can_use_touch_id();
    document.getElementById("touchid-btn").style.display = canTouch ? "block" : "none";
  }

  window.addEventListener("pywebviewready", async () => {
    isNewVault = !(await pywebview.api.vault_exists());
    if (isNewVault) {
      document.getElementById("lock-title").textContent = "Create Master Password";
      document.getElementById("lock-subtitle").textContent = "Encrypted locally with Argon2id + AES-256-GCM. Never forget this password.";
      document.getElementById("confirm-pw").style.display = "block";
      document.getElementById("unlock-btn").textContent = "Create Encrypted Vault";
    } else {
      await refreshLockScreenBiometrics();
    }
  });

  function completeUnlock(res) {
    entries = res.entries;
    if (res.settings) appSettings = res.settings;
    document.getElementById("master-pw").value = "";
    document.getElementById("confirm-pw").value = "";
    document.getElementById("lock-screen").style.display = "none";
    document.getElementById("app-shell").style.display = "flex";
    touchActivity();
    const sorted = getSortedIndices();
    activeIndex = sorted.length > 0 ? sorted[0] : null;
    renderSidebar();
    renderDetail();

    if (pendingQuickFill) {
      pendingQuickFill = false;
      openQuickFill();
    }
  }

  async function handleTouchID() {
    const err = document.getElementById("lock-error");
    err.textContent = "";
    const res = await pywebview.api.unlock_with_touch_id();
    if (res.ok) {
      completeUnlock(res);
    } else {
      err.textContent = res.error;
    }
  }

  async function handleAuth() {
    const pw = document.getElementById("master-pw").value;
    const err = document.getElementById("lock-error");
    err.textContent = "";

    if (isNewVault) {
      const cf = document.getElementById("confirm-pw").value;
      if (pw !== cf) { err.textContent = "Master Passwords do not match."; return; }
      const res = await pywebview.api.create_vault(pw);
      if (!res.ok) { err.textContent = res.error; return; }
      completeUnlock(res);
    } else {
      const res = await pywebview.api.unlock_vault(pw);
      if (!res.ok) { err.textContent = res.error; document.getElementById("master-pw").value = ""; return; }
      completeUnlock(res);
    }
  }

  document.getElementById("unlock-btn").addEventListener("click", handleAuth);
  document.getElementById("master-pw").addEventListener("keydown", e => { if (e.key === "Enter") handleAuth(); });
  document.getElementById("confirm-pw").addEventListener("keydown", e => { if (e.key === "Enter") handleAuth(); });

  async function lockVault() {
    closeQuickFill();
    await pywebview.api.lock_vault();
    entries = [];
    activeIndex = null;
    revealPw = false;
    showHistory = false;
    isNewVault = false;
    document.getElementById("lock-title").textContent = "Voltes IIV";
    document.getElementById("lock-subtitle").textContent = "Enter your Master Password to unlock your local encrypted vault.";
    document.getElementById("confirm-pw").style.display = "none";
    document.getElementById("unlock-btn").textContent = "Unlock Vault";
    document.getElementById("app-shell").style.display = "none";
    document.getElementById("lock-screen").style.display = "flex";
    await refreshLockScreenBiometrics();
    document.getElementById("master-pw").focus();
  }

  function getSortedIndices() {
    return entries
      .map((item, idx) => ({ item, idx }))
      .sort((a, b) => (b.item.favorite ? 1 : 0) - (a.item.favorite ? 1 : 0))
      .map(x => x.idx);
  }

  /* WATCHTOWER SECURITY AUDIT */
  async function openWatchtower() {
    activeIndex = null;
    setNavHighlight("watchtower");
    renderSidebar();
    const rep = await pywebview.api.get_watchtower_report();
    const pane = document.getElementById("main-content");

    const buildAuditList = (indices, badgeText, badgeCls) => {
      if (indices.length === 0) {
        return `<div class="field-row"><div class="field-sub">No issues detected in this category.</div></div>`;
      }
      return indices.map(idx => {
        const item = entries[idx];
        return `
          <div class="field-row" style="cursor:pointer;" onclick="activeIndex=${idx}; revealPw=false; showHistory=false; renderSidebar(); renderDetail();">
            <div>
              <div class="field-label">${escapeHtml(item.title)}</div>
              <div class="field-sub">${escapeHtml(item.username || "No username")}</div>
            </div>
            <div class="field-actions">
              <span class="status-pill ${badgeCls}">${badgeText}</span>
              <button class="pill-btn" onclick="event.stopPropagation(); openForm(${idx});">Fix</button>
            </div>
          </div>
        `;
      }).join("");
    };

    const scoreColor = rep.score >= 85 ? "var(--success)" : (rep.score >= 60 ? "var(--warning)" : "var(--danger)");

    pane.innerHTML = `
      <div class="detail-top">
        <div class="detail-title">Watchtower Audit</div>
        <button class="pill-btn" onclick="const s=getSortedIndices();if(s.length>0){activeIndex=s[0];renderSidebar();}renderDetail();">Done</button>
      </div>

      <div class="wt-grid">
        <div class="wt-stat">
          <div class="wt-num" style="color:${scoreColor};">${rep.score}%</div>
          <div class="wt-lbl">Vault Health</div>
        </div>
        <div class="wt-stat">
          <div class="wt-num" style="color:${rep.reused.length ? 'var(--danger)' : 'var(--text-primary)'};">${rep.reused.length}</div>
          <div class="wt-lbl">Reused</div>
        </div>
        <div class="wt-stat">
          <div class="wt-num" style="color:${rep.weak.length ? '#ff9f0a' : 'var(--text-primary)'};">${rep.weak.length}</div>
          <div class="wt-lbl">Weak</div>
        </div>
        <div class="wt-stat">
          <div class="wt-num" style="color:var(--accent);">${rep.no_2fa.length}</div>
          <div class="wt-lbl">Missing 2FA</div>
        </div>
      </div>

      <div class="section-heading">Reused Passwords (${rep.reused.length})</div>
      <div class="group-card">${buildAuditList(rep.reused, "Reused", "warn")}</div>

      <div class="section-heading">Weak Passwords (${rep.weak.length})</div>
      <div class="group-card">${buildAuditList(rep.weak, "Weak", "warn")}</div>

      <div class="section-heading">Accounts Without 2FA (${rep.no_2fa.length})</div>
      <div class="group-card">${buildAuditList(rep.no_2fa, "No 2FA", "")}</div>
    `;
  }

  /* 1PASSWORD-STYLE STANDALONE GENERATOR */
  function colorizePassword(pw) {
    return Array.from(pw).map(ch => {
      const esc = escapeHtml(ch);
      if (/[0-9]/.test(ch)) return `<span class="ch-num">${esc}</span>`;
      if (/[^A-Za-z0-9]/.test(ch)) return `<span class="ch-sym">${esc}</span>`;
      return `<span>${esc}</span>`;
    }).join("");
  }

  async function refreshGeneratedPassword() {
    const res = await pywebview.api.generate_password(genState);
    genState.currentPassword = res.password;
    genState.bits = res.bits;
    const disp = document.getElementById("gen-color-display");
    if (disp) disp.innerHTML = colorizePassword(res.password);

    const bar = document.getElementById("gen-strength-bar");
    const lbl = document.getElementById("gen-strength-label");
    if (bar && lbl) {
      const pct = Math.min(100, Math.round((res.bits / 128) * 100));
      bar.style.width = pct + "%";
      if (res.bits >= 80) {
        bar.style.background = "var(--success)";
        lbl.textContent = `Strong (${res.bits}-bit entropy)`;
      } else if (res.bits >= 55) {
        bar.style.background = "var(--warning)";
        lbl.textContent = `Good (${res.bits}-bit entropy)`;
      } else {
        bar.style.background = "var(--danger)";
        lbl.textContent = `Fair (${res.bits}-bit entropy)`;
      }
    }
  }

  async function openGenerator() {
    activeIndex = null;
    setNavHighlight("generator");
    renderSidebar();
    const pane = document.getElementById("main-content");

    const controlsHtml = genState.mode === "random" ? `
      <div class="group-card">
        <div class="field-row">
          <div>
            <div class="field-label">Characters: <span id="g-len-txt" style="color:var(--accent);">${genState.length}</span></div>
            <div class="field-sub">Recommended: 16 to 24 characters</div>
          </div>
          <div class="field-actions" style="width:200px;">
            <input type="range" min="8" max="64" value="${genState.length}" style="width:100%;"
              oninput="genState.length=Number(this.value); document.getElementById('g-len-txt').textContent=this.value; refreshGeneratedPassword();" />
          </div>
        </div>

        <div class="field-row">
          <div>
            <div class="field-label">Numbers (0-9)</div>
          </div>
          <div class="field-actions">
            <label class="switch">
              <input type="checkbox" ${genState.numbers ? "checked" : ""} onchange="genState.numbers=this.checked; refreshGeneratedPassword();">
              <span class="slider"></span>
            </label>
          </div>
        </div>

        <div class="field-row">
          <div>
            <div class="field-label">Symbols (!@#$%^&*)</div>
          </div>
          <div class="field-actions">
            <label class="switch">
              <input type="checkbox" ${genState.symbols ? "checked" : ""} onchange="genState.symbols=this.checked; refreshGeneratedPassword();">
              <span class="slider"></span>
            </label>
          </div>
        </div>

        <div class="field-row">
          <div>
            <div class="field-label">Avoid Ambiguous Characters</div>
            <div class="field-sub">Excludes 0, O, 1, l, I for easy manual typing</div>
          </div>
          <div class="field-actions">
            <label class="switch">
              <input type="checkbox" ${genState.avoid_ambiguous ? "checked" : ""} onchange="genState.avoid_ambiguous=this.checked; refreshGeneratedPassword();">
              <span class="slider"></span>
            </label>
          </div>
        </div>
      </div>
    ` : `
      <div class="group-card">
        <div class="field-row">
          <div>
            <div class="field-label">Words: <span id="g-words-txt" style="color:var(--accent);">${genState.words}</span></div>
            <div class="field-sub">4+ words creates a high-entropy passphrase</div>
          </div>
          <div class="field-actions" style="width:200px;">
            <input type="range" min="3" max="10" value="${genState.words}" style="width:100%;"
              oninput="genState.words=Number(this.value); document.getElementById('g-words-txt').textContent=this.value; refreshGeneratedPassword();" />
          </div>
        </div>

        <div class="field-row">
          <div>
            <div class="field-label">Separator</div>
          </div>
          <div class="field-actions">
            <select class="apple-select" onchange="genState.separator=this.value; refreshGeneratedPassword();">
              <option value="-" ${genState.separator==="-"?"selected":""}>Hyphen ( - )</option>
              <option value="_" ${genState.separator==="_"?"selected":""}>Underscore ( _ )</option>
              <option value="." ${genState.separator==="."?"selected":""}>Period ( . )</option>
              <option value=" " ${genState.separator===" "?"selected":""}>Space</option>
            </select>
          </div>
        </div>

        <div class="field-row">
          <div>
            <div class="field-label">Capitalize Words</div>
          </div>
          <div class="field-actions">
            <label class="switch">
              <input type="checkbox" ${genState.capitalize ? "checked" : ""} onchange="genState.capitalize=this.checked; refreshGeneratedPassword();">
              <span class="slider"></span>
            </label>
          </div>
        </div>

        <div class="field-row">
          <div>
            <div class="field-label">Include Number</div>
          </div>
          <div class="field-actions">
            <label class="switch">
              <input type="checkbox" ${genState.include_number ? "checked" : ""} onchange="genState.include_number=this.checked; refreshGeneratedPassword();">
              <span class="slider"></span>
            </label>
          </div>
        </div>
      </div>
    `;

    pane.innerHTML = `
      <div class="detail-top">
        <div class="detail-title">Password Generator</div>
        <button class="btn-autofill" onclick="openForm(null, genState.currentPassword)">+ Save as New Login</button>
      </div>

      <div class="seg-control">
        <button class="seg-btn ${genState.mode==='random'?'active':''}" onclick="genState.mode='random'; openGenerator();">Random Password</button>
        <button class="seg-btn ${genState.mode==='memorable'?'active':''}" onclick="genState.mode='memorable'; openGenerator();">Memorable Passphrase</button>
      </div>

      <div class="gen-hero">
        <div id="gen-color-display" class="gen-display"></div>
        <div class="strength-bar-track"><div id="gen-strength-bar" class="strength-bar-fill"></div></div>
        <div class="gen-hero-footer">
          <span id="gen-strength-label" style="font-size:12px; color:var(--text-secondary);">Strong</span>
          <div style="display:flex; gap:8px;">
            <button class="pill-btn" onclick="refreshGeneratedPassword()">↻ Regenerate</button>
            <button class="btn-primary" style="width:auto; height:30px; padding:0 14px; font-size:12.5px;" onclick="copyGeneratedPassword()">Copy Password</button>
          </div>
        </div>
      </div>

      ${controlsHtml}
    `;

    await refreshGeneratedPassword();
  }

  async function copyGeneratedPassword() {
    if (!genState.currentPassword) return;
    await pywebview.api.copy_to_clipboard(genState.currentPassword);
    showToast("Generated password copied");
  }

  /* QUICK FILL SPOTLIGHT LOGIC */
  function openQuickFill() {
    const ov = document.getElementById("quick-overlay");
    const inp = document.getElementById("spot-input");
    ov.style.display = "flex";
    inp.value = "";
    spotSelected = 0;
    renderSpotlight();
    setTimeout(() => inp.focus(), 30);
  }

  function closeQuickFill() {
    document.getElementById("quick-overlay").style.display = "none";
  }

  function renderSpotlight() {
    const q = document.getElementById("spot-input").value.toLowerCase().trim();
    const box = document.getElementById("spot-results");
    box.innerHTML = "";
    spotMatches = getSortedIndices()
      .map(idx => ({ item: entries[idx], idx }))
      .filter(({ item }) => !q || item.title.toLowerCase().includes(q) || (item.username || "").toLowerCase().includes(q));

    if (spotSelected >= spotMatches.length) spotSelected = Math.max(0, spotMatches.length - 1);

    if (spotMatches.length === 0) {
      box.innerHTML = `<div style="padding:20px; text-align:center; color:var(--text-secondary); font-size:13px;">No matching logins</div>`;
      return;
    }

    spotMatches.forEach(({ item, idx }, i) => {
      const row = document.createElement("div");
      row.className = "spot-row" + (i === spotSelected ? " selected" : "");
      const letter = (item.title[0] || "?").toUpperCase();
      row.innerHTML = `
        <div class="spot-left">
          <div class="avatar" style="width:28px; height:28px; font-size:12px; background:${avatarColor(item.title)}">${letter}</div>
          <div>
            <div class="item-title">${item.favorite ? "★ " : ""}${escapeHtml(item.title)}</div>
            <div class="item-sub" style="${i === spotSelected ? 'color:rgba(255,255,255,0.85)' : ''}">${escapeHtml(item.username || "No username")}</div>
          </div>
        </div>
        <span class="spot-badge">↵ Auto-Type</span>
      `;
      row.onclick = () => executeAutoType(idx);
      box.appendChild(row);
    });
  }

  document.getElementById("spot-input").addEventListener("input", () => {
    spotSelected = 0;
    renderSpotlight();
  });

  document.getElementById("spot-input").addEventListener("keydown", async (e) => {
    if (e.key === "Escape") {
      closeQuickFill();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (spotMatches.length > 0) { spotSelected = (spotSelected + 1) % spotMatches.length; renderSpotlight(); }
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      if (spotMatches.length > 0) { spotSelected = (spotSelected - 1 + spotMatches.length) % spotMatches.length; renderSpotlight(); }
    } else if (e.key === "Enter" && spotMatches[spotSelected]) {
      e.preventDefault();
      const targetIdx = spotMatches[spotSelected].idx;
      if (e.shiftKey) {
        await pywebview.api.copy_to_clipboard(entries[targetIdx].password);
        closeQuickFill();
        showToast("Password copied");
      } else {
        executeAutoType(targetIdx);
      }
    }
  });

  async function executeAutoType(idx) {
    closeQuickFill();
    const res = await pywebview.api.auto_type_entry(idx);
    if (res && res.need_accessibility) {
      showToast("Enable Accessibility permission in Settings first");
      openSettings();
    }
  }

  function renderSidebar() {
    const list = document.getElementById("item-list");
    const q = document.getElementById("search-input").value.toLowerCase().trim();
    list.innerHTML = "";

    getSortedIndices().forEach(idx => {
      const item = entries[idx];
      if (q && !item.title.toLowerCase().includes(q) && !(item.username || "").toLowerCase().includes(q)) return;
      const div = document.createElement("div");
      div.className = "vault-item" + (idx === activeIndex ? " active" : "");
      const letter = (item.title[0] || "?").toUpperCase();
      div.innerHTML = `
        <div class="avatar" style="background:${avatarColor(item.title)}">${letter}</div>
        <div class="item-meta">
          <div class="item-title">${escapeHtml(item.title)}</div>
          <div class="item-sub">${escapeHtml(item.username || "No username")}</div>
        </div>
        ${item.favorite ? '<span class="star-badge">★</span>' : ''}
      `;
      div.onclick = () => { activeIndex = idx; revealPw = false; showHistory = false; renderSidebar(); renderDetail(); };
      list.appendChild(div);
    });
  }

  function passwordStrength(pw) {
    if (pw.length < 8) return { label: "Weak Password", cls: "weak" };
    let score = 0;
    if (pw.length >= 12) score++;
    if (pw.length >= 16) score++;
    if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    if (score >= 4) return { label: "Strong Password", cls: "" };
    return { label: "Fair Password", cls: "fair" };
  }

  async function toggleFavorite(idx) {
    const res = await pywebview.api.toggle_favorite(idx);
    if (res.ok) {
      entries = res.entries;
      renderSidebar();
      renderDetail();
    }
  }

  async function copyHistoryPw(pw) {
    await pywebview.api.copy_to_clipboard(pw);
    showToast("Previous password copied");
  }

  async function clearHistory(idx) {
    const res = await pywebview.api.clear_entry_history(idx);
    if (res.ok) {
      entries = res.entries;
      showHistory = false;
      renderDetail();
      showToast("Password history cleared");
    }
  }

  async function renderDetail() {
    setNavHighlight("detail");
    const pane = document.getElementById("main-content");
    if (activeIndex === null || !entries[activeIndex]) {
      pane.innerHTML = `
        <div class="empty-state">
          <div class="big-icon">🛡️</div>
          <h3 style="color:var(--text-primary); margin-bottom:6px;">No Item Selected</h3>
          <p style="font-size:13px;">Select a login from the sidebar, open <b>Watchtower</b>, or press <b>⌘⇧L</b> anywhere to Quick-Fill.</p>
        </div>
      `;
      return;
    }

    const item = entries[activeIndex];
    const st = passwordStrength(item.password);
    const letter = (item.title[0] || "?").toUpperCase();
    const masked = "•".repeat(Math.min(item.password.length, 16));
    const history = item.history || [];

    let totpHtml = "";
    if (item.totp) {
      const res = await pywebview.api.get_totp(item.totp);
      const fmt = res && res.code.length === 6 ? res.code.slice(0,3) + " " + res.code.slice(3) : (res ? res.code : "");
      totpHtml = `
        <div class="field-row">
          <div>
            <div class="field-label">2FA Verification Code</div>
            <div id="live-totp" class="totp-code">${fmt} (${res ? res.remaining : 0}s)</div>
          </div>
          <div class="field-actions">
            <button class="pill-btn" onclick="copyTotp()">Copy</button>
          </div>
        </div>
      `;
    }

    let notesHtml = "";
    if (item.notes) {
      notesHtml = `
        <div class="group-card">
          <div class="field-row">
            <div>
              <div class="field-label">Notes</div>
              <div class="field-value" style="white-space:pre-wrap;">${escapeHtml(item.notes)}</div>
            </div>
          </div>
        </div>
      `;
    }

    let historyHtml = "";
    if (history.length > 0) {
      const rows = showHistory ? history.map(h => `
        <div class="field-row">
          <div>
            <div class="field-value mono" style="font-size:13px;">${escapeHtml(h.password)}</div>
            <div class="field-sub">Replaced on ${escapeHtml(h.changed_at || "Unknown date")}</div>
          </div>
          <div class="field-actions">
            <button class="pill-btn" onclick="copyHistoryPw(${JSON.stringify(h.password).replace(/"/g, '&quot;')})">Copy</button>
          </div>
        </div>
      `).join("") : "";

      historyHtml = `
        <div class="group-card">
          <div class="field-row">
            <div>
              <div class="field-label">Previous Passwords (${history.length})</div>
              <div class="field-sub">Archived automatically when you update this login's password</div>
            </div>
            <div class="field-actions">
              <button class="pill-btn" onclick="showHistory = !showHistory; renderDetail();">${showHistory ? "Hide" : "View"}</button>
              ${showHistory ? `<button class="btn-danger" onclick="clearHistory(${activeIndex})">Clear</button>` : ""}
            </div>
          </div>
          ${rows}
        </div>
      `;
    }

    pane.innerHTML = `
      <div class="detail-top">
        <div class="detail-header-left">
          <div class="detail-avatar" style="background:${avatarColor(item.title)}">${letter}</div>
          <div>
            <div class="detail-title">${escapeHtml(item.title)}</div>
            <span class="strength-pill ${st.cls}">${st.label}</span>
          </div>
        </div>
        <div class="action-group">
          <button class="pill-btn" onclick="toggleFavorite(${activeIndex})" title="Pin to top">${item.favorite ? "★ Pinned" : "☆ Pin"}</button>
          <button class="btn-autofill" onclick="executeAutoType(${activeIndex})">Auto-Type</button>
          <button class="pill-btn" onclick="openForm(${activeIndex})">Edit</button>
          <button class="btn-danger" onclick="deleteItem(${activeIndex})">Delete</button>
        </div>
      </div>

      <div class="group-card">
        <div class="field-row">
          <div>
            <div class="field-label">Username or Email</div>
            <div class="field-value">${escapeHtml(item.username || "—")}</div>
          </div>
          <div class="field-actions">
            <button class="pill-btn" onclick="copyField('username')">Copy</button>
          </div>
        </div>

        <div class="field-row">
          <div>
            <div class="field-label">Password</div>
            <div class="field-value mono">${revealPw ? colorizePassword(item.password) : masked}</div>
          </div>
          <div class="field-actions">
            <button class="pill-btn" onclick="revealPw = !revealPw; renderDetail();">${revealPw ? "Hide" : "Show"}</button>
            <button class="pill-btn" onclick="copyField('password')">Copy</button>
          </div>
        </div>

        ${totpHtml}

        <div class="field-row">
          <div>
            <div class="field-label">Website</div>
            <div class="field-value">${escapeHtml(item.url || "—")}</div>
          </div>
          ${item.url ? `
            <div class="field-actions">
              <button class="pill-btn" onclick="pywebview.api.open_url(entries[activeIndex].url)">Open</button>
              <button class="pill-btn" onclick="copyField('url')">Copy</button>
            </div>` : ""}
        </div>
      </div>

      ${notesHtml}
      ${historyHtml}
    `;
  }

  /* SETTINGS SCREEN */
  async function openSettings() {
    activeIndex = null;
    setNavHighlight("settings");
    renderSidebar();
    const info = await pywebview.api.get_settings();
    appSettings = info.settings;
    const granted = info.accessibility_granted;

    const pane = document.getElementById("main-content");
    pane.innerHTML = `
      <div class="detail-top">
        <div class="detail-title">Settings</div>
        <button class="pill-btn" onclick="const s=getSortedIndices();if(s.length>0){activeIndex=s[0];renderSidebar();}renderDetail();">Done</button>
      </div>

      <div class="section-heading">Import & Zero-Knowledge Sync</div>
      <div class="group-card">
        <div class="field-row">
          <div>
            <div class="field-label">Import Passwords from CSV</div>
            <div class="field-sub">Supports Apple Passwords, Chrome, Brave, 1Password, and Bitwarden CSV files.</div>
          </div>
          <div class="field-actions">
            <button class="btn-autofill" onclick="handleImportCSV()">Import CSV</button>
          </div>
        </div>

        <div class="field-row">
          <div>
            <div class="field-label">Vault Sync Folder (iCloud Drive / USB)</div>
            <div id="sync-path-label" class="field-sub mono" style="font-size:11px;">${escapeHtml(info.vault_path)}</div>
          </div>
          <div class="field-actions">
            <button class="pill-btn" onclick="handleChooseSyncFolder()">Change Folder</button>
            <button class="pill-btn" onclick="handleResetSyncFolder()">Default</button>
          </div>
        </div>

        <div class="field-row">
          <div>
            <div class="field-label">Export Encrypted Backup</div>
            <div class="field-sub">Save a standalone AES-256-GCM snapshot (.enc) anywhere.</div>
          </div>
          <div class="field-actions">
            <button class="pill-btn" onclick="exportBackup()">Export Backup</button>
          </div>
        </div>
      </div>

      <div class="section-heading">Biometrics & Startup</div>
      <div class="group-card">
        <div class="field-row">
          <div>
            <div class="field-label">Unlock with Touch ID / Apple Watch / Mac Password</div>
            <div class="field-sub">Stores your Master Key in macOS hardware Keychain for instant biometric unlock.</div>
          </div>
          <div class="field-actions">
            <label class="switch">
              <input type="checkbox" ${appSettings.touch_id_enabled ? 'checked' : ''} onchange="handleToggleTouchID(this)">
              <span class="slider"></span>
            </label>
          </div>
        </div>

        <div class="field-row">
          <div>
            <div class="field-label">Launch Voltes IIV at Login</div>
            <div class="field-sub">Keep Voltes IIV ready in your macOS Menu Bar whenever you start your Mac.</div>
          </div>
          <div class="field-actions">
            <label class="switch">
              <input type="checkbox" ${info.launch_at_login ? 'checked' : ''} onchange="handleToggleLogin(this)">
              <span class="slider"></span>
            </label>
          </div>
        </div>
      </div>

      <div class="section-heading">macOS Permissions & Auto-Type</div>
      <div class="group-card">
        <div class="field-row">
          <div>
            <div class="field-label">
              Accessibility Permission
              <span class="status-pill ${granted ? '' : 'warn'}" style="margin-left:8px;">
                ${granted ? '✓ Granted' : 'Action Required'}
              </span>
            </div>
            <div class="field-sub">Required for <b>⌘⇧L</b> Quick-Fill and Auto-Type to type passwords into browsers.</div>
          </div>
          <div class="field-actions">
            <button class="pill-btn" onclick="pywebview.api.open_accessibility_settings()">Open Panel</button>
            <button class="pill-btn" onclick="openSettings()">Refresh</button>
          </div>
        </div>

        <div class="field-row">
          <div>
            <div class="field-label">Press Enter After Auto-Type</div>
            <div class="field-sub">Automatically submit login forms after typing Username and Password.</div>
          </div>
          <div class="field-actions">
            <label class="switch">
              <input type="checkbox" ${appSettings.auto_submit ? 'checked' : ''} onchange="savePref('auto_submit', this.checked)">
              <span class="slider"></span>
            </label>
          </div>
        </div>
      </div>

      <div class="section-heading">Security & Auto-Lock</div>
      <div class="group-card">
        <div class="field-row">
          <div>
            <div class="field-label">Auto-Lock Inactivity Timer</div>
            <div class="field-sub">Automatically lock the vault when idle.</div>
          </div>
          <div class="field-actions">
            <select class="apple-select" onchange="savePref('auto_lock_seconds', Number(this.value))">
              <option value="60" ${appSettings.auto_lock_seconds===60?'selected':''}>1 minute</option>
              <option value="180" ${appSettings.auto_lock_seconds===180?'selected':''}>3 minutes</option>
              <option value="300" ${appSettings.auto_lock_seconds===300?'selected':''}>5 minutes</option>
              <option value="600" ${appSettings.auto_lock_seconds===600?'selected':''}>10 minutes</option>
              <option value="0" ${appSettings.auto_lock_seconds===0?'selected':''}>Never</option>
            </select>
          </div>
        </div>

        <div class="field-row">
          <div>
            <div class="field-label">Clear Clipboard Automatically</div>
            <div class="field-sub">Wipe copied passwords from macOS clipboard after delay.</div>
          </div>
          <div class="field-actions">
            <select class="apple-select" onchange="savePref('clear_clipboard_seconds', Number(this.value))">
              <option value="10" ${appSettings.clear_clipboard_seconds===10?'selected':''}>10 seconds</option>
              <option value="20" ${appSettings.clear_clipboard_seconds===20?'selected':''}>20 seconds</option>
              <option value="60" ${appSettings.clear_clipboard_seconds===60?'selected':''}>1 minute</option>
              <option value="0" ${appSettings.clear_clipboard_seconds===0?'selected':''}>Never</option>
            </select>
          </div>
        </div>
      </div>

      <div class="section-heading">Change Master Password</div>
      <div class="group-card" style="padding:18px;">
        <div class="form-group">
          <label>Current Master Password</label>
          <input id="cp-current" type="password" class="apple-input" placeholder="Current Master Password" />
        </div>
        <div class="form-group">
          <label>New Master Password (min 8 characters)</label>
          <input id="cp-new" type="password" class="apple-input" placeholder="New Master Password" />
        </div>
        <button class="btn-primary" style="width:190px;" onclick="submitChangeMasterPw()">Update Master Password</button>
      </div>
    `;
  }

  async function handleImportCSV() {
    const res = await pywebview.api.import_csv_file();
    if (!res) return;
    if (res.ok) {
      entries = res.entries;
      renderSidebar();
      showToast(`Imported ${res.imported} logins (${res.skipped} skipped)`);
    } else if (res.error) {
      showToast(res.error);
    }
  }

  async function handleChooseSyncFolder() {
    const res = await pywebview.api.choose_sync_folder();
    if (!res) return;
    if (res.ok) {
      entries = res.entries;
      renderSidebar();
      const lbl = document.getElementById("sync-path-label");
      if (lbl) lbl.textContent = res.vault_path;
      showToast(res.message);
    } else if (res.error) {
      showToast(res.error);
    }
  }

  async function handleResetSyncFolder() {
    const res = await pywebview.api.reset_sync_folder();
    if (res && res.ok) {
      const lbl = document.getElementById("sync-path-label");
      if (lbl) lbl.textContent = res.vault_path;
      showToast(res.message);
    }
  }

  async function handleToggleTouchID(el) {
    const res = await pywebview.api.toggle_touch_id(el.checked);
    if (res.ok) {
      appSettings.touch_id_enabled = res.enabled;
      showToast(res.enabled ? "Biometric unlock enabled" : "Biometric unlock disabled");
    } else {
      el.checked = !el.checked;
      showToast(res.error || "Could not update Touch ID");
    }
  }

  async function handleToggleLogin(el) {
    const res = await pywebview.api.toggle_launch_at_login(el.checked);
    if (res.ok) {
      showToast(res.enabled ? "Will launch at login" : "Removed from login items");
    }
  }

  async function savePref(key, value) {
    appSettings[key] = value;
    await pywebview.api.update_settings({ [key]: value });
    showToast("Settings updated");
  }

  async function submitChangeMasterPw() {
    const cur = document.getElementById("cp-current").value;
    const nxt = document.getElementById("cp-new").value;
    const res = await pywebview.api.change_master_password(cur, nxt);
    if (res.ok) {
      document.getElementById("cp-current").value = "";
      document.getElementById("cp-new").value = "";
      showToast("Master Password updated & vault re-encrypted");
    } else {
      showToast(res.error || "Failed to update Master Password");
    }
  }

  function openForm(editIdx = null, prefillPassword = "") {
    setNavHighlight("form");
    const item = editIdx !== null
      ? entries[editIdx]
      : { title: "", username: "", password: prefillPassword || "", url: "", totp: "", notes: "", favorite: false };
    const pane = document.getElementById("main-content");
    pane.innerHTML = `
      <div class="detail-top">
        <div class="detail-title">${editIdx !== null ? "Edit Login" : "New Login"}</div>
      </div>
      <div class="group-card" style="padding:20px;">
        <div class="form-group">
          <label>Title</label>
          <input id="f-title" class="apple-input" placeholder="e.g. Apple ID, GitHub" value="${escapeAttr(item.title)}" />
        </div>
        <div class="form-group">
          <label>Username or Email</label>
          <input id="f-user" class="apple-input" placeholder="name@example.com" value="${escapeAttr(item.username)}" />
        </div>
        <div class="form-group">
          <label>Password</label>
          <div class="pw-gen-row">
            <input id="f-pw" class="apple-input mono" placeholder="Strong password" value="${escapeAttr(item.password)}" />
            <button class="pill-btn" style="height:38px; padding:0 12px;" onclick="genFormPw('random')">Random</button>
            <button class="pill-btn" style="height:38px; padding:0 12px;" onclick="genFormPw('memorable')">Passphrase</button>
          </div>
          <div class="gen-opts">
            <span>Length: <b id="gen-len-val">20</b></span>
            <input id="gen-len" type="range" min="12" max="40" value="20" oninput="document.getElementById('gen-len-val').textContent=this.value" />
            <label style="display:flex; align-items:center; gap:5px; margin:0; cursor:pointer;">
              <input id="gen-num" type="checkbox" checked /> Numbers
            </label>
            <label style="display:flex; align-items:center; gap:5px; margin:0; cursor:pointer;">
              <input id="gen-sym" type="checkbox" checked /> Symbols
            </label>
          </div>
        </div>
        <div class="form-group">
          <label>Website URL (Optional)</label>
          <input id="f-url" class="apple-input" placeholder="https://example.com" value="${escapeAttr(item.url || "")}" />
        </div>
        <div class="form-group">
          <label>2FA Secret Key (Optional Base32 TOTP)</label>
          <input id="f-totp" class="apple-input mono" placeholder="JBSWY3DPEHPK3PXP" value="${escapeAttr(item.totp || "")}" />
        </div>
        <div class="form-group" style="margin-bottom:0;">
          <label>Notes</label>
          <textarea id="f-notes" class="apple-input" placeholder="Recovery codes or security notes...">${escapeHtml(item.notes || "")}</textarea>
        </div>
      </div>
      <div style="display:flex; gap:10px;">
        <button class="btn-primary" style="width:150px;" onclick="saveForm(${editIdx})">Save Encrypted</button>
        <button class="pill-btn" style="height:38px; padding:0 16px;" onclick="renderDetail()">Cancel</button>
      </div>
    `;
  }

  async function genFormPw(mode) {
    const len = Number(document.getElementById("gen-len").value || 20);
    const num = Boolean(document.getElementById("gen-num").checked);
    const sym = Boolean(document.getElementById("gen-sym").checked);
    const res = await pywebview.api.generate_password({
      mode,
      length: len,
      numbers: num,
      symbols: sym,
      words: 4,
      separator: "-",
      capitalize: true,
      include_number: true
    });
    document.getElementById("f-pw").value = res.password;
  }

  async function saveForm(editIdx) {
    const title = document.getElementById("f-title").value.trim();
    const password = document.getElementById("f-pw").value;
    if (!title || !password) { showToast("Title and Password are required"); return; }

    const existingFav = editIdx !== null && entries[editIdx] ? Boolean(entries[editIdx].favorite) : false;
    const record = {
      title,
      username: document.getElementById("f-user").value.trim(),
      password,
      url: document.getElementById("f-url").value.trim(),
      totp: document.getElementById("f-totp").value.trim(),
      notes: document.getElementById("f-notes").value.trim(),
      favorite: existingFav,
    };
    const res = await pywebview.api.save_entry(editIdx, record);
    if (res.ok) {
      entries = res.entries;
      activeIndex = res.activeIndex;
      renderSidebar();
      renderDetail();
      showToast("Saved & encrypted");
    }
  }

  async function deleteItem(idx) {
    const res = await pywebview.api.delete_entry(idx);
    if (res.ok) {
      entries = res.entries;
      const s = getSortedIndices();
      activeIndex = s.length > 0 ? s[0] : null;
      renderSidebar();
      renderDetail();
      showToast("Deleted");
    }
  }

  async function copyField(key) {
    const val = entries[activeIndex][key];
    if (!val) return;
    await pywebview.api.copy_to_clipboard(val);
    showToast("Copied to clipboard");
  }

  async function copyTotp() {
    const res = await pywebview.api.get_totp(entries[activeIndex].totp);
    if (res && res.code !== "INVALID") {
      await pywebview.api.copy_to_clipboard(res.code);
      showToast("2FA code copied");
    }
  }

  async function exportBackup() {
    const res = await pywebview.api.export_backup();
    if (res && res.ok) showToast("Encrypted backup saved");
  }

  function escapeHtml(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function escapeAttr(s) {
    return escapeHtml(s).replace(/'/g, "&#39;");
  }
</script>
</body>
</html>
"""


class MenuBarDelegate(NSObject):
    def initWithWindow_(self, window):
        self = super().init()
        self.window = window
        return self

    def openVault_(self, sender):
        app = NSApplication.sharedApplication()
        app.unhide_(None)
        app.activateIgnoringOtherApps_(True)
        self.window.show()

    def quickFill_(self, sender):
        app = NSApplication.sharedApplication()
        app.unhide_(None)
        app.activateIgnoringOtherApps_(True)
        self.window.show()
        self.window.evaluate_js("window.triggerQuickFillFromSystem()")

    def openSettings_(self, sender):
        app = NSApplication.sharedApplication()
        app.unhide_(None)
        app.activateIgnoringOtherApps_(True)
        self.window.show()
        self.window.evaluate_js("window.openSettingsFromSystem()")

    def lockNow_(self, sender):
        self.window.evaluate_js("lockVault()")


def setup_system_integration(window):
    app = NSApplication.sharedApplication()
    if ICON_PATH.exists():
        icon = NSImage.alloc().initWithContentsOfFile_(str(ICON_PATH))
        if icon:
            app.setApplicationIconImage_(icon)

    status_bar = NSStatusBar.systemStatusBar()
    status_item = status_bar.statusItemWithLength_(NSVariableStatusItemLength)
    status_item.button().setTitle_("🔒 IIV")

    delegate = MenuBarDelegate.alloc().initWithWindow_(window)
    window._status_item = status_item
    window._menu_delegate = delegate

    menu = NSMenu.alloc().init()
    item_open = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_("Open Voltes IIV", "openVault:", "")
    item_open.setTarget_(delegate)
    menu.addItem_(item_open)

    item_qf = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_("Quick Fill (⌘⇧L)", "quickFill:", "")
    item_qf.setTarget_(delegate)
    menu.addItem_(item_qf)

    item_set = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_("Settings...", "openSettings:", ",")
    item_set.setTarget_(delegate)
    menu.addItem_(item_set)

    menu.addItem_(NSMenuItem.separatorItem())

    item_lock = NSMenuItem.alloc().initWithTitle_action_keyEquivalent_("Lock Vault", "lockNow:", "")
    item_lock.setTarget_(delegate)
    menu.addItem_(item_lock)

    status_item.setMenu_(menu)

    def on_hotkey():
        AppHelper.callAfter(lambda: delegate.quickFill_(None))

    listener = keyboard.GlobalHotKeys({"<cmd>+<shift>+l": on_hotkey})
    listener.daemon = True
    listener.start()


if __name__ == "__main__":
    api = VaultAPI()
    window = webview.create_window(
        "Voltes IIV",
        html=HTML_UI,
        js_api=api,
        width=940,
        height=650,
        min_size=(780, 520),
        background_color="#161618",
        hidden=False,
    )
    api.set_window(window)
    webview.start(setup_system_integration, window)
