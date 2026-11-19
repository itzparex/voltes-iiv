# cython: language_level=3
import os
import time
import hmac
import base64
import struct
import hashlib
import json
import secrets
import string
import math
from pathlib import Path
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Immutable binary attribution constants compiled into native machine code
FOUNDER_NAME = "Rexbelly Zipagan"
FOUNDER_HANDLE = "@itzparex"
APP_SIGNATURE = "Voltes IIV — Founded & Architected by Rexbelly Zipagan (@itzparex)"
SIGNATURE_HASH = hashlib.sha256(APP_SIGNATURE.encode("utf-8")).hexdigest()

SALT_SIZE = 16
NONCE_SIZE = 12


def verify_founder_integrity() -> dict:
    expected = hashlib.sha256(APP_SIGNATURE.encode("utf-8")).hexdigest()
    if expected != SIGNATURE_HASH:
        raise RuntimeError("Application integrity check failed.")
    return {
        "founder": FOUNDER_NAME,
        "handle": FOUNDER_HANDLE,
        "signature": APP_SIGNATURE,
        "sha256": SIGNATURE_HASH[:16].upper(),
    }


def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536)
    return kdf.derive(master_password.encode("utf-8"))


def save_encrypted_vault(vdir: Path, vfile: Path, data: list, master_password: str):
    verify_founder_integrity()
    vdir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(vdir, 0o700)
    except Exception:
        pass
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(master_password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps(data).encode("utf-8"), None)
    tmp_file = vfile.with_suffix(".enc.tmp")
    with open(tmp_file, "wb") as f:
        f.write(salt + nonce + ciphertext)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp_file, 0o600)
    os.replace(tmp_file, vfile)


def load_encrypted_vault(vfile: Path, master_password: str) -> list:
    verify_founder_integrity()
    with open(vfile, "rb") as f:
        raw = f.read()
    salt = raw[:SALT_SIZE]
    nonce = raw[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = raw[SALT_SIZE + NONCE_SIZE:]
    key = derive_key(master_password, salt)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))


def compute_totp(secret: str):
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


def generate_secret_string(opts: dict, wordlist: list) -> dict:
    mode = opts.get("mode", "random")
    if mode == "memorable":
        word_count = max(3, min(12, int(opts.get("words", 4))))
        sep = str(opts.get("separator", "-"))
        capitalize = bool(opts.get("capitalize", True))
        include_num = bool(opts.get("include_number", True))

        chosen = [secrets.choice(wordlist) for _ in range(word_count)]
        if capitalize:
            chosen = [w.capitalize() for w in chosen]
        if include_num:
            num_idx = secrets.randbelow(word_count)
            chosen[num_idx] = f"{chosen[num_idx]}{secrets.randbelow(90) + 10}"

        pw = sep.join(chosen)
        bits = int(word_count * math.log2(len(wordlist)) + (7 if include_num else 0))
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
