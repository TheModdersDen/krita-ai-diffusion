from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import os
import platform
import secrets
import uuid

from .util import client_logger as log
from .util import user_data_dir

SERVICE_NAME = "KritaAIDiffusion"


# ---------------------------------------------------------------------------
# Pure Python RFC 7539 ChaCha20 Cipher Implementation
# ---------------------------------------------------------------------------
def _quarter_round(x: list[int], a: int, b: int, c: int, d: int):
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] = x[d] ^ x[a]
    x[d] = ((x[d] << 16) | (x[d] >> 16)) & 0xFFFFFFFF

    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] = x[b] ^ x[c]
    x[b] = ((x[b] << 12) | (x[b] >> 20)) & 0xFFFFFFFF

    x[a] = (x[a] + x[b]) & 0xFFFFFFFF
    x[d] = x[d] ^ x[a]
    x[d] = ((x[d] << 8) | (x[d] >> 24)) & 0xFFFFFFFF

    x[c] = (x[c] + x[d]) & 0xFFFFFFFF
    x[b] = x[b] ^ x[c]
    x[b] = ((x[b] << 7) | (x[b] >> 25)) & 0xFFFFFFFF


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    key_words = [int.from_bytes(key[i : i + 4], "little") for i in range(0, 32, 4)]
    nonce_words = [int.from_bytes(nonce[i : i + 4], "little") for i in range(0, 12, 4)]

    state = constants + key_words + [counter] + nonce_words
    initial_state = list(state)

    for _ in range(10):  # 20 rounds (10 iterations of column + diagonal rounds)
        # Column round
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        # Diagonal round
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)

    out = [(state[i] + initial_state[i]) & 0xFFFFFFFF for i in range(16)]
    return b"".join(x.to_bytes(4, "little") for x in out)


def chacha20_crypt(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """Encrypts or decrypts data using ChaCha20 stream cipher."""
    res = bytearray()
    for block_num in range((len(data) + 63) // 64):
        keystream = _chacha20_block(key, block_num, nonce)
        block = data[block_num * 64 : (block_num + 1) * 64]
        res.extend(b1 ^ b2 for b1, b2 in zip(block, keystream))
    return bytes(res)


# ---------------------------------------------------------------------------
# Key Derivation & File Helpers
# ---------------------------------------------------------------------------
def _get_machine_fingerprint() -> bytes:
    try:
        parts = [
            str(uuid.getnode()),
            platform.system(),
            platform.machine(),
            getpass.getuser(),
        ]
        return "|".join(parts).encode("utf-8")
    except Exception as e:
        log.warning(f"Failed to generate machine fingerprint: {e}")
        return b"default_fallback_machine_fingerprint_for_krita_ai_diffusion"


def _get_or_create_master_seed() -> bytes:
    """Gets or creates a 32-byte master key seed, preferring keyring storage."""
    # 1. Try to read from keyring
    try:
        import keyring

        key = keyring.get_password(SERVICE_NAME, "master_seed")
        if key:
            return base64.b64decode(key.encode("utf-8"))
    except (ImportError, Exception):  # noqa: S110
        pass

    # 2. Fall back to local key file mixed with machine fingerprint
    key_file = user_data_dir / ".key"
    if not key_file.exists():
        seed = secrets.token_bytes(32)
        try:
            key_file.write_bytes(seed)
            try:
                os.chmod(key_file, 0o600)
            except Exception:  # noqa: S110
                pass
        except Exception as e:
            log.warning(f"Could not write secure key file: {e}")
            seed = b"default_fallback_seed_for_krita_ai_diffusion"
    else:
        try:
            seed = key_file.read_bytes()
        except Exception as e:
            log.warning(f"Could not read secure key file: {e}")
            seed = b"default_fallback_seed_for_krita_ai_diffusion"

    fingerprint = _get_machine_fingerprint()
    derived = hashlib.pbkdf2_hmac("sha256", seed, fingerprint, 10000)

    # 3. Try to save back to keyring so we have it there next time
    try:
        import keyring

        keyring.set_password(SERVICE_NAME, "master_seed", base64.b64encode(derived).decode("utf-8"))
    except (ImportError, Exception):  # noqa: S110
        pass

    return derived


# ---------------------------------------------------------------------------
# Public Encryption & Decryption API
# ---------------------------------------------------------------------------
def encrypt_token(token: str) -> str:
    """Encrypts plaintext token and returns a prefixed base64 string."""
    if not token:
        return ""
    if token.startswith("enc:chacha:"):
        return token

    try:
        seed = _get_or_create_master_seed()
        enc_key = hmac.digest(seed, b"encryption_key_derivation", "sha256")
        mac_key = hmac.digest(seed, b"mac_key_derivation", "sha256")

        nonce = secrets.token_bytes(12)
        ciphertext = chacha20_crypt(token.encode("utf-8"), enc_key, nonce)
        mac = hmac.digest(mac_key, nonce + ciphertext, "sha256")

        payload = nonce + ciphertext + mac
        encoded = base64.b64encode(payload).decode("utf-8")
        return f"enc:chacha:{encoded}"
    except Exception as e:
        log.error(f"Failed to encrypt token: {e}")
        return token


def decrypt_token(token: str) -> str:
    """Decrypts a prefixed token string. Returns plaintext unmodified."""
    if not token or not token.startswith("enc:chacha:"):
        return token

    try:
        seed = _get_or_create_master_seed()
        encrypted_part = token[len("enc:chacha:") :]
        payload = base64.b64decode(encrypted_part.encode("utf-8"))

        if len(payload) < 44:  # 12 bytes nonce + 0+ bytes ciphertext + 32 bytes MAC
            raise ValueError("Invalid encrypted payload length")

        nonce = payload[:12]
        ciphertext = payload[12:-32]
        expected_mac = payload[-32:]

        enc_key = hmac.digest(seed, b"encryption_key_derivation", "sha256")
        mac_key = hmac.digest(seed, b"mac_key_derivation", "sha256")

        actual_mac = hmac.digest(mac_key, nonce + ciphertext, "sha256")
        if not hmac.compare_digest(actual_mac, expected_mac):
            raise ValueError("MAC verification failed. Payload is corrupted or key is incorrect.")

        decrypted = chacha20_crypt(ciphertext, enc_key, nonce)
        return decrypted.decode("utf-8")
    except Exception as e:
        log.error(f"Failed to decrypt token: {e}")
        return ""
