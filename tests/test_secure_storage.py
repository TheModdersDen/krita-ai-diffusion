from __future__ import annotations

import base64
import sys
from unittest.mock import MagicMock, patch

from ai_diffusion.secure_storage import (
    chacha20_crypt,
    decrypt_token,
    encrypt_token,
)
from ai_diffusion.settings import Settings
from ai_diffusion.util import user_data_dir


def test_chacha20_symmetry():
    key = b"0" * 32
    nonce = b"1" * 12
    plaintext = b"Hello, World! Custom ChaCha20 testing."

    ciphertext = chacha20_crypt(plaintext, key, nonce)
    assert ciphertext != plaintext

    decrypted = chacha20_crypt(ciphertext, key, nonce)
    assert decrypted == plaintext


def test_chacha20_avalanche():
    key = b"0" * 32
    nonce = b"1" * 12
    plaintext = b"Test plaintext."

    c1 = chacha20_crypt(plaintext, key, nonce)

    c2 = chacha20_crypt(plaintext, b"1" + key[1:], nonce)
    assert c1 != c2

    c3 = chacha20_crypt(plaintext, key, b"2" + nonce[1:])
    assert c1 != c3


def test_encrypt_decrypt_token_success():
    token = "my-secret-token-12345"
    encrypted = encrypt_token(token)
    assert encrypted.startswith("enc:chacha:")

    decrypted = decrypt_token(encrypted)
    assert decrypted == token


def test_decrypt_plaintext():
    plaintext = "my-unencrypted-legacy-token"
    # If no prefix is present, it should return unmodified
    assert decrypt_token(plaintext) == plaintext
    assert decrypt_token("") == ""


def test_decrypt_tampered():
    token = "sensitive-token"
    encrypted = encrypt_token(token)
    assert encrypted.startswith("enc:chacha:")

    # Tamper with the base64 content
    prefix_len = len("enc:chacha:")
    encrypted_part = encrypted[prefix_len:]
    payload = bytearray(base64.b64decode(encrypted_part))

    payload[-1] ^= 0x01  # Alter MAC
    tampered_encoded = base64.b64encode(payload).decode("utf-8")
    tampered_token = f"enc:chacha:{tampered_encoded}"

    # Decryption should fail and return empty string (logged as error internally)
    assert decrypt_token(tampered_token) == ""


def test_keyring_seed_persistence():
    mock_keyring = MagicMock()
    mock_keyring.get_password.return_value = None

    # Clear local .key file if it exists so we force regeneration
    key_file = user_data_dir / ".key"
    if key_file.exists():
        key_file.unlink()

    with patch.dict(sys.modules, {"keyring": mock_keyring}):
        # First call generates seed, saves to keyring, and returns derived key
        token = "test-token"
        enc = encrypt_token(token)
        assert enc.startswith("enc:chacha:")

        # Verify keyring set_password was called to save the master_seed
        mock_keyring.set_password.assert_called_once()
        args = mock_keyring.set_password.call_args[0]
        assert args[0] == "KritaAIDiffusion"
        assert args[1] == "master_seed"


def test_settings_integration(tmp_path):
    settings_file = tmp_path / "settings.json"

    # Create settings
    settings = Settings()
    settings.server_authorization = "super-secret-comfyui-key"
    settings.save(settings_file)

    # Read settings file directly to verify it was encrypted
    with open(settings_file) as f:
        import json

        data = json.load(f)
        saved_auth = data.get("server_authorization", "")
        assert saved_auth.startswith("enc:chacha:")

    # Load in new Settings instance to check decryption works
    new_settings = Settings()
    new_settings.load(settings_file)
    assert new_settings.server_authorization == "super-secret-comfyui-key"


def test_legacy_settings_migration(tmp_path):
    settings_file = tmp_path / "settings.json"

    # Write settings file with legacy blank authorization
    with open(settings_file, "w") as f:
        import json

        json.dump({"server_authorization": ""}, f)

    # Mock keyring to simulate a legacy saved token
    mock_keyring = MagicMock()
    mock_keyring.get_password.return_value = "legacy-stored-key"

    with patch.dict(sys.modules, {"keyring": mock_keyring}):
        settings = Settings()
        settings.load(settings_file)

        # Check migration worked
        assert settings.server_authorization == "legacy-stored-key"

        # Check legacy keyring item was deleted
        mock_keyring.delete_password.assert_called_once_with("KritaAIDiffusion", "comfyui_auth")
