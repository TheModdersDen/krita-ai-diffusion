from __future__ import annotations

import platform
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from ai_diffusion.secure_storage import (
    SERVICE_NAME,
    USERNAME,
    delete_token,
    load_token,
    save_token,
)


# ---------------------------------------------------------------------------
# Test Keyring Library Integration
# ---------------------------------------------------------------------------
def test_keyring_integration_success():
    mock_keyring = MagicMock()
    with patch.dict(sys.modules, {"keyring": mock_keyring}):
        assert save_token("test-token-keyring") is True
        mock_keyring.set_password.assert_called_once_with(
            SERVICE_NAME, USERNAME, "test-token-keyring"
        )

        mock_keyring.get_password.return_value = "retrieved-token"
        assert load_token() == "retrieved-token"
        mock_keyring.get_password.assert_called_once_with(SERVICE_NAME, USERNAME)

        assert delete_token() is True
        mock_keyring.delete_password.assert_called_once_with(SERVICE_NAME, USERNAME)


def test_keyring_import_error_falls_back():
    # Hide keyring module to trigger native fallbacks
    with patch.dict(sys.modules, {"keyring": None}):
        sys_plat = platform.system()
        if sys_plat == "Windows":
            # Test real Windows Credential Manager ctypes integration
            try:
                assert save_token("win32-test-token") is True
                assert load_token() == "win32-test-token"
                assert delete_token() is True
                assert load_token() == ""
            except Exception as e:
                pytest.fail(f"Windows native credential storage failed: {e}")

        elif sys_plat == "Darwin":
            # Mock subprocess for macOS
            with (
                patch("subprocess.run") as mock_run,
                patch("subprocess.check_output") as mock_check,
            ):
                mock_check.return_value = b"macos-test-token\n"

                assert save_token("macos-test-token") is True
                mock_run.assert_called_with(
                    [
                        "security",
                        "add-generic-password",
                        "-a",
                        USERNAME,
                        "-s",
                        SERVICE_NAME,
                        "-w",
                        "macos-test-token",
                        "-U",
                    ],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

                assert load_token() == "macos-test-token"
                mock_check.assert_called_with(
                    ["security", "find-generic-password", "-a", USERNAME, "-s", SERVICE_NAME, "-w"],
                    stderr=subprocess.DEVNULL,
                )

                assert delete_token() is True
                mock_run.assert_called_with(
                    ["security", "delete-generic-password", "-a", USERNAME, "-s", SERVICE_NAME],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

        elif sys_plat == "Linux":
            # Mock subprocess for Linux
            with (
                patch("subprocess.run") as mock_run,
                patch("subprocess.check_output") as mock_check,
            ):
                mock_check.return_value = b"linux-test-token\n"

                assert save_token("linux-test-token") is True
                mock_run.assert_called_with(
                    [
                        "secret-tool",
                        "store",
                        f"--label={SERVICE_NAME} Token",
                        "service",
                        SERVICE_NAME,
                        "username",
                        USERNAME,
                    ],
                    input=b"linux-test-token",
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

                assert load_token() == "linux-test-token"
                mock_check.assert_called_with(
                    ["secret-tool", "lookup", "service", SERVICE_NAME, "username", USERNAME],
                    stderr=subprocess.DEVNULL,
                )

                assert delete_token() is True
                mock_run.assert_called_with(
                    ["secret-tool", "clear", "service", SERVICE_NAME, "username", USERNAME],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
