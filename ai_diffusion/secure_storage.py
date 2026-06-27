from __future__ import annotations

import platform
import subprocess

from .util import client_logger as log

SERVICE_NAME = "KritaAIDiffusion"
USERNAME = "comfyui_auth"


# ---------------------------------------------------------------------------
# Windows Native Credential Manager via ctypes
# ---------------------------------------------------------------------------
def _save_win32_cred(target: str, username: str, secret: str) -> bool:
    try:
        import ctypes
        from ctypes import wintypes

        class CREDENTIALW(ctypes.Structure):
            _fields_ = [
                ("Flags", wintypes.DWORD),
                ("Type", wintypes.DWORD),
                ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR),
                ("LastWritten", wintypes.FILETIME),
                ("CredentialBlobSize", wintypes.DWORD),
                ("CredentialBlob", ctypes.c_void_p),
                ("Persist", wintypes.DWORD),
                ("AttributeCount", wintypes.DWORD),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR),
            ]

        CRED_TYPE_GENERIC = 1
        CRED_PERSIST_LOCAL_MACHINE = 2

        secret_bytes = secret.encode("utf-16le")
        cred = CREDENTIALW()
        cred.Flags = 0
        cred.Type = CRED_TYPE_GENERIC
        cred.TargetName = target
        cred.Comment = "Krita AI Diffusion Token"
        cred.CredentialBlobSize = len(secret_bytes)
        cred.CredentialBlob = ctypes.cast(
            ctypes.create_string_buffer(secret_bytes), ctypes.c_void_p
        )
        cred.Persist = CRED_PERSIST_LOCAL_MACHINE
        cred.UserName = username
        cred.AttributeCount = 0
        cred.Attributes = None
        cred.TargetAlias = None

        advapi32 = ctypes.windll.advapi32
        if advapi32.CredWriteW(ctypes.byref(cred), 0):
            return True
        else:
            log.warning(f"Windows CredWriteW failed: {ctypes.WinError()}")
    except Exception as e:
        log.warning(f"Failed to write Windows credential: {e}")
    return False


def _load_win32_cred(target: str) -> str | None:
    try:
        import ctypes
        from ctypes import wintypes

        class CREDENTIALW(ctypes.Structure):
            _fields_ = [
                ("Flags", wintypes.DWORD),
                ("Type", wintypes.DWORD),
                ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR),
                ("LastWritten", wintypes.FILETIME),
                ("CredentialBlobSize", wintypes.DWORD),
                ("CredentialBlob", ctypes.c_void_p),
                ("Persist", wintypes.DWORD),
                ("AttributeCount", wintypes.DWORD),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR),
            ]

        CRED_TYPE_GENERIC = 1

        advapi32 = ctypes.windll.advapi32
        cred_ptr = ctypes.POINTER(CREDENTIALW)()
        if advapi32.CredReadW(target, CRED_TYPE_GENERIC, 0, ctypes.byref(cred_ptr)):
            try:
                cred = cred_ptr.contents
                blob = ctypes.string_at(cred.CredentialBlob, cred.CredentialBlobSize)
                return blob.decode("utf-16le")
            finally:
                advapi32.CredFree(cred_ptr)
    except Exception as e:
        log.warning(f"Failed to read Windows credential: {e}")
    return None


def _delete_win32_cred(target: str) -> bool:
    try:
        import ctypes

        CRED_TYPE_GENERIC = 1
        advapi32 = ctypes.windll.advapi32
        if advapi32.CredDeleteW(target, CRED_TYPE_GENERIC, 0):
            return True
    except Exception as e:
        log.warning(f"Failed to delete Windows credential: {e}")
    return False


# ---------------------------------------------------------------------------
# macOS Native Keychain via subprocess (security CLI)
# ---------------------------------------------------------------------------
def _save_macos_cred(service: str, username: str, secret: str) -> bool:
    try:
        # -U updates the password if it already exists, -a is account, -s is service
        subprocess.run(
            ["security", "add-generic-password", "-a", username, "-s", service, "-w", secret, "-U"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception as e:
        log.warning(f"Failed to write macOS Keychain credential: {e}")
    return False


def _load_macos_cred(service: str, username: str) -> str | None:
    try:
        output = subprocess.check_output(
            ["security", "find-generic-password", "-a", username, "-s", service, "-w"],
            stderr=subprocess.DEVNULL,
        )
        return output.decode("utf-8").strip()
    except Exception as e:
        log.warning(f"Failed to read macOS Keychain credential: {e}")
    return None


def _delete_macos_cred(service: str, username: str) -> bool:
    try:
        subprocess.run(
            ["security", "delete-generic-password", "-a", username, "-s", service],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception as e:
        log.warning(f"Failed to delete macOS Keychain credential: {e}")
    return False


# ---------------------------------------------------------------------------
# Linux Native Secret Service via subprocess (secret-tool CLI)
# ---------------------------------------------------------------------------
def _save_linux_cred(service: str, username: str, secret: str) -> bool:
    try:
        subprocess.run(
            [
                "secret-tool",
                "store",
                f"--label={SERVICE_NAME} Token",
                "service",
                service,
                "username",
                username,
            ],
            input=secret.encode("utf-8"),
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception as e:
        log.warning(f"Failed to write Linux Secret Service credential: {e}")
    return False


def _load_linux_cred(service: str, username: str) -> str | None:
    try:
        output = subprocess.check_output(
            ["secret-tool", "lookup", "service", service, "username", username],
            stderr=subprocess.DEVNULL,
        )
        return output.decode("utf-8").strip()
    except Exception:  # noqa: S110
        # Failure to find the credential is normal if it doesn't exist yet
        pass
    return None


def _delete_linux_cred(service: str, username: str) -> bool:
    try:
        subprocess.run(
            ["secret-tool", "clear", "service", service, "username", username],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception as e:
        log.warning(f"Failed to delete Linux Secret Service credential: {e}")
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def save_token(token: str) -> bool:
    """Stores the authentication token securely in the native OS keyring."""
    if not token:
        return delete_token()

    # 1. Try python-keyring library if available
    try:
        import keyring

        keyring.set_password(SERVICE_NAME, USERNAME, token)
        return True
    except (ImportError, Exception):  # noqa: S110
        pass

    # 2. Fallback to native OS-specific implementations
    sys_plat = platform.system()
    if sys_plat == "Windows":
        return _save_win32_cred(SERVICE_NAME, USERNAME, token)
    elif sys_plat == "Darwin":
        return _save_macos_cred(SERVICE_NAME, USERNAME, token)
    elif sys_plat == "Linux":
        return _save_linux_cred(SERVICE_NAME, USERNAME, token)

    log.warning(f"Platform {sys_plat} is not supported for secure token storage.")
    return False


def load_token() -> str:
    """Loads the authentication token from the secure native OS keyring."""
    # 1. Try python-keyring library if available
    try:
        import keyring

        val = keyring.get_password(SERVICE_NAME, USERNAME)
        if val is not None:
            return val
    except (ImportError, Exception):  # noqa: S110
        pass

    # 2. Fallback to native OS-specific implementations
    sys_plat = platform.system()
    if sys_plat == "Windows":
        val = _load_win32_cred(SERVICE_NAME)
        if val is not None:
            return val
    elif sys_plat == "Darwin":
        val = _load_macos_cred(SERVICE_NAME, USERNAME)
        if val is not None:
            return val
    elif sys_plat == "Linux":
        val = _load_linux_cred(SERVICE_NAME, USERNAME)
        if val is not None:
            return val

    return ""


def delete_token() -> bool:
    """Deletes the authentication token from the secure native OS keyring."""
    # 1. Try python-keyring library if available
    deleted = False
    try:
        import keyring

        keyring.delete_password(SERVICE_NAME, USERNAME)
        deleted = True
    except (ImportError, Exception):  # noqa: S110
        pass

    # 2. Fallback to native OS-specific implementations
    sys_plat = platform.system()
    if sys_plat == "Windows":
        deleted = _delete_win32_cred(SERVICE_NAME) or deleted
    elif sys_plat == "Darwin":
        deleted = _delete_macos_cred(SERVICE_NAME, USERNAME) or deleted
    elif sys_plat == "Linux":
        deleted = _delete_linux_cred(SERVICE_NAME, USERNAME) or deleted

    return deleted
