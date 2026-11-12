"""Credential configuration for one explicitly selected Pixsee login profile.

Precedence is explicit keyword overrides > PIXSEE_* environment variables > JSON
file > profile defaults. Within JSON, ``password``/``auth_key`` take precedence
over the app's ``newPassword``/``newAuthKey`` aliases. An empty supplied value is
invalid; it does not silently fall back to another source or profile.

The legacy/current defaults reproduce TUTKUtils.getConfigValue in Pixsee Android
4.030.006. They are app protocol constants, not credentials discovered from a
particular camera. No profile is tried automatically. ``custom`` requires a
password and auth key supplied by the caller, environment, or file.

UID can be absent for discovery. AV account/password use UTF-8; embedded NULs and
values beyond a conservative 255-byte limit are rejected. A configuration
file should remain private and outside version control. Secret values never
appear in the dataclass repr or validation errors.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional, Union


_PROFILE_DEFAULTS = {
    "legacy": {"password": "q25k0qR5", "auth_key": "GSPmcD4c"},
    "current": {"password": "Aa123456", "auth_key": "00000000"},
    "custom": {},
}
_ENV_NAMES = {
    "uid": "PIXSEE_UID",
    "account": "PIXSEE_ACCOUNT",
    "password": "PIXSEE_PASSWORD",
    "auth_key": "PIXSEE_AUTH_KEY",
}
_MAX_CONFIG_BYTES = 64 * 1024


def _validate_text(value: object, name: str, max_bytes: int) -> None:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{name} must be a nonempty string without NUL bytes")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"{name} must contain valid UTF-8 text") from None
    if len(encoded) > max_bytes:
        raise ValueError(f"{name} must be at most {max_bytes} UTF-8 bytes")


@dataclass(frozen=True)
class PixseeCredentials:
    uid: Optional[str] = None
    account: str = "admin"
    password: str = field(default="", repr=False)
    auth_key: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        if self.uid is not None and (
            not isinstance(self.uid, str)
            or re.fullmatch(r"[A-Za-z0-9]{1,20}", self.uid) is None
        ):
            raise ValueError("uid must be 1 to 20 ASCII letters or digits, or absent")
        _validate_text(self.account, "account", 255)
        _validate_text(self.password, "password", 255)
        if not isinstance(self.auth_key, str) or re.fullmatch(
            r"[A-Za-z0-9]{8}", self.auth_key
        ) is None:
            raise ValueError("auth_key must be exactly 8 ASCII letters or digits")


def credentials_for_profile(
    profile: str = "legacy",
    *,
    uid: Optional[str] = None,
    account: Optional[str] = None,
    password: Optional[str] = None,
    auth_key: Optional[str] = None,
) -> PixseeCredentials:
    """Resolve one profile with explicit overrides; never attempt a connection.

    ``None`` means no override. In particular, omitting UID permits a discovery
    command to run before the device identity is known.
    """
    if not isinstance(profile, str) or profile not in _PROFILE_DEFAULTS:
        raise ValueError("profile must be legacy, current, or custom")
    values = {"uid": uid, "account": "admin", **_PROFILE_DEFAULTS[profile]}
    for name, value in (
        ("account", account), ("password", password), ("auth_key", auth_key)
    ):
        if value is not None:
            values[name] = value
    if "password" not in values or "auth_key" not in values:
        raise ValueError("custom profile requires both password and auth_key")
    return PixseeCredentials(**values)


def _read_config(config_path: Union[str, os.PathLike]) -> dict:
    # Bounded reads prevent a mistaken APK/video path from loading into memory.
    with Path(config_path).open("rb") as handle:
        data = handle.read(_MAX_CONFIG_BYTES + 1)
    if len(data) > _MAX_CONFIG_BYTES:
        raise ValueError("credential JSON exceeds the 64 KiB size limit")
    try:
        values = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ValueError("credential file must contain valid UTF-8 JSON") from None
    if not isinstance(values, dict):
        raise ValueError("credential JSON must be an object")
    known = set(_ENV_NAMES) | {"newPassword", "newAuthKey", "newAvToken"}
    if set(values) - known:
        raise ValueError("credential JSON contains an unsupported field")
    result = {}
    for direct, alias in (("password", "newPassword"), ("auth_key", "newAuthKey")):
        if direct in values:
            result[direct] = values[direct]
        elif alias in values:
            result[direct] = values[alias]
    for name in ("uid", "account"):
        if name in values:
            result[name] = values[name]
    # newAvToken is deliberately ignored: the inspected app uses auth_type=0.
    return result


def load_credentials(
    *,
    profile: str = "custom",
    config_path: Optional[Union[str, os.PathLike]] = None,
    environ: Optional[Mapping[str, str]] = None,
    uid: Optional[str] = None,
    account: Optional[str] = None,
    password: Optional[str] = None,
    auth_key: Optional[str] = None,
) -> PixseeCredentials:
    """Load and validate credentials using the precedence documented above.

    Pass ``environ={}`` to ignore the process environment. Explicit ``None``
    arguments mean no override. JSON ``uid: null`` means absent; other null
    credential values are errors, even when profile defaults exist.
    """
    values = _read_config(config_path) if config_path is not None else {}
    environment = os.environ if environ is None else environ
    for name, variable in _ENV_NAMES.items():
        if variable in environment:
            values[name] = environment[variable]
    for name, value in (
        ("uid", uid), ("account", account), ("password", password), ("auth_key", auth_key)
    ):
        if value is not None:
            values[name] = value
    for name, value in values.items():
        if value is None and name != "uid":
            raise ValueError(f"{name} must not be null")
    return credentials_for_profile(profile, **values)


def profile_for_firmware(
    version: Optional[Union[str, int]], *, is_pixsee_play: bool = False
) -> str:
    """Suggest a profile using the APK helper's exact firmware boundary.

    Accept a nonnegative encoded integer or a version string such as
    ``V1.006.013`` (the app searches for the first major.minor.patch substring).
    Missing firmware maps to legacy, as in the app. Invalid nonempty values are
    rejected rather than silently selecting credentials. This helper never
    selects or retries a profile in ``load_credentials``.
    """
    if version is None:
        return "legacy"
    if isinstance(version, str):
        match = re.search(r"(?<!\d)([0-9]+)\.([0-9]+)\.([0-9]+)(?!\d)", version)
        if match is None:
            raise ValueError("firmware must include a major.minor.patch version")
        major, minor, patch = (int(part) for part in match.groups())
        if minor > 999 or patch > 999:
            raise ValueError("firmware minor and patch components must be at most 999")
        encoded = major * 1_000_000 + minor * 1000 + patch
    elif isinstance(version, int) and not isinstance(version, bool) and version >= 0:
        encoded = version
    else:
        raise ValueError("firmware must be a version string, nonnegative integer, or absent")
    threshold = 1_002_013 if is_pixsee_play else 1_006_013
    return "legacy" if encoded <= threshold else "current"
