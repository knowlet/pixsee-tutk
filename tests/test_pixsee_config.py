"""Offline credential validation; no camera or network access."""

import json
from pathlib import Path
import tempfile
import unittest

from pixsee_config import (
    PixseeCredentials,
    credentials_for_profile,
    load_credentials,
    profile_for_firmware,
)


class PixseeConfigTests(unittest.TestCase):
    def write_config(self, directory, value):
        path = Path(directory) / "credentials.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_explicit_profiles_match_apk_constants_and_have_optional_uid(self):
        legacy = credentials_for_profile("legacy")
        current = credentials_for_profile("current")
        self.assertIsNone(legacy.uid)
        self.assertEqual(legacy.account, "admin")
        self.assertEqual((legacy.password, legacy.auth_key), ("q25k0qR5", "GSPmcD4c"))
        self.assertEqual((current.password, current.auth_key), ("Aa123456", "00000000"))
        with self.assertRaisesRegex(ValueError, "profile"):
            credentials_for_profile("automatic")

    def test_repr_and_errors_do_not_disclose_secret_values(self):
        creds = PixseeCredentials(password="private-password", auth_key="ABCD1234")
        self.assertNotIn(creds.password, repr(creds))
        self.assertNotIn(creds.auth_key, repr(creds))
        secret = "do-not-print-this-secret"
        with self.assertRaises(ValueError) as raised:
            PixseeCredentials(password="valid", auth_key=secret)
        self.assertNotIn(secret, str(raised.exception))

    def test_complete_precedence_and_json_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_config(directory, {
                "uid": "JSONUID", "account": "json-account",
                "newPassword": "alias-password", "newAuthKey": "ALIAS123",
                "password": "direct-password", "auth_key": "DIRECT12",
                "newAvToken": "unused-token",
            })
            file_only = load_credentials(config_path=path, environ={})
            self.assertEqual(file_only.password, "direct-password")
            self.assertEqual(file_only.auth_key, "DIRECT12")
            resolved = load_credentials(
                profile="current", config_path=path,
                environ={"PIXSEE_UID": "ENVUID", "PIXSEE_ACCOUNT": "env-account",
                         "PIXSEE_PASSWORD": "env-password", "PIXSEE_AUTH_KEY": "ENVKEY12"},
                uid="CLIUID", password="explicit-password",
            )
            self.assertEqual(resolved.uid, "CLIUID")
            self.assertEqual(resolved.account, "env-account")
            self.assertEqual(resolved.password, "explicit-password")
            self.assertEqual(resolved.auth_key, "ENVKEY12")
            alias_path = self.write_config(directory, {
                "newPassword": "alias-password", "newAuthKey": "ALIAS123", "uid": None,
            })
            alias = load_credentials(config_path=alias_path, environ={})
            self.assertEqual(alias.password, "alias-password")
            self.assertEqual(alias.auth_key, "ALIAS123")
            self.assertIsNone(alias.uid)

    def test_custom_requires_both_secrets_and_does_not_fallback(self):
        for kwargs in ({}, {"password": "supplied"}, {"auth_key": "ABCDEFGH"}):
            with self.subTest(kwargs=tuple(kwargs)):
                with self.assertRaisesRegex(ValueError, "requires both"):
                    load_credentials(environ={}, **kwargs)
        with self.assertRaisesRegex(ValueError, "password"):
            load_credentials(profile="legacy", environ={"PIXSEE_PASSWORD": ""})

    def test_uid_and_auth_key_have_strict_ascii_bounds(self):
        for uid in ("", "x" * 21, "hello world", "uid\x00", "ＡBCD", 123):
            with self.subTest(uid_type=type(uid).__name__):
                with self.assertRaisesRegex(ValueError, "uid"):
                    credentials_for_profile(uid=uid)
        self.assertEqual(credentials_for_profile(uid="A" * 20).uid, "A" * 20)
        for key in ("", "x" * 7, "x" * 9, "abcd-123", "ＡBCD1234", "ABC1234\n", 123):
            with self.subTest(key_type=type(key).__name__):
                with self.assertRaisesRegex(ValueError, "auth_key"):
                    credentials_for_profile(auth_key=key)

    def test_protocol_text_limits_use_bytes_without_truncating(self):
        self.assertEqual(len(credentials_for_profile(password="x" * 255).password), 255)
        for name in ("account", "password"):
            for value in ("", "x" * 256, "密" * 86, "ab\x00cd", "\ud800", 123):
                with self.subTest(field=name, value_type=type(value).__name__):
                    with self.assertRaisesRegex(ValueError, name):
                        credentials_for_profile(**{name: value})

    def test_json_rejects_invalid_types_null_secrets_and_unknown_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            for content in ([], "text", {"password": None}, {"auth_key": 123},
                            {"account": None}, {"passwrod": "typo"}):
                with self.subTest(content_type=type(content).__name__):
                    path = self.write_config(directory, content)
                    with self.assertRaises(ValueError):
                        load_credentials(profile="legacy", config_path=path, environ={})

    def test_json_is_bounded_and_rejects_non_json_without_echoing_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "credentials.json"
            for content in (b"sensitive malformed content", b"\xff\xfe", b"x" * 65537):
                path.write_bytes(content)
                with self.assertRaises(ValueError) as raised:
                    load_credentials(config_path=path, environ={})
                self.assertNotIn("sensitive", str(raised.exception))

    def test_firmware_boundaries_are_model_specific_and_do_not_change_config(self):
        self.assertEqual(profile_for_firmware(None), "legacy")
        self.assertEqual(profile_for_firmware("V1.006.013-release"), "legacy")
        self.assertEqual(profile_for_firmware(1_006_014), "current")
        self.assertEqual(profile_for_firmware("1.002.013", is_pixsee_play=True), "legacy")
        self.assertEqual(profile_for_firmware("1.002.014", is_pixsee_play=True), "current")
        self.assertEqual(profile_for_firmware("1.002.014"), "legacy")
        for invalid in ("", "bad", -1, True, "1.1000.0", 1.5):
            with self.subTest(value_type=type(invalid).__name__):
                with self.assertRaises(ValueError):
                    profile_for_firmware(invalid)


if __name__ == "__main__":
    unittest.main()
