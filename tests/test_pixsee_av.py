import struct
import unittest

from pixsee_av import AVProtocolError, build_av_login, derive_psk, parse_av_grant


def grant_packet(*, token=0x12345679, status=0, opcode=0x21, version=12):
    # Independent native server layout from 0x12548 and 0x20b4e.
    size = 36 if opcode == 1 else 56
    if opcode == 0x21:
        size = 62 if version >= 12 else 60
    packet = bytearray(size)
    packet[1] = opcode
    struct.pack_into("<H", packet, 2, version)
    struct.pack_into("<I", packet, 4, 0x01FEFEE0)
    struct.pack_into("<H", packet, 16, size - 24)
    struct.pack_into("<I", packet, 20, token)
    packet[24] = status
    packet[28:32] = b"\x00\x01\x00\x01"
    packet[32] = 1
    if opcode != 1:
        packet[36:56] = bytes.fromhex("04000000fb071f00000000000000000000000300")
    return bytes(packet)


class PixseeAVTests(unittest.TestCase):
    def test_psk_is_raw_digest_with_native_c_string_semantics(self):
        identity, key = derive_psk("admin", "unit-test-password")
        self.assertEqual(identity, b"AUTHPWD_admin")
        self.assertEqual(key.hex(), "3f2d928bbf8c7e07434febb19f8b03d79f22ec5fd8e2ca5f792dff4f8558e559")
        _, truncated_key = derive_psk("admin", "test-password-2")
        self.assertEqual(truncated_key, bytes.fromhex("6eee3a5257a1329afe1dceb4ce1ebe") + bytes(17))
        self.assertEqual(len(truncated_key), 32)

    def test_psk_identity_matches_native_snprintf_bound(self):
        identity, _ = derive_psk("a" * 120, "password")
        self.assertEqual(identity, b"AUTHPWD_" + b"a" * 111)
        with self.assertRaises(AVProtocolError):
            derive_psk("a" * 121, "password")

    def test_primary_login_offsets_and_reserved_fields(self):
        packet = build_av_login("admin", "password", 0x12345678)
        self.assertEqual(len(packet), 570)
        self.assertEqual(packet[:24].hex(), "00000c000000000000000000000000002202010078563412")
        self.assertEqual(packet[24:281], b"admin" + bytes(252))
        self.assertEqual(packet[281:538], b"password" + bytes(249))
        self.assertEqual(packet[538:].hex(), "0100000004000000fb071f000000000000000000000003000000000001000000")

    def test_resend_login_has_two_additional_fields_and_token_carry(self):
        primary = build_av_login("admin", "password", 0x123456FF)
        companion = build_av_login("admin", "password", 0x123456FF, resend=True)
        self.assertEqual(len(companion), 572)
        self.assertEqual(companion[:24].hex(), "00200c000000000000000000000000002402000000573412")
        self.assertEqual(primary[24:], companion[24:570])
        self.assertEqual(companion[570:], b"\0\0")

    def test_credentials_cannot_resize_packet_or_inject_nul(self):
        packet = build_av_login("a" * 255, "b" * 255, 1)
        self.assertEqual(len(packet), 570)
        self.assertEqual(packet[279:281], b"\0\0")
        self.assertEqual(packet[536:538], b"\0\0")
        for account, password in (("", "x"), ("x", ""), ("a" * 256, "x"),
                                  ("x", "b" * 256), ("a\0b", "x"),
                                  ("x", "b\0c"), ("\ud800", "x")):
            with self.subTest(account=account), self.assertRaises(AVProtocolError):
                build_av_login(account, password, 1)
        for token in (0, -1, True, 1.5, 0x100000000):
            with self.subTest(token=token), self.assertRaises(AVProtocolError):
                build_av_login("admin", "password", token)
        with self.assertRaises(AVProtocolError):
            build_av_login("admin", "password", 0xFFFFFFFF, resend=True)

    def test_authenticated_grant_matches_token(self):
        grant = parse_av_grant(grant_packet(), 0x12345679)
        self.assertTrue(grant.authenticated)
        self.assertEqual(grant.status, 0)
        self.assertEqual(grant.token, 0x12345679)
        self.assertTrue(grant.resend_supported)
        self.assertEqual(grant.capabilities, (0x001F07FB, 0, 0, 0x00030000))

    def test_primary_and_legacy_grant_variants(self):
        for opcode, version in ((1, 1), (0x14, 12), (0x21, 11)):
            with self.subTest(opcode=opcode, version=version):
                self.assertTrue(parse_av_grant(
                    grant_packet(opcode=opcode, version=version), 0x12345679,
                ).authenticated)

    def test_authentication_failure_is_never_success(self):
        for status in (1, 2, 3, 4, 255):
            grant = parse_av_grant(grant_packet(status=status), 0x12345679)
            self.assertFalse(grant.authenticated)
            self.assertEqual(grant.status, status)

    def test_replay_malformed_and_non_grant_messages_rejected(self):
        valid = grant_packet()
        with self.assertRaises(AVProtocolError):
            parse_av_grant(valid, 0x12345678)
        for malformed in (b"", valid[:24], valid[:-1], valid + b"\0"):
            with self.assertRaises(AVProtocolError):
                parse_av_grant(malformed, 0x12345679)
        for offset, value in ((0, 1), (1, 0x20), (2, 0), (2, 13),
                              (16, 0), (36, 5)):
            packet = bytearray(valid)
            packet[offset] = value
            with self.subTest(offset=offset, value=value), self.assertRaises(AVProtocolError):
                parse_av_grant(bytes(packet), 0x12345679)


if __name__ == "__main__":
    unittest.main()
