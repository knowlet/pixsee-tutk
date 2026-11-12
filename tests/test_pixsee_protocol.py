import struct
import unittest

from cuboai_pure import inv_transcode, transcode
from pixsee_protocol import (
    PixseeProtocolError,
    build_connect_ack,
    build_connect_probe,
    build_discovery_probe,
    build_dtls_data,
    build_session_close,
    decode_iotc_packet,
    encode_iotc_packet,
    keepalive_reply,
    parse_dtls_data,
    parse_discovery_reply,
)


UID = "TESTCAMERA1234567890"
FINGERPRINT = bytes.fromhex("aabbccddeeff")


def reply_packet(*, status=1, nonce=0x1234, uid=UID):
    # Independent synthetic reply layout from native builder 0x1d414.
    packet = bytearray(200)
    packet[:16] = bytes.fromhex("04021d02b80000000206120000000000")
    packet[16:36] = uid.encode("ascii").ljust(20, b"\0")
    packet[52:61] = b"Test room"
    packet[184:188] = bytes((1, 8, 3, 4))
    struct.pack_into("<H", packet, 188, nonce)
    packet[190:196] = FINGERPRINT
    struct.pack_into("<I", packet, 196, status)
    return transcode(bytes(packet), swap_tail=True)


class PixseeProtocolTests(unittest.TestCase):
    def test_uidless_discovery_has_no_connection_identity(self):
        plain = inv_transcode(build_discovery_probe())
        self.assertEqual(len(plain), 88)
        self.assertEqual(plain[:16].hex(), "04021d02480000000106210000000001")
        self.assertEqual(plain[16:52], bytes(36))
        self.assertEqual(plain[52:56], bytes((1, 8, 3, 4)))
        self.assertEqual(plain[56:], bytes(32))

    def test_discovery_retry_variant(self):
        plain = inv_transcode(build_discovery_probe(15))
        self.assertEqual(struct.unpack_from("<H", plain, 8)[0], 0x0603)
        self.assertEqual(struct.unpack_from("<I", plain, 68)[0], 15)
        for bad in (-1, 16, True, 1.5):
            with self.subTest(bad=bad), self.assertRaises(PixseeProtocolError):
                build_discovery_probe(bad)

    def test_auth_key_crossing_tail_and_ack_identity(self):
        probe = build_connect_probe(UID, 0x1234, "Key12345", FINGERPRINT)
        ack = build_connect_ack(UID, 0x1234, b"Key12345", FINGERPRINT)
        plain = inv_transcode(probe)
        ack_plain = inv_transcode(ack)
        self.assertEqual(plain[15], 0)
        self.assertEqual(plain[16:36], UID.encode())
        self.assertEqual(plain[56:64], b"\x34\x12" + FINGERPRINT)
        self.assertEqual(plain[74:82], b"Key12345")
        self.assertEqual(plain[64:68], b"\x01\0\0\0")
        self.assertEqual(ack_plain[64:68], b"\x02\0\0\0")
        self.assertEqual(plain[:64] + plain[68:], ack_plain[:64] + ack_plain[68:])
        # Regression: the old Cubo no-swap tail corrupts the final auth bytes.
        self.assertNotEqual(probe, transcode(plain, swap_tail=False))

    def test_connection_inputs_never_resize_packet(self):
        cases = (
            ("X" * 21, 1, "Key12345", FINGERPRINT),
            ("", 1, "Key12345", FINGERPRINT),
            ("攝影機", 1, "Key12345", FINGERPRINT),
            ("ABC\0DEF", 1, "Key12345", FINGERPRINT),
            (UID, 0, "Key12345", FINGERPRINT),
            (UID, 0xFFFF, "Key12345", FINGERPRINT),
            (UID, True, "Key12345", FINGERPRINT),
            (UID, 1, "short", FINGERPRINT),
            (UID, 1, "too-long-key", FINGERPRINT),
            (UID, 1, b"1234567\0", FINGERPRINT),
            (UID, 1, "Key12345", b"short"),
        )
        for values in cases:
            with self.subTest(values=values), self.assertRaises(PixseeProtocolError):
                build_connect_probe(*values)

    def test_reply_matches_complete_identity(self):
        parsed = parse_discovery_reply(
            reply_packet(), expected_uid=UID, expected_nonce=0x1234,
            expected_fingerprint=FINGERPRINT,
        )
        self.assertEqual(parsed.uid, UID)
        self.assertEqual(parsed.sdk_version, "4.3.8.1")
        self.assertEqual(parsed.device_name, "Test room")
        self.assertEqual(parsed.status, 1)
        self.assertNotIn(UID, repr(parsed))

    def test_stale_foreign_reply_rejected(self):
        for expected in (
            {"expected_uid": "OTHERDEVICE"},
            {"expected_nonce": 0x1235},
            {"expected_fingerprint": bytes(6)},
        ):
            with self.subTest(expected=expected), self.assertRaises(PixseeProtocolError):
                parse_discovery_reply(reply_packet(), **expected)

    def test_auth_rejections_are_preserved_not_success(self):
        for status in (0, 1, 3, 4, 5, 6, 7, 0xFFFFFFFF):
            with self.subTest(status=status):
                self.assertEqual(parse_discovery_reply(reply_packet(status=status)).status, status)

    def test_malformed_reply_rejected(self):
        valid = reply_packet()
        for bad in (b"", valid[:-1], valid + b"\0"):
            with self.assertRaises(PixseeProtocolError):
                parse_discovery_reply(bad)
        for offset, value in ((0, 0), (4, 183), (8, 3), (16, 255)):
            plain = bytearray(inv_transcode(valid))
            plain[offset] = value
            with self.subTest(offset=offset), self.assertRaises(PixseeProtocolError):
                parse_discovery_reply(transcode(bytes(plain)))


class PixseeSessionPacketTests(unittest.TestCase):
    def camera_packet(self, payload=b"test", *, partial=True):
        # Camera header differs from the client header in direction and MID.
        plain = bytearray.fromhex("04021d0b1000070008041200efbe00010c0000003412aabbccddeeff")
        plain[3] = 0x0B if partial else 0x0A
        struct.pack_into("<H", plain, 4, 12 + len(payload))
        plain += payload
        # Independent expression of the native encoder's 64-byte boundary.
        limit = min(len(plain), 64) if partial else len(plain)
        return transcode(bytes(plain[:limit])) + bytes(plain[limit:])

    def test_partial_encryption_preserves_suffix_at_byte_64(self):
        payload = bytes(range(128))
        wire = build_dtls_data(payload, 0x1234, 0xFFFF, FINGERPRINT)
        self.assertEqual(wire[64:], payload[36:])
        plain = decode_iotc_packet(wire)
        self.assertEqual(plain[:20].hex(), "04021d0b8c00ffff07042100341200010c000000")
        self.assertEqual(plain[20:28], b"\x34\x12" + FINGERPRINT)
        self.assertEqual(plain[28:], payload)
        # Full-packet decoding corrupts the unencoded DTLS suffix.
        self.assertNotEqual(inv_transcode(wire)[64:], payload[36:])

    def test_camera_dtls_full_and_partial_encodings(self):
        for size in (0, 13, 36, 37, 38, 40, 44, 64, 512, 1388):
            payload = bytes(i & 255 for i in range(size))
            for partial in (False, True):
                with self.subTest(size=size, partial=partial):
                    self.assertEqual(parse_dtls_data(
                        self.camera_packet(payload, partial=partial), 0x1234,
                        expected_fingerprint=FINGERPRINT), payload)

    def test_captured_camera_marker(self):
        # Observed non-DTLS notification; contains no UID/account/media data.
        wire = bytes.fromhex("4e6fad0740dab0db3d2de83df0efcad86e2eed8941e666ad8dad280cb0e5ea6a630c151e1f4901411d1201")
        self.assertEqual(parse_dtls_data(
            wire, 0xAB3F, expected_fingerprint=bytes.fromhex("000200000000")),
            b"recv dtls data!")

    def test_foreign_identity_and_wrong_channel_rejected(self):
        wire = self.camera_packet()
        for kwargs in (
            {"expected_nonce": 0x1235, "expected_fingerprint": FINGERPRINT},
            {"expected_nonce": 0x1234, "expected_fingerprint": bytes(6)},
            {"expected_nonce": 0x1234, "expected_fingerprint": FINGERPRINT, "channel": 1},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(PixseeProtocolError):
                parse_dtls_data(wire, **kwargs)

    def test_malformed_and_wrong_type_dtls_packets_rejected(self):
        valid = decode_iotc_packet(self.camera_packet())
        for offset, replacement in ((2, 0x1A), (3, 2), (8, 7), (10, 0x21),
                                    (15, 0), (16, 8), (20, 0)):
            plain = bytearray(valid)
            plain[offset] = replacement
            with self.subTest(offset=offset), self.assertRaises(PixseeProtocolError):
                parse_dtls_data(encode_iotc_packet(bytes(plain)), 0x1234,
                                expected_fingerprint=FINGERPRINT)
        wire = self.camera_packet()
        for bad in (b"", wire[:15], wire[:-1], wire + b"\0"):
            with self.assertRaises(PixseeProtocolError):
                decode_iotc_packet(bad)

    def test_keepalive_echo_and_close_use_exact_session_identity(self):
        plain = bytes.fromhex("04021d0a0800000028041200000000003412aabbccddeeff")
        reply = keepalive_reply(transcode(plain), 0x1234, expected_fingerprint=FINGERPRINT)
        self.assertEqual(decode_iotc_packet(reply).hex(),
                         "04021d0a0800000027042100000000003412aabbccddeeff")
        self.assertEqual(decode_iotc_packet(build_session_close(0x1234, FINGERPRINT)).hex(),
                         "04021d0a0800000017042100000000003412aabbccddeeff")
        self.assertIsNone(keepalive_reply(self.camera_packet(), 0x1234,
                                         expected_fingerprint=FINGERPRINT))
        with self.assertRaises(PixseeProtocolError):
            keepalive_reply(transcode(plain), 0x1235, expected_fingerprint=FINGERPRINT)
        with self.assertRaises(PixseeProtocolError):
            keepalive_reply(transcode(plain), 0x1234, expected_fingerprint=bytes(6))

    def test_builder_rejects_invalid_lengths_and_counters(self):
        for kwargs in ({"payload": b"x" * 1389}, {"payload": "text"},
                       {"sequence": -1}, {"sequence": 65536}, {"sequence": True},
                       {"nonce": 0}, {"nonce": True}, {"channel": 32},
                       {"fingerprint": b"short"}):
            args = dict(payload=b"x", nonce=1, sequence=0)
            args.update(kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises(PixseeProtocolError):
                build_dtls_data(**args)


if __name__ == "__main__":
    unittest.main()
