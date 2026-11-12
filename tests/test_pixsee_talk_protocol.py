"""Independent native talk envelope fixtures; no device credentials or sockets."""

import struct
import unittest

from cuboai_pure import _CLIENT_FINGERPRINT, transcode
from pixsee_protocol import (
    PixseeProtocolError,
    build_talk_data,
    decode_iotc_packet,
    parse_talk_data,
)


NONCE = 0x3456


def camera_talk_packet(payload=b"synthetic AV payload", *, channel=1, datatype=0,
                       nonce=NONCE, fingerprint=_CLIENT_FINGERPRINT,
                       message=0x0408, subtype=0x12, extension=12,
                       flags=0x0B, version=0x1D):
    """Encode the observed 28-byte camera header independently of talk builders."""
    plain = bytearray(28 + len(payload))
    struct.pack_into("<BBBBHHHHHBBI", plain, 0,
                     4, 2, version, flags, len(payload) + 12, 0x789A,
                     message, subtype, 0x2345, channel, datatype, extension)
    # Camera MID 0x2345 deliberately differs from session nonce.
    plain[20:28] = struct.pack("<H", nonce) + fingerprint
    plain[28:] = payload
    limit = min(len(plain), 64) if flags & 1 else len(plain)
    return transcode(bytes(plain[:limit]), swap_tail=True) + bytes(plain[limit:])


class PixseeTalkProtocolTests(unittest.TestCase):
    def test_client_native_channel_and_datatype(self):
        payload = bytes(range(80))
        wire = build_talk_data(payload, NONCE, 0xFFFF)
        plain = decode_iotc_packet(wire)
        self.assertEqual(plain[:16], bytes.fromhex("04021d0b5c00ffff0704210056340100"))
        self.assertEqual(plain[16:20], bytes.fromhex("0c000000"))
        self.assertEqual(plain[20:28], struct.pack("<H", NONCE) + _CLIENT_FINGERPRINT)
        self.assertEqual(plain[28:], payload)
        # Native partial transform leaves this part of AV clear on the LAN.
        self.assertEqual(wire[64:], payload[36:])

    def test_camera_fixture_returns_payload_without_assuming_mid_is_nonce(self):
        for length in (0, 1, 15, 35, 36, 37, 570, 572, 1388):
            payload = bytes(index & 255 for index in range(length))
            for flags in (0x0A, 0x0B):
                with self.subTest(length=length, flags=flags):
                    self.assertEqual(parse_talk_data(camera_talk_packet(payload, flags=flags), NONCE), payload)

    def test_foreign_session_channel_datatype_and_directions_are_rejected(self):
        cases = (
            {"nonce": NONCE + 1},
            {"fingerprint": bytes.fromhex("010203040506")},
            {"channel": 0}, {"channel": 2}, {"datatype": 1},
            {"message": 0x0407}, {"subtype": 0x21},
            {"extension": 8}, {"version": 0x1C}, {"flags": 0x02},
        )
        for values in cases:
            with self.subTest(values=values), self.assertRaises(PixseeProtocolError):
                parse_talk_data(camera_talk_packet(**values), NONCE)

    def test_truncation_bad_length_and_oversized_application_are_rejected(self):
        wire = camera_talk_packet()
        cases = (wire[:15], wire[:16], wire[:-1], camera_talk_packet(bytes(1389)))
        for value in cases:
            with self.subTest(length=len(value)), self.assertRaises(PixseeProtocolError):
                parse_talk_data(value, NONCE)

    def test_client_bounds_prevent_wrapped_session_or_sequence(self):
        cases = (
            (bytes(1389), NONCE, 0), ("text", NONCE, 0),
            (b"", 0, 0), (b"", 65535, 0), (b"", True, 0),
            (b"", NONCE, -1), (b"", NONCE, 65536), (b"", NONCE, True),
        )
        for payload, nonce, sequence in cases:
            with self.subTest(nonce=nonce, sequence=sequence), self.assertRaises(PixseeProtocolError):
                build_talk_data(payload, nonce, sequence)


if __name__ == "__main__":
    unittest.main()
