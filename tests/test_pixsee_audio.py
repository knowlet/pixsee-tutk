import struct
import unittest

from pixsee_audio import (
    TALK_CHUNK_BYTES, TALK_CHUNK_SECONDS, TALK_MAX_PCM_BYTES,
    parse_pcm_audio_unit, parse_talk_login, build_talk_grant, build_talk_audio,
)
from pixsee_av import AVProtocolError, parse_av_grant


def talk_login(*, resend=True, token=0x12345679):
    # Synthetic independent fixture: camera's reverse login has empty account
    # and password, unlike the main-channel login. No live packet is published.
    packet = bytearray(572 if resend else 570)
    packet[:4] = bytes((0, 0x20 if resend else 0, 12, 0))
    struct.pack_into("<H", packet, 16, len(packet) - 24)
    packet[18] = 0 if resend else 1
    struct.pack_into("<I", packet, 20, token)
    packet[538:562] = bytes.fromhex(
        "0100000004000000fb071f00000000000000000000000300")
    return bytes(packet)


class PixseeAudioTests(unittest.TestCase):
    def test_receive_pcm_preserves_samples_and_camera_clock(self):
        pcm = struct.pack("<4h", -32768, -1, 0, 32767)
        tail = bytearray(16)
        struct.pack_into("<H", tail, 0, 0x8C)
        struct.pack_into("<I", tail, 12, 0xFEDCBA98)
        data, info = parse_pcm_audio_unit(pcm + tail)
        self.assertEqual(data, pcm)
        self.assertEqual(info, {
            "codec": "pcm_s16le", "codec_id": 0x8C, "sample_rate": 8000,
            "channels": 1, "sample_width": 2, "complete": True,
            "timestamp_ms": 0xFEDCBA98,
        })

    def test_incomplete_wrong_codec_and_partial_samples_are_rejected(self):
        tail = bytes.fromhex("8c000200000000000000000000000000")
        for data in (b"", tail, b"\0" + tail, b"\0\0" + bytes(16),
                     bytearray(b"\0\0" + tail)):
            with self.subTest(data_type=type(data)), self.assertRaises(AVProtocolError):
                parse_pcm_audio_unit(data)
        for complete in (False, None, 1):
            with self.subTest(complete=complete), self.assertRaises(AVProtocolError):
                parse_pcm_audio_unit(b"\0\0" + tail, complete=complete)

    def test_talk_login_and_token_are_not_printed(self):
        login = parse_talk_login(talk_login())
        self.assertTrue(login.resend)
        self.assertEqual(login.protocol_version, 12)
        self.assertEqual(login.capabilities, (0x001F07FB, 0, 0, 0x00030000))
        self.assertEqual(login.token, 0x12345679)
        self.assertNotIn(str(login.token), repr(login))
        self.assertNotIn("header=", repr(login))
        self.assertFalse(parse_talk_login(talk_login(resend=False)).resend)

    def test_malformed_or_unknown_talk_login_is_not_granted(self):
        valid = talk_login()
        malformed = [b"", valid[:-1], valid + b"\0", valid[:570]]
        for offset, value in ((0, 1), (1, 1), (2, 11), (16, 0), (18, 1),
                              (24, 1), (281, 1), (538, 0), (542, 5),
                              (562, 1), (566, 1), (570, 1)):
            changed = bytearray(valid)
            changed[offset] = value
            malformed.append(bytes(changed))
        malformed.append(talk_login(token=0))
        for data in malformed:
            with self.subTest(length=len(data)), self.assertRaises(AVProtocolError):
                parse_talk_login(data)

    def test_resend_grant_matches_native_version12_layout(self):
        login = parse_talk_login(talk_login())
        packet = build_talk_grant(login)
        self.assertEqual(len(packet), 62)
        self.assertEqual(packet[:24].hex(),
                         "00210c003c00000000000000000000002600000079563412")
        self.assertEqual(packet[24:].hex(),
                         "00000000000100010100000004000000fb071f0000000000"
                         "0000000000000300000000000000")
        grant = parse_av_grant(packet, 0x12345679)
        self.assertTrue(grant.authenticated)
        self.assertTrue(grant.resend_supported)
        self.assertEqual(grant.server_word, 60)
        with self.assertRaises(AVProtocolError):
            build_talk_grant(parse_talk_login(talk_login(resend=False)), 0)
        for word in (-1, True, 0x100000000):
            with self.subTest(word=word), self.assertRaises(AVProtocolError):
                build_talk_grant(login, word)

    def test_native_talk_packet_uses_pcm_and_16_byte_frameinfo(self):
        pcm = bytes.fromhex("01000200feffffff")
        packet = build_talk_audio(pcm, 7, 2)
        # 8-byte AV header + 20-byte native audio header + PCM + 16-byte info.
        self.assertEqual(packet.hex(),
            "03050c00070000000301020001001000180000000200000003000000"
            "01000200feffffff8c000200000000000000000000000000")
        self.assertEqual(parse_pcm_audio_unit(packet[28:])[0], pcm)
        self.assertEqual(TALK_CHUNK_BYTES, 640)
        self.assertEqual(TALK_CHUNK_SECONDS, 0.04)
        self.assertLessEqual(len(build_talk_audio(bytes(TALK_MAX_PCM_BYTES), 0, 0)), 1052)

    def test_counter_wrap_and_resend_preserve_frame_identity(self):
        pcm = bytes(640)
        first = build_talk_audio(pcm, 65535, 65535)
        resent = build_talk_audio(pcm, 65536, 65535)
        self.assertEqual(first[8:], resent[8:])
        self.assertEqual(struct.unpack_from("<H", resent, 4)[0], 0)
        following = build_talk_audio(pcm, 65537, 65536)
        self.assertEqual(struct.unpack_from("<H", following, 10)[0], 0)
        self.assertEqual(struct.unpack_from("<II", following, 20), (65536, 65537))

    def test_first_global_frame_satisfies_native_receiver_start(self):
        # Native init 0x1fdb4/0x1ff4e/0x1ff52 seeds global send/receive
        # counters with -1. Send 0x13120 increments to 0, and receive
        # 0x1452e..0x14556 waits for that exact first global frame. Audio
        # counter starts zero and is incremented at 0x132bc..0x132c6.
        packet = build_talk_audio(bytes(640), 0, 0)
        self.assertEqual(packet[20:28], bytes.fromhex("0000000001000000"))
        self.assertEqual(packet[8:20], bytes.fromhex("030100000100100090020000"))

    def test_global_and_audio_frame_numbers_wrap_independently(self):
        # Native 32-bit stores preserve the one-frame offset across rollover.
        cases = (
            (0xFFFFFFFE, "feffffffffffffff"),
            (0xFFFFFFFF, "ffffffff00000000"),
            (0x100000000, "0000000001000000"),
        )
        for frame, expected in cases:
            with self.subTest(frame=frame):
                packet = build_talk_audio(bytes(640), 0, frame)
                self.assertEqual(packet[20:28], bytes.fromhex(expected))

    def test_talk_rejects_non_pcm_oversize_and_invalid_counters(self):
        for pcm in (b"", bytes(3), bytes(1010), "audio", bytearray(640)):
            with self.subTest(data_type=type(pcm)), self.assertRaises(AVProtocolError):
                build_talk_audio(pcm, 0, 0)
        for counter in (-1, True, 1.5):
            for kwargs in ({"relseq": counter, "frame_number": 0},
                           {"relseq": 0, "frame_number": counter}):
                with self.subTest(kwargs=kwargs), self.assertRaises(AVProtocolError):
                    build_talk_audio(bytes(640), **kwargs)
        for stamp in (-1, True, 0x100000000):
            with self.subTest(timestamp=stamp), self.assertRaises(AVProtocolError):
                build_talk_audio(bytes(640), 0, 0, timestamp_ms=stamp)


if __name__ == "__main__":
    unittest.main()
