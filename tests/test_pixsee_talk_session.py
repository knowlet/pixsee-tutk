"""Offline reverse-channel trust, lifecycle, and acknowledgment tests."""

from collections import deque
from contextlib import contextmanager
import queue
import struct
import unittest
from unittest.mock import Mock, patch

import cuboai_pure as transport
import pixsee_talk as talk_module
from pixsee_config import PixseeCredentials
from pixsee_protocol import encode_iotc_packet
from pixsee_session import PixseeConnectionError, PixseeSession, _DtlsSocket


CAMERA = ("192.0.2.10", 45678)
NONCE = 0x3456
TOKEN = 0x12345679
SERVER_WORD = 0x01FEFEE0
PCM = bytes(640)


def camera_login(*, resend=True, token=TOKEN):
    # Empty reverse-login credential fields are native protocol behavior.
    app = bytearray(572 if resend else 570)
    app[:4] = bytes((0, 0x20 if resend else 0, 12, 0))
    struct.pack_into("<H", app, 16, len(app) - 24)
    app[18] = 0 if resend else 1
    struct.pack_into("<I", app, 20, token)
    app[538:562] = bytes.fromhex(
        "0100000004000000fb071f00000000000000000000000300")
    return bytes(app)


def camera_ack(high=0xFFFF, *, kind=9):
    app = bytearray(24)
    app[0], app[2] = kind, 12
    struct.pack_into("<HH", app, 8, 0xFFFF, high)
    return bytes(app)


def camera_wire(payload, *, channel=1, datatype=0, nonce=NONCE,
                fingerprint=transport._CLIENT_FINGERPRINT):
    plain = bytearray(28 + len(payload))
    struct.pack_into("<BBBBHHHHHBBI", plain, 0,
                     4, 2, 0x1D, 0x0B, len(payload) + 12, 1,
                     0x0408, 0x12, 0x2222, channel, datatype, 12)
    plain[20:28] = struct.pack("<H", nonce) + fingerprint
    plain[28:] = payload
    return encode_iotc_packet(bytes(plain))


class Clock:
    now = 100.0

    def monotonic(self):
        return self.now


class TalkAdapter:
    """Replace the network only; real parsers and builders remain under test."""
    def __init__(self, clock, *, login=None, ack_audio=True,
                 ready=True, future_ack=False, cancel=False, start_error=False,
                 ack_limit=None, request_resend=False):
        self.clock, self.ack_audio = clock, ack_audio
        self.login = [camera_login()] if login is None else list(login)
        self.ready, self.future_ack = ready, future_ack
        self.cancel, self.start_error = cancel, start_error
        self.ack_limit, self.request_resend = ack_limit, request_resend
        self.did_request_resend = False
        self.talk_enabled = False
        self.talk_pending, self.pending = deque(), deque()
        self.talk_sequence = 0
        self.error = None
        self.ioctls, self.grants, self.audio = [], [], []
        self.did_login = False
        self.highest_seen = -1

    def sendto(self, wire, peer):
        if peer != CAMERA:
            raise AssertionError("Unexpected destination")
        plain = transport.inv_transcode(wire)
        kind, = struct.unpack_from("<I", plain, 64)
        self.ioctls.append(kind)
        if kind == 0x0350 and self.start_error:
            raise OSError("Synthetic speaker start failure")
        return len(wire)

    def send_talk(self, app):
        if not self.talk_enabled:
            raise AssertionError("Talk sent outside the enabled scope")
        if app[0] == 0 and app[1] == 0x21:
            self.grants.append(app)
            if self.ready:
                self.talk_pending.append(camera_ack(kind=10))
        elif app[0] == 3:
            self.audio.append(app)
            frame, = struct.unpack_from("<H", app, 10)
            self.highest_seen = max(self.highest_seen, frame)
            if self.ack_audio and (self.ack_limit is None or frame < self.ack_limit):
                high = 1000 if self.future_ack else self.highest_seen
                ack = bytearray(camera_ack(high))
                if self.request_resend and frame == 2 and not self.did_request_resend:
                    self.did_request_resend = True
                    struct.pack_into("<H", ack, 8, 0)
                    struct.pack_into("<H", ack, 14, 1)
                    struct.pack_into("<H", ack, 22, 1)
                self.talk_pending.append(bytes(ack))
        else:
            raise AssertionError("Unexpected talk application")

    def pump(self, timeout):
        self.clock.now += max(timeout, 0.001)
        if self.cancel and self.audio:
            raise KeyboardInterrupt()
        if not self.did_login:
            self.did_login = True
            self.talk_pending.extend(self.login)


def session_with(adapter):
    credentials = PixseeCredentials(uid="TESTCAMERA1234567890", account="test-admin",
                                    password="test-password", auth_key="Test1234")
    session = PixseeSession(CAMERA[0], credentials)
    session.authenticated = True
    session._sock, session._cam, session._R = adapter, CAMERA, NONCE
    session._seq = session._relseq = session._frmno = 0
    session._av_server_word = SERVER_WORD
    session._send_ack = Mock()
    session._send_nak = Mock()
    session._note_cam_data = Mock()
    return session


def camera_sack(high, base, offsets):
    app = bytearray(max(24, 22 + 2 * len(offsets)))
    app[:24] = camera_ack(high)
    struct.pack_into("<H", app, 8, base)
    struct.pack_into("<H", app, 14, len(offsets))
    for index, offset in enumerate(offsets):
        struct.pack_into("<H", app, 22 + 2 * index, offset)
    return bytes(app)


class SackAdapter(TalkAdapter):
    def __init__(self, clock, response):
        super().__init__(clock, ack_audio=False)
        self.response = response

    def send_talk(self, app):
        super().send_talk(app)
        if app[0] != 3:
            return
        frame, = struct.unpack_from("<H", app, 10)
        if len(self.audio) <= 2:
            self.talk_pending.append(camera_ack(frame))
        elif len(self.audio) == 3:
            offsets = [1] * 128 if self.response == "duplicates" else [1]
            # Multiple same-batch NAKs must not create a resend storm.
            self.talk_pending.extend([camera_sack(2, 0, offsets)] * 4)
        elif self.response in ("clear", "duplicates"):
            self.talk_pending.append(camera_ack(2))
        elif self.response == "stale":
            self.talk_pending.append(camera_ack(1))


class MalformedSackAdapter(TalkAdapter):
    def __init__(self, clock, mode):
        super().__init__(clock, ack_audio=False)
        self.mode = mode

    def send_talk(self, app):
        super().send_talk(app)
        if app[0] != 3:
            return
        packet = bytearray(camera_sack(0, 0xFFFF, [1]))
        if self.mode == "truncated":
            struct.pack_into("<H", packet, 14, 2)
        elif self.mode == "extra":
            packet += bytes(2)
        elif self.mode == "excess_count":
            packet = bytearray(camera_sack(0, 0xFFFF, [1] * 129))
        elif self.mode == "future_hole":
            struct.pack_into("<H", packet, 22, 2)
        elif self.mode == "zero_offset":
            struct.pack_into("<H", packet, 22, 0)
        self.talk_pending.append(bytes(packet))


@contextmanager
def virtual_time(clock):
    with patch.object(talk_module.time, "monotonic", side_effect=clock.monotonic):
        yield


class PixseeTalkTransportTests(unittest.TestCase):
    def test_disabled_or_foreign_packets_never_enter_talk_queue(self):
        sock, dtls = Mock(), Mock()
        dtls.feed_datagram.return_value = []
        dtls.receive_application.return_value = []
        adapter = _DtlsSocket(sock, CAMERA, NONCE, dtls)
        adapter._receive_wire(camera_wire(b"reply"), CAMERA)
        self.assertFalse(adapter.talk_pending)
        adapter.talk_enabled = True
        for wire, peer in (
            (camera_wire(b"reply"), ("192.0.2.99", CAMERA[1])),
            (camera_wire(b"reply"), (CAMERA[0], CAMERA[1] + 1)),
            (camera_wire(b"reply", nonce=NONCE + 1), CAMERA),
            (camera_wire(b"reply", fingerprint=bytes(6)), CAMERA),
            (camera_wire(b"reply", channel=2), CAMERA),
            (camera_wire(b"reply", datatype=1), CAMERA),
        ):
            adapter._receive_wire(wire, peer)
        self.assertFalse(adapter.talk_pending)
        dtls.feed_datagram.assert_not_called()
        adapter._receive_wire(camera_wire(b"reply"), CAMERA)
        self.assertEqual(list(adapter.talk_pending), [b"reply"])
        self.assertEqual(adapter.received_datagrams, 0)

    def test_talk_send_requires_enable_and_wraps_own_sequence(self):
        sock, dtls = Mock(), Mock()
        adapter = _DtlsSocket(sock, CAMERA, NONCE, dtls)
        with self.assertRaises(PixseeConnectionError):
            adapter.send_talk(b"audio")
        sock.sendto.assert_not_called()
        adapter.talk_enabled, adapter.talk_sequence = True, 0xFFFF
        adapter.send_talk(b"audio")
        self.assertEqual(adapter.talk_sequence, 0)
        self.assertEqual(sock.sendto.call_args.args[1], CAMERA)
        dtls.send_application.assert_not_called()


class PixseeTalkLifecycleTests(unittest.TestCase):
    def assert_stopped(self, adapter):
        self.assertFalse(adapter.talk_enabled)
        self.assertFalse(adapter.talk_pending)
        self.assertEqual(adapter.ioctls[-1], 0x0351)
        self.assertEqual(adapter.ioctls.count(0x0350), 1)
        self.assertEqual(adapter.ioctls.count(0x0351), 1)

    def test_invalid_empty_or_failed_input_does_not_enable_speaker(self):
        cases = ([], [b""], [b"x"], [bytes(642)], ["not bytes"])
        for chunks in cases:
            with self.subTest(chunks=chunks):
                clock = Clock()
                adapter = TalkAdapter(clock)
                with virtual_time(clock), self.assertRaises(ValueError):
                    session_with(adapter).talk_pcm(chunks, timeout=0.2)
                self.assertEqual(adapter.ioctls, [])
                self.assertFalse(adapter.talk_enabled)

    def test_prefetch_timeout_never_enables_speaker_and_closes_source(self):
        clock = Clock()
        adapter, source = TalkAdapter(clock), Mock()
        source.queue.get.side_effect = queue.Empty
        with patch.object(talk_module, "_PcmInput", return_value=source), \
                virtual_time(clock), self.assertRaisesRegex(PixseeConnectionError, "input timed out"):
            session_with(adapter).talk_pcm(iter(()), timeout=0.2)
        self.assertEqual(adapter.ioctls, [])
        source.close.assert_called_once()

    def test_authentication_and_exclusive_reader_are_required_before_input(self):
        for condition in ("unauthenticated", "reader", "talk"):
            with self.subTest(condition=condition):
                clock = Clock()
                adapter = TalkAdapter(clock)
                session = session_with(adapter)
                if condition == "unauthenticated":
                    session.authenticated = False
                elif condition == "reader":
                    session._av_reader_thread = object()
                else:
                    adapter.talk_enabled = True
                with patch.object(talk_module, "_PcmInput") as source, \
                        self.assertRaises(PixseeConnectionError):
                    session.talk_pcm([PCM])
                source.assert_not_called()
                self.assertEqual(adapter.ioctls, [])

    def test_talk_ownership_rejects_later_stream_before_any_io(self):
        adapter = TalkAdapter(Clock())
        session = session_with(adapter)
        adapter.talk_enabled = True
        with self.assertRaises(PixseeConnectionError):
            next(session.av_frames_timed(duration=1))
        self.assertEqual(adapter.ioctls, [])
        self.assertIsNone(session._av_reader_thread)

    def test_talk_holds_media_lock_before_source_prefetch_and_releases_on_failure(self):
        adapter = TalkAdapter(Clock())
        session = session_with(adapter)

        def prefetch(*args, **kwargs):
            self.assertTrue(session._media_lock.locked())
            self.assertFalse(adapter.talk_enabled)
            with self.assertRaises(PixseeConnectionError):
                next(session.av_frames_timed(duration=1))
            self.assertEqual(adapter.ioctls, [])
            raise ValueError("Synthetic prefetch failure")

        with patch.object(talk_module, "run_talk", side_effect=prefetch), \
                self.assertRaisesRegex(ValueError, "Synthetic prefetch"):
            session.talk_pcm([PCM])
        self.assertFalse(session._media_lock.locked())

    def test_only_valid_resend_companion_is_granted_and_token_echoed(self):
        clock = Clock()
        adapter = TalkAdapter(clock, login=[camera_login(resend=False), b"\0\x20bad", camera_login()])
        with virtual_time(clock):
            result = session_with(adapter).talk_pcm([PCM, PCM], timeout=0.2)
        self.assertEqual(len(adapter.grants), 1)
        self.assertEqual(struct.unpack_from("<I", adapter.grants[0], 20)[0], TOKEN)
        self.assertEqual(result["sent_frames"], 2)
        self.assertEqual(result["camera_high_water_frames"], 2)
        self.assertTrue(result["final_high_water_observed"])
        self.assertNotIn("acked_frames", result)
        self.assertFalse(result["talk_encrypted"])
        self.assert_stopped(adapter)

    def test_primary_only_or_no_grant_ack_times_out_and_stops(self):
        for kwargs in ({"login": [camera_login(resend=False)]}, {"ready": False}):
            with self.subTest(kwargs=kwargs):
                clock = Clock()
                adapter = TalkAdapter(clock, **kwargs)
                with virtual_time(clock), self.assertRaises(PixseeConnectionError):
                    session_with(adapter).talk_pcm([PCM], timeout=0.2)
                self.assertEqual(adapter.audio, [])
                self.assert_stopped(adapter)

    def test_ready_or_future_ack_does_not_count_as_acknowledged_audio(self):
        for kwargs in ({"ack_audio": False}, {"future_ack": True}):
            with self.subTest(kwargs=kwargs):
                clock = Clock()
                adapter = TalkAdapter(clock, **kwargs)
                with virtual_time(clock), self.assertRaisesRegex(PixseeConnectionError, "acknowledg"):
                    session_with(adapter).talk_pcm([PCM], timeout=0.2)
                self.assertEqual(len(adapter.audio), 1)
                self.assert_stopped(adapter)

    def test_lost_final_ack_reports_partial_high_water_without_inventing_success(self):
        clock = Clock()
        adapter = TalkAdapter(clock, ack_limit=1)
        with virtual_time(clock):
            result = session_with(adapter).talk_pcm([PCM, PCM], timeout=2)
        self.assertEqual(result["sent_frames"], 2)
        self.assertEqual(result["camera_high_water_frames"], 1)
        self.assertFalse(result["final_high_water_observed"])
        self.assertNotIn("all_acknowledged", result)
        self.assertGreaterEqual(clock.now, 101.5)
        self.assert_stopped(adapter)

    def test_requested_resend_preserves_pcm_metadata_and_frame_identity(self):
        clock = Clock()
        adapter = TalkAdapter(clock, request_resend=True)
        with virtual_time(clock):
            result = session_with(adapter).talk_pcm([PCM, PCM, PCM], timeout=0.2)
        self.assertEqual(result["sent_frames"], 3)
        self.assertEqual(result["resends"], 1)
        self.assertEqual(result["pending_missing_frames"], 0)
        self.assertEqual(len(adapter.audio), 4)
        original, resent = adapter.audio[1], adapter.audio[3]
        self.assertEqual(original[8:], resent[8:])
        self.assertNotEqual(original[4:6], resent[4:6])
        self.assert_stopped(adapter)

    def test_continuous_input_cannot_mask_missing_camera_feedback(self):
        clock, source = Clock(), Mock()
        source.queue.get.return_value = PCM
        source.queue.get_nowait.return_value = PCM
        adapter = TalkAdapter(clock, ack_audio=False)
        with patch.object(talk_module, "_PcmInput", return_value=source), \
                virtual_time(clock), self.assertRaisesRegex(PixseeConnectionError, "acknowledg"):
            session_with(adapter).talk_pcm(iter(()), timeout=0.2)
        self.assertGreaterEqual(len(adapter.audio), 1)
        self.assertLess(clock.now, 100.5)
        self.assert_stopped(adapter)
        source.close.assert_called_once()

    def test_latest_missing_list_controls_drain_without_claiming_delivery(self):
        for response in ("clear", "hold", "stale", "duplicates"):
            with self.subTest(response=response):
                clock = Clock()
                adapter = SackAdapter(clock, response=response)
                with virtual_time(clock):
                    result = session_with(adapter).talk_pcm([PCM, PCM, PCM], timeout=2)
                self.assertTrue(result["final_high_water_observed"])
                self.assertEqual(result["resends"], 1)
                if response in ("hold", "stale"):
                    self.assertEqual(result["pending_missing_frames"], 1)
                    self.assertGreaterEqual(clock.now, 101.5)
                else:
                    self.assertEqual(result["pending_missing_frames"], 0)
                    self.assertLess(clock.now, 100.5)
                self.assertNotIn("all_acknowledged", result)
                self.assert_stopped(adapter)

    def test_malformed_sack_cannot_advance_high_water_or_trigger_resends(self):
        for mode in ("truncated", "extra", "excess_count", "future_hole", "zero_offset"):
            with self.subTest(mode=mode):
                clock = Clock()
                adapter = MalformedSackAdapter(clock, mode)
                with virtual_time(clock), self.assertRaisesRegex(PixseeConnectionError, "acknowledg"):
                    session_with(adapter).talk_pcm([PCM], timeout=0.2)
                self.assertEqual(len(adapter.audio), 1)
                self.assert_stopped(adapter)

    def test_changed_token_cancellation_and_start_failure_always_stop(self):
        cases = (
            ({"login": [camera_login(), camera_login(token=TOKEN + 1)]}, PixseeConnectionError),
            ({"cancel": True}, KeyboardInterrupt),
            ({"start_error": True}, OSError),
        )
        for kwargs, exception in cases:
            with self.subTest(kwargs=kwargs):
                clock = Clock()
                adapter = TalkAdapter(clock, **kwargs)
                with virtual_time(clock), self.assertRaises(exception):
                    session_with(adapter).talk_pcm([PCM], timeout=0.2)
                self.assert_stopped(adapter)

    def test_midstream_input_stall_stops_speaker_and_producer(self):
        clock, source = Clock(), Mock()
        source.queue.get.return_value = PCM
        source.queue.get_nowait.side_effect = queue.Empty
        adapter = TalkAdapter(clock)
        with patch.object(talk_module, "_PcmInput", return_value=source), \
                virtual_time(clock), self.assertRaisesRegex(PixseeConnectionError, "input stalled"):
            session_with(adapter).talk_pcm(iter(()), timeout=0.2)
        self.assert_stopped(adapter)
        source.close.assert_called_once()


def pcm_unit():
    info = bytearray(16)
    struct.pack_into("<H", info, 0, 0x8C)
    struct.pack_into("<I", info, 12, 123456)
    return bytes(1024) + bytes(info)


def audio_fragment(payload, *, index=7, fragment=10):
    app = bytearray(36 + len(payload))
    app[0], app[2], app[30] = 12, 12, 1
    struct.pack_into("<H", app, 18, fragment)
    struct.pack_into("<H", app, 24, len(payload))
    struct.pack_into("<H", app, 28, index)
    app[36:] = payload
    return bytes(app)


class PixseeTalkMonitorTests(unittest.TestCase):
    def test_non_audio_fragment_backlog_stays_bounded_per_frame(self):
        callback = Mock()
        monitor = talk_module._AudioMonitor(callback)
        # Video shares the stream and routinely has far more PCM-sized fragments.
        for fragment in range(20):
            monitor.feed(audio_fragment(bytes(1024), fragment=fragment))
        retained = sum(len(part) for parts in monitor.messages.values() for part in parts.values())
        self.assertLessEqual(retained, 1040)
        callback.assert_not_called()

    def test_complete_reordered_pcm_emits_once(self):
        callback = Mock()
        monitor = talk_module._AudioMonitor(callback)
        unit = pcm_unit()
        first = audio_fragment(unit[:1024], fragment=10)
        last = audio_fragment(unit[1024:], fragment=11)
        monitor.feed(last)
        callback.assert_not_called()
        monitor.feed(first)
        callback.assert_called_once()
        self.assertEqual(callback.call_args.args[0], bytes(1024))
        self.assertEqual(callback.call_args.args[1]["timestamp_ms"], 123456)
        monitor.feed(first)
        monitor.feed(last)
        callback.assert_called_once()

    def test_missing_fragment_wrong_codec_and_bad_lengths_emit_nothing(self):
        for mode in ("missing", "wrong_codec", "bad_length", "ioctrl"):
            with self.subTest(mode=mode):
                callback = Mock()
                monitor = talk_module._AudioMonitor(callback)
                unit = bytearray(pcm_unit())
                if mode == "wrong_codec":
                    unit[-16:] = bytes(16)
                first = audio_fragment(bytes(unit[:1024]), fragment=10)
                last = audio_fragment(bytes(unit[1024:]), fragment=12 if mode == "missing" else 11)
                if mode == "bad_length":
                    first = first[:-1]
                if mode == "ioctrl":
                    first = first[:30] + bytes(6) + first[36:]
                monitor.feed(first)
                monitor.feed(last)
                callback.assert_not_called()


if __name__ == "__main__":
    unittest.main()
