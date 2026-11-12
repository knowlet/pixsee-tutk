"""Offline session gates and lifecycle tests; every socket/DTLS peer is a fake."""

from collections import deque
from contextlib import contextmanager
import queue
import struct
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import pixsee_session as session_module
from pixsee_config import PixseeCredentials
from pixsee_dtls import DtlsError
from pixsee_protocol import encode_iotc_packet
from pixsee_session import (
    PixseeAuthenticationError, PixseeConnectionError, PixseeSession, _DtlsSocket,
)


CAMERA = ("192.0.2.10", 45678)
UID = "TESTCAMERA1234567890"
NONCE = 0x1234
TOKEN = 0x12345678
CREDENTIALS = PixseeCredentials(uid=UID, account="test-admin",
                                password="test-password", auth_key="Test1234")


def precheck_reply(status=1, *, nonce=NONCE, uid=UID):
    plain = bytearray(200)
    plain[:16] = bytes.fromhex("04021d02b80000000206120000000000")
    plain[16:36] = uid.encode().ljust(20, b"\0")
    plain[184:188] = bytes((1, 8, 3, 4))
    struct.pack_into("<H", plain, 188, nonce)
    plain[190:196] = session_module.transport._CLIENT_FINGERPRINT
    struct.pack_into("<I", plain, 196, status)
    return encode_iotc_packet(bytes(plain))


def av_grant(token=TOKEN + 1, status=0):
    plain = bytearray(62)
    plain[1] = 0x21
    struct.pack_into("<H", plain, 2, 12)
    struct.pack_into("<H", plain, 16, len(plain) - 24)
    struct.pack_into("<I", plain, 20, token)
    plain[24] = status
    plain[32] = 1
    return bytes(plain)


def camera_data(payload=b"test-dtls-record", nonce=NONCE):
    plain = bytearray(28)
    plain[:16] = bytes.fromhex("04021d0b0c0000000804120000000001")
    struct.pack_into("<H", plain, 4, 12 + len(payload))
    struct.pack_into("<I", plain, 16, 12)
    struct.pack_into("<H", plain, 20, nonce)
    plain[22:28] = session_module.transport._CLIENT_FINGERPRINT
    return encode_iotc_packet(bytes(plain) + payload)


class Clock:
    def __init__(self):
        self.now = 100.0

    def monotonic(self):
        return self.now


class FakeSocket:
    def __init__(self, incoming=(), *, bind_error=None, send_error=None):
        self.incoming = deque(incoming)
        self.sent = []
        self.closed = False
        self.bind_error, self.send_error = bind_error, send_error

    def setsockopt(self, *args):
        pass

    def bind(self, *args):
        if self.bind_error:
            raise self.bind_error

    def setblocking(self, value):
        pass

    def sendto(self, packet, peer):
        if self.send_error:
            raise self.send_error
        self.sent.append((packet, peer))
        return len(packet)

    def recvfrom(self, size):
        if not self.incoming:
            raise BlockingIOError()
        return self.incoming.popleft()

    def close(self):
        self.closed = True


@contextmanager
def connection_io(sock):
    """A bounded virtual clock makes no-reply tests immediate and deterministic."""
    clock = Clock()

    def ready(readers, writers, errors, timeout):
        if sock.incoming:
            return readers, [], []
        clock.now += max(timeout, 0.001)
        return [], [], []

    with patch.object(session_module.socket, "socket", return_value=sock), \
            patch.object(session_module.select, "select", side_effect=ready), \
            patch.object(session_module.time, "monotonic", side_effect=clock.monotonic), \
            patch.object(session_module.transport, "gen_R", return_value=NONCE), \
            patch.object(session_module.os, "urandom", return_value=struct.pack("<I", TOKEN)):
        yield clock


class LoginAdapter:
    """Keep real AV building/parsing while substituting only the DTLS channel."""
    def __init__(self, sock, clock, grants=(), handshake_error=None):
        self.socket, self.clock = sock, clock
        self.pending = deque()
        self.grants = list(grants)
        self.handshake_error = handshake_error
        self.sent = []
        self.closed = False
        self.nonce, self.peer, self.error = NONCE, CAMERA, None

    def handshake(self, timeout):
        if self.handshake_error:
            raise self.handshake_error

    def send_application(self, packet):
        self.sent.append(packet)

    def pump(self, timeout):
        self.clock.now += max(timeout, 0.001)
        self.pending.extend(self.grants)
        self.grants.clear()

    def close(self):
        self.closed = True
        self.socket.close()


class PixseeSessionConnectionTests(unittest.TestCase):
    def test_rejected_iotc_key_never_attempts_dtls_or_av(self):
        for status in (5, 6):
            with self.subTest(status=status):
                sock = FakeSocket([(precheck_reply(status), CAMERA)])
                session = PixseeSession(CAMERA[0], CREDENTIALS)
                with connection_io(sock), patch.object(session_module, "DtlsPskClient") as dtls:
                    with self.assertRaises(PixseeAuthenticationError):
                        session.connect(timeout=1)
                    dtls.assert_not_called()
                self.assertTrue(sock.closed)
                self.assertFalse(session.authenticated)

    def test_foreign_or_stale_precheck_cannot_start_dtls(self):
        for wire, peer in (
            (precheck_reply(), ("192.0.2.99", CAMERA[1])),
            (precheck_reply(nonce=NONCE + 1), CAMERA),
            (precheck_reply(uid="OTHERDEVICE"), CAMERA),
        ):
            with self.subTest(peer=peer):
                sock = FakeSocket([(wire, peer)])
                session = PixseeSession(CAMERA[0], CREDENTIALS)
                with connection_io(sock), patch.object(session_module, "DtlsPskClient") as dtls:
                    with self.assertRaises(PixseeConnectionError):
                        session.connect(timeout=1)
                    dtls.assert_not_called()
                self.assertFalse(session.authenticated)
                self.assertTrue(sock.closed)

    def test_bind_failure_and_cancellation_close_socket(self):
        for kind, error in (("bind_error", OSError("synthetic bind failure")),
                            ("send_error", KeyboardInterrupt())):
            with self.subTest(kind=kind):
                sock = FakeSocket(**{kind: error})
                session = PixseeSession(CAMERA[0], CREDENTIALS)
                with connection_io(sock), self.assertRaises(type(error)):
                    session.connect(timeout=1)
                self.assertTrue(sock.closed)
                self.assertIsNone(session._sock)
                self.assertFalse(session.authenticated)

    def test_dtls_failure_never_sends_av_credentials(self):
        sock = FakeSocket([(precheck_reply(), CAMERA)])
        session = PixseeSession(CAMERA[0], CREDENTIALS)
        with connection_io(sock) as clock:
            adapter = LoginAdapter(sock, clock, handshake_error=DtlsError("synthetic failure"))
            with patch.object(session_module, "DtlsPskClient"), \
                    patch.object(session_module, "_DtlsSocket", return_value=adapter):
                with self.assertRaises(DtlsError):
                    session.connect(timeout=1)
        self.assertEqual(adapter.sent, [])
        self.assertTrue(adapter.closed)
        self.assertTrue(sock.closed)
        self.assertFalse(session.authenticated)

    def test_av_login_requires_matching_token_and_success_status(self):
        for grant in (av_grant(token=TOKEN + 2), av_grant(status=1)):
            with self.subTest(grant=grant.hex()):
                sock = FakeSocket([(precheck_reply(), CAMERA)])
                session = PixseeSession(CAMERA[0], CREDENTIALS)
                with connection_io(sock) as clock:
                    adapter = LoginAdapter(sock, clock, [grant])
                    with patch.object(session_module, "DtlsPskClient"), \
                            patch.object(session_module, "_DtlsSocket", return_value=adapter):
                        with self.assertRaises(PixseeConnectionError):
                            session.connect(timeout=1)
                self.assertFalse(session.authenticated)
                self.assertTrue(adapter.closed)

    def test_resend_grant_uses_companion_token_and_disconnects(self):
        sock = FakeSocket([(precheck_reply(), CAMERA)])
        session = PixseeSession(CAMERA[0], CREDENTIALS)
        with connection_io(sock) as clock:
            adapter = LoginAdapter(sock, clock, [av_grant()])
            with patch.object(session_module, "DtlsPskClient"), \
                    patch.object(session_module, "_DtlsSocket", return_value=adapter):
                self.assertTrue(session.connect(timeout=1))
                self.assertTrue(session.authenticated)
                self.assertEqual([p[1] for p in adapter.sent], [0, 0x20])
                self.assertEqual([struct.unpack_from("<I", p, 20)[0] for p in adapter.sent],
                                 [TOKEN, TOKEN + 1])
                session.disconnect()
        self.assertTrue(adapter.closed)
        self.assertTrue(sock.closed)
        self.assertFalse(session.authenticated)

    def test_dtls_channel_rejects_foreign_peer_port_and_session(self):
        sock, dtls = FakeSocket(), Mock()
        dtls.feed_datagram.return_value = []
        dtls.receive_application.return_value = []
        adapter = _DtlsSocket(sock, CAMERA, NONCE, dtls)
        for wire, peer in ((camera_data(), ("192.0.2.99", CAMERA[1])),
                           (camera_data(), (CAMERA[0], CAMERA[1] + 1)),
                           (camera_data(nonce=NONCE + 1), CAMERA)):
            adapter._receive_wire(wire, peer)
        dtls.feed_datagram.assert_not_called()
        adapter._receive_wire(camera_data(), CAMERA)
        dtls.feed_datagram.assert_called_once_with(b"test-dtls-record")


def video_unit(nals, *, flags=1, timestamp=123456):
    trailer = bytearray(16)
    struct.pack_into("<H", trailer, 0, 0x4E)
    trailer[2] = flags
    struct.pack_into("<I", trailer, 12, timestamp)
    return nals + bytes(trailer)


IDR = bytes.fromhex("0000000165888421")
P_SLICE = bytes.fromhex("00000001419a2421")
PARAMETER_SETS = bytes.fromhex("000000016742001f0000000168ce3c80")


class PixseeSessionStreamTests(unittest.TestCase):
    def session(self):
        return PixseeSession(CAMERA[0], CREDENTIALS)

    def streaming_session(self):
        session = self.session()
        session.authenticated = True
        session._sock = SimpleNamespace(error=None, sendto=Mock())
        session._R, session._cam = NONCE, CAMERA
        return session

    def test_incomplete_frame_blocks_gop_until_complete_idr(self):
        session = self.session()
        prepare = lambda data, complete=True: session._prepare_av_unit("video", data, None, complete)
        self.assertIsNone(prepare(video_unit(P_SLICE, flags=1)))
        frame, meta = prepare(video_unit(IDR, flags=0))
        self.assertEqual(frame, IDR)
        self.assertTrue(meta["keyframe"])
        self.assertEqual(meta["timestamp_ms"], 123456)
        frame, meta = prepare(video_unit(P_SLICE, flags=1))
        self.assertEqual(frame, P_SLICE)
        self.assertFalse(meta["keyframe"])
        self.assertIsNone(prepare(video_unit(P_SLICE), complete=False))
        self.assertIsNone(prepare(video_unit(P_SLICE)))
        self.assertIsNone(prepare(video_unit(IDR), complete=False))
        self.assertIsNotNone(prepare(video_unit(IDR)))
        self.assertIsNone(session._prepare_av_unit("audio", b"audio", None, True))

    def test_parameter_sets_without_idr_do_not_resynchronize(self):
        session = self.session()
        for nals in (PARAMETER_SETS, PARAMETER_SETS + P_SLICE):
            with self.subTest(nals=nals.hex()):
                self.assertIsNone(session._prepare_av_unit("video", video_unit(nals), None, True))
                self.assertFalse(session._video_synced)
        self.assertIsNotNone(session._prepare_av_unit("video", video_unit(PARAMETER_SETS + IDR), None, True))

    def test_transport_error_is_reported_without_any_video_frame(self):
        session = self.streaming_session()
        exited = threading.Event()
        error = DtlsError("synthetic read failure")

        def fail_without_frame(sock, output, stop):
            sock.error = error
            stop.wait(1)
            exited.set()

        with patch.object(session, "_av_reader", side_effect=fail_without_frame):
            with self.assertRaises(PixseeConnectionError) as raised:
                next(session.video_frames_timed(duration=1))
        self.assertIs(raised.exception.__cause__, error)
        self.assertTrue(exited.is_set())
        self.assertIsNone(session._av_reader_thread)

    def test_early_consumer_stop_joins_reader_with_full_queue(self):
        session = self.streaming_session()
        full, exited = threading.Event(), threading.Event()
        item = ("video", IDR, {"keyframe": True})

        def queued_reader(sock, output, stop):
            try:
                while True:
                    try:
                        output.put_nowait(item)
                    except queue.Full:
                        full.set()
                        break
                stop.wait(1)
            finally:
                output.put(None)
                exited.set()

        with patch.object(session, "_av_reader", side_effect=queued_reader):
            units = session._read_av_units()
            self.assertEqual(next(units), item)
            self.assertTrue(full.wait(1))
            units.close()
        self.assertTrue(exited.is_set())
        self.assertIsNone(session._av_reader_thread)
        self.assertIsNone(session._av_stop_evt)


if __name__ == "__main__":
    unittest.main()
