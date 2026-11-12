"""Authenticated Pixsee LAN audio/video session (IOTC + DTLS-PSK + AV).

Discovery, connection, live media, talk start/stop and acknowledgements are
supported. Camera settings, cloud APIs, pairing and firmware are untouched.
The existing Cubo engine supplies AV fragment recovery behind a DTLS adapter;
the Cubo connect routine and brand-specific startup commands are not used.
"""

from collections import deque
from dataclasses import replace
import ipaddress
import os
import queue
import select
import socket
import struct
import sys
import threading
import time

import cuboai_pure as transport
from pixsee_config import PixseeCredentials
from pixsee_dtls import DtlsPskClient, DtlsError
from pixsee_protocol import (
    PixseeProtocolError, build_discovery_probe, build_connect_probe,
    build_connect_ack, parse_discovery_reply, build_dtls_data, parse_dtls_data,
    decode_iotc_packet, keepalive_reply, build_session_close,
    build_talk_data, parse_talk_data,
)
from pixsee_av import derive_psk, build_av_login, parse_av_grant, AVProtocolError
from pixsee_audio import parse_pcm_audio_unit


class PixseeConnectionError(RuntimeError):
    pass


class PixseeAuthenticationError(PixseeConnectionError):
    pass


def _camera_ip(value):
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise ValueError("camera_ip must be an IPv4 address") from None
    if address.is_multicast or address.is_unspecified or address == ipaddress.IPv4Address('255.255.255.255'):
        raise ValueError("camera_ip must identify a single camera")
    return str(address)


def _timeout(value):
    value = float(value)
    if not 0 < value <= 120:
        raise ValueError("timeout must be greater than zero and at most 120 seconds")
    return value


def discover(camera_ip, timeout=3.0):
    """Discover only the specified IP. This does not establish an AV session."""
    camera_ip, timeout = _camera_ip(camera_ip), _timeout(timeout)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('', 0))
        sock.setblocking(False)
        deadline = time.monotonic() + timeout
        next_send, attempts = 0.0, 0
        while time.monotonic() < deadline:
            now = time.monotonic()
            if attempts < 3 and now >= next_send:
                sock.sendto(build_discovery_probe(), (camera_ip, 32761))
                attempts += 1
                next_send = now + 0.75
            ready, _, _ = select.select([sock], [], [], min(0.2, max(0, deadline-now)))
            if not ready:
                continue
            wire, peer = sock.recvfrom(4096)
            if peer[0] != camera_ip:
                continue
            try:
                reply = parse_discovery_reply(wire)
            except PixseeProtocolError:
                continue
            if reply.status == 0:
                return reply, peer
    raise PixseeConnectionError("No valid Pixsee discovery reply from the specified IP")


class _DtlsSocket:
    """Present decrypted AV packets to the existing reliable AV engine.

    One thread owns this adapter at a time. Synthetic packets exist only in
    process. Main-channel AV uses authenticated DTLS. Explicit talk exchanges
    also enable the native plaintext reverse AV channel on the same peer.
    """
    def __init__(self, sock, peer, nonce, dtls):
        self.socket, self.peer, self.nonce, self.dtls = sock, peer, nonce, dtls
        self.sequence = 0
        self.pending = deque()
        self.error = None
        self.received_datagrams = 0
        self.sent_datagrams = 0
        self.remote_identity = None
        self.talk_enabled = False
        self.talk_pending = deque()
        self.talk_sequence = 0

    def fileno(self):
        return self.socket.fileno()

    def setblocking(self, flag):
        self.socket.setblocking(flag)

    def _send_records(self, records):
        for record in records:
            wire = build_dtls_data(record, self.nonce, self.sequence)
            self.socket.sendto(wire, self.peer)
            self.sequence = (self.sequence + 1) & 0xffff
            self.sent_datagrams += 1

    def send_application(self, application):
        self._send_records(self.dtls.send_application(application))

    def send_talk(self, application):
        if not self.talk_enabled:
            raise PixseeConnectionError("Talk channel is not enabled")
        self.socket.sendto(build_talk_data(application, self.nonce, self.talk_sequence), self.peer)
        self.talk_sequence = (self.talk_sequence + 1) & 0xffff

    def _receive_wire(self, wire, peer):
        if peer != self.peer:
            return
        try:
            response = keepalive_reply(wire, self.nonce)
            if response is not None:
                self.remote_identity = decode_iotc_packet(wire)[16:24]
                self.socket.sendto(response, self.peer)
                return
            if self.talk_enabled:
                plain = decode_iotc_packet(wire)
                if len(plain) >= 16 and plain[14] == 1:
                    self.talk_pending.append(parse_talk_data(wire, self.nonce))
                    if len(self.talk_pending) > 256:
                        raise PixseeConnectionError("Talk receive queue exceeded its limit")
                    return
            record = parse_dtls_data(wire, self.nonce)
        except PixseeProtocolError:
            return
        self.received_datagrams += 1
        self._send_records(self.dtls.feed_datagram(record))
        self.pending.extend(self.dtls.receive_application())
        if len(self.pending) > 1024:
            raise PixseeConnectionError("AV receive queue exceeded its limit")

    def pump(self, timeout=0.2):
        ready, _, _ = select.select([self.socket], [], [], max(0, timeout))
        if ready:
            while True:
                try:
                    wire, peer = self.socket.recvfrom(65535)
                except BlockingIOError:
                    break
                self._receive_wire(wire, peer)
        timer = self.dtls.timeout_seconds
        if timer is not None and timer <= 0.001:
            self._send_records(self.dtls.handle_timeout())

    def handshake(self, timeout):
        self._send_records(self.dtls.start())
        deadline = time.monotonic() + timeout
        while not self.dtls.handshake_complete:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PixseeAuthenticationError(
                    "DTLS authentication timed out; check the selected device password")
            timer = self.dtls.timeout_seconds
            self.pump(min(0.2, remaining, timer if timer is not None else 0.2))

    def recvfrom(self, size):
        try:
            while not self.pending:
                wire, peer = self.socket.recvfrom(65535)
                self._receive_wire(wire, peer)
            application = self.pending.popleft()
            # The engine expects a fully scrambled IOTC packet with a 28-byte
            # prefix. Restore only that envelope, after DTLS authentication.
            plain = bytearray(28 + len(application))
            plain[:4] = bytes.fromhex('04021d0a')
            struct.pack_into('<H', plain, 4, len(plain)-16)
            plain[8:12] = bytes.fromhex('08041200')
            struct.pack_into('<H', plain, 12, self.nonce)
            struct.pack_into('<I', plain, 16, 12)
            struct.pack_into('<H', plain, 20, self.nonce)
            plain[28:] = application
            synthetic = transport.transcode(bytes(plain))
            if len(synthetic) > size:
                raise PixseeConnectionError("AV packet exceeds the reader buffer")
            return synthetic, self.peer
        except BlockingIOError:
            raise
        except (DtlsError, PixseeConnectionError) as exc:
            self.error = exc
            raise OSError("Pixsee DTLS receive failed") from exc

    def sendto(self, wire, peer):
        if peer != self.peer:
            raise ValueError("Pixsee session cannot send to another peer")
        plain = transport.inv_transcode(wire)
        if len(plain) < 28 or plain[8:10] != b'\x07\x04':
            raise PixseeProtocolError("Only AV data may pass through the DTLS adapter")
        try:
            self.send_application(plain[28:])
        except DtlsError as exc:
            self.error = exc
            raise OSError("Pixsee DTLS send failed") from exc
        return len(wire)

    def close(self):
        self.dtls.close()
        self.socket.close()


class PixseeSession(transport.TUTKDirectSession):
    """One authenticated LAN session; credentials are never tried in a loop."""
    _VIDEO_START = ()
    _VIDEO_START_MID = (0x01ff, bytes(8))
    _VIDEO_START_LATE = (0x0300, bytes(8))
    _audio_is_adts = False

    def __init__(self, camera_ip, credentials: PixseeCredentials, *, verbose=False,
                 openssl_library=None):
        super().__init__(camera_ip=_camera_ip(camera_ip), uid=credentials.uid,
                         account=credentials.account.encode(), password=credentials.password.encode(),
                         channels=[0, 1], verbose=verbose,
                         defer_stream_start=False, defer_video_start_late=False)
        self.credentials = credentials
        self.openssl_library = openssl_library
        self.discovery = None
        self.phase = 'not_connected'
        self.authenticated = False
        self._strip_frameinfo = False
        self._video_synced = False
        self.video_dropped = 0
        self.audio_dropped = 0
        self._reader_failure = None
        self._media_lock = threading.Lock()

    def _vlog(self, message):
        if self._verbose:
            print(message, file=sys.stderr, flush=True)

    def connect(self, timeout=20.0, attempts=1):
        timeout = _timeout(timeout)
        if attempts != 1:
            raise ValueError("Pixsee connect performs one credential attempt")
        if self._sock is not None:
            raise PixseeConnectionError("Disconnect the existing session first")
        credentials = self.credentials
        if credentials.uid is None:
            self.discovery, _ = discover(self.camera_ip, min(timeout, 3.0))
            credentials = replace(credentials, uid=self.discovery.uid)
        self.uid = credentials.uid
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        nonce = transport.gen_R()
        deadline = time.monotonic() + timeout
        peer = None
        adapter = None
        self.phase = 'iotc_precheck'
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4*1024*1024)
            sock.bind(('', 0))
            sock.setblocking(False)
            probe = build_connect_probe(credentials.uid, nonce, credentials.auth_key)
            next_send, sent = 0.0, 0
            while time.monotonic() < deadline and peer is None:
                now = time.monotonic()
                if now >= next_send and sent < 3:
                    sock.sendto(probe, (self.camera_ip, 32761))
                    sent += 1
                    next_send = now + 0.75
                ready, _, _ = select.select([sock], [], [], min(0.2, max(0, deadline-now)))
                if not ready:
                    continue
                wire, candidate = sock.recvfrom(4096)
                if candidate[0] != self.camera_ip:
                    continue
                try:
                    reply = parse_discovery_reply(wire, expected_uid=credentials.uid,
                        expected_nonce=nonce, expected_fingerprint=transport._CLIENT_FINGERPRINT)
                except PixseeProtocolError:
                    continue
                if reply.status in (5, 6):
                    raise PixseeAuthenticationError(
                        f"Camera rejected the IOTC auth key (status {reply.status})")
                if reply.status not in (1, 7):
                    raise PixseeConnectionError(f"Camera refused IOTC connection (status {reply.status})")
                self.discovery, peer = reply, candidate
            if peer is None:
                raise PixseeConnectionError("IOTC connection precheck timed out")
            sock.sendto(build_connect_ack(credentials.uid, nonce, credentials.auth_key), peer)
            self._vlog('[pixsee] IOTC precheck accepted')
            identity, psk = derive_psk(credentials.account, credentials.password)
            dtls = DtlsPskClient(identity, psk, library_path=self.openssl_library)
            adapter = _DtlsSocket(sock, peer, nonce, dtls)
            self.phase = 'dtls_authentication'
            adapter.handshake(max(0.001, deadline-time.monotonic()))
            self._vlog('[pixsee] DTLS authenticated')
            self.phase = 'av_login'
            token = (int.from_bytes(os.urandom(4), 'little') & 0x7fffffff) or 1
            adapter.send_application(build_av_login(credentials.account, credentials.password, token))
            adapter.send_application(build_av_login(credentials.account, credentials.password, token, resend=True))
            login_last_sent, login_sends = time.monotonic(), 1
            grant = None
            while time.monotonic() < deadline and grant is None:
                adapter.pump(min(0.2, max(0, deadline-time.monotonic())))
                while adapter.pending:
                    application = adapter.pending.popleft()
                    try:
                        grant = parse_av_grant(application, (token + 1) & 0xffffffff
                                               if len(application) > 1 and application[1] == 0x21 else token)
                    except AVProtocolError as exc:
                        self._vlog(f'[pixsee] ignored AV reply: bytes={len(application)} '
                                   f'opcode={application[1] if len(application) > 1 else -1}: {exc}')
                        continue
                    if not grant.authenticated:
                        raise PixseeAuthenticationError(f"Camera rejected AV login (status {grant.status})")
                    break
                if grant is None and login_sends < 4 and time.monotonic()-login_last_sent >= 0.75:
                    # Retransmit the same request/token, never another credential.
                    adapter.send_application(build_av_login(credentials.account, credentials.password, token, resend=True))
                    login_last_sent, login_sends = time.monotonic(), login_sends+1
            if grant is None:
                raise PixseeConnectionError("DTLS completed but AV login was not confirmed")
            self._sock, self._cam, self._R = adapter, peer, nonce
            self.session_hdr = bytes(16)  # engine readiness marker only
            self._seq = 2
            self._relseq = self._frmno = self._ack_ord = self._data_ack = 0
            self._cam_msgs.clear()
            self._frag_D = self._frag_edge = None
            self._frag_C = self._frag_edge_acked = 0xffff
            self._frag_received.clear()
            self._frag_gap_ts.clear()
            self._hole_req_ts.clear()
            self._hole_first_req.clear()
            self._ts_ref = None
            self._video_synced = False
            self._reader_failure = None
            self.phase, self.authenticated = 'av_authenticated', True
            self._av_server_word = grant.server_word
            self._vlog('[pixsee] AV login accepted')
            return True
        except BaseException:
            self.phase = 'failed'
            if peer is not None:
                try:
                    sock.sendto(build_session_close(nonce), peer)
                except OSError:
                    pass
            if adapter is not None:
                adapter.close()
            else:
                sock.close()
            raise

    def _classify_av_unit(self, unit):
        if len(unit) > 16 and struct.unpack_from('<H', unit, len(unit)-16)[0] == 0x8c:
            return 'audio'
        return super()._classify_av_unit(unit)

    def _prepare_av_unit(self, kind, unit, frameinfo, complete):
        if kind == 'audio':
            try:
                return parse_pcm_audio_unit(unit, complete=complete)
            except AVProtocolError:
                self.audio_dropped += 1
                return None
        if kind != 'video':
            return None
        if not complete or len(unit) <= 20 or struct.unpack_from('<H', unit, len(unit)-16)[0] != 0x4e:
            self._video_synced = False
            self.video_dropped += 1
            return None
        info, video = unit[-16:], unit[:-16]
        # Real firmware 1.006.25 sets FRAMEINFO flags=1 on P frames too.
        # Use the H.264 IDR NAL to decide whether decoding can safely resume.
        keyframe = any(not (header & 0x80) and header & 0x1f == 5
                       for header in transport._iter_nal_headers(video))
        if keyframe:
            self._video_synced = True
        if not self._video_synced:
            self.video_dropped += 1
            return None
        return video, {'codec': 'h264', 'codec_id': 0x4e, 'keyframe': keyframe,
                       'complete': True, 'timestamp_ms': struct.unpack_from('<I', info, 12)[0]}

    def _av_reader(self, sock, output, stop):
        try:
            super()._av_reader(sock, output, stop)
        except Exception as exc:
            self._reader_failure = exc

    def _read_av_units(self, timeout=None, max_items=None):
        if not self._media_lock.acquire(blocking=False):
            raise PixseeConnectionError("Only one stream or talk consumer may use a session")
        try:
            yield from self._read_av_units_owned(timeout, max_items)
        finally:
            self._media_lock.release()

    def _read_av_units_owned(self, timeout=None, max_items=None):
        if not self.authenticated or self._sock is None:
            raise PixseeConnectionError("Connect and authenticate before requesting video")
        if self._av_reader_thread is not None or getattr(self._sock, 'talk_enabled', False):
            raise PixseeConnectionError("Only one stream reader may use a session")
        # Native Pixsee order. There are no Cubo configuration requests here.
        for io_type in (0x01ff, 0x0300):
            self._sock.sendto(transport.build_ioctl_data(self._R, self._seq,
                self._relseq, self._frmno, io_type, bytes(8)), self._cam)
            self._seq += 1
            self._relseq += 1
            self._frmno += 1
        output = queue.Queue(maxsize=600)
        stop = threading.Event()
        reader = threading.Thread(target=self._av_reader, args=(self._sock, output, stop), daemon=True)
        self._av_reader_thread, self._av_stop_evt = reader, stop
        self._reader_failure = None
        reader.start()
        deadline = time.monotonic()+timeout if timeout is not None else None
        count = 0
        try:
            while deadline is None or time.monotonic() < deadline:
                if self._sock.error is not None or self._reader_failure is not None:
                    raise PixseeConnectionError("Pixsee stream transport failed") from (self._sock.error or self._reader_failure)
                try:
                    item = output.get(timeout=0.2)
                except queue.Empty:
                    if not reader.is_alive():
                        raise PixseeConnectionError("Pixsee stream reader stopped")
                    continue
                if item is None:
                    if self._sock.error or self._reader_failure:
                        raise PixseeConnectionError("Pixsee stream transport failed") from (self._sock.error or self._reader_failure)
                    return
                yield item
                count += 1
                if max_items is not None and count >= max_items:
                    return
        finally:
            stop.set()
            # Drain the bounded queue as the reader exits so its end marker
            # cannot block when a consumer stopped early with a full queue.
            while reader.is_alive():
                try:
                    output.get_nowait()
                except queue.Empty:
                    pass
                reader.join(timeout=0.05)
            self._av_reader_thread = self._av_stop_evt = None

    def av_frames_timed(self, duration=None, max_frames=None):
        if duration is not None:
            duration = _timeout(duration)
        yield from self._read_av_units(timeout=duration, max_items=max_frames)

    def audio_frames_timed(self, duration=None, max_frames=None):
        count = 0
        for kind, unit, metadata in self.av_frames_timed(duration):
            if kind == 'audio':
                yield unit, metadata
                count += 1
                if max_frames is not None and count >= max_frames:
                    break

    def talk_pcm(self, chunks, *, timeout=8.0, duration=None, on_audio=None):
        """Play PCM16LE mono 8 kHz, optionally observing simultaneous camera audio.

        Native talk channel 1 is unencrypted. Transport ACKs do not establish
        physical speaker output. ``on_audio(pcm, info)`` receives complete audio.
        """
        from pixsee_talk import run_talk
        if not self._media_lock.acquire(blocking=False):
            raise PixseeConnectionError("Only one stream or talk consumer may use a session")
        try:
            return run_talk(self, chunks, timeout=timeout, duration=duration, on_audio=on_audio)
        finally:
            self._media_lock.release()

    def video_frames_timed(self, duration=None, max_frames=None):
        if not self.authenticated:
            raise PixseeConnectionError("Connect and authenticate before requesting video")
        if duration is not None:
            duration = _timeout(duration)
        count = 0
        for kind, unit, metadata in self._read_av_units(timeout=duration):
            if self._sock.error is not None:
                raise PixseeConnectionError(str(self._sock.error))
            if kind != 'video':
                continue
            yield unit, metadata
            count += 1
            if max_frames is not None and count >= max_frames:
                break
        if self._sock is not None and self._sock.error is not None:
            raise PixseeConnectionError(str(self._sock.error))

    def disconnect(self):
        self._stop_reader()
        adapter = self._sock
        self._sock = None
        self.authenticated = False
        self.session_hdr = None
        if adapter is not None:
            try:
                for _ in range(2):
                    adapter.socket.sendto(build_session_close(adapter.nonce), adapter.peer)
            except OSError:
                pass
            finally:
                adapter.close()
        self._R = self._cam = None
        self.phase = 'disconnected'

    close = disconnect

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.disconnect()
