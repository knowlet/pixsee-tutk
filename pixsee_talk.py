"""Native Pixsee reverse AV channel, with one network owner and bounded buffers.

Channel 0 stays DTLS authenticated. Native avServStart3 opens channel 1 as
plaintext AV, pinned to that same camera IP/port and session fingerprint.
ACK counters describe camera transport feedback, not audible playback.
"""

from collections import OrderedDict
import queue
import struct
import threading
import time

from pixsee_audio import (parse_talk_login, build_talk_grant, build_talk_audio,
                          parse_pcm_audio_unit)
from pixsee_av import AVProtocolError


class _PcmInput:
    """Keep a slow file/pipe producer from blocking camera keepalives/timeouts."""
    def __init__(self, chunks):
        self.queue = queue.Queue(maxsize=16)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._feed, args=(chunks,), daemon=True)
        self.thread.start()

    def _feed(self, chunks):
        try:
            for chunk in chunks:
                if self.stop.is_set():
                    return
                if not isinstance(chunk, bytes) or not chunk or len(chunk) > 640 or len(chunk) % 2:
                    raise ValueError("Talk input must contain even PCM16 chunks of 2..640 bytes")
                if not self._put(chunk):
                    return
        except BaseException as exc:
            self._put(exc)
        finally:
            self._put(None)

    def _put(self, item):
        while not self.stop.is_set():
            try:
                self.queue.put(item, timeout=0.1)
                return True
            except queue.Full:
                pass
        return False

    def close(self):
        self.stop.set()
        self.thread.join(timeout=0.2)


class _AudioMonitor:
    """Capture complete, fixed-size native PCM AUs during a talk exchange."""
    def __init__(self, callback):
        self.callback = callback
        self.messages = OrderedDict()
        self.done = OrderedDict()

    def _finish(self, index):
        self.messages.pop(index, None)
        self.done[index] = None
        while len(self.done) > 128:
            self.done.popitem(last=False)

    def feed(self, application):
        if self.callback is None or len(application) < 40 or application[0] != 12:
            return
        if application[30:36] == bytes(6):  # Reliable IO rather than media.
            return
        size, = struct.unpack_from('<H', application, 24)
        index, = struct.unpack_from('<H', application, 28)
        fragment, = struct.unpack_from('<H', application, 18)
        if size > 1024 or len(application) != 36 + size or index in self.done:
            return
        parts = self.messages.setdefault(index, {})
        parts[fragment] = application[36:]
        while len(self.messages) > 32:
            self.messages.popitem(last=False)
        if len(parts) > 3 or sum(map(len, parts.values())) > 1040:
            self._finish(index)
            return  # PCM downlink is 1024 bytes plus its 16-byte trailer.
        order = sorted(parts)
        if order[-1] - order[0] + 1 != len(order):
            return
        unit = b''.join(parts[n] for n in order)
        if len(unit) != 1040:
            return
        try:
            pcm, info = parse_pcm_audio_unit(unit)
        except ValueError:
            return
        self._finish(index)
        self.callback(pcm, info)


def run_talk(session, chunks, *, timeout=8.0, duration=None, on_audio=None):
    from pixsee_session import PixseeConnectionError, _timeout
    timeout = _timeout(timeout)
    if duration is not None:
        duration = _timeout(duration)
    if not session.authenticated or session._sock is None:
        raise PixseeConnectionError("Connect and authenticate before talking")
    if session._av_reader_thread is not None or session._sock.talk_enabled:
        raise PixseeConnectionError("Talk requires sole ownership of this session")
    source = _PcmInput(iter(chunks))
    adapter = session._sock
    monitor = _AudioMonitor(on_audio)
    sent = acked = resends = relative = 0
    sent_buffer = OrderedDict()
    pending_missing = set()
    missing_last_sent = {}
    grant_token = None
    ready = speaker_started = False
    eof = False
    next_send = first_send = last_send = None
    last_ack = last_input = time.monotonic()
    start = last_ack
    last_feedback = start
    session._talk_stop = False

    def ioctl(kind, payload):
        session._sock.sendto(session_transport.build_ioctl_data(session._R,
            session._seq, session._relseq, session._frmno, kind, payload), session._cam)
        session._seq += 1
        session._relseq += 1
        session._frmno += 1

    # Local import avoids making the wire helpers depend on the Cubo engine.
    import cuboai_pure as session_transport
    try:
        # Validate/prefetch before enabling the speaker, without unbounded waits.
        try:
            first_chunk = source.queue.get(timeout=timeout)
        except queue.Empty:
            raise PixseeConnectionError("Talk input timed out") from None
        if isinstance(first_chunk, BaseException):
            raise first_chunk
        if first_chunk is None:
            raise ValueError("Talk input contains no PCM samples")
        next_chunk = first_chunk
        adapter.talk_pending.clear()
        adapter.talk_sequence = 0
        adapter.talk_enabled = True
        ioctl(0x01ff, bytes(8))
        ioctl(0x0300, bytes(8))
        # Mark before send, so interruption or send failure still attempts stop.
        speaker_started = True
        ioctl(0x0350, bytes((1,)) + bytes(7))
        start = time.monotonic()
        while not session._talk_stop:
            now = time.monotonic()
            if grant_token is None and now - start >= timeout:
                raise PixseeConnectionError("Camera did not open the talk channel")
            if grant_token is not None and not ready and now - start >= timeout:
                raise PixseeConnectionError("Camera did not acknowledge the talk grant")
            if ready and now-last_feedback >= timeout:
                raise PixseeConnectionError("Camera stopped acknowledging talk audio")
            if first_send is not None and duration is not None and now - first_send >= duration:
                eof = True
                next_chunk = None
            if eof and ((acked >= sent and not pending_missing)
                        or (last_send is not None and now-last_send >= 1.5)):
                break
            if ready and not eof and next_send is not None and now >= next_send:
                if next_chunk is None:
                    try:
                        item = source.queue.get_nowait()
                    except queue.Empty:
                        if now-last_input > timeout:
                            raise PixseeConnectionError("Talk input stalled")
                    else:
                        if isinstance(item, BaseException):
                            raise item
                        if item is None:
                            eof = True
                        else:
                            next_chunk = item
                            last_input = now
                if next_chunk is not None:
                    packet = build_talk_audio(next_chunk, relative, sent)
                    adapter.send_talk(packet)
                    sent_buffer[sent] = next_chunk
                    while len(sent_buffer) > 128:
                        expired, _ = sent_buffer.popitem(last=False)
                        missing_last_sent.pop(expired, None)
                    if first_send is None:
                        first_send = now
                    last_send = now
                    sent += 1
                    relative += 1
                    next_send += len(next_chunk)/16000
                    if now-next_send > 0.2:
                        next_send = now + len(next_chunk)/16000
                    next_chunk = None
            if now-last_ack >= 0.08:
                session._send_ack()
                session._send_nak()
                last_ack = now
            wait = 0.02
            if ready and not eof and next_send is not None:
                wait = max(0.001, min(wait, next_send-time.monotonic()))
            adapter.pump(wait)
            while adapter.pending:
                app = adapter.pending.popleft()
                if len(app) >= 40 and app[0] == 12:
                    session._note_cam_data(bytes(28)+app)
                    monitor.feed(app)
                elif len(app) >= 10 and app[0] == 0x0a:
                    session._cam_clock = struct.unpack_from('<H', app, 8)[0]
                    session._cam_clock_ts = time.time()
            while adapter.talk_pending:
                app = adapter.talk_pending.popleft()
                if len(app) >= 2 and app[0] == 0:
                    try:
                        login = parse_talk_login(app)
                    except ValueError:
                        continue
                    if not login.resend:
                        continue
                    if grant_token is not None and login.token != grant_token:
                        raise PixseeConnectionError("Camera changed talk token during streaming")
                    adapter.send_talk(build_talk_grant(login, 60))
                    grant_token = login.token
                elif grant_token is not None and len(app) >= 24 and app[0] in (9, 10):
                    high_count = None
                    requested_missing = set()
                    if app[0] == 9:
                        base, high = struct.unpack_from('<HH', app, 8)
                        count, = struct.unpack_from('<H', app, 14)
                        # No-list ACKs carry a two-byte clock; a SACK list
                        # replaces it. Do not accept truncated/extra entries.
                        if count > 128 or len(app) != 22 + 2 * max(count, 1):
                            continue
                        if sent and (high != 0xffff or sent >= 65536):
                            high_index = session_transport._unwrap_index_back(high, sent-1)
                            if not 0 <= high_index < sent:
                                continue
                            high_count = high_index + 1
                            base_index = session_transport._unwrap_index_back(base, high_index)
                            valid_missing = True
                            for k in range(count):
                                offset, = struct.unpack_from('<H', app, 22+k*2)
                                number = base_index + offset
                                if not (base_index < number <= high_index and 0 <= number < sent):
                                    valid_missing = False
                                    break
                                requested_missing.add(number)
                            if not valid_missing:
                                continue
                        elif count:
                            continue
                    last_feedback = time.monotonic()
                    ready = True
                    if next_send is None:
                        next_send = time.monotonic()
                    if high_count is not None and high_count >= acked:
                        acked = high_count
                        # Latest bounded missing-request list, not proof of
                        # delivery/playback. Older ACKs cannot clear new holes.
                        pending_missing = requested_missing
                        for number in sorted(pending_missing):
                            pcm = sent_buffer.get(number)
                            previous = missing_last_sent.get(number, -float('inf'))
                            if pcm is not None and last_feedback-previous >= 0.15:
                                adapter.send_talk(build_talk_audio(pcm, relative, number))
                                missing_last_sent[number] = last_feedback
                                relative += 1
                                resends += 1
            if adapter.error is not None:
                raise PixseeConnectionError("Talk transport failed") from adapter.error
        if not sent:
            raise PixseeConnectionError("No audio frames were sent")
        if not acked:
            raise PixseeConnectionError("Camera did not acknowledge any talk audio")
        return {'sent_frames': sent, 'camera_high_water_frames': acked, 'resends': resends,
                'final_high_water_observed': acked >= sent,
                'pending_missing_frames': len(pending_missing),
                'sample_rate': 8000, 'channels': 1, 'codec': 'pcm_s16le',
                'talk_encrypted': False}
    finally:
        source.close()
        if speaker_started:
            try:
                ioctl(0x0351, bytes(8))
            except (OSError, RuntimeError):
                pass
        adapter.talk_enabled = False
        adapter.talk_pending.clear()
