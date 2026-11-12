"""Bounded local media conversion for Pixsee PCM16 mono 8 kHz audio."""

from __future__ import annotations

from collections import deque
from contextlib import contextmanager
import os
from pathlib import Path
import queue
import select
import shutil
import statistics
import subprocess
import sys
import threading
import time
import wave


SAMPLE_RATE = 8000
SAMPLE_WIDTH = 2
TALK_CHUNK_BYTES = 640


def _ffmpeg():
    executable = shutil.which(os.environ.get("PIXSEE_FFMPEG", "ffmpeg"))
    if executable is None:
        raise RuntimeError("FFmpeg is required for combined audio/video or audio-file conversion")
    return executable


def validate_pcm(data, metadata=None):
    if len(data) % SAMPLE_WIDTH:
        raise ValueError("PCM audio must contain complete 16-bit samples")
    info = metadata or {}
    for key, expected in (("sample_rate", SAMPLE_RATE), ("channels", 1), ("sample_width", 2)):
        if key in info and info[key] != expected:
            raise ValueError("Pixsee audio must be PCM16 little-endian, mono, 8000 Hz")


class MediaClock:
    """One camera-clock origin for both tracks, with independent fallback cadence.

    A one-second headroom permits the AAC encoder's 128 ms priming packet to
    precede the first source sample without wrapping the 33-bit MPEG PTS clock.
    """

    def __init__(self):
        self.origin = None
        self.arrival_origin = time.monotonic()
        self.previous = {}

    def feed(self, kind, metadata, samples=0):
        timestamp = (metadata or {}).get("timestamp_ms")
        valid_timestamp = type(timestamp) is int and 0 <= timestamp <= 0xffffffff
        if valid_timestamp:
            if self.origin is None:
                self.origin = timestamp
            delta = ((timestamp - self.origin + 0x80000000) & 0xffffffff) - 0x80000000
            pts = 90000 + delta * 90
        else:
            pts = round(90000 + (time.monotonic() - self.arrival_origin) * 90000)
        previous = self.previous.get(kind)
        if kind == "audio" and previous is not None and not valid_timestamp:
            pts = previous[0] + previous[1]
        if kind != "audio" and previous is not None and pts <= previous[0]:
            pts = previous[0] + previous[1]
        pts = max(11520, pts)
        cadence = round(samples * 90000 / SAMPLE_RATE) if samples else 1
        self.previous[kind] = (pts, cadence)
        return pts


class PCMTimeline:
    """Place PCM samples on one clock, rejecting block-level timestamp jitter.

    Three source blocks provide two blocks of lookahead (128 ms at the tested
    camera's block size). The median clock offset rejects a single timestamp
    excursion. Differences within 32 ms preserve every source sample; sustained
    differences beyond that deadband insert silence or trim overlapping samples.
    AAC timestamps can then follow the exact sample count without frame overlap
    or cumulative drift after packet loss. Only the audio payload is adjusted.
    """

    JITTER_TICKS = 32 * 90
    MAX_GAP_SAMPLES = 120 * SAMPLE_RATE

    def __init__(self):
        self.pending = deque()
        self.recent_offsets = deque(maxlen=2)
        self.received_samples = 0
        self.emitted_samples = 0
        self.anchor = None
        self.inserted_samples = 0
        self.trimmed_samples = 0

    @staticmethod
    def _ticks(samples):
        return samples * 90000 / SAMPLE_RATE

    def _emit(self, final=False):
        pcm, start, offset = self.pending[0]
        offsets = [entry[2] for entry in self.pending]
        if self.recent_offsets and len(offsets) >= 2:
            # The preceding, current and following blocks distinguish a real
            # step from one bad timestamp without moving the gap one block early.
            offsets = [self.recent_offsets[-1], offsets[0], offsets[1]]
        elif final and len(offsets) < 3:
            offsets = list(self.recent_offsets)[-(3 - len(offsets)):] + offsets
        estimated_offset = statistics.median(offsets)
        self.pending.popleft()
        self.recent_offsets.append(offset)
        if self.anchor is None:
            self.anchor = estimated_offset = offset
        expected = self.anchor + self._ticks(self.emitted_samples)
        target = estimated_offset + self._ticks(start)
        delta = target - expected
        result = []
        if delta > self.JITTER_TICKS:
            missing = round(delta * SAMPLE_RATE / 90000)
            if missing > self.MAX_GAP_SAMPLES:
                raise ValueError("Camera audio timestamp discontinuity exceeds 120 seconds")
            self.inserted_samples += missing
            while missing:
                count = min(missing, 8192)
                result.append((bytes(count * SAMPLE_WIDTH),
                               round(self.anchor + self._ticks(self.emitted_samples))))
                self.emitted_samples += count
                missing -= count
        elif delta < -self.JITTER_TICKS:
            overlap = min(round(-delta * SAMPLE_RATE / 90000), len(pcm) // SAMPLE_WIDTH)
            pcm = pcm[overlap * SAMPLE_WIDTH:]
            self.trimmed_samples += overlap
        if pcm:
            result.append((pcm, round(self.anchor + self._ticks(self.emitted_samples))))
            self.emitted_samples += len(pcm) // SAMPLE_WIDTH
        return result

    def feed(self, pcm, pts):
        validate_pcm(pcm)
        if not pcm:
            return []
        if len(pcm) > 65536:
            raise ValueError("PCM encoder input chunks must not exceed 65536 bytes")
        if type(pts) is not int:
            raise ValueError("PCM timestamp must be an integer MPEG-TS clock value")
        self.pending.append((pcm, self.received_samples,
                             pts - self._ticks(self.received_samples)))
        self.received_samples += len(pcm) // SAMPLE_WIDTH
        return self._emit() if len(self.pending) >= 3 else []

    def finish(self):
        result = []
        while self.pending:
            result.extend(self._emit(final=True))
        return result


class AACEncoder:
    """Continuous FFmpeg encoder with bounded output and source-sample timestamps.

    FFmpeg's AAC-LC encoder emits one 1024-sample priming packet. It is retained
    at source PTS minus 1024 samples so the audible content stays synchronized.
    """

    def __init__(self):
        self.process = subprocess.Popen(
            [_ffmpeg(), "-hide_banner", "-loglevel", "error", "-nostdin",
             "-probesize", "32", "-analyzeduration", "0", "-f", "s16le",
             "-ar", str(SAMPLE_RATE), "-ac", "1", "-i", "pipe:0", "-vn",
             "-c:a", "aac", "-b:a", "24k", "-f", "adts", "-flush_packets", "1", "pipe:1"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            bufsize=0)
        os.set_blocking(self.process.stdin.fileno(), False)
        self.frames = queue.Queue(maxsize=64)
        self.error = None
        self.finished = threading.Event()
        self.stop = threading.Event()
        self.samples = 0
        self.encoded_samples = -1024
        self.timeline = PCMTimeline()
        self.first_pts = None
        self.reader = threading.Thread(target=self._read, name="pixsee-aac", daemon=True)
        self.reader.start()

    def _read(self):
        pending = bytearray()
        try:
            while not self.stop.is_set():
                block = self.process.stdout.read(4096)
                if not block:
                    break
                pending.extend(block)
                while len(pending) >= 7:
                    if pending[0] != 0xff or pending[1] & 0xf6 != 0xf0:
                        raise RuntimeError("FFmpeg returned an invalid AAC ADTS header")
                    length = ((pending[3] & 3) << 11) | (pending[4] << 3) | (pending[5] >> 5)
                    if length < 7 or length > 8191:
                        raise RuntimeError("FFmpeg returned an invalid AAC frame length")
                    if len(pending) < length:
                        break
                    frame = bytes(pending[:length])
                    del pending[:length]
                    self.frames.put(frame, timeout=5)
            if pending and not self.stop.is_set():
                raise RuntimeError("FFmpeg ended with an incomplete AAC frame")
        except (OSError, RuntimeError, queue.Full) as error:
            self.error = error
        finally:
            self.finished.set()

    def _drain(self):
        result = []
        while True:
            try:
                frame = self.frames.get_nowait()
            except queue.Empty:
                break
            sample = self.encoded_samples
            if sample < 0:
                pts = self.first_pts + round(sample * 90000 / SAMPLE_RATE)
            else:
                pts = self.first_pts + round(sample * 90000 / SAMPLE_RATE)
            result.append((frame, pts))
            self.encoded_samples += 1024
        if self.error is not None:
            raise RuntimeError("AAC encoder output failed") from self.error
        return result

    def feed(self, pcm, pts):
        result = self._drain()
        for block, block_pts in self.timeline.feed(pcm, pts):
            result.extend(self._write(block, block_pts))
        return result

    def _write(self, pcm, pts):
        if self.first_pts is None:
            self.first_pts = pts
        self.samples += len(pcm) // 2
        remaining = memoryview(pcm)
        result = self._drain()
        deadline = time.monotonic() + 5
        while remaining:
            if self.process.poll() is not None:
                raise RuntimeError("FFmpeg audio encoder exited unexpectedly")
            if time.monotonic() >= deadline:
                raise RuntimeError("FFmpeg audio encoder input timed out")
            _, writable, _ = select.select([], [self.process.stdin], [], 0.1)
            result.extend(self._drain())
            if writable:
                try:
                    remaining = remaining[os.write(self.process.stdin.fileno(), remaining):]
                except BlockingIOError:
                    pass
                except BrokenPipeError:
                    raise RuntimeError("FFmpeg audio encoder closed its input") from None
        result.extend(self._drain())
        return result

    def finish(self):
        result = []
        for block, pts in self.timeline.finish():
            result.extend(self._write(block, pts))
        if self.process.stdin and not self.process.stdin.closed:
            self.process.stdin.close()
        deadline = time.monotonic() + 5
        while not self.finished.is_set():
            result.extend(self._drain())
            if time.monotonic() >= deadline:
                raise RuntimeError("FFmpeg audio encoder did not finish")
            self.finished.wait(0.02)
        result.extend(self._drain())
        if self.process.wait(timeout=2) != 0:
            raise RuntimeError("FFmpeg could not encode the received audio")
        return result

    def close(self):
        self.stop.set()
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        for pipe in (self.process.stdin, self.process.stdout):
            if pipe is not None:
                pipe.close()
        self.reader.join(timeout=5.5)


@contextmanager
def pcm_input(path, input_format="auto", duration=None):
    """Yield at most 40 ms chunks, converting files/streams without buffering them.

    Auto input uses FFmpeg. Raw input is already PCM16LE mono 8 kHz. The caller
    should obtain the first chunk before connecting so empty/bad files fail early.
    """
    process = None
    owned = False
    if path == "-":
        source = getattr(sys.stdin, "buffer", None)
        if source is None:
            raise ValueError("stdin must support binary audio input")
    else:
        source = open(Path(path), "rb")
        owned = True
    try:
        if input_format == "auto":
            # Passing an open descriptor avoids interpreting a path as a URL.
            command = [_ffmpeg(), "-hide_banner", "-loglevel", "error", "-nostdin",
                       "-protocol_whitelist", "file,pipe", "-i", "pipe:0", "-vn",
                       "-ac", "1", "-ar", str(SAMPLE_RATE), "-c:a", "pcm_s16le"]
            if duration is not None:
                command += ["-t", str(duration)]
            command += ["-f", "s16le", "pipe:1"]
            process = subprocess.Popen(command, stdin=source, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, bufsize=0)
            stream = process.stdout
        elif input_format == "s16le":
            stream = source
        else:
            raise ValueError("Unsupported audio input format")

        def chunks():
            remaining = None if duration is None else int(duration * SAMPLE_RATE) * SAMPLE_WIDTH
            pending = b""
            while remaining is None or remaining > 0:
                needed = TALK_CHUNK_BYTES if remaining is None else min(TALK_CHUNK_BYTES, remaining)
                data = stream.read(needed - len(pending))
                if data:
                    pending += data
                if len(pending) == needed or not data:
                    validate_pcm(pending)
                    if pending:
                        yield pending
                        if remaining is not None:
                            remaining -= len(pending)
                        pending = b""
                    if not data:
                        break
            if process is not None and remaining != 0:
                try:
                    status = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    raise RuntimeError("FFmpeg audio conversion did not finish") from None
                if status != 0:
                    raise RuntimeError("FFmpeg could not decode the audio input")
        yield chunks()
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            process.stdout.close()
        if owned:
            source.close()


def wav_writer(output):
    writer = wave.open(output, "wb")
    writer.setnchannels(1)
    writer.setsampwidth(SAMPLE_WIDTH)
    writer.setframerate(SAMPLE_RATE)
    return writer
