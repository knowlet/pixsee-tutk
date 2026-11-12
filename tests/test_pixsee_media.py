"""Media boundaries and real FFmpeg conversion, without camera/network access."""

import io
import math
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import wave

from pixsee_media import AACEncoder, MediaClock, PCMTimeline, pcm_input, validate_pcm


class PixseeMediaTests(unittest.TestCase):
    def test_clock_shares_camera_origin_and_handles_rollover(self):
        clock = MediaClock()
        self.assertEqual(clock.feed("video", {"timestamp_ms": 0xfffffff0}), 90000)
        self.assertEqual(clock.feed("audio", {"timestamp_ms": 0x10}, 512), 90000 + 32 * 90)
        self.assertEqual(clock.feed("video", {"timestamp_ms": 0x30}), 90000 + 64 * 90)
        # Audio retains raw metadata for the PCM jitter filter; it must not
        # invent a forward step that the next real timestamp then reverses.
        self.assertEqual(clock.feed("audio", {"timestamp_ms": 0x10}, 512), 90000 + 32 * 90)

    def test_pcm_clock_preserves_every_sample_through_timestamp_jitter(self):
        clock = PCMTimeline()
        blocks = [struct.pack("<h", index + 1) * 512 for index in range(14)]
        jitter = [0, 1, -1, 0, 64, 0, -64, 0, 3, -2, 0, 1, 0, 0]
        output = []
        for index, block in enumerate(blocks):
            output.extend(clock.feed(block, 90000 + (index * 64 + jitter[index]) * 90))
        output.extend(clock.finish())
        self.assertEqual(b"".join(block for block, _ in output), b"".join(blocks))
        self.assertEqual([pts for _, pts in output], [90000 + index * 5760 for index in range(14)])
        self.assertEqual((clock.inserted_samples, clock.trimmed_samples), (0, 0))

    def test_pcm_clock_preserves_a_real_gap_as_silence_at_its_boundary(self):
        clock = PCMTimeline()
        output = []
        blocks = [struct.pack("<h", index + 1) * 512 for index in range(20)]
        for index, block in enumerate(blocks):
            timestamp = index * 64 + (128 if index >= 10 else 0)
            output.extend(clock.feed(block, 90000 + timestamp * 90))
        output.extend(clock.finish())
        expected = b"".join(blocks[:10]) + bytes(1024 * 2) + b"".join(blocks[10:])
        self.assertEqual(b"".join(block for block, _ in output), expected)
        self.assertEqual((clock.inserted_samples, clock.trimmed_samples), (1024, 0))
        for (previous, previous_pts), (_, pts) in zip(output, output[1:]):
            self.assertEqual(pts, previous_pts + len(previous) // 2 * 90000 // 8000)

    def test_pcm_clock_removes_a_confirmed_overlapping_block(self):
        clock = PCMTimeline()
        source = [struct.pack("<h", index + 1) * 512 for index in range(20)]
        blocks = source[:10] + [source[9]] + source[10:]
        output = []
        for index, block in enumerate(blocks):
            timestamp = index * 64 - (64 if index >= 10 else 0)
            output.extend(clock.feed(block, 90000 + timestamp * 90))
        output.extend(clock.finish())
        self.assertEqual(b"".join(block for block, _ in output), b"".join(source))
        self.assertEqual((clock.inserted_samples, clock.trimmed_samples), (0, 512))

    def test_pcm_clock_bounds_long_running_clock_skew_in_both_directions(self):
        for skew in (-1, 1):
            clock = PCMTimeline()
            for index in range(10000):
                # About 1000 ppm clock mismatch over more than ten minutes.
                timestamp = index * 64 + round(skew * index * 0.064)
                clock.feed(bytes(1024), 90000 + timestamp * 90)
            clock.finish()
            target_end = 90000 + (9999 * 64 + round(skew * 9999 * 0.064) + 64) * 90
            actual_end = clock.anchor + clock.emitted_samples * 90000 / 8000
            self.assertLessEqual(abs(actual_end - target_end), 32 * 90)
            self.assertGreater(clock.inserted_samples + clock.trimmed_samples, 0)

    def test_pcm_validation_rejects_wrong_rate_or_partial_samples(self):
        for data, info in ((b"\x00", None), (b"\x00\x00", {"sample_rate": 16000}),
                           (b"\x00\x00", {"channels": 2}), (b"\x00\x00", {"sample_width": 1})):
            with self.subTest(info=info), self.assertRaises(ValueError):
                validate_pcm(data, info)

    def test_raw_stdin_is_bounded_by_sample_duration(self):
        stdin = type("Input", (), {"buffer": io.BytesIO(b"\x01\x02" * 2000)})()
        with patch("sys.stdin", stdin), pcm_input("-", "s16le", 0.05) as chunks:
            result = list(chunks)
        self.assertEqual(list(map(len, result)), [640, 160])
        self.assertEqual(b"".join(result), b"\x01\x02" * 400)
        self.assertFalse(stdin.buffer.closed)

    def test_raw_odd_byte_input_is_rejected(self):
        stdin = type("Input", (), {"buffer": io.BytesIO(b"\x01")})()
        with patch("sys.stdin", stdin), pcm_input("-", "s16le") as chunks:
            with self.assertRaisesRegex(ValueError, "complete 16-bit"):
                list(chunks)

    @unittest.skipUnless(shutil.which("ffmpeg"), "FFmpeg unavailable")
    def test_aac_roundtrip_preserves_priming_and_camera_gap_timestamps(self):
        encoder = AACEncoder()
        encoded = []
        pcm = b"".join(struct.pack("<h", round(3000 * math.sin(2 * math.pi * 440 * n / 8000)))
                       for n in range(8192))
        try:
            for offset in range(0, len(pcm), 1024):
                pts = 90000 + offset // 2 * 90000 // 8000
                if offset >= 8192:
                    pts += 90000
                encoded.extend(encoder.feed(pcm[offset:offset + 1024], pts))
            encoded.extend(encoder.finish())
        finally:
            encoder.close()
        self.assertEqual(len(encoded), 17)
        self.assertEqual(encoded[0][1], 90000 - 11520)
        self.assertEqual(encoded[1][1], 90000)
        self.assertEqual(encoder.timeline.inserted_samples, 8000)
        self.assertEqual(encoder.timeline.trimmed_samples, 0)
        self.assertTrue(all(b[1] - a[1] == 11520 for a, b in zip(encoded, encoded[1:])))
        result = subprocess.run([shutil.which("ffmpeg"), "-v", "error", "-f", "aac", "-i", "pipe:0",
                                 "-f", "s16le", "pipe:1"],
                                input=b"".join(frame for frame, _ in encoded), capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(len(result.stdout), 17 * 1024 * 2)
        decoded = struct.unpack(f"<{len(result.stdout) // 2}h", result.stdout)
        original = struct.unpack("<8192h", pcm)
        # Account for AAC's initial 1024 samples: the source tone's phase and
        # intended silent gap must survive conversion, not merely its headers.
        source = original[512:3584]
        recovered = decoded[1024 + 512:1024 + 3584]
        correlation = sum(a * b for a, b in zip(source, recovered)) / math.sqrt(
            sum(a * a for a in source) * sum(b * b for b in recovered))
        self.assertGreater(correlation, 0.99)
        gap = decoded[1024 + 4096 + 2000:1024 + 4096 + 6000]
        self.assertLess(math.sqrt(sum(value * value for value in gap) / len(gap)), 1)
        self.assertFalse(encoder.reader.is_alive())
        self.assertIsNotNone(encoder.process.poll())

    @unittest.skipUnless(shutil.which("ffmpeg"), "FFmpeg unavailable")
    def test_auto_input_resamples_stereo_wav_and_closes_converter(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stereo.wav"
            with wave.open(str(path), "wb") as output:
                output.setnchannels(2)
                output.setsampwidth(2)
                output.setframerate(16000)
                output.writeframes(b"\x10\x00\x20\x00" * 16000)
            with pcm_input(str(path)) as chunks:
                result = list(chunks)
        self.assertEqual(sum(map(len, result)), 16000)
        self.assertTrue(all(0 < len(block) <= 640 and not len(block) % 2 for block in result))

    @unittest.skipUnless(shutil.which("ffmpeg"), "FFmpeg unavailable")
    def test_invalid_auto_input_reports_decoder_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.wav"
            path.write_bytes(b"not an audio recording")
            with pcm_input(str(path)) as chunks:
                with self.assertRaisesRegex(RuntimeError, "could not decode"):
                    list(chunks)


if __name__ == "__main__":
    unittest.main()
