"""CLI validation and streaming checks with mock sessions, never a camera."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import wave
from unittest.mock import patch

import pixsee


_FRAME = b"\x00\x00\x00\x01\x67\x42\x00\x1f\x00\x00\x00\x01\x65\x88\x84"
_UID = "UNITTESTDEVICE123456"


class FakeSession:
    frames = [(_FRAME, {"timestamp_ms": 1000, "keyframe": True})]
    instances = []

    def __init__(self, ip, credentials, **kwargs):
        self.credentials, self.kwargs = credentials, kwargs
        self.authenticated, self.disconnected = False, False
        self.instances.append(self)

    def connect(self, **kwargs):
        print("session diagnostic")
        self.authenticated = True

    def video_frames_timed(self, **kwargs):
        yield from self.frames

    def audio_frames_timed(self, **kwargs):
        yield b"\x10\x00" * 512, {"timestamp_ms": 1000, "sample_rate": 8000,
                                   "channels": 1, "sample_width": 2}

    def av_frames_timed(self, **kwargs):
        for frame, metadata in self.frames:
            yield "video", frame, metadata
        for pcm, metadata in self.audio_frames_timed(**kwargs):
            yield "audio", pcm, metadata

    def talk_pcm(self, chunks, **kwargs):
        self.talk_chunks = list(chunks)
        self.talk_options = kwargs
        return {"sent_frames": len(self.talk_chunks), "acked_frames": len(self.talk_chunks), "resends": 0}

    def disconnect(self):
        print("session closed")
        self.disconnected = True
        self.authenticated = False


class BinaryStdout:
    def __init__(self):
        self.buffer = io.BytesIO()
        self.text = io.StringIO()

    def write(self, value):
        return self.text.write(value)

    def flush(self):
        pass


class PixseeCliTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        FakeSession.instances = []
        FakeSession.frames = [(_FRAME, {"timestamp_ms": 1000, "keyframe": True})]

    def run_json(self, arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = pixsee.main(arguments)
        return code, json.loads(stdout.getvalue()), stderr.getvalue()

    def test_help_and_invalid_arguments_do_not_connect(self):
        with patch.object(pixsee, "PixseeSession") as session, patch.object(pixsee, "discover") as discover:
            for args, expected in ((["--help"], 0), (["stream", "--help"], 0),
                                   (["probe"], 2), (["probe", "--camera-ip", "239.1.1.1"], 2),
                                   (["probe", "--camera-ip", "127.0.0.1", "--duration", "nan"], 2),
                                   (["stream", "--camera-ip", "127.0.0.1", "--timeout", "0"], 2)):
                with self.subTest(args=args), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        pixsee.main(args)
                    self.assertEqual(raised.exception.code, expected)
            session.assert_not_called()
            discover.assert_not_called()

    def test_discovery_redacts_uid_unless_requested(self):
        reply = SimpleNamespace(uid=_UID, device_name="pixsee " + _UID, sdk_version="4.3.8.1")
        with patch.object(pixsee, "discover", return_value=(reply, ("127.0.0.1", 12345))):
            code, result, _ = self.run_json(["discover", "--camera-ip", "127.0.0.1"])
            self.assertEqual(code, 0)
            self.assertNotIn(_UID, json.dumps(result))
            _, explicit, _ = self.run_json(["discover", "--camera-ip", "127.0.0.1", "--show-uid"])
            self.assertEqual(explicit["uid"], _UID)

    def test_custom_default_requires_credentials_before_connect(self):
        with patch.object(pixsee, "PixseeSession") as session:
            code, result, _ = self.run_json(["probe", "--camera-ip", "127.0.0.1"])
            self.assertEqual(code, 1)
            self.assertFalse(result["authenticated"])
            session.assert_not_called()

    def test_probe_requires_a_frame_and_keeps_diagnostics_off_json(self):
        with patch.object(pixsee, "PixseeSession", FakeSession):
            code, result, stderr = self.run_json(["probe", "--camera-ip", "127.0.0.1", "--profile", "legacy"])
            self.assertEqual(code, 0)
            self.assertTrue(result["authenticated"])
            self.assertEqual(result["video_frames"], 1)
            self.assertEqual(result["video_bytes"], len(_FRAME))
            self.assertIn("session diagnostic", stderr)
            self.assertTrue(FakeSession.instances[-1].disconnected)
            FakeSession.frames = []
            code, result, _ = self.run_json(["probe", "--camera-ip", "127.0.0.1", "--profile", "legacy"])
            self.assertEqual(code, 1)
            self.assertTrue(result["authenticated"])
            self.assertEqual(result["video_frames"], 0)

    def test_explicit_profile_overrides_firmware_suggestion(self):
        with patch.object(pixsee, "PixseeSession", FakeSession):
            code, _, _ = self.run_json(["probe", "--camera-ip", "127.0.0.1",
                                       "--firmware", "1.006.25", "--profile", "legacy"])
            self.assertEqual(code, 0)
            self.assertEqual(FakeSession.instances[-1].credentials,
                             pixsee.load_credentials(profile="legacy", environ={}))
            self.run_json(["probe", "--camera-ip", "127.0.0.1", "--firmware", "1.006.25"])
            self.assertEqual(FakeSession.instances[-1].credentials,
                             pixsee.load_credentials(profile="current", environ={}))

    def test_stream_stdout_is_only_valid_mpegts_packets(self):
        stdout, stderr = BinaryStdout(), io.StringIO()
        with patch.object(pixsee, "PixseeSession", FakeSession), redirect_stdout(stdout), redirect_stderr(stderr):
            code = pixsee.main(["stream", "--camera-ip", "127.0.0.1", "--profile", "legacy", "--duration", "1"])
        payload = stdout.buffer.getvalue()
        self.assertEqual(code, 0)
        self.assertGreater(len(payload), 0)
        self.assertEqual(len(payload) % 188, 0)
        self.assertTrue(all(payload[index] == 0x47 for index in range(0, len(payload), 188)))
        self.assertEqual(stdout.text.getvalue(), "")
        self.assertNotIn(b"session diagnostic", payload)
        self.assertIn("session diagnostic", stderr.getvalue())

    def test_file_output_refuses_overwrite_before_connect_and_raw_bytes_match(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "out.h264"
            path.write_bytes(b"existing")
            args = ["stream", "--camera-ip", "127.0.0.1", "--profile", "legacy",
                    "--format", "h264", "--output", str(path), "--duration", "1"]
            with patch.object(pixsee, "PixseeSession") as session, redirect_stderr(io.StringIO()):
                self.assertEqual(pixsee.main(args), 1)
                session.assert_not_called()
            self.assertEqual(path.read_bytes(), b"existing")
            with patch.object(pixsee, "PixseeSession", FakeSession), redirect_stderr(io.StringIO()):
                self.assertEqual(pixsee.main(args + ["--overwrite"]), 0)
            self.assertEqual(path.read_bytes(), _FRAME)

    def test_environment_ip_and_secret_redaction_on_errors(self):
        class FailingSession(FakeSession):
            def connect(self, **kwargs):
                raise RuntimeError("Failure " + self.credentials.password + " " + self.credentials.auth_key + " " + self.credentials.uid)

        environment = {"PIXSEE_CAMERA_IP": "127.0.0.1", "PIXSEE_UID": _UID,
                       "PIXSEE_PASSWORD": "test-private-password", "PIXSEE_AUTH_KEY": "KEY12345"}
        with patch.dict(os.environ, environment), patch.object(pixsee, "PixseeSession", FailingSession):
            code, result, _ = self.run_json(["probe"])
        self.assertEqual(code, 1)
        for value in (environment["PIXSEE_PASSWORD"], environment["PIXSEE_AUTH_KEY"], _UID):
            self.assertNotIn(value, json.dumps(result))
        self.assertTrue(FakeSession.instances[-1].disconnected)

    def test_camera_clock_handles_rollover_and_missing_metadata(self):
        clock = pixsee._VideoClock()
        with patch.object(pixsee.time, "monotonic", side_effect=[1.0, 1.01, 1.03]):
            self.assertEqual(clock.feed({"timestamp_ms": 0xfffffff0}), 0)
            self.assertEqual(clock.feed({"timestamp_ms": 0x10}), 32 * 90)
            self.assertEqual(clock.feed(None), 52 * 90)

    def test_audio_stdout_wav_has_final_length_and_no_diagnostics(self):
        stdout, stderr = BinaryStdout(), io.StringIO()
        with patch.object(pixsee, "PixseeSession", FakeSession), redirect_stdout(stdout), redirect_stderr(stderr):
            code = pixsee.main(["audio", "--camera-ip", "127.0.0.1", "--profile", "legacy", "--duration", "1"])
        self.assertEqual(code, 0)
        with wave.open(io.BytesIO(stdout.buffer.getvalue()), "rb") as recording:
            self.assertEqual((recording.getnchannels(), recording.getsampwidth(), recording.getframerate()), (1, 2, 8000))
            self.assertEqual(recording.getnframes(), 512)
            self.assertEqual(recording.readframes(512), b"\x10\x00" * 512)
        self.assertEqual(stdout.text.getvalue(), "")
        self.assertIn("session diagnostic", stderr.getvalue())
        self.assertTrue(FakeSession.instances[-1].disconnected)

    def test_audio_raw_stdout_is_exact_pcm(self):
        stdout = BinaryStdout()
        with patch.object(pixsee, "PixseeSession", FakeSession), redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            code = pixsee.main(["audio", "--camera-ip", "127.0.0.1", "--profile", "legacy", "--format", "s16le"])
        self.assertEqual(code, 0)
        self.assertEqual(stdout.buffer.getvalue(), b"\x10\x00" * 512)

    def test_audio_combinations_rejected_before_network(self):
        with patch.object(pixsee, "PixseeSession") as session:
            for args in (["stream", "--audio", "--format", "h264"], ["audio"]):
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                    pixsee.main(args + ["--camera-ip", "127.0.0.1", "--profile", "legacy"])
                self.assertEqual(raised.exception.code, 2)
            session.assert_not_called()

    def test_stream_audio_multiplexes_second_track_and_closes_encoder(self):
        class FakeEncoder:
            closed = False
            def feed(self, pcm, pts):
                self.pcm, self.pts = pcm, pts
                return [(b"\xff\xf1\x6c\x40\x01\x3f\xfc\x00", pts - 11520)]
            def finish(self):
                return []
            def close(self):
                self.closed = True
        encoder = FakeEncoder()
        stdout = BinaryStdout()
        with patch.object(pixsee, "PixseeSession", FakeSession), patch.object(pixsee, "AACEncoder", return_value=encoder), redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            code = pixsee.main(["stream", "--camera-ip", "127.0.0.1", "--profile", "legacy", "--audio", "--duration", "1"])
        self.assertEqual(code, 0)
        self.assertTrue(encoder.closed)
        self.assertEqual(encoder.pcm, b"\x10\x00" * 512)
        self.assertEqual(encoder.pts, 90000)
        data = stdout.buffer.getvalue()
        pids = {((data[n + 1] & 0x1f) << 8) | data[n + 2] for n in range(0, len(data), 188)}
        self.assertTrue({0x100, 0x101}.issubset(pids))

    def test_talk_raw_file_is_chunked_bounded_and_reports_ack_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.pcm"
            path.write_bytes(b"\x01\x00" * 1000)
            with patch.object(pixsee, "PixseeSession", FakeSession):
                code, result, stderr = self.run_json(["talk", "--camera-ip", "127.0.0.1", "--profile", "legacy",
                    "--input", str(path), "--input-format", "s16le", "--duration", "0.05"])
        self.assertEqual(code, 0)
        self.assertEqual(result, {"ok": True, "sent_frames": 2, "acked_frames": 2, "resends": 0})
        session = FakeSession.instances[-1]
        self.assertEqual(list(map(len, session.talk_chunks)), [640, 160])
        self.assertEqual(session.talk_options, {"timeout": 8, "duration": 0.05})
        self.assertTrue(session.disconnected)
        self.assertIn("session closed", stderr)

    def test_empty_talk_input_fails_before_connection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.pcm"
            path.write_bytes(b"")
            with patch.object(pixsee, "PixseeSession") as session:
                code, result, _ = self.run_json(["talk", "--camera-ip", "127.0.0.1", "--profile", "legacy",
                    "--input", str(path), "--input-format", "s16le"])
                session.assert_not_called()
        self.assertEqual(code, 1)
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
