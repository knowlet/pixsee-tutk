"""Gateway boundaries and owned-process lifecycle; no camera traffic."""

from dataclasses import replace
import json
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from pixsee_config import credentials_for_profile
import pixsee_gateway as gateway
from pixsee_onvif import MediaProfile


class Clock:
    def __init__(self):
        self.now = 0.0
        self.stopped = False

    def monotonic(self):
        return self.now

    def is_set(self):
        return self.stopped

    def set(self):
        self.stopped = True

    def wait(self, delay):
        self.now += delay
        return self.stopped


class GatewayTests(unittest.TestCase):
    def config(self, **kwargs):
        return gateway.GatewayConfig(camera_ip="192.0.2.10",
                                      camera_credentials=credentials_for_profile("legacy"), **kwargs)

    def test_credentials_strict_bounded_and_secret_safe(self):
        self.assertEqual(gateway.load_viewer_credentials(environ={}), (None, None))
        self.assertEqual(gateway.load_viewer_credentials(environ={
            "PIXSEE_GATEWAY_USERNAME": "reader", "PIXSEE_GATEWAY_PASSWORD": "sensitive"}),
            ("reader", "sensitive"))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth.json"
            for data in (b'{"username":"reader","password":"sensitive","password":"other"}',
                         b"x" * 4097, b'{"username":"reader"}', b'{"username":"reader","password":null}',
                         b'[]', b'{"username":"any","password":"sensitive"}'):
                path.write_bytes(data)
                with self.assertRaises(ValueError) as raised:
                    gateway.load_viewer_credentials(path, environ={})
                self.assertNotIn("sensitive", str(raised.exception))
            path.write_text(json.dumps({"username": "reader", "password": "fromfile"}))
            self.assertEqual(gateway.load_viewer_credentials(path, environ={
                "PIXSEE_GATEWAY_PASSWORD": "ignored"}), ("reader", "fromfile"))

    def test_configuration_rejects_unsafe_bindings_before_work(self):
        invalid = [{"bind_host": "192.0.2.20"}, {"bind_host": "0.0.0.0"},
                   {"bind_host": "0.0.0.0", "advertised_host": "192.0.2.20"},
                   {"advertised_host": "192.0.2.20"}, {"discovery": True},
                   {"username": "reader"}, {"password": "secret"},
                   {"rtsp_port": True}, {"rtsp_port": 80}, {"rtsp_port": 9997},
                   {"stream_path": "../secret"}, {"media_timeout": float("nan")},
                   {"camera_timeout": 121}, {"duration": 0}]
        with patch.object(gateway.subprocess, "Popen") as spawn:
            for value in invalid:
                with self.subTest(value=value), self.assertRaises(ValueError):
                    self.config(**value)
            spawn.assert_not_called()
        config = self.config(bind_host="0.0.0.0", advertised_host="192.0.2.20",
                             username="reader", password="secret", discovery=True)
        self.assertEqual(config.host, "192.0.2.20")
        self.assertNotIn("secret", repr(config))
        self.assertNotIn(config.camera_credentials.password, repr(config))

    def test_backend_permissions_are_loopback_publisher_and_read_only_viewer(self):
        config = self.config(bind_host="0.0.0.0", advertised_host="192.0.2.20",
                             username="reader", password="secret")
        data = gateway.mediamtx_config(config)
        local, viewer = data["authInternalUsers"]
        self.assertEqual(local["ips"], ["127.0.0.1", "::1"])
        self.assertEqual(viewer["permissions"], [{"action": "read", "path": "pixsee"}])
        self.assertEqual(set(data["paths"]), {"pixsee"})
        self.assertFalse(data["paths"]["pixsee"]["overridePublisher"])
        self.assertEqual(data["apiAddress"], "127.0.0.1:9997")
        self.assertEqual(data["rtspTransports"], ["tcp", "udp"])

    def test_rtp_requires_even_consecutive_pair_before_processes_or_sockets(self):
        with patch.object(gateway.subprocess, "Popen") as spawn, patch.object(gateway.socket, "socket") as network:
            for rtp, rtcp in ((65066, 64279), (18000, 18002), (18001, 18002), (18002, 18001)):
                with self.subTest(rtp=rtp, rtcp=rtcp), self.assertRaisesRegex(ValueError, "RTP port"):
                    self.config(rtp_port=rtp, rtcp_port=rtcp)
            spawn.assert_not_called()
            network.assert_not_called()
        for rtp in (1024, 18000, 65534):
            config = self.config(rtp_port=rtp, rtcp_port=rtp + 1)
            self.assertEqual(config.rtcp_port, rtp + 1)

    def test_commands_never_contain_credentials_and_require_selected_audio(self):
        config = self.config(username="reader", password="viewer-secret")
        argv = gateway.producer_command(config) + gateway.publisher_command(config, "/ffmpeg")
        joined = " ".join(argv)
        for secret in (config.password, config.camera_credentials.password, config.camera_credentials.auth_key):
            self.assertNotIn(secret, joined)
        self.assertIn("0:a:0", argv)
        self.assertIn("-c:a", argv)
        self.assertIn("24k", argv)
        self.assertNotIn("0:a:0?", argv)
        self.assertNotIn("--audio", gateway.producer_command(replace(config, with_audio=False)))
        self.assertNotIn("-c:a", gateway.publisher_command(replace(config, with_audio=False), "/ffmpeg"))

    def test_identity_persists_increments_locks_and_preserves_invalid_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            with gateway._identity(path) as one:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                with self.assertRaisesRegex(RuntimeError, "already in use"):
                    with gateway._identity(path):
                        pass
            with gateway._identity(path) as two:
                self.assertEqual(one["device_uuid"], two["device_uuid"])
                self.assertEqual(two["instance_id"], one["instance_id"] + 1)
            path.write_text("invalid-preserve-me")
            with self.assertRaisesRegex(ValueError, "invalid"):
                with gateway._identity(path):
                    pass
            self.assertEqual(path.read_text(), "invalid-preserve-me")

    def test_ingress_requires_current_api_real_online_source_and_selected_tracks(self):
        valid = {"online": True, "available": True, "source": {"id": "source-one"},
                 "tracks2": [{"codec": "H264"}, {"codec": "MPEG-4 Audio"}], "inboundBytes": 12}
        self.assertEqual(gateway._ingress(valid, True), ("source-one", 12))
        for change in ({"online": False}, {"available": False}, {"inboundBytes": True},
                       {"source": None}, {"tracks2": [{"codec": "H264"}]},
                       {"tracks2": None}):
            self.assertIsNone(gateway._ingress({**valid, **change}, True))
        self.assertIsNone(gateway._ingress({"ready": True, "tracks": ["H264"], "bytesReceived": 12}, False))

    def test_probe_preserves_1088_and_actual_nominal_rate(self):
        streams = [{"codec_type": "video", "codec_name": "h264", "width": 1920,
                    "height": 1088, "avg_frame_rate": "0/0", "r_frame_rate": "25000/1001"},
                   {"codec_type": "audio", "codec_name": "aac", "sample_rate": "8000", "channels": 1}]
        with patch.object(gateway, "_capture", return_value=json.dumps({"streams": streams}).encode()):
            profile = gateway.probe_profile(self.config(), "/ffprobe")
        self.assertEqual((profile.width, profile.height), (1920, 1088))
        self.assertAlmostEqual(profile.frame_rate, 25000 / 1001)
        self.assertEqual(profile.audio_sample_rate, 8000)
        self.assertIsNone(profile.video_bitrate)
        self.assertIsNone(profile.gop)
        streams.pop()
        with patch.object(gateway, "_capture", return_value=json.dumps({"streams": streams}).encode()):
            with self.assertRaisesRegex(RuntimeError, "metadata"):
                gateway.probe_profile(self.config(), "/ffprobe")
            self.assertIsNone(gateway.probe_profile(self.config(with_audio=False), "/ffprobe").audio_encoding)

    def test_probe_requires_a_usable_frame_rate_for_onvif_bootstrap(self):
        for average, nominal in (("0/0", "0/0"), (None, None), ("0/0", "90000/1")):
            video = {"codec_type": "video", "codec_name": "h264", "width": 1920,
                     "height": 1088, "avg_frame_rate": average, "r_frame_rate": nominal}
            with self.subTest(average=average, nominal=nominal), patch.object(
                    gateway, "_capture", return_value=json.dumps({"streams": [video]}).encode()):
                with self.assertRaisesRegex(RuntimeError, "metadata"):
                    gateway.probe_profile(self.config(with_audio=False), "/ffprobe")

    def test_capture_bounds_output_and_timeout_and_reaps_child(self):
        self.assertEqual(gateway._capture([sys.executable, "-c", "print('ok')"], 2), b"ok\n")
        for command, timeout, limit in (
            ([sys.executable, "-c", "print('x' * 200000)"], 2, 4096),
            ([sys.executable, "-c", "import time; time.sleep(60)"], 0.1, 4096),
        ):
            with self.assertRaises(RuntimeError):
                gateway._capture(command, timeout, max_bytes=limit)

    def test_capture_deadline_survives_exited_leader_with_inherited_pipes(self):
        owned = []
        real_process = gateway._Process

        class RecordedProcess(real_process):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                owned.append(self)

        # The leader exits successfully while a separately grouped child keeps
        # both pipes open. EOF and buffered-stream close must not extend the
        # capture deadline or leave a diagnostic reader behind.
        command = """import os, sys, time
pid = os.fork()
if pid:
    with open(sys.argv[1], 'w') as handle:
        handle.write(str(pid))
    os._exit(0)
os.setsid()
time.sleep(8)
"""
        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "inherited-pipe-holder.pid"
            try:
                started = time.monotonic()
                with patch.object(gateway, "_Process", RecordedProcess):
                    with self.assertRaisesRegex(RuntimeError, "time limit"):
                        gateway._capture([sys.executable, "-c", command, str(pid_path)], 0.4)
                self.assertLess(time.monotonic() - started, 2,
                                "inherited pipes extended the capture/cleanup deadline")
                self.assertTrue(pid_path.exists(), "pipe holder did not start")
                self.assertEqual(len(owned), 1)
                self.assertEqual(owned[0].process.returncode, 0)
                self.assertTrue(owned[0].stopped)
                self.assertFalse(owned[0].thread.is_alive())
            finally:
                # This deliberately escaped child belongs to the test, not the
                # gateway group; never leave it behind after an assertion.
                if pid_path.exists():
                    try:
                        os.kill(int(pid_path.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                for child in owned:
                    child.stop()

    def test_explicit_auth_rejection_recognized_without_diagnostic_retention(self):
        process = gateway._Process([sys.executable, "-c",
            "import sys; sys.stderr.write('Camera rejected the IOTC auth key (status 5) secret')"])
        process.process.wait(timeout=2)
        process.thread.join(timeout=2)
        self.assertTrue(process.auth_rejected.is_set())
        self.assertNotIn("secret", repr(process.__dict__))
        process.stop()
        process.stop()

    def test_stop_reaps_already_exited_child_before_signalling_group(self):
        process = gateway._Process([sys.executable, "-c", "pass"])
        process.thread.join(timeout=2)  # EOF without polling/reaping the child.
        self.assertFalse(process.thread.is_alive())
        calls = []
        original_poll = process.process.poll
        original_killpg = gateway.os.killpg

        def poll():
            calls.append("poll")
            return original_poll()

        def killpg(pid, sig):
            calls.append("signal")
            return original_killpg(pid, sig)

        with patch.object(process.process, "poll", side_effect=poll), patch.object(gateway.os, "killpg", side_effect=killpg):
            process.stop()
        self.assertEqual(calls[0], "poll")
        self.assertEqual(process.process.returncode, 0)
        self.assertTrue(process.stopped)

    def test_stop_permission_race_requires_reaped_child_and_absent_group(self):
        for reaped, group_result in ((True, "absent"), (True, "present"),
                                     (True, "denied"), (False, "present")):
            with self.subTest(reaped=reaped, group=group_result):
                owned = gateway._Process.__new__(gateway._Process)
                owned.stopped = False
                owned._drain_stop = threading.Event()
                owned.process = Mock(pid=12345, returncode=None, stdout=None, stderr=None)
                owned.thread = Mock()
                owned.thread.is_alive.return_value = False
                polls, signals = [], []

                def poll():
                    polls.append(True)
                    if len(polls) > 1 and reaped:
                        owned.process.returncode = 0
                    return owned.process.returncode

                def killpg(_pid, sig):
                    signals.append(sig)
                    if sig != 0 or group_result == "denied":
                        raise PermissionError("EPERM")
                    if group_result == "absent":
                        raise ProcessLookupError("ESRCH")

                owned.process.poll.side_effect = poll
                with patch.object(gateway.os, "killpg", side_effect=killpg):
                    if reaped and group_result == "absent":
                        owned.stop()
                        self.assertTrue(owned.stopped)
                        owned.process.wait.assert_called_once_with(timeout=2)
                    else:
                        with self.assertRaises(PermissionError):
                            owned.stop()
                        self.assertFalse(owned.stopped)
                        owned.process.wait.assert_not_called()
                self.assertEqual(len(polls), 2)
                self.assertEqual(signals, [signal.SIGINT, 0] if reaped else [signal.SIGINT])

    def test_snapshot_cache_has_one_source_and_rejects_offline_or_invalid_jpeg(self):
        healthy = [True]
        snapshot = gateway._Snapshots(self.config(), "/ffmpeg", lambda: healthy[0])
        jpeg = b"\xff\xd8payload\xff\xd9"
        with patch.object(gateway, "_capture", return_value=jpeg) as capture:
            self.assertEqual(snapshot(), jpeg)
            self.assertEqual(snapshot(), jpeg)
            self.assertEqual(capture.call_count, 1)
            self.assertIn(self.config().local_rtsp_url, capture.call_args.args[0])
            healthy[0] = False
            with self.assertRaises(RuntimeError):
                snapshot()
        healthy[0] = True
        snapshot.clear()
        with patch.object(gateway, "_capture", return_value=b"notjpeg"), self.assertRaises(RuntimeError):
            snapshot()

    def test_signal_handlers_restore(self):
        previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        stop = threading.Event()
        with gateway._signals(stop):
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            self.assertTrue(stop.is_set())
        self.assertEqual(previous, {sig: signal.getsignal(sig) for sig in previous})

    def test_pair_spawn_failure_closes_and_stops_producer(self):
        producer = Mock()
        with patch.object(gateway, "_Process", side_effect=[producer, OSError("failed")]), self.assertRaises(OSError):
            gateway._start_pair(self.config(), {"ffmpeg": "/bin/ffmpeg"})
        producer.stop.assert_called_once()
        producer.process.stdout.close.assert_called_once()

    def run_mocked(self, directory, *, stall=False, callback_error=False, auth_rejected=False,
                   never_ready=False, cleanup_error=False, probe_behavior=None):
        clock, children, pairs = Clock(), [], []
        profile = MediaProfile(width=1920, height=1088, frame_rate=25)
        counter = [0]
        epoch = [0]

        def child(*_args, **_kwargs):
            obj = Mock()
            obj.process.poll.return_value = None
            obj.auth_rejected = threading.Event()
            children.append(obj)
            return obj

        def pair(*_args):
            p, f = child(), child()
            if auth_rejected:
                p.auth_rejected.set()
            pairs.append((p, f))
            return p, f

        def api(_config, endpoint):
            if endpoint == "info":
                return {"version": "v1.21.3"}
            if never_ready:
                return {"online": False, "available": False}
            counter[0] += 1
            return {"online": True, "available": True, "source": {"id": f"{len(pairs)}-{epoch[0]}"},
                    "tracks2": [{"codec": "H264"}],
                    "inboundBytes": min(counter[0], 4) if stall else counter[0]}

        def probe(_config, _ffprobe, *, timeout):
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, config.startup_timeout)
            if probe_behavior == "stop":
                clock.set()
            elif probe_behavior == "startup_deadline":
                clock.now += config.startup_timeout
            elif probe_behavior == "duration_deadline":
                clock.now += config.duration
            elif probe_behavior == "source_changed":
                epoch[0] += 1
            elif probe_behavior == "publisher_exited":
                pairs[-1][1].process.poll.return_value = 1
            return profile

        onvif = Mock(rtsp_url="rtsp://127.0.0.1:8554/pixsee",
                     device_url="http://127.0.0.1:8080/onvif/device_service",
                     snapshot_url="http://127.0.0.1:8080/snapshot.jpg")
        if cleanup_error:
            onvif.close.side_effect = OSError("close failed")
        ready = Mock(side_effect=RuntimeError("callback failed") if callback_error else None)
        config = self.config(with_audio=False, duration=0.5 if never_ready else 3, startup_timeout=2,
                             media_timeout=0.4, state_path=str(Path(directory) / "state.json"))
        with patch.object(gateway.shutil, "which", side_effect=lambda x: "/bin/" + x), \
                patch.object(gateway, "_capture", return_value=b"v1.21.3\n"), \
                patch.object(gateway, "_check_ports"), \
                patch.object(gateway, "_Process", side_effect=child), \
                patch.object(gateway, "_start_pair", side_effect=pair), \
                patch.object(gateway, "_api", side_effect=api), \
                patch.object(gateway, "probe_profile", side_effect=probe), \
                patch("pixsee_onvif.OnvifServer", return_value=onvif) as server_factory, \
                patch.object(gateway.time, "monotonic", side_effect=clock.monotonic):
            probe_failure = probe_behavior not in (None, "stop")
            if callback_error or auth_rejected or never_ready or cleanup_error or probe_failure:
                with self.assertRaisesRegex(RuntimeError, "callback failed|authentication was rejected|duration expired|complete cleanup|startup timed out"):
                    gateway.run_gateway(config, stop_event=clock, on_ready=ready)
                result = None
            else:
                result = gateway.run_gateway(config, stop_event=clock, on_ready=ready)
        for item in children:
            item.stop.assert_called_once()
        if probe_behavior is not None:
            server_factory.assert_not_called()
            ready.assert_not_called()
        elif not auth_rejected and not never_ready:
            onvif.close.assert_called_once()
        else:
            ready.assert_not_called()
            self.assertEqual(len(pairs), 1)
        return result, pairs, ready

    def test_runtime_ready_once_and_reaps_on_duration(self):
        with tempfile.TemporaryDirectory() as directory:
            result, pairs, ready = self.run_mocked(directory)
        self.assertTrue(result["ready"])
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(len(pairs), 1)
        ready.assert_called_once()
        self.assertEqual(ready.call_args.args[0]["status"], "ready")
        self.assertEqual(result["metadata"]["height"], 1088)

    def test_stall_restarts_owned_pair_and_callback_failure_still_cleans(self):
        with tempfile.TemporaryDirectory() as directory:
            result, pairs, ready = self.run_mocked(directory, stall=True)
        self.assertGreater(result["restarts"], 0)
        self.assertGreater(len(pairs), 1)
        ready.assert_called_once()
        with tempfile.TemporaryDirectory() as directory:
            self.run_mocked(directory, callback_error=True)

    def test_auth_rejection_is_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            self.run_mocked(directory, auth_rejected=True)

    def test_stop_before_start_performs_no_process_work(self):
        stop = threading.Event()
        stop.set()
        with patch.object(gateway, "_capture") as capture:
            result = gateway.run_gateway(self.config(), stop_event=stop)
        capture.assert_not_called()
        self.assertFalse(result["ready"])

    def test_duration_without_media_fails_and_cleanup_error_reaps_every_child(self):
        with tempfile.TemporaryDirectory() as directory:
            self.run_mocked(directory, never_ready=True)
        with tempfile.TemporaryDirectory() as directory:
            self.run_mocked(directory, cleanup_error=True)

    def test_probe_result_cannot_announce_after_stop_deadline_or_source_change(self):
        for behavior in ("stop", "startup_deadline", "duration_deadline", "source_changed", "publisher_exited"):
            with self.subTest(behavior=behavior), tempfile.TemporaryDirectory() as directory:
                result, _, _ = self.run_mocked(directory, probe_behavior=behavior)
                if behavior == "stop":
                    self.assertFalse(result["ready"])


if __name__ == "__main__":
    unittest.main()
