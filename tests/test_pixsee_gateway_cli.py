"""Gateway command contracts; no camera or server process is started here."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import pixsee


class GatewayCliTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_help_and_invalid_ports_need_no_gateway_dependency(self):
        with patch.dict("sys.modules", {"pixsee_gateway": None}):
            cases = [(["serve", "--help"], 0)]
            for port in ("0", "-1", "1023", "65536", "nan", "123.5"):
                cases.append((["serve", "--rtsp-port", port], 2))
            for args, expected in cases:
                with self.subTest(args=args), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        pixsee.main(args)
                    self.assertEqual(raised.exception.code, expected)

    def test_separate_credentials_and_gateway_options_reach_supervisor(self):
        options = {}
        def configure(**kwargs):
            options.update(kwargs)
            return SimpleNamespace(**kwargs)
        def serve(config, *, on_ready):
            on_ready({"rtsp_url": "rtsp://192.0.2.10:9554/nursery"})
            return {"restarts": 1}
        gateway = SimpleNamespace(GatewayConfig=configure,
                                  load_viewer_credentials=Mock(return_value=("viewer", "viewer-private")),
                                  run_gateway=Mock(side_effect=serve))
        stdout, stderr = io.StringIO(), io.StringIO()
        environment = {"PIXSEE_PASSWORD": "camera-private", "PIXSEE_AUTH_KEY": "UNITKEY8"}
        with patch.dict(os.environ, environment), patch.dict("sys.modules", {"pixsee_gateway": gateway}), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            result = pixsee.main([
                "serve", "--camera-ip", "192.0.2.20", "--listen", "0.0.0.0",
                "--advertise-ip", "192.0.2.10", "--gateway-credentials", "/private/viewer credentials.json",
                "--stream-name", "nursery", "--rtsp-port", "9554", "--onvif-port", "9080",
                "--hls-port", "9888", "--rtp-port", "9000", "--rtcp-port", "9001", "--api-port", "9998",
                "--discovery", "--no-audio", "--no-hls", "--duration", "15",
                "--state-file", "/private/bridge state.json", "--mediamtx", "/tools/media server",
                "--ffmpeg", "/tools/custom ffmpeg", "--ffprobe", "/tools/custom ffprobe",
                "--timeout", "12", "--media-timeout", "8", "--startup-timeout", "25",
            ])
        self.assertEqual(result, 0)
        self.assertEqual(options["camera_credentials"].password, "camera-private")
        self.assertEqual((options["username"], options["password"]), ("viewer", "viewer-private"))
        self.assertEqual(options["rtsp_port"], 9554)
        self.assertEqual(options["stream_path"], "nursery")
        self.assertEqual(options["advertised_host"], "192.0.2.10")
        self.assertEqual(options["ffmpeg"], "/tools/custom ffmpeg")
        self.assertEqual((options["camera_timeout"], options["media_timeout"], options["startup_timeout"]),
                         (12, 8, 25))
        self.assertFalse(options["with_audio"])
        self.assertFalse(options["hls"])
        self.assertTrue(options["discovery"])
        gateway.load_viewer_credentials.assert_called_once_with("/private/viewer credentials.json")
        self.assertEqual([json.loads(line)["event"] for line in stdout.getvalue().splitlines()],
                         ["ready", "stopped"])
        for secret in ("viewer-private", "camera-private", "UNITKEY8"):
            self.assertNotIn(secret, stdout.getvalue() + stderr.getvalue())

    def test_runtime_error_redacts_camera_and_viewer_secrets(self):
        gateway = SimpleNamespace(
            GatewayConfig=lambda **kwargs: SimpleNamespace(**kwargs),
            load_viewer_credentials=lambda path: ("viewer", "viewer-private"),
            run_gateway=Mock(side_effect=RuntimeError("camera-private UNITKEY8 viewer-private")),
        )
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {"PIXSEE_PASSWORD": "camera-private", "PIXSEE_AUTH_KEY": "UNITKEY8"}), \
                patch.dict("sys.modules", {"pixsee_gateway": gateway}), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            result = pixsee.main(["serve", "--camera-ip", "192.0.2.20"])
        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("[redacted]", stderr.getvalue())
        for secret in ("viewer-private", "camera-private", "UNITKEY8"):
            self.assertNotIn(secret, stderr.getvalue())

    def test_invalid_viewer_file_fails_before_server_start(self):
        gateway = SimpleNamespace(
            GatewayConfig=Mock(),
            load_viewer_credentials=Mock(side_effect=ValueError("Invalid viewer credentials")),
            run_gateway=Mock(),
        )
        with patch.dict("sys.modules", {"pixsee_gateway": gateway}), redirect_stderr(io.StringIO()):
            result = pixsee.main(["serve", "--camera-ip", "192.0.2.20", "--profile", "legacy"])
        self.assertEqual(result, 1)
        gateway.GatewayConfig.assert_not_called()
        gateway.run_gateway.assert_not_called()


if __name__ == "__main__":
    unittest.main()
