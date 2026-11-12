"""Opt-in real localhost gateway acceptance with generated media only.

Run with PIXSEE_TEST_MEDIAMTX=/absolute/path/to/mediamtx (version 1.21.3).
FFmpeg and ffprobe must be installed. No camera connection or discovery is used.
The complete test has a 90-second work budget plus bounded process cleanup.
"""

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import HTTPDigestAuthHandler, HTTPPasswordMgrWithDefaultRealm, ProxyHandler, Request, build_opener
import xml.etree.ElementTree as ET

from pixsee_config import PixseeCredentials
import pixsee_gateway as gateway


def _ports():
    """Choose six distinct free ports while reserving all choices together."""
    reservations, ports = [], []
    try:
        for kind in (socket.SOCK_STREAM,) * 4:
            while True:
                sock = socket.socket(socket.AF_INET, kind)
                sock.bind(("127.0.0.1", 0))
                port = sock.getsockname()[1]
                if port not in ports:
                    reservations.append(sock)
                    ports.append(port)
                    break
                sock.close()
        # MediaMTX requires the RTP/RTCP pair to be consecutive. Reserve an
        # even/odd pair together; independently chosen UDP ports cannot boot it.
        for _ in range(100):
            rtp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            rtp.bind(("127.0.0.1", 0))
            port = rtp.getsockname()[1]
            if port % 2 or port in ports or port + 1 in ports or port == 65535:
                rtp.close()
                continue
            rtcp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                rtcp.bind(("127.0.0.1", port + 1))
            except OSError:
                rtp.close()
                rtcp.close()
                continue
            reservations.extend((rtp, rtcp))
            ports.extend((port, port + 1))
            break
        else:
            raise RuntimeError("could not reserve a free localhost RTP/RTCP pair")
        return ports
    finally:
        for sock in reservations:
            sock.close()


def _synthetic_producer(ffmpeg):
    return [ffmpeg, "-hide_banner", "-loglevel", "warning", "-nostdin",
            "-re", "-f", "lavfi", "-i", "testsrc2=size=320x240:rate=10",
            "-f", "lavfi", "-i", "sine=frequency=880:sample_rate=8000",
            "-map", "0:v:0", "-map", "1:a:0",
            "-c:v", "libx264", "-preset", "ultrafast", "-tune", "zerolatency",
            "-pix_fmt", "yuv420p", "-g", "10", "-keyint_min", "10", "-sc_threshold", "0",
            "-c:a", "aac", "-b:a", "24k", "-ar", "8000", "-ac", "1",
            "-f", "mpegts", "-flush_packets", "1", "pipe:1"]


@unittest.skipUnless(os.environ.get("PIXSEE_TEST_MEDIAMTX"),
                     "set PIXSEE_TEST_MEDIAMTX to run real MediaMTX/FFmpeg localhost acceptance")
class GatewayIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.ffmpeg, self.ffprobe = shutil.which("ffmpeg"), shutil.which("ffprobe")
        self.assertTrue(self.ffmpeg and self.ffprobe, "opt-in acceptance requires FFmpeg and ffprobe")
        self.backend = shutil.which(os.environ["PIXSEE_TEST_MEDIAMTX"])
        self.assertIsNotNone(self.backend, "PIXSEE_TEST_MEDIAMTX must name an executable MediaMTX 1.21.3")
        self.deadline = time.monotonic() + 90
        self.readers = []
        self.reader_lock = threading.Lock()
        self.addCleanup(self._stop_readers)

    def budget(self, requested=20):
        remaining = self.deadline - time.monotonic()
        self.assertGreater(remaining, 0, "localhost acceptance exceeded its 90-second work budget")
        return min(requested, remaining)

    def _stop_readers(self):
        for process in self.readers:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.communicate(timeout=3)

    def run_process(self, command, timeout=20):
        # Reader processes are real, separate clients. They are never inserted
        # into the gateway's owner list or used as substitutes for its helpers.
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        with self.reader_lock:
            self.readers.append(process)
        try:
            output, error = process.communicate(timeout=self.budget(timeout))
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            output, error = process.communicate(timeout=3)
            self.fail("media client timed out: " + error.decode("utf-8", "replace")[-2000:])
        self.assertEqual(process.returncode, 0, error.decode("utf-8", "replace")[-2000:])
        return output

    def decode(self, source, output, transport=None):
        command = [self.ffmpeg, "-hide_banner", "-loglevel", "error", "-nostdin", "-y"]
        if transport:
            command.extend(["-rtsp_transport", transport])
        command.extend(["-analyzeduration", "1000000", "-probesize", "2000000", "-i", source,
                        "-map", "0:v:0", "-map", "0:a:0", "-t", "1.2",
                        "-c:v", "rawvideo", "-c:a", "pcm_s16le", "-f", "nut", str(output)])
        self.run_process(command)
        streams = json.loads(self.run_process([self.ffprobe, "-v", "error", "-count_frames",
                                               "-show_streams", "-of", "json", str(output)], 5))["streams"]
        video = next(stream for stream in streams if stream["codec_type"] == "video")
        audio = next(stream for stream in streams if stream["codec_type"] == "audio")
        self.assertEqual((video["codec_name"], video["width"], video["height"]), ("rawvideo", 320, 240))
        self.assertEqual((audio["codec_name"], audio["sample_rate"], audio["channels"]), ("pcm_s16le", "8000", 1))
        self.assertGreater(int(video["nb_read_frames"]), 0)
        self.assertGreater(int(audio["nb_read_frames"]), 0)

    def _wait(self, predicate, worker, errors, timeout, description):
        until = time.monotonic() + self.budget(timeout)
        while time.monotonic() < until:
            if errors:
                raise errors[0]
            if predicate():
                return
            self.assertTrue(worker.is_alive(), "gateway exited while " + description)
            time.sleep(0.05)
        self.fail("timed out while " + description)

    def test_real_protocol_playback_recovery_and_complete_shutdown(self):
        owned, producers, messages, errors, results = [], [], [], [], []
        lock = threading.Lock()
        ready, stop = threading.Event(), threading.Event()
        synthetic = _synthetic_producer(self.ffmpeg)
        real_process = gateway._Process

        class RecordedProcess(real_process):
            def __init__(self, command, **kwargs):
                super().__init__(command, **kwargs)
                with lock:
                    owned.append(self)
                    if command == synthetic:
                        producers.append(self)

            def stop(self):
                try:
                    return super().stop()
                except OSError as error:
                    role = "synthetic producer" if self.process.args == synthetic else Path(self.process.args[0]).name
                    raise RuntimeError(f"owned {role} cleanup failed (pid={self.process.pid}, "
                                       f"returncode={self.process.poll()}, errno={error.errno})") from error

        def on_ready(message):
            messages.append(message)
            ready.set()

        with tempfile.TemporaryDirectory(prefix="pixsee-local-acceptance-") as directory:
            directory = Path(directory)
            rtsp, onvif, hls, api, rtp, rtcp = _ports()
            config = gateway.GatewayConfig(
                # Reserved documentation address; the replaced producer never
                # creates a Pixsee client, socket, or camera discovery request.
                camera_ip="192.0.2.10",
                camera_credentials=PixseeCredentials(account="synthetic", password="unused-test-only",
                                                     auth_key="TESTONLY"),
                mediamtx=self.backend, ffmpeg=self.ffmpeg, ffprobe=self.ffprobe,
                state_path=str(directory / "gateway-state.json"),
                rtsp_port=rtsp, onvif_port=onvif, hls_port=hls, api_port=api,
                rtp_port=rtp, rtcp_port=rtcp, username="viewer", password="test-viewer-secret",
                startup_timeout=25, camera_timeout=3, media_timeout=10, duration=85)

            def run():
                try:
                    results.append(gateway.run_gateway(config, stop_event=stop, on_ready=on_ready))
                except BaseException as error:
                    errors.append(error)

            worker = threading.Thread(target=run, name="pixsee-local-acceptance", daemon=True)
            with patch.object(gateway, "producer_command", return_value=synthetic), \
                    patch.object(gateway, "_Process", RecordedProcess):
                worker.start()
                try:
                    self._wait(ready.is_set, worker, errors, 30, "waiting for actual media readiness")
                    announced = messages[0]
                    self.assertTrue(announced["ready"])
                    self.assertTrue(announced["authentication_required"])
                    self.assertFalse(announced["discovery"])
                    metadata = announced["metadata"]
                    self.assertEqual((metadata["width"], metadata["height"], metadata["video_encoding"]),
                                     (320, 240, "H264"))
                    self.assertEqual((metadata["audio_encoding"], metadata["audio_sample_rate"], metadata["audio_channels"]),
                                     ("AAC", 8000, 1))
                    self.assertEqual(metadata["frame_rate"], 10)
                    self.assertNotIn("test-viewer-secret", json.dumps(announced))

                    # Both clients open real sockets together, independently
                    # decode both tracks, and verify the resulting media frames.
                    with ThreadPoolExecutor(max_workers=2) as executor:
                        futures = [executor.submit(self.decode, announced["rtsp_url"],
                                                   directory / f"{transport}.nut", transport)
                                   for transport in ("tcp", "udp")]
                        for future in futures:
                            future.result(timeout=self.budget(25))
                    self.decode(announced["hls_url"], directory / "hls.nut")

                    # Use Python's independent Digest client against the actual
                    # JPEG endpoint, then decode that JPEG with FFmpeg.
                    opener = build_opener(ProxyHandler({}))
                    with self.assertRaises(HTTPError) as denied:
                        opener.open(announced["snapshot_url"], timeout=self.budget(5))
                    self.assertEqual(denied.exception.code, 401)
                    denied.exception.close()
                    credentials = HTTPPasswordMgrWithDefaultRealm()
                    credentials.add_password(None, f"http://127.0.0.1:{onvif}/", "viewer", "test-viewer-secret")
                    authenticated = build_opener(ProxyHandler({}), HTTPDigestAuthHandler(credentials))
                    with authenticated.open(announced["snapshot_url"], timeout=self.budget(12)) as response:
                        self.assertEqual(response.headers.get_content_type(), "image/jpeg")
                        jpeg = response.read(8 * 1024 * 1024 + 1)
                    self.assertLessEqual(len(jpeg), 8 * 1024 * 1024)
                    image = directory / "snapshot.jpg"
                    image.write_bytes(jpeg)
                    checksum = self.run_process([self.ffmpeg, "-hide_banner", "-loglevel", "error", "-nostdin",
                                                 "-i", str(image), "-frames:v", "1", "-f", "md5", "pipe:1"], 5)
                    self.assertRegex(checksum.decode(), r"^MD5=[0-9a-f]{32}\s*$")

                    before = gateway._api(config, "paths/get/" + config.stream_path)["source"]["id"]
                    with lock:
                        self.assertEqual(len(producers), 1, "producer restarted before the deliberate failure")
                        original = producers[0]
                    # Kill only the synthetic process group that this test owns.
                    os.killpg(original.process.pid, signal.SIGKILL)
                    original.process.wait(timeout=self.budget(3))

                    def recovered():
                        with lock:
                            if len(producers) < 2:
                                return False
                        try:
                            current = gateway._api(config, "paths/get/" + config.stream_path)
                            if not current.get("available") or current.get("source", {}).get("id") == before:
                                return False
                            xml = b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetProfiles xmlns="http://www.onvif.org/ver10/media/wsdl"/></s:Body></s:Envelope>'
                            # urllib retains a Digest retry count after an HTTP
                            # error. During recovery a truthful temporary SOAP
                            # fault must not poison later authentication probes.
                            probe = build_opener(ProxyHandler({}), HTTPDigestAuthHandler(credentials))
                            with probe.open(Request(f"http://127.0.0.1:{onvif}/onvif/media_service",
                                                    data=xml, headers={"Content-Type": "application/soap+xml"}),
                                            timeout=2) as response:
                                root = ET.fromstring(response.read(65536))
                            return root.find(".//{http://www.onvif.org/ver10/media/wsdl}Profiles") is not None
                        except HTTPError as error:
                            error.close()
                            return False
                        except (OSError, ValueError, ET.ParseError):
                            return False

                    self._wait(recovered, worker, errors, 25, "waiting for a new publisher and fresh ONVIF profile")
                    self.decode(announced["rtsp_url"], directory / "recovered.nut", "tcp")
                finally:
                    stop.set()
                    worker.join(timeout=12)
                    # Even a gateway cleanup exception must leave no test-owned
                    # processes. Do not use broad process-name matching here.
                    with lock:
                        survivors = [child.process for child in owned if child.process.poll() is None]
                    for process in survivors:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait(timeout=3)
                    if worker.is_alive():
                        worker.join(timeout=3)
                    self.assertFalse(worker.is_alive(), "gateway did not stop within its cleanup budget")
                    self.assertFalse(survivors, "gateway cleanup left owned processes running")

            if errors:
                raise errors[0]
            self.assertEqual(len(messages), 1, "recovery must not emit a second initial readiness event")
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["status"], "stopped")
            self.assertEqual(results[0]["restarts"], 1)
            self.assertTrue(results[0]["healthy_at_stop"])
            self.assertEqual(len(producers), 2)
            for child in owned:
                self.assertIsNotNone(child.process.poll(), "an owned gateway process survived shutdown")
                self.assertFalse(child.thread.is_alive(), "an owned diagnostic reader survived shutdown")
            self._stop_readers()
            for kind, port in ((socket.SOCK_STREAM, rtsp), (socket.SOCK_STREAM, onvif),
                               (socket.SOCK_STREAM, hls), (socket.SOCK_STREAM, api),
                               (socket.SOCK_DGRAM, rtp), (socket.SOCK_DGRAM, rtcp)):
                with self.subTest(port=port, kind=kind), socket.socket(socket.AF_INET, kind) as listener:
                    if kind == socket.SOCK_STREAM:
                        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                        with self.assertRaises(OSError):
                            socket.create_connection(("127.0.0.1", port), timeout=0.2)
                    listener.bind(("127.0.0.1", port))


if __name__ == "__main__":
    unittest.main()
