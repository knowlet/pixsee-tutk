"""Real loopback DTLS checks; lsof verifies the test server owns its UDP port."""

import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import time
import unittest

from pixsee_dtls import DEFAULT_CIPHERS, DtlsError, DtlsPskClient


_OPENSSL = next((str(path) for path in (
    Path("/opt/homebrew/opt/openssl@3/bin/openssl"),
    Path("/usr/local/opt/openssl@3/bin/openssl"),
) if path.is_file()), shutil.which("openssl"))
_IDENTITY = b"pixsee-local-unit-test"
_TEST_KEY = bytes.fromhex("00112233445566778899aabbccddeeff")


class LocalServer:
    def __init__(self, *, launch_delay=0, startup_timeout=5):
        self.launch_delay = launch_delay
        self.startup_timeout = startup_timeout
        self.process = self.socket = None

    def __enter__(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]
        command = [
            _OPENSSL, "s_server", "-dtls1_2", "-accept", f"127.0.0.1:{self.port}",
            "-nocert", "-psk_identity", _IDENTITY.decode("ascii"),
            "-psk", _TEST_KEY.hex(), "-cipher", DEFAULT_CIPHERS,
            "-quiet", "-naccept", "1",
        ]
        if self.launch_delay:
            # The regression delays the actual bind, not Popen's return. exec
            # preserves the child PID so normal cleanup also covers the delay.
            command = [sys.executable, "-c",
                       "import os,sys,time; time.sleep(float(sys.argv[1])); "
                       "os.execv(sys.argv[2], sys.argv[2:])",
                       str(self.launch_delay), *command]
        try:
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self._wait_until_listening()
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.connect(("127.0.0.1", self.port))
            self.socket.settimeout(0.05)
            return self
        except BaseException:
            # A failing __enter__ does not get a matching context-manager exit.
            self.close()
            raise

    def _wait_until_listening(self):
        inspector = shutil.which("lsof")
        if inspector is None:
            raise RuntimeError("DTLS loopback tests require lsof to verify server readiness")
        deadline = time.monotonic() + self.startup_timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("Local OpenSSL DTLS server exited before listening")
            # UDP connect cannot establish readiness, and a temporary bind
            # probe could steal the port during OpenSSL startup. Inspect only
            # this child instead, without occupying or sending to the port.
            try:
                inspected = subprocess.run(
                    [inspector, "-nP", "-a", "-p", str(self.process.pid),
                     f"-iUDP:{self.port}", "-Fpn"],
                    capture_output=True, text=True,
                    timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise RuntimeError("Local OpenSSL DTLS server timed out before listening") from None
            if inspected.returncode not in (0, 1):
                raise RuntimeError("lsof failed to inspect the local DTLS server")
            fields = inspected.stdout.splitlines()
            if (f"p{self.process.pid}" in fields
                    and f"n127.0.0.1:{self.port}" in fields
                    and self.process.poll() is None):
                return
            time.sleep(min(0.01, max(0, deadline - time.monotonic())))
        raise RuntimeError("Local OpenSSL DTLS server timed out before listening")

    def send(self, datagrams):
        for datagram in datagrams:
            self.socket.send(datagram)

    def pump(self, client, predicate, timeout=4):
        end = time.monotonic() + timeout
        while time.monotonic() < end and not predicate():
            try:
                data = self.socket.recv(65535)
            except socket.timeout:
                self.send(client.handle_timeout())
                continue
            self.send(client.feed_datagram(data))
        return predicate()

    def close(self):
        if self.socket is not None:
            self.socket.close()
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
            for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
                if pipe is not None:
                    pipe.close()

    def __exit__(self, *_):
        self.close()


class DtlsInputTests(unittest.TestCase):
    def test_validation_happens_before_native_loading(self):
        for kwargs in ({"identity": b"a\0b", "psk": _TEST_KEY},
                       {"identity": b"a", "psk": b""},
                       {"identity": b"a", "psk": _TEST_KEY, "mtu": 255},
                       {"identity": b"a", "psk": _TEST_KEY, "ciphers": "DEFAULT"}):
            with self.subTest(fields=tuple(kwargs)):
                with self.assertRaises(ValueError):
                    DtlsPskClient(library_path="/does/not/exist", **kwargs)


@unittest.skipUnless(_OPENSSL, "Installed OpenSSL executable is unavailable")
class DtlsLoopbackTests(unittest.TestCase):
    def test_delayed_server_bind_still_completes_real_dtls_handshake(self):
        started = time.monotonic()
        with LocalServer(launch_delay=0.25) as server, \
                DtlsPskClient(_IDENTITY, _TEST_KEY) as client:
            self.assertGreaterEqual(time.monotonic() - started, 0.25)
            server.send(client.start())
            self.assertTrue(server.pump(client, lambda: client.handshake_complete))

    def test_startup_timeout_reaps_child_and_closes_pipes(self):
        server = LocalServer(launch_delay=0.25, startup_timeout=0.05)
        with self.assertRaisesRegex(RuntimeError, "before listening"):
            server.__enter__()
        self.assertIsNotNone(server.process.poll())
        self.assertIsNone(server.socket)
        self.assertTrue(all(pipe.closed for pipe in (
            server.process.stdin, server.process.stdout, server.process.stderr)))
        server.close()  # Cleanup remains idempotent after a failed entry.

    def test_handshake_bidirectional_binary_data_and_mtu(self):
        with LocalServer() as server, DtlsPskClient(_IDENTITY, _TEST_KEY, mtu=600) as client:
            hello = client.start()
            self.assertTrue(hello)
            self.assertTrue(all(len(packet) <= 600 for packet in hello))
            server.send(hello)
            self.assertTrue(server.pump(client, lambda: client.handshake_complete))
            self.assertGreater(client.data_mtu, 0)
            prefix = b"client binary\x00\xff bytes "
            payload = prefix + b"x" * (client.data_mtu - len(prefix) - 1) + b"\n"
            outgoing = client.send_application(payload)
            self.assertTrue(all(len(packet) <= 600 for packet in outgoing))
            server.send(outgoing)
            readable, _, _ = select.select([server.process.stdout], [], [], 2)
            self.assertTrue(readable)
            self.assertEqual(os.read(server.process.stdout.fileno(), 4096), payload)
            reply = b"server binary\x00\xfe response\n"
            server.process.stdin.write(reply)
            server.process.stdin.flush()
            received = []

            def got_reply():
                received.extend(client.receive_application())
                return bool(received)

            self.assertTrue(server.pump(client, got_reply))
            self.assertEqual(b"".join(received), reply)
            with self.assertRaisesRegex(ValueError, "MTU"):
                client.send_application(b"x" * (client.data_mtu + 1))

    def test_wrong_psk_cannot_complete_or_send_application_data(self):
        with LocalServer() as server, DtlsPskClient(_IDENTITY, b"wrong-key") as client:
            server.send(client.start())
            try:
                completed = server.pump(client, lambda: client.handshake_complete, timeout=2.2)
            except DtlsError:
                completed = False
            self.assertFalse(completed)
            self.assertFalse(client.handshake_complete)
            with self.assertRaises(DtlsError):
                client.send_application(b"must not be sent")
            # DTLS may silently discard a bad-MAC Finished instead of emitting
            # an alert. The independent server must deliver no application data.
            readable, _, _ = select.select([server.process.stdout], [], [], 0.1)
            self.assertFalse(readable)

    def test_initial_flight_retransmission_and_close(self):
        with DtlsPskClient(_IDENTITY, _TEST_KEY) as client:
            first = client.start()
            timeout = client.timeout_seconds
            self.assertIsNotNone(timeout)
            self.assertLess(timeout, 2)
            self.assertEqual(client.handle_timeout(), [])
            time.sleep(timeout + 0.03)
            retransmitted = client.handle_timeout()
            self.assertTrue(retransmitted)
            # OpenSSL may update record sequence numbers, but retransmits same flight.
            self.assertEqual(sum(map(len, first)), sum(map(len, retransmitted)))
            client.close()
            client.close()
            with self.assertRaisesRegex(DtlsError, "closed"):
                client.start()


if __name__ == "__main__":
    unittest.main()
