"""DTLS checks against a real independent OpenSSL s_server on loopback only."""

import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
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
    def __enter__(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]
        self.process = subprocess.Popen([
            _OPENSSL, "s_server", "-dtls1_2", "-accept", f"127.0.0.1:{self.port}",
            "-nocert", "-psk_identity", _IDENTITY.decode("ascii"),
            "-psk", _TEST_KEY.hex(), "-cipher", DEFAULT_CIPHERS,
            "-quiet", "-naccept", "1",
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.connect(("127.0.0.1", self.port))
        self.socket.settimeout(0.05)
        time.sleep(0.08)
        if self.process.poll() is not None:
            raise RuntimeError("Local OpenSSL DTLS server did not start")
        return self

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

    def __exit__(self, *_):
        self.socket.close()
        self.process.terminate()
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=2)
        for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
            pipe.close()


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
