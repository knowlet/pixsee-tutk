"""Independent WS-Discovery requests; UDP is limited to the loopback interface."""

import socket
import time
import unittest
import uuid
from unittest import mock
import xml.etree.ElementTree as ET

import pixsee_discovery as discovery
from pixsee_discovery import DiscoveryService


S = "http://www.w3.org/2003/05/soap-envelope"
A = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
D = "http://schemas.xmlsoap.org/ws/2005/04/discovery"
T = "http://www.onvif.org/ver10/device/wsdl"
N = "http://www.onvif.org/ver10/network/wsdl"
TO = "urn:schemas-xmlsoap-org:ws:2005:04:discovery"
IDENTITY = "d1bb92bc-acb1-4d2d-a1bd-2318d97856a5"
SCOPES = ("onvif://www.onvif.org/hardware/PixseeGateway",
          "onvif://www.onvif.org/name/Living%20Room")
GROUP = "239.255.42.99"


def service(**changes):
    options = dict(interface_ip="127.0.0.1", device_uuid=IDENTITY,
                   xaddr="http://127.0.0.1:18080/onvif/device_service",
                   scopes=SCOPES, port=0, multicast_group=GROUP, instance_id=123)
    options.update(changes)
    return DiscoveryService(**options)


def request(kind="Probe", content="", message_id=None, extra_header="", extra_ns=""):
    message_id = message_id or uuid.uuid4().urn
    xml = f'''<env:Envelope xmlns:env="{S}" xmlns:addr="{A}" xmlns:disc="{D}"
        xmlns:camera="{T}" xmlns:video="{N}" {extra_ns}>
        <env:Header><addr:Action>{D}/{kind}</addr:Action>
        <addr:MessageID>{message_id}</addr:MessageID><addr:To>{TO}</addr:To>
        {extra_header}</env:Header>
        <env:Body><disc:{kind}>{content}</disc:{kind}></env:Body></env:Envelope>'''
    return xml.encode(), message_id


def field(root, namespace, name):
    return root.findtext(f".//{{{namespace}}}{name}")


class DiscoveryProtocolTests(unittest.TestCase):
    def setUp(self):
        self.service = service()

    def test_construction_does_not_open_a_socket(self):
        with mock.patch("pixsee_discovery.socket.socket", side_effect=AssertionError):
            unused = service()
            self.assertIsNone(unused.address)
            self.assertFalse(unused.running)
            unused.close()

    def test_rejects_unreachable_advertisement_and_bad_configuration(self):
        cases = [dict(interface_ip="0.0.0.0"), dict(interface_ip="localhost"),
                 dict(xaddr="http://192.0.2.2/onvif/device_service"),
                 dict(xaddr="http://user:secret@127.0.0.1/onvif/device_service"),
                 dict(xaddr="http://127.0.0.1:65536/onvif/device_service"),
                 dict(bind_ip="127.0.0.2"), dict(multicast_group="127.0.0.1"),
                 dict(device_uuid="unstable"), dict(instance_id=0),
                 dict(instance_id=True), dict(metadata_version=-1), dict(port=65536),
                 dict(scopes=("not absolute",)), dict(scopes=("urn:x",) * 17),
                 dict(scopes=("urn:" + "&" * 252,) * 8)]
        for options in cases:
            with self.subTest(options=options), self.assertRaises(ValueError):
                service(**options)

    def test_probe_correlation_and_qname_aliases(self):
        for content in ("", "<disc:Types/>", "<disc:Types>camera:Device</disc:Types>",
                        "<disc:Types>video:NetworkVideoTransmitter camera:Device</disc:Types>",
                        f'<disc:Types xmlns:alias="{T}">alias:Device</disc:Types>',
                        f'<disc:Types xmlns="{T}">Device</disc:Types>'):
            with self.subTest(content=content):
                packet, message_id = request(content=content)
                self.assertEqual(self.service._request(packet), ("ProbeMatches", message_id))
        for content in ('<disc:Types xmlns:camera="urn:wrong">camera:Device</disc:Types>',
                        '<disc:Types>camera:Device camera:Other</disc:Types>',
                        '<disc:Types>undefined:Device</disc:Types>',
                        '<disc:Types>Device</disc:Types>'):
            with self.subTest(content=content):
                self.assertIsNone(self.service._request(request(content=content)[0]))

    def test_scope_rules_compare_full_path_segments_and_all_requested_scopes(self):
        matching = ["onvif://www.onvif.org", "ONVIF://WWW.ONVIF.ORG/hardware",
                    "onvif://www.onvif.org/name/Living%20Room",
                    "onvif://www.onvif.org/name/Living%20Room?ignored=yes#ignored",
                    "onvif://www.onvif.org/name onvif://www.onvif.org/hardware"]
        for rule in ("rfc2396", "rfc3986"):
            for scopes in matching:
                with self.subTest(rule=rule, scopes=scopes):
                    content = f'<disc:Scopes MatchBy="{D}/{rule}">{scopes}</disc:Scopes>'
                    self.assertIsNotNone(self.service._request(request(content=content)[0]))
        nonmatching = ["onvif://www.onvif.org/hard", "onvif://www.onvif.org/name/living%20Room",
                       "onvif://wrong.example/name", "onvif://www.onvif.org/name/../hardware",
                       "onvif://www.onvif.org/%2e/name", "onvif://www.onvif.org/name/Missing",
                       "onvif://www.onvif.org/name onvif://www.onvif.org/ptz",
                       "onvif://www.onvif.org/name/Living%ZZRoom"]
        for scopes in nonmatching:
            with self.subTest(scopes=scopes):
                content = f'<disc:Scopes>{scopes}</disc:Scopes>'
                self.assertIsNone(self.service._request(request(content=content)[0]))
        for rule, scope, matches in (("strcmp0", SCOPES[0], True),
                                     ("strcmp0", "onvif://www.onvif.org/hardware", False),
                                     ("unsupported", SCOPES[0], False)):
            content = f'<disc:Scopes MatchBy="{D}/{rule}">{scope}</disc:Scopes>'
            self.assertEqual(self.service._request(request(content=content)[0]) is not None, matches)

    def test_resolve_requires_exact_endpoint_and_empty_reference_properties(self):
        body = f'<addr:EndpointReference><addr:Address>urn:uuid:{IDENTITY}</addr:Address></addr:EndpointReference>'
        packet, message_id = request("Resolve", body)
        self.assertEqual(self.service._request(packet), ("ResolveMatches", message_id))
        wrong = body.replace(IDENTITY, str(uuid.uuid4()))
        self.assertIsNone(self.service._request(request("Resolve", wrong)[0]))
        extra = body.replace("</addr:EndpointReference>",
                             "<addr:ReferenceProperties><camera:Other/></addr:ReferenceProperties></addr:EndpointReference>")
        self.assertIsNone(self.service._request(request("Resolve", extra)[0]))

    def test_rejects_malformed_ambiguous_and_redirected_packets(self):
        valid, _ = request()
        cases = [b"not xml", valid.replace(S.encode(), b"urn:wrong"),
                 valid.replace(b"/Probe</addr:Action>", b"/Resolve</addr:Action>"),
                 valid.replace(TO.encode(), b"urn:wrong"),
                 valid.replace(b"<disc:Probe>", b"<disc:Probe><disc:Types/><disc:Types/>"),
                 valid.replace(b"</env:Body>", b"<disc:Probe/></env:Body>"),
                 valid.replace(b"</env:Header>", b"<addr:MessageID>urn:extra</addr:MessageID></env:Header>"),
                 valid.replace(b"</env:Header>", b"<addr:ReplyTo><addr:Address>http://127.0.0.2/</addr:Address></addr:ReplyTo></env:Header>"),
                 b'<!DOCTYPE env:Envelope [<!ENTITY bad "expanded">]>' + valid,
                 valid + b" " * discovery.MAX_DATAGRAM,
                 valid.decode().encode("utf-16"),
                 request(content="<camera:Nested>" * 25 + "</camera:Nested>" * 25)[0]]
        for index, packet in enumerate(cases):
            with self.subTest(case=index):
                self.assertIsNone(self.service._request(packet))

    def test_response_namespaces_identity_truthful_scopes_and_sequence(self):
        seen_ids = set()
        for number, kind in enumerate(("Hello", "ProbeMatches", "ResolveMatches", "Bye"), 1):
            related = "urn:request:1" if "Matches" in kind else ""
            wire = self.service._message(kind, related)
            self.assertLess(len(wire), discovery.MAX_DATAGRAM)
            root = ET.fromstring(wire)
            self.assertEqual(root.tag, f"{{{S}}}Envelope")
            self.assertEqual(field(root, A, "Action"), D + "/" + kind)
            self.assertEqual(field(root, A, "Address"), "urn:uuid:" + IDENTITY)
            self.assertEqual(field(root, A, "RelatesTo"), related or None)
            message_id = field(root, A, "MessageID")
            self.assertNotIn(message_id, seen_ids)
            seen_ids.add(message_id)
            sequence = root.find(f".//{{{D}}}AppSequence")
            self.assertEqual(sequence.attrib["InstanceId"], "123")
            self.assertEqual(sequence.attrib["MessageNumber"], str(number))
            if kind != "Bye":
                self.assertEqual(field(root, D, "Scopes"), " ".join(SCOPES))
                self.assertEqual(field(root, D, "XAddrs"), self.service.xaddr)
                self.assertNotIn(b"Profile/", wire)
                self.assertNotIn(b"ptz", wire)
            if related:
                self.assertIsNotNone(root.find(f".//{{{D}}}{kind[:-2]}"))

    def test_queue_and_rate_state_are_bounded(self):
        for number in range(1000):
            self.service._schedule("ProbeMatches", ("127.0.0.1", 12345), f"urn:request:{number}")
        self.assertEqual(len(self.service._queue), 64)
        now = time.monotonic()
        self.assertEqual(sum(self.service._allow("127.0.0.1", now) for _ in range(30)), 5)
        for number in range(100):
            self.service._allow(f"192.0.2.{number}", now + number + 1)
        self.assertLessEqual(len(self.service._peers), 64)


class DiscoveryLoopbackTests(unittest.TestCase):
    def client(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(2.0)
        self.addCleanup(sock.close)
        return sock

    def test_probe_resolve_retries_and_port_release(self):
        responder = service().start()
        self.addCleanup(responder.close)
        self.assertIs(responder.start(), responder)
        client = self.client()
        target = ("127.0.0.1", responder.address[1])
        for kind in ("Probe", "Resolve"):
            content = "" if kind == "Probe" else (
                f'<addr:EndpointReference><addr:Address>urn:uuid:{IDENTITY}</addr:Address></addr:EndpointReference>')
            packet, message_id = request(kind, content)
            client.sendto(packet, target)
            first, source = client.recvfrom(16384)
            second, _ = client.recvfrom(16384)
            self.assertEqual(first, second, "transport retries preserve MessageID and AppSequence")
            self.assertEqual(source, target)
            root = ET.fromstring(first)
            self.assertEqual(field(root, A, "RelatesTo"), message_id)
            self.assertEqual(field(root, A, "Action"), D + "/" + kind + "Matches")
            client.sendto(packet, target)
            client.settimeout(0.15)
            with self.assertRaises(socket.timeout):
                client.recvfrom(16384)
            client.settimeout(2.0)
        started = time.monotonic()
        responder.close()
        self.assertLess(time.monotonic() - started, 2.0)
        responder.close()
        self.assertFalse(responder.running)
        self.assertIsNone(responder.error)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as replacement:
            replacement.bind(("0.0.0.0", target[1]))
        with self.assertRaises(RuntimeError):
            responder.start()

    def test_multicast_hello_probe_and_bye_on_loopback(self):
        monitor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(monitor.close)
        monitor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            monitor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        monitor.bind(("0.0.0.0", 0))
        port = monitor.getsockname()[1]
        monitor.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                           socket.inet_aton(GROUP) + socket.inet_aton("127.0.0.1"))
        monitor.settimeout(2.0)
        responder = service(port=port).start()
        self.addCleanup(responder.close)
        hello = None
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            root = ET.fromstring(monitor.recvfrom(16384)[0])
            if field(root, A, "Action") == D + "/Hello":
                hello = root
                break
        self.assertIsNotNone(hello)
        client = self.client()
        client.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton("127.0.0.1"))
        client.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        packet, message_id = request(content="<disc:Types>video:NetworkVideoTransmitter</disc:Types>")
        client.sendto(packet, (GROUP, port))
        response = ET.fromstring(client.recvfrom(16384)[0])
        self.assertEqual(field(response, A, "RelatesTo"), message_id)
        responder.close()
        byes = []
        while len(byes) < 4:
            wire = monitor.recvfrom(16384)[0]
            root = ET.fromstring(wire)
            if field(root, A, "Action") == D + "/Bye":
                byes.append(wire)
        self.assertEqual(len(set(byes)), 1)
        bye = ET.fromstring(byes[0])
        self.assertEqual(field(bye, A, "Address"), field(hello, A, "Address"))
        self.assertGreater(int(bye.find(f".//{{{D}}}AppSequence").get("MessageNumber")),
                           int(hello.find(f".//{{{D}}}AppSequence").get("MessageNumber")))
        self.assertIsNone(responder.error)


if __name__ == "__main__":
    unittest.main()
