"""Independent SOAP fixtures and real loopback HTTP authentication checks.

Response element order/units follow the official Device and Media1 WSDL and
schema (wsdl/ver10/{device,media}/wsdl and wsdl/ver10/schema/onvif.xsd).
These checks do not establish ONVIF certification or a particular NVR's support.
"""

import base64
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import re
import socket
import threading
import time
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from pixsee_onvif import MediaProfile, OnvifConfig, OnvifServer


NS = {"s": "http://www.w3.org/2003/05/soap-envelope",
      "d": "http://www.onvif.org/ver10/device/wsdl",
      "m": "http://www.onvif.org/ver10/media/wsdl",
      "t": "http://www.onvif.org/ver10/schema"}
DEVICE_PATH = "/onvif/device_service"
MEDIA_PATH = "/onvif/media_service"
CONFIG = OnvifConfig(device_uuid="03c7acb7-6847-4bf7-9eeb-89346ee6724f",
                     serial_number="virtual-03c7acb7", port=0)
PROFILE = MediaProfile(1920, 1088, 25, audio_encoding="AAC",
                       audio_sample_rate=8000, audio_channels=1, audio_bitrate=24)
JPEG = b"\xff\xd8test-jpeg\xff\xd9"


def soap(action, namespace="d", arguments="", header=""):
    # Deliberately use unrelated prefixes, exercising expanded namespace parsing.
    return (f'<soap:Envelope xmlns:soap="{NS["s"]}" xmlns:op="{NS[namespace]}" '
            f'xmlns:types="{NS["t"]}"><soap:Header>{header}</soap:Header>'
            f'<soap:Body><op:{action}>{arguments}</op:{action}>'
            '</soap:Body></soap:Envelope>').encode()


def request(server, body=None, path=DEVICE_PATH, authorization=None, method="POST", headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=3)
    headers = dict(headers or {})
    if authorization:
        headers["Authorization"] = authorization
    headers.setdefault("Content-Type", "application/soap+xml")
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def digest(challenge, method="POST", path=DEVICE_PATH, password="bridge-secret",
           nc="00000001", cnonce="independent-client-nonce"):
    nonce = re.search(r'nonce="([^"]+)"', challenge).group(1)
    realm = re.search(r'realm="([^"]+)"', challenge).group(1)
    md5 = lambda s: hashlib.md5(s.encode()).hexdigest()
    a1, a2 = md5(f"viewer:{realm}:{password}"), md5(f"{method}:{path}")
    response = md5(f"{a1}:{nonce}:{nc}:{cnonce}:auth:{a2}")
    return (f'Digest username="viewer", realm="{realm}", nonce="{nonce}", uri="{path}", '
            f'algorithm=MD5, response="{response}", qop=auth, nc={nc}, cnonce="{cnonce}"')


def wsse(password="bridge-secret", offset=0, nonce=b"independent-wsse-nonce", created=None):
    created = created or (datetime.now(timezone.utc) + timedelta(seconds=offset)).isoformat().replace("+00:00", "Z")
    password_digest = base64.b64encode(hashlib.sha1(nonce + created.encode() + password.encode()).digest()).decode()
    return ('''<Security soap:mustUnderstand="1" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <UsernameToken><Username>viewer</Username>
      <Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">'''
            + password_digest + '</Password><Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">'
            + base64.b64encode(nonce).decode() + '</Nonce><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
            + created + '</Created></UsernameToken></Security>')


def children(element):
    return [child.tag.rsplit("}", 1)[-1] for child in element]


class OnvifContractTests(unittest.TestCase):
    def setUp(self):
        self.profile = PROFILE
        self.server = OnvifServer(CONFIG, lambda: self.profile, lambda: JPEG).start()
        self.addCleanup(self.server.close)

    def call(self, action, namespace="d", arguments=""):
        status, _, body = request(self.server, soap(action, namespace, arguments),
                                  MEDIA_PATH if namespace == "m" else DEVICE_PATH)
        return status, ET.fromstring(body)

    def test_scrypted_bootstrap_and_profile_source_correspondence(self):
        status, root = self.call("GetSystemDateAndTime")
        self.assertEqual(status, 200)
        self.assertEqual(root.findtext(".//t:UTCDateTime/t:Date/t:Year", namespaces=NS), str(datetime.now(timezone.utc).year))
        status, root = self.call("GetServices", arguments="<op:IncludeCapability>true</op:IncludeCapability>")
        self.assertEqual(status, 200)
        services = root.findall(".//d:Service", NS)
        self.assertEqual([s.findtext("d:Namespace", namespaces=NS) for s in services], [NS["d"], NS["m"]])
        self.assertEqual([s.findtext("d:XAddr", namespaces=NS) for s in services], [self.server.device_url, self.server.media_url])
        self.assertIsNotNone(services[0].find("d:Capabilities/d:Capabilities/d:Security", NS))
        self.assertIsNotNone(services[1].find("d:Capabilities/m:Capabilities/m:StreamingCapabilities", NS))
        for service in services:
            self.assertEqual(children(service), ["Namespace", "XAddr", "Capabilities", "Version"])
        status, root = self.call("GetProfiles", "m")
        self.assertEqual(status, 200)
        profile = root.find(".//m:Profiles", NS)
        self.assertEqual(profile.get("token"), "profile_1")
        self.assertEqual(profile.get("fixed"), "true")
        self.assertEqual(children(profile), ["Name", "VideoSourceConfiguration", "AudioSourceConfiguration",
                                              "VideoEncoderConfiguration", "AudioEncoderConfiguration"])
        source_token = profile.findtext("t:VideoSourceConfiguration/t:SourceToken", namespaces=NS)
        _, sources = self.call("GetVideoSources", "m")
        source = sources.find(".//m:VideoSources", NS)
        self.assertEqual(source.get("token"), source_token)
        self.assertEqual(source.findtext("t:Framerate", namespaces=NS), "25")
        self.assertEqual(source.findtext("t:Resolution/t:Height", namespaces=NS), "1088")
        status, root = self.call("GetDeviceInformation")
        self.assertEqual(status, 200)
        self.assertEqual(root.findtext(".//d:SerialNumber", namespaces=NS), CONFIG.serial_number)

    def test_service_capability_namespaces_and_unsupported_features(self):
        for namespace in ("d", "m"):
            status, root = self.call("GetServiceCapabilities", namespace)
            self.assertEqual(status, 200)
            caps = root.find(f".//{namespace}:Capabilities", NS)
            self.assertIsNotNone(caps)
            self.assertEqual(children(caps), ["Network", "Security", "System"] if namespace == "d"
                             else ["ProfileCapabilities", "StreamingCapabilities"])
        self.assertEqual(caps.get("SnapshotUri"), "true")
        self.assertEqual(caps.get("OSD"), "false")
        status, root = self.call("GetCapabilities")
        self.assertEqual(status, 200)
        self.assertEqual(children(root.find(".//d:Capabilities", NS)), ["Device", "Media"])
        self.assertIsNone(root.find(".//t:Events", NS))
        _, root = self.call("GetDiscoveryMode")
        self.assertEqual(root.findtext(".//d:DiscoveryMode", namespaces=NS), "NonDiscoverable")

    def test_get_services_honors_include_capability_false(self):
        status, root = self.call("GetServices", arguments="<op:IncludeCapability>false</op:IncludeCapability>")
        self.assertEqual(status, 200)
        self.assertIsNone(root.find(".//d:Capabilities", NS))

    def test_real_audio_units_and_no_invented_video_rate_or_gop(self):
        _, root = self.call("GetProfiles", "m")
        video = root.find(".//t:VideoEncoderConfiguration", NS)
        self.assertIsNone(video.find("t:RateControl", NS))
        self.assertIsNone(video.find("t:H264", NS))
        self.assertEqual(children(video), ["Name", "UseCount", "Encoding", "Resolution", "Quality", "Multicast", "SessionTimeout"])
        audio = root.find(".//t:AudioEncoderConfiguration", NS)
        self.assertEqual(audio.findtext("t:Encoding", namespaces=NS), "AAC")
        self.assertEqual(audio.findtext("t:SampleRate", namespaces=NS), "8")
        self.assertEqual(audio.findtext("t:Bitrate", namespaces=NS), "24")
        self.assertEqual(children(audio), ["Name", "UseCount", "Encoding", "Bitrate", "SampleRate", "Multicast", "SessionTimeout"])
        _, root = self.call("GetAudioEncoderConfigurationOptions", "m")
        self.assertEqual(root.findtext(".//t:SampleRateList/t:Items", namespaces=NS), "8")
        self.assertEqual(root.findtext(".//t:BitrateList/t:Items", namespaces=NS), "24")

    def test_known_encoder_values_and_options_match(self):
        self.profile = replace(PROFILE, video_bitrate=4096, gop=50, h264_profile="High")
        _, root = self.call("GetProfiles", "m")
        self.assertEqual(root.findtext(".//t:RateControl/t:BitrateLimit", namespaces=NS), "4096")
        self.assertEqual(root.findtext(".//t:H264/t:GovLength", namespaces=NS), "50")
        _, root = self.call("GetVideoEncoderConfigurationOptions", "m")
        self.assertEqual(root.findtext(".//t:H264/t:GovLengthRange/t:Max", namespaces=NS), "50")
        self.assertEqual(root.findtext(".//t:H264/t:H264ProfilesSupported", namespaces=NS), "High")

    def test_video_only_profile_omits_audio_and_audio_lists_are_empty(self):
        self.profile = MediaProfile(640, 480, 30)
        _, root = self.call("GetProfiles", "m")
        self.assertIsNone(root.find(".//t:AudioEncoderConfiguration", NS))
        for action in ("GetAudioSources", "GetAudioEncoderConfigurations", "GetAudioSourceConfigurations"):
            status, root = self.call(action, "m")
            self.assertEqual(status, 200)
            self.assertEqual(len(root.find(f".//m:{action}Response", NS)), 0)
        status, root = self.call("GetAudioSourceConfigurationOptions", "m")
        self.assertEqual(status, 500)
        self.assertIn("ter:NoConfig", ET.tostring(root).decode())

    def test_all_configuration_queries_validate_and_return_expected_shape(self):
        for kind, token in (("VideoSource", "video_source_config_1"), ("VideoEncoder", "video_encoder_1"),
                            ("AudioSource", "audio_source_config_1"), ("AudioEncoder", "audio_encoder_1")):
            for suffix in ("Configuration", "Configurations", "ConfigurationOptions"):
                with self.subTest(kind=kind, suffix=suffix):
                    status, root = self.call(f"Get{kind}{suffix}", "m", f"<op:ConfigurationToken>{token}</op:ConfigurationToken>")
                    self.assertEqual(status, 200)
                    response = root.find(f".//m:Get{kind}{suffix}Response", NS)
                    self.assertEqual(children(response), ["Options" if suffix.endswith("Options") else suffix])
            status, root = self.call(f"GetCompatible{kind}Configurations", "m", "<op:ProfileToken>profile_1</op:ProfileToken>")
            self.assertEqual(status, 200)
        _, root = self.call("GetVideoSourceConfigurationOptions", "m")
        self.assertEqual(root.findtext(".//t:BoundsRange/t:HeightRange/t:Min", namespaces=NS), "1088")

    def test_tokens_are_checked_for_profiles_uris_and_options(self):
        for action, argument in (("GetProfile", "ProfileToken"), ("GetStreamUri", "ProfileToken"),
                                 ("GetSnapshotUri", "ProfileToken"), ("GetVideoEncoderConfigurationOptions", "ConfigurationToken"),
                                 ("GetVideoEncoderConfigurationOptions", "ProfileToken")):
            with self.subTest(action=action, argument=argument):
                status, root = self.call(action, "m", f"<op:{argument}>missing</op:{argument}>")
                self.assertEqual(status, 500)
                self.assertIn("ter:InvalidArgVal", ET.tostring(root).decode())

    def test_stream_transport_and_media_uri_validity(self):
        for protocol in ("RTSP", "UDP"):
            args = f"<op:StreamSetup><types:Stream>RTP-Unicast</types:Stream><types:Transport><types:Protocol>{protocol}</types:Protocol></types:Transport></op:StreamSetup><op:ProfileToken>profile_1</op:ProfileToken>"
            status, root = self.call("GetStreamUri", "m", args)
            self.assertEqual(status, 200)
            uri = root.find(".//m:MediaUri", NS)
            self.assertEqual(children(uri), ["Uri", "InvalidAfterConnect", "InvalidAfterReboot", "Timeout"])
            self.assertEqual(uri.findtext("t:Uri", namespaces=NS), "rtsp://127.0.0.1:8554/pixsee")
            self.assertEqual(uri.findtext("t:Timeout", namespaces=NS), "PT0S")
        for setup in ("", "<op:StreamSetup><types:Stream>RTP-Multicast</types:Stream></op:StreamSetup>",
                      "<op:StreamSetup><types:Stream>RTP-Unicast</types:Stream><types:Transport><types:Protocol>HTTP</types:Protocol></types:Transport></op:StreamSetup>"):
            status, _ = self.call("GetStreamUri", "m", setup + "<op:ProfileToken>profile_1</op:ProfileToken>")
            self.assertEqual(status, 500)

    def test_snapshot_uri_is_actual_endpoint_and_host_header_is_ignored(self):
        status, _, body = request(self.server, soap("GetSnapshotUri", "m", "<op:ProfileToken>profile_1</op:ProfileToken>"),
                                  MEDIA_PATH, headers={"Host": "attacker.invalid:9999"})
        self.assertEqual(status, 200)
        self.assertEqual(ET.fromstring(body).findtext(".//t:Uri", namespaces=NS), self.server.snapshot_url)
        status, headers, body = request(self.server, path="/snapshot.jpg", method="GET")
        self.assertEqual((status, headers["Content-Type"], body), (200, "image/jpeg", JPEG))
        self.assertIn(f":{self.server.port}/", self.server.device_url)
        self.assertNotEqual(self.server.port, 0)

    def test_snapshot_failure_is_unavailable_and_masks_details(self):
        def failure():
            raise RuntimeError("secret-camera-password")
        self.server.snapshot_provider = failure
        status, _, body = request(self.server, path="/snapshot.jpg", method="GET")
        self.assertEqual(status, 503)
        self.assertNotIn(b"secret", body)
        self.server.snapshot_provider = lambda: b"not a JPEG"
        self.assertEqual(request(self.server, path="/snapshot.jpg", method="GET")[0], 503)
        self.server.snapshot_provider = None
        status, root = self.call("GetServiceCapabilities", "m")
        self.assertEqual(root.find(".//m:Capabilities", NS).get("SnapshotUri"), "false")
        self.assertEqual(self.call("GetSnapshotUri", "m", "<op:ProfileToken>profile_1</op:ProfileToken>")[0], 500)

    def test_unavailable_media_keeps_device_bootstrap_available(self):
        self.profile = None
        self.assertEqual(self.call("GetDeviceInformation")[0], 200)
        status, root = self.call("GetProfiles", "m")
        self.assertEqual(status, 500)
        self.assertEqual(root.findtext(".//s:Code/s:Value", namespaces=NS), "s:Receiver")
        self.assertIsNone(root.find(".//m:Profiles", NS))

    def test_unsupported_mutations_events_and_wrong_namespace_fault(self):
        for namespace, action in (("d", "SystemReboot"), ("d", "SetSystemDateAndTime"),
                                  ("m", "SetVideoEncoderConfiguration"), ("m", "CreateProfile"),
                                  ("m", "CreatePullPointSubscription"), ("m", "ContinuousMove")):
            with self.subTest(action=action):
                status, root = self.call(action, namespace)
                self.assertEqual(status, 500)
                self.assertIn("ter:ActionNotSupported", ET.tostring(root).decode())
        body = soap("GetDeviceInformation").replace(NS["d"].encode(), b"urn:wrong")
        self.assertEqual(request(self.server, body)[0], 500)
        self.assertEqual(request(self.server, soap("GetProfiles", "m"), DEVICE_PATH)[0], 500)

    def test_xml_entities_duplicate_operations_and_excess_depth_are_rejected(self):
        base = soap("GetDeviceInformation")
        invalid = [b"<!DOCTYPE x [<!ENTITY secret SYSTEM 'file:///etc/passwd'>]>" + base,
                   b"<!DOCTYPE x [<!ENTITY bomb 'huge'>]>" + base,
                   base.decode().encode("utf-16"),
                   base.replace(b"</soap:Body>", b"<op:GetDeviceInformation/></soap:Body>"),
                   soap("GetDeviceInformation", arguments="<x>" * 34 + "</x>" * 34),
                   b"not xml"]
        for body in invalid:
            self.assertEqual(request(self.server, body)[0], 500)
        self.assertEqual(request(self.server, b"x" * 65537)[0], 413)

    def test_duplicate_or_chunked_http_lengths_are_rejected(self):
        for header in ("Content-Length: 1\r\nContent-Length: 1", "Transfer-Encoding: chunked\r\nContent-Length: 1"):
            with socket.create_connection(("127.0.0.1", self.server.port), timeout=2) as connection:
                connection.sendall(f"POST {DEVICE_PATH} HTTP/1.1\r\nHost: localhost\r\n{header}\r\n\r\nx".encode())
                self.assertIn(b"400", connection.recv(1024).split(b"\r\n", 1)[0])

    def test_addressing_correlation_and_virtual_identity_are_stable(self):
        body = soap("GetDeviceInformation", header='<a:MessageID xmlns:a="http://www.w3.org/2005/08/addressing">urn:uuid:client-id</a:MessageID>')
        _, _, response = request(self.server, body)
        root = ET.fromstring(response)
        self.assertEqual(root.findtext(".//{http://www.w3.org/2005/08/addressing}RelatesTo"), "urn:uuid:client-id")
        self.assertEqual(root.findtext(".//d:SerialNumber", namespaces=NS), "virtual-03c7acb7")
        for action in ("GetHostname", "GetScopes", "GetNetworkInterfaces", "GetNetworkProtocols"):
            self.assertEqual(self.call(action)[0], 200)

    def test_network_interface_exposes_a_stable_hardware_address(self):
        # Home Assistant reads interface.Info.HwAddress before it falls back to
        # GetDeviceInformation.SerialNumber, so an empty Info aborts the flow
        # with an AttributeError that surfaces as a generic "no ONVIF service".
        status, root = self.call("GetNetworkInterfaces")
        self.assertEqual(status, 200)
        interface = root.find(".//d:NetworkInterfaces", NS)
        self.assertIsNotNone(interface)
        assert interface is not None
        self.assertEqual(interface.findtext("t:Enabled", namespaces=NS), "true")
        self.assertTrue(interface.findtext("t:Info/t:Name", namespaces=NS))
        first = interface.findtext("t:Info/t:HwAddress", namespaces=NS)
        self.assertIsNotNone(first)
        assert first is not None
        self.assertRegex(first, r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")
        octets = [int(part, 16) for part in first.split(":")]
        self.assertEqual(octets[0] & 0x01, 0, "HwAddress must be unicast")
        self.assertEqual(octets[0] & 0x02, 0x02, "HwAddress must be locally administered")
        self.assertEqual(self.call("GetNetworkInterfaces")[1].findtext(
            ".//d:NetworkInterfaces/t:Info/t:HwAddress", namespaces=NS), first)

    def test_network_interface_identity_uses_full_uuid_and_survives_restart(self):
        def address(device_uuid):
            with OnvifServer(replace(CONFIG, device_uuid=device_uuid),
                             lambda: PROFILE, lambda: JPEG) as server:
                status, _, body = request(server, soap("GetNetworkInterfaces"), DEVICE_PATH)
                self.assertEqual(status, 200)
                value = ET.fromstring(body).findtext(
                    ".//d:NetworkInterfaces/t:Info/t:HwAddress", namespaces=NS)
                self.assertRegex(value, r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")
                self.assertEqual(int(value[:2], 16) & 0x03, 0x02)
                return value

        first = address(CONFIG.device_uuid)
        # Same first six bytes, different tail: truncating UUID.bytes collides.
        second_uuid = "03c7acb7-6847-4bf7-9eeb-89346ee67250"
        second = address(second_uuid)
        self.assertNotEqual(first, second)
        self.assertEqual(address(CONFIG.device_uuid), first)
        self.assertEqual(address(second_uuid), second)
        self.assertEqual(address("urn:uuid:" + CONFIG.device_uuid.upper()), first)


class OnvifAuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.server = OnvifServer(replace(CONFIG, username="viewer", password="bridge-secret"),
                                   lambda: PROFILE, lambda: JPEG).start()
        self.addCleanup(self.server.close)

    def challenge(self):
        status, headers, _ = request(self.server, soap("GetDeviceInformation"))
        self.assertEqual(status, 401)
        return headers["WWW-Authenticate"]

    def test_public_time_and_protected_device_media_and_snapshot(self):
        self.assertEqual(request(self.server, soap("GetSystemDateAndTime"))[0], 200)
        for body, path, method in ((soap("GetDeviceInformation"), DEVICE_PATH, "POST"),
                                   (soap("GetProfiles", "m"), MEDIA_PATH, "POST"),
                                   (None, "/snapshot.jpg", "GET")):
            status, headers, _ = request(self.server, body, path, method=method)
            self.assertEqual(status, 401)
            self.assertIn("Digest", headers["WWW-Authenticate"])

    def test_http_digest_correct_wrong_password_and_replay(self):
        challenge = self.challenge()
        wrong = digest(challenge, password="camera-password-is-not-bridge-password")
        self.assertEqual(request(self.server, soap("GetDeviceInformation"), authorization=wrong)[0], 401)
        correct = digest(challenge)
        self.assertEqual(request(self.server, soap("GetDeviceInformation"), authorization=correct)[0], 200)
        self.assertEqual(request(self.server, soap("GetDeviceInformation"), authorization=correct)[0], 401)
        increased = digest(challenge, nc="00000002")
        self.assertEqual(request(self.server, soap("GetDeviceInformation"), authorization=increased)[0], 200)

    def test_http_digest_is_bound_to_method_path_and_server_nonce(self):
        challenge = self.challenge()
        for authorization in (digest(challenge, method="GET"), digest(challenge, path=MEDIA_PATH),
                              digest(challenge).replace('realm="Pixsee bridge"', 'realm="other"'),
                              digest(challenge) + ', username="viewer"'):
            self.assertEqual(request(self.server, soap("GetDeviceInformation"), authorization=authorization)[0], 401)
        other = OnvifServer(self.server.config, lambda: PROFILE)
        self.assertFalse(other.auth.http(digest(challenge), "POST", DEVICE_PATH))

    def test_digest_expired_nonce_and_zero_count_are_rejected(self):
        challenge = self.challenge()
        with patch("pixsee_onvif.time.time", return_value=time.time() + 301):
            self.assertFalse(self.server.auth.http(digest(challenge), "POST", DEVICE_PATH))
        self.assertEqual(request(self.server, soap("GetDeviceInformation"), authorization=digest(challenge, nc="00000000"))[0], 401)

    def test_snapshot_digest_authentication(self):
        status, headers, _ = request(self.server, path="/snapshot.jpg", method="GET")
        authorization = digest(headers["WWW-Authenticate"], method="GET", path="/snapshot.jpg")
        self.assertEqual(request(self.server, path="/snapshot.jpg", method="GET", authorization=authorization)[::2], (200, JPEG))

    def test_wsse_works_without_http_authorization_and_rejects_replay(self):
        body = soap("GetServices", arguments="<op:IncludeCapability>true</op:IncludeCapability>", header=wsse())
        self.assertEqual(request(self.server, body)[0], 200)
        self.assertEqual(request(self.server, body)[0], 401)

    def test_wsse_wrong_password_stale_future_and_bad_type_rejected(self):
        headers = [wsse(password="wrong"), wsse(offset=-301), wsse(offset=31),
                   wsse().replace("#PasswordDigest", "#PasswordText"),
                   wsse().replace("<Username>viewer</Username>", "<Username>other</Username>"),
                   wsse(created="not-a-date")]
        for header in headers:
            self.assertEqual(request(self.server, soap("GetDeviceInformation", header=header))[0], 401)

    def test_authentication_replay_store_is_bounded_without_weakening_replay(self):
        now = time.time()
        auth = self.server.auth
        for index in range(4096):
            self.assertTrue(auth._remember(("test", index), now + 100))
        self.assertFalse(auth._remember(("new", 0), now + 100))
        self.assertFalse(auth._remember(("test", 0), now + 100))
        self.assertEqual(len(auth.seen), 4096)


class OnvifLifecycleTests(unittest.TestCase):
    def test_invalid_lan_configuration_and_credentials_fail_before_listening(self):
        for changes in ({"bind_host": "0.0.0.0", "advertised_host": "192.0.2.10"},
                        {"username": "viewer"}, {"password": "secret"},
                        {"advertised_host": "0.0.0.0"}, {"advertised_host": "evil.example"},
                        {"bind_host": "0.0.0.0", "username": "a", "password": "b"},
                        {"device_uuid": "bad"}, {"snapshot_path": "/snapshot.jpg?bad"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(CONFIG, **changes)
        self.assertNotIn("bridge-secret", repr(replace(CONFIG, username="viewer", password="bridge-secret")))

    def test_invalid_profile_does_not_claim_unsupported_or_incomplete_media(self):
        for changes in ({"width": 0}, {"video_encoding": "H265"}, {"frame_rate": float("nan")},
                        {"audio_sample_rate": 44100}, {"audio_encoding": None}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(PROFILE, **changes)

    def test_close_releases_listener_and_start_is_idempotent(self):
        server = OnvifServer(CONFIG, lambda: PROFILE).start()
        try:
            self.assertIs(server.start(), server)
            port = server.port
        finally:
            server.close()
            server.close()
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=0.3)

    def test_concurrent_clients_are_bounded_and_idle_connections_time_out(self):
        with OnvifServer(replace(CONFIG, max_clients=1, socket_timeout=0.2), lambda: PROFILE) as server:
            first = socket.create_connection(("127.0.0.1", server.port), timeout=2)
            self.addCleanup(first.close)
            first.sendall(b"POST /onvif/device_service HTTP/1.1\r\n")
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline:
                with server._http.clients_lock:
                    if server._http.clients:
                        break
                time.sleep(0.005)
            second = socket.create_connection(("127.0.0.1", server.port), timeout=2)
            self.addCleanup(second.close)
            self.assertIn(b"503", second.recv(1024))
            self.assertEqual(first.recv(1024), b"")
            self.assertEqual(request(server, soap("GetSystemDateAndTime"))[0], 200)

    def test_close_interrupts_idle_connections(self):
        server = OnvifServer(CONFIG, lambda: PROFILE).start()
        client = socket.create_connection(("127.0.0.1", server.port), timeout=2)
        self.addCleanup(client.close)
        client.sendall(b"POST /onvif/device_service HTTP/1.1\r\n")
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline:
            with server._http.clients_lock:
                if server._http.clients:
                    break
            time.sleep(0.005)
        started = time.monotonic()
        server.close()
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(client.recv(1024), b"")

    def test_continuously_dripped_headers_and_body_have_absolute_deadline(self):
        prefixes = (
            b"POST /onvif/device_service HTTP/1.1\r\nX-Slow: ",
            b"POST /onvif/device_service HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1000\r\n\r\n",
        )
        for prefix in prefixes:
            with self.subTest(body=prefix.endswith(b"\r\n\r\n")), OnvifServer(
                    replace(CONFIG, max_clients=1, socket_timeout=0.25), lambda: PROFILE) as server:
                client = socket.create_connection(("127.0.0.1", server.port), timeout=1)
                stopped = threading.Event()

                def drip():
                    try:
                        while not stopped.wait(0.04):
                            client.sendall(b" ")
                    except OSError:
                        pass

                sender = threading.Thread(target=drip, daemon=True)
                started = time.monotonic()
                try:
                    client.sendall(prefix)
                    sender.start()
                    try:
                        self.assertEqual(client.recv(1024), b"")
                    except ConnectionResetError:
                        # Closing with unread dripped input may produce RST on
                        # macOS instead of EOF. Both mean the peer was closed;
                        # socket.timeout and other errors must still fail.
                        pass
                    self.assertLess(time.monotonic() - started, 0.8)
                finally:
                    stopped.set()
                    client.close()
                    sender.join(timeout=1)
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline:
                    with server._http.clients_lock:
                        if not server._http.clients:
                            break
                    time.sleep(0.005)
                self.assertEqual(request(server, soap("GetSystemDateAndTime"))[0], 200)

    def test_completed_snapshot_request_outlives_header_deadline(self):
        def snapshot():
            time.sleep(0.25)
            return JPEG

        with OnvifServer(replace(CONFIG, socket_timeout=0.1), lambda: PROFILE, snapshot) as server:
            self.assertEqual(request(server, path="/snapshot.jpg", method="GET")[0], 200)


if __name__ == "__main__":
    unittest.main()
