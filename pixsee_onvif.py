"""Read-only ONVIF Device/Media1 adapter for the local protocol gateway.

This deliberately implements an interoperability subset, not an ONVIF profile.
The gateway owns stream probing and the bounded, cached JPEG provider.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import math
import re
import secrets
import socket
from socketserver import TCPServer
import threading
import time
from typing import Callable
from urllib.parse import quote
import uuid
import xml.etree.ElementTree as ET


SOAP = "http://www.w3.org/2003/05/soap-envelope"
DEVICE = "http://www.onvif.org/ver10/device/wsdl"
MEDIA = "http://www.onvif.org/ver10/media/wsdl"
SCHEMA = "http://www.onvif.org/ver10/schema"
ERROR = "http://www.onvif.org/ver10/error"
WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
PASSWORD_DIGEST = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
NONCE_BASE64 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
ADDRESSING = "http://www.w3.org/2005/08/addressing"
PROFILE = "profile_1"
VIDEO_SOURCE = "video_source_1"
VIDEO_SOURCE_CONFIG = "video_source_config_1"
VIDEO_ENCODER = "video_encoder_1"
AUDIO_SOURCE = "audio_source_1"
AUDIO_SOURCE_CONFIG = "audio_source_config_1"
AUDIO_ENCODER = "audio_encoder_1"

for _prefix, _namespace in (("s", SOAP), ("tds", DEVICE), ("trt", MEDIA),
                             ("tt", SCHEMA), ("ter", ERROR), ("wsa", ADDRESSING)):
    ET.register_namespace(_prefix, _namespace)


@dataclass(frozen=True)
class MediaProfile:
    width: int
    height: int
    frame_rate: float | None = None
    video_encoding: str = "H264"
    video_bitrate: int | None = None  # kb/s; None means unknown, never guessed
    gop: int | None = None
    h264_profile: str | None = None
    audio_encoding: str | None = None
    audio_sample_rate: int | None = None  # Hz; Media1 exposes integer kHz
    audio_channels: int | None = None
    audio_bitrate: int | None = None  # kb/s

    def __post_init__(self):
        if self.width <= 0 or self.height <= 0 or self.video_encoding != "H264":
            raise ValueError("Media1 requires positive dimensions and H264 video")
        for value in (self.frame_rate, self.video_bitrate, self.gop):
            if value is not None and (not math.isfinite(value) or value <= 0):
                raise ValueError("known media rates must be positive")
        if self.h264_profile not in (None, "Baseline", "Main", "Extended", "High"):
            raise ValueError("unsupported H264 profile")
        audio = (self.audio_sample_rate, self.audio_channels, self.audio_bitrate)
        if self.audio_encoding is None:
            if any(value is not None for value in audio):
                raise ValueError("audio metadata requires an audio encoding")
        elif (self.audio_encoding not in ("AAC", "G711", "G726")
              or any(value is None or value <= 0 for value in audio)
              or self.audio_sample_rate % 1000):
            raise ValueError("audio requires encoding, integer kHz rate, channels and bitrate")


@dataclass(frozen=True)
class OnvifConfig:
    device_uuid: str
    serial_number: str
    bind_host: str = "127.0.0.1"
    port: int = 8000
    advertised_host: str = "127.0.0.1"
    rtsp_port: int = 8554
    rtsp_path: str = "pixsee"
    username: str | None = None
    password: str | None = field(default=None, repr=False)
    name: str = "Pixsee bridge"
    manufacturer: str = "Pixsee interoperability project"
    model: str = "Pixsee protocol bridge"
    firmware_version: str = "0.1.0"
    discoverable: bool = False
    supports_rtsp_udp: bool = True
    snapshot_path: str = "/snapshot.jpg"
    max_body_bytes: int = 65536
    max_clients: int = 8
    socket_timeout: float = 5.0
    auth_ttl: int = 300

    def __post_init__(self):
        uuid.UUID(self.device_uuid.removeprefix("urn:uuid:"))
        bind = ipaddress.IPv4Address(self.bind_host)
        advertised = ipaddress.IPv4Address(self.advertised_host)
        if advertised.is_unspecified or advertised.is_multicast:
            raise ValueError("advertised_host must be a reachable unicast IPv4 address")
        if not 0 <= self.port <= 65535 or not 1 <= self.rtsp_port <= 65535:
            raise ValueError("invalid service port")
        if bool(self.username) != bool(self.password):
            raise ValueError("both bridge username and password are required")
        if not bind.is_loopback and not self.username:
            raise ValueError("bridge credentials are required for a non-loopback listener")
        if not bind.is_loopback and advertised.is_loopback:
            raise ValueError("a LAN listener requires an explicit LAN advertised address")
        if not self.rtsp_path or any(c in self.rtsp_path for c in "?#\r\n"):
            raise ValueError("invalid RTSP path")
        if (not self.snapshot_path.startswith("/") or "?" in self.snapshot_path
                or "#" in self.snapshot_path or any(c.isspace() for c in self.snapshot_path)
                or self.snapshot_path.startswith("/onvif/")):
            raise ValueError("invalid snapshot path")
        if not self.serial_number or any(ord(c) < 32 for c in self.serial_number):
            raise ValueError("a virtual bridge serial number is required")
        if not (1024 <= self.max_body_bytes <= 1024 * 1024 and 1 <= self.max_clients <= 64
                and 0 < self.socket_timeout <= 60 and 1 <= self.auth_ttl <= 3600):
            raise ValueError("invalid ONVIF resource limits")


class _Fault(Exception):
    def __init__(self, reason="Action not supported", code="ActionNotSupported",
                 detail="", receiver=False):
        self.reason, self.code, self.detail, self.receiver = reason, code, detail, receiver


def _add(parent, namespace, name, text=None, **attributes):
    element = ET.SubElement(parent, f"{{{namespace}}}{name}",
                            {key: str(value) for key, value in attributes.items()})
    if text is not None:
        element.text = str(text)
    return element


def _tt(parent, name, text=None, **attributes):
    return _add(parent, SCHEMA, name, text, **attributes)


def _text(parent, namespace, name, default=None):
    found = parent.findall(f"{{{namespace}}}{name}")
    if len(found) > 1:
        raise _Fault("Duplicate request parameter", "InvalidArgVal")
    return found[0].text if found else default


def _range(parent, name, value):
    result = _tt(parent, name)
    _tt(result, "Min", value)
    _tt(result, "Max", value)


def _envelope(payload, request=None):
    envelope = ET.Element(f"{{{SOAP}}}Envelope")
    if request is not None:
        message_id = request.findtext(f"{{{SOAP}}}Header/{{{ADDRESSING}}}MessageID")
        if message_id:
            header = _add(envelope, SOAP, "Header")
            _add(header, ADDRESSING, "RelatesTo", message_id)
    _add(envelope, SOAP, "Body").append(payload)
    return ET.tostring(envelope, encoding="utf-8", xml_declaration=True)


def _fault_bytes(fault, request=None):
    result = ET.Element(f"{{{SOAP}}}Fault", {"xmlns:ter": ERROR})
    code = _add(result, SOAP, "Code")
    _add(code, SOAP, "Value", "s:Receiver" if fault.receiver else "s:Sender")
    subcode = _add(code, SOAP, "Subcode")
    _add(subcode, SOAP, "Value", f"ter:{fault.code}")
    if fault.detail:
        _add(_add(subcode, SOAP, "Subcode"), SOAP, "Value", f"ter:{fault.detail}")
    reason = _add(result, SOAP, "Reason")
    text = _add(reason, SOAP, "Text", fault.reason)
    text.set("{http://www.w3.org/XML/1998/namespace}lang", "en")
    return _envelope(result, request)


def _parse_soap(data):
    # UTF-8 only prevents UTF-16/NUL encodings from bypassing declaration checks.
    if b"\x00" in data or re.search(br"<!\s*(?:DOCTYPE|ENTITY)\b", data, re.I):
        raise _Fault("XML declarations are not supported", "InvalidArgVal")
    try:
        root = ET.fromstring(data.decode("utf-8-sig"))
    except (UnicodeError, ET.ParseError, ValueError):
        raise _Fault("Malformed SOAP request", "InvalidArgVal") from None
    if root.tag != f"{{{SOAP}}}Envelope":
        raise _Fault("SOAP 1.2 is required", "InvalidArgVal")
    pending = [(root, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if depth > 32 or count > 2048:
            raise _Fault("SOAP structure exceeds limits", "InvalidArgVal")
        pending.extend((child, depth + 1) for child in node)
    bodies = root.findall(f"{{{SOAP}}}Body")
    if len(bodies) != 1 or len(bodies[0]) != 1:
        raise _Fault("One SOAP operation is required", "InvalidArgVal")
    if len(root.findall(f"{{{SOAP}}}Header")) > 1:
        raise _Fault("One SOAP header is permitted", "InvalidArgVal")
    return root, bodies[0][0]


class _Authentication:
    """Bounded freshness/replay protection for HTTP Digest and WSSE digests."""

    realm = "Pixsee bridge"

    def __init__(self, config):
        self.config = config
        self.secret = secrets.token_bytes(32)
        self.lock = threading.Lock()
        self.seen = {}

    def challenge(self):
        payload = f"{int(time.time())}:{secrets.token_hex(16)}"
        signature = hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()
        nonce = base64.b64encode(f"{payload}:{signature}".encode()).decode()
        return f'Digest realm="{self.realm}", nonce="{nonce}", algorithm=MD5, qop="auth"'

    def _remember(self, key, expiry, counter=1):
        now = time.time()
        with self.lock:
            self.seen = {k: v for k, v in self.seen.items() if v[0] > now}
            previous = self.seen.get(key)
            if previous and counter <= previous[1]:
                return False
            if previous is None and len(self.seen) >= 4096:
                return False  # Do not evict still-valid replay evidence.
            self.seen[key] = (expiry, counter)
            return True

    def http(self, header, method, uri):
        if not header or not header.startswith("Digest ") or len(header) > 8192:
            return False
        try:
            fields = {}
            remainder = header[7:]
            pattern = r'\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^,\s]+))\s*(?:,|$)'
            while remainder:
                match = re.match(pattern, remainder)
                if not match or match[1] in fields:
                    return False
                fields[match[1]] = re.sub(r"\\(.)", r"\1", match[2]) if match[2] is not None else match[3]
                remainder = remainder[match.end():]
            if (fields.get("username") != self.config.username or fields.get("realm") != self.realm
                    or fields.get("uri") != uri or fields.get("qop") != "auth"
                    or fields.get("algorithm", "MD5").upper() != "MD5"
                    or not re.fullmatch(r"[0-9a-fA-F]{8}", fields.get("nc", ""))
                    or fields.get("nc") == "00000000"
                    or not 1 <= len(fields.get("cnonce", "")) <= 256):
                return False
            nonce = fields["nonce"]
            decoded = base64.b64decode(nonce, validate=True).decode("ascii")
            timestamp, random, signature = decoded.split(":")
            payload = f"{timestamp}:{random}"
            expected = hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()
            age = time.time() - int(timestamp)
            if not hmac.compare_digest(signature, expected) or not 0 <= age < self.config.auth_ttl:
                return False
            md5 = lambda text: hashlib.md5(text.encode("utf-8")).hexdigest()
            a1 = md5(f"{self.config.username}:{self.realm}:{self.config.password}")
            a2 = md5(f"{method}:{uri}")
            response = md5(f'{a1}:{nonce}:{fields["nc"]}:{fields["cnonce"]}:auth:{a2}')
            if not hmac.compare_digest(fields.get("response", ""), response):
                return False
            return self._remember(("http", nonce, fields["cnonce"]),
                                  int(timestamp) + self.config.auth_ttl, int(fields["nc"], 16))
        except (ValueError, KeyError, UnicodeError, TypeError):
            return False

    def wsse(self, root):
        try:
            tokens = root.findall(f"{{{SOAP}}}Header/{{{WSSE}}}Security/{{{WSSE}}}UsernameToken")
            if len(tokens) != 1:
                return False
            token = tokens[0]
            username = _text(token, WSSE, "Username")
            password = token.findall(f"{{{WSSE}}}Password")
            nonce = token.findall(f"{{{WSSE}}}Nonce")
            created = _text(token, WSU, "Created")
            if (username != self.config.username or len(password) != 1 or len(nonce) != 1
                    or password[0].get("Type") != PASSWORD_DIGEST
                    or nonce[0].get("EncodingType", NONCE_BASE64) != NONCE_BASE64
                    or not created):
                return False
            when = datetime.fromisoformat(created.replace("Z", "+00:00"))
            if when.tzinfo is None:
                return False
            timestamp = when.timestamp()
            if not -30 <= time.time() - timestamp <= self.config.auth_ttl:
                return False
            nonce_bytes = base64.b64decode(nonce[0].text or "", validate=True)
            if not 8 <= len(nonce_bytes) <= 128:
                return False
            digest = base64.b64encode(hashlib.sha1(nonce_bytes + created.encode("utf-8")
                                                 + self.config.password.encode("utf-8")).digest()).decode()
            if not hmac.compare_digest(password[0].text or "", digest):
                return False
            # One nonce may be used only once during its whole validity window.
            return self._remember(("wsse", nonce_bytes), timestamp + self.config.auth_ttl + 1)
        except (ValueError, UnicodeError, TypeError, _Fault):
            return False


class _BoundedHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, address, handler, config):
        self.slots = threading.BoundedSemaphore(config.max_clients)
        self.config = config
        self.clients = set()
        self.clients_lock = threading.Lock()
        super().__init__(address, handler)

    def server_bind(self):
        # HTTPServer.server_bind performs an unbounded reverse DNS lookup.
        # Our validated numeric listener address is already the server name.
        TCPServer.server_bind(self)
        self.server_name = self.config.bind_host
        self.server_port = self.server_address[1]

    def get_request(self):
        client, address = super().get_request()
        client.settimeout(self.config.socket_timeout)
        return client, address

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            finally:
                self.shutdown_request(request)
            return
        with self.clients_lock:
            self.clients.add(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self.clients_lock:
                self.clients.discard(request)
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.clients_lock:
                self.clients.discard(request)
            self.slots.release()

    def handle_error(self, request, client_address):
        pass  # Never log request bodies, credentials, or callback exceptions.

    def close_clients(self):
        with self.clients_lock:
            clients = list(self.clients)
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            client.close()


class OnvifServer:
    def __init__(self, config: OnvifConfig,
                 profile_provider: Callable[[], MediaProfile | None],
                 snapshot_provider: Callable[[], bytes] | None = None):
        self.config = config
        self.profile_provider = profile_provider
        self.snapshot_provider = snapshot_provider
        self.auth = _Authentication(config)
        self._http = None
        self._thread = None

    @property
    def port(self):
        return self._http.server_port if self._http else self.config.port

    @property
    def device_url(self):
        return f"http://{self.config.advertised_host}:{self.port}/onvif/device_service"

    @property
    def media_url(self):
        return f"http://{self.config.advertised_host}:{self.port}/onvif/media_service"

    @property
    def snapshot_url(self):
        return f"http://{self.config.advertised_host}:{self.port}{self.config.snapshot_path}"

    @property
    def rtsp_url(self):
        path = quote(self.config.rtsp_path.strip("/"), safe="/-._~")
        return f"rtsp://{self.config.advertised_host}:{self.config.rtsp_port}/{path}"

    @property
    def scopes(self):
        return ("onvif://www.onvif.org/type/video_encoder",
                "onvif://www.onvif.org/name/" + quote(self.config.name, safe=""),
                "onvif://www.onvif.org/hardware/" + quote(self.config.model, safe=""))

    def start(self):
        if self._http:
            return self
        owner = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "PixseeBridge"
            sys_version = ""
            protocol_version = "HTTP/1.1"

            def setup(self):
                super().setup()
                self._input_lock = threading.Lock()
                self._input_complete = False
                self._input_expired = False
                # Socket timeouts bound inactivity only. A fixed deadline also
                # releases the slot when a peer continuously drips headers/body.
                self._input_timer = threading.Timer(owner.config.socket_timeout,
                                                    self._expire_input)
                self._input_timer.daemon = True
                self._input_timer.start()

            def _expire_input(self):
                with self._input_lock:
                    if self._input_complete:
                        return
                    self._input_expired = True
                    try:
                        self.connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

            def _complete_input(self):
                with self._input_lock:
                    if self._input_expired:
                        self.close_connection = True
                        return False
                    self._input_complete = True
                    self._input_timer.cancel()
                    return True

            def finish(self):
                self._complete_input()
                super().finish()

            def log_message(self, format, *args):
                pass

            def reply(self, status, body=b"", content_type="application/soap+xml; charset=utf-8", challenge=False):
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.send_header("Cache-Control", "no-store")
                if challenge:
                    self.send_header("WWW-Authenticate", owner.auth.challenge())
                self.end_headers()
                self.close_connection = True
                self.wfile.write(body)

            def do_GET(self):
                # The snapshot callback has its own bounded execution time;
                # the header deadline must not abort a complete valid request.
                if not self._complete_input():
                    return
                if self.path != owner.config.snapshot_path or owner.snapshot_provider is None:
                    self.reply(404, b"Not found", "text/plain")
                    return
                if owner.config.username and not owner.auth.http(self.headers.get("Authorization"), "GET", self.path):
                    self.reply(401, b"Authentication required", "text/plain", challenge=True)
                    return
                try:
                    jpeg = owner.snapshot_provider()
                    if (not isinstance(jpeg, bytes) or not jpeg.startswith(b"\xff\xd8")
                            or not jpeg.endswith(b"\xff\xd9") or len(jpeg) > 8 * 1024 * 1024):
                        raise ValueError("invalid snapshot")
                except Exception:
                    self.reply(503, b"Snapshot unavailable", "text/plain")
                    return
                self.reply(200, jpeg, "image/jpeg")

            def do_POST(self):
                if self.path not in ("/onvif/device_service", "/onvif/media_service"):
                    self.reply(404, b"Not found", "text/plain")
                    return
                lengths = self.headers.get_all("Content-Length", [])
                if self.headers.get("Transfer-Encoding") or len(lengths) != 1:
                    self.reply(400, b"Content-Length required", "text/plain")
                    return
                try:
                    length = int(lengths[0])
                except ValueError:
                    self.reply(400, b"Invalid length", "text/plain")
                    return
                if not 0 < length <= owner.config.max_body_bytes:
                    self.reply(413, b"Request exceeds limit", "text/plain")
                    return
                root = None
                try:
                    data = self.rfile.read(length)
                    if not self._complete_input():
                        return
                    if len(data) != length:
                        raise _Fault("Incomplete request", "InvalidArgVal")
                    root, operation = _parse_soap(data)
                    public = operation.tag == f"{{{DEVICE}}}GetSystemDateAndTime"
                    if (owner.config.username and not public
                            and not owner.auth.http(self.headers.get("Authorization"), "POST", self.path)
                            and not owner.auth.wsse(root)):
                        self.reply(401, _fault_bytes(_Fault("Not authorized", "NotAuthorized")), challenge=True)
                        return
                    expected = DEVICE if self.path.endswith("device_service") else MEDIA
                    if not operation.tag.startswith(f"{{{expected}}}"):
                        raise _Fault()
                    result = owner._dispatch(operation)
                    self.reply(200, _envelope(result, root))
                except _Fault as fault:
                    self.reply(500, _fault_bytes(fault, root))
                except (TimeoutError, OSError):
                    self.close_connection = True
                except Exception:
                    self.reply(500, _fault_bytes(_Fault("Service unavailable", "Action", receiver=True), root))

        self._http = _BoundedHTTPServer((self.config.bind_host, self.config.port), Handler, self.config)
        self._thread = threading.Thread(target=self._http.serve_forever,
                                        kwargs={"poll_interval": 0.05}, name="pixsee-onvif", daemon=True)
        self._thread.start()
        return self

    def close(self):
        if self._http:
            self._http.shutdown()
            self._http.close_clients()
            self._http.server_close()
            self._thread.join(timeout=2)
            self._http = None
            self._thread = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *args):
        self.close()

    def _hardware_address(self):
        """Return a stable locally administered unicast MAC for this bridge."""
        device_id = uuid.UUID(self.config.device_uuid.removeprefix("urn:uuid:"))
        # Include every UUID byte, not just a prefix that configured UUIDs may
        # share. This is a 46-bit virtual identity, not a collision-free physical
        # MAC allocation; local/unicast flags do not guarantee uniqueness.
        raw = bytearray(hashlib.sha256(device_id.bytes).digest()[:6])
        raw[0] = (raw[0] | 0x02) & 0xFE
        return ":".join(f"{byte:02X}" for byte in raw)

    def _service_capabilities(self, namespace):
        result = ET.Element(f"{{{namespace}}}Capabilities")
        if namespace == MEDIA:
            result.set("SnapshotUri", str(self.snapshot_provider is not None).lower())
            result.set("Rotation", "false")
            result.set("VideoSourceMode", "false")
            result.set("OSD", "false")
            _add(result, MEDIA, "ProfileCapabilities", MaximumNumberOfProfiles="1")
            _add(result, MEDIA, "StreamingCapabilities", RTPMulticast="false",
                 RTP_TCP="false", RTP_RTSP_TCP="true", NonAggregateControl="false")
        else:
            _add(result, DEVICE, "Network", IPFilter="false", ZeroConfiguration="false",
                 IPVersion6="false", DynDNS="false", HostnameFromDHCP="false")
            _add(result, DEVICE, "Security", **{"TLS1.0": "false", "TLS1.1": "false",
                 "TLS1.2": "false", "UsernameToken": "true", "HttpDigest": "true",
                 "OnboardKeyGeneration": "false", "AccessPolicyConfig": "false"})
            _add(result, DEVICE, "System", DiscoveryResolve=str(self.config.discoverable).lower(),
                 DiscoveryBye=str(self.config.discoverable).lower(), RemoteDiscovery="false",
                 SystemBackup="false", SystemLogging="false", FirmwareUpgrade="false")
        return result

    def _dispatch(self, operation):
        namespace, action = operation.tag[1:].split("}", 1)
        result = ET.Element(f"{{{namespace}}}{action}Response")
        if action == "GetServiceCapabilities" and namespace in (DEVICE, MEDIA):
            result.append(self._service_capabilities(namespace))
        elif namespace == DEVICE:
            self._device(operation, action, result)
        elif namespace == MEDIA:
            self._media(operation, action, result)
        else:
            raise _Fault()
        return result

    def _device(self, request, action, result):
        if action == "GetSystemDateAndTime":
            now = datetime.now(timezone.utc)
            system = _add(result, DEVICE, "SystemDateAndTime")
            _tt(system, "DateTimeType", "Manual")
            _tt(system, "DaylightSavings", "false")
            _tt(_tt(system, "TimeZone"), "TZ", "UTC0")
            utc = _tt(system, "UTCDateTime")
            clock, date = _tt(utc, "Time"), _tt(utc, "Date")
            for key, value in (("Hour", now.hour), ("Minute", now.minute), ("Second", now.second)):
                _tt(clock, key, value)
            for key, value in (("Year", now.year), ("Month", now.month), ("Day", now.day)):
                _tt(date, key, value)
        elif action == "GetServices":
            include = _text(request, DEVICE, "IncludeCapability", "false")
            if include not in ("false", "true", "0", "1"):
                raise _Fault("Invalid IncludeCapability", "InvalidArgVal")
            for namespace, address in ((DEVICE, self.device_url), (MEDIA, self.media_url)):
                service = _add(result, DEVICE, "Service")
                _add(service, DEVICE, "Namespace", namespace)
                _add(service, DEVICE, "XAddr", address)
                if include in ("true", "1"):
                    _add(service, DEVICE, "Capabilities").append(self._service_capabilities(namespace))
                version = _add(service, DEVICE, "Version")
                _tt(version, "Major", 2)
                _tt(version, "Minor", 0)
        elif action == "GetDeviceInformation":
            for key, value in (("Manufacturer", self.config.manufacturer), ("Model", self.config.model),
                               ("FirmwareVersion", self.config.firmware_version),
                               ("SerialNumber", self.config.serial_number), ("HardwareId", "software-bridge")):
                _add(result, DEVICE, key, value)
        elif action == "GetCapabilities":
            categories = [node.text for node in request.findall(f"{{{DEVICE}}}Category")] or ["All"]
            if any(value not in ("All", "Device", "Media") for value in categories):
                raise _Fault("Requested service is unavailable", "ActionNotSupported", "NoSuchService")
            caps = _add(result, DEVICE, "Capabilities")
            if "All" in categories or "Device" in categories:
                device = _tt(caps, "Device")
                _tt(device, "XAddr", self.device_url)
                network = _tt(device, "Network")
                for name in ("IPFilter", "ZeroConfiguration", "IPVersion6", "DynDNS"):
                    _tt(network, name, "false")
                system = _tt(device, "System")
                for name in ("DiscoveryResolve", "DiscoveryBye", "RemoteDiscovery", "SystemBackup", "SystemLogging", "FirmwareUpgrade"):
                    _tt(system, name, str(self.config.discoverable and name in ("DiscoveryResolve", "DiscoveryBye")).lower())
                version = _tt(system, "SupportedVersions")
                _tt(version, "Major", 2)
                _tt(version, "Minor", 0)
                security = _tt(device, "Security")
                for name in ("TLS1.1", "TLS1.2", "OnboardKeyGeneration", "AccessPolicyConfig", "X.509Token", "SAMLToken", "KerberosToken", "RELToken"):
                    _tt(security, name, "false")
            if "All" in categories or "Media" in categories:
                media = _tt(caps, "Media")
                _tt(media, "XAddr", self.media_url)
                stream = _tt(media, "StreamingCapabilities")
                for name, value in (("RTPMulticast", "false"), ("RTP_TCP", "false"), ("RTP_RTSP_TCP", "true")):
                    _tt(stream, name, value)
        elif action == "GetScopes":
            for scope in self.scopes:
                item = _add(result, DEVICE, "Scopes")
                _tt(item, "ScopeDef", "Fixed")
                _tt(item, "ScopeItem", scope)
        elif action == "GetDiscoveryMode":
            _add(result, DEVICE, "DiscoveryMode", "Discoverable" if self.config.discoverable else "NonDiscoverable")
        elif action == "GetHostname":
            hostname = _add(result, DEVICE, "HostnameInformation")
            _tt(hostname, "FromDHCP", "false")
            _tt(hostname, "Name", "pixsee-bridge-" + uuid.UUID(self.config.device_uuid.removeprefix("urn:uuid:")).hex[:8])
        elif action == "GetNetworkInterfaces":
            interface = _add(result, DEVICE, "NetworkInterfaces", token="bridge")
            _tt(interface, "Enabled", "true")
            info = _tt(interface, "Info")
            _tt(info, "Name", "pixsee-bridge")
            # ONVIF clients read Info.HwAddress as the device's stable identity;
            # Home Assistant dereferences it before falling back to the serial
            # number, so an empty Info makes the integration reject the bridge.
            _tt(info, "HwAddress", self._hardware_address())
            _tt(info, "MTU", 1500)
            ipv4 = _tt(interface, "IPv4")
            _tt(ipv4, "Enabled", "true")
            config = _tt(ipv4, "Config")
            manual = _tt(config, "Manual")
            _tt(manual, "Address", self.config.advertised_host)
            _tt(manual, "PrefixLength", 32)  # virtual endpoint, not a claim about host LAN netmask
            _tt(config, "DHCP", "false")
        elif action == "GetNetworkProtocols":
            for name, port in (("HTTP", self.port), ("RTSP", self.config.rtsp_port)):
                protocol = _add(result, DEVICE, "NetworkProtocols")
                _tt(protocol, "Name", name)
                _tt(protocol, "Enabled", "true")
                _tt(protocol, "Port", port)
        else:
            raise _Fault()

    def _profile(self):
        try:
            profile = self.profile_provider()
        except Exception:
            profile = None
        if not isinstance(profile, MediaProfile):
            raise _Fault("Media is not ready", "Action", receiver=True)
        return profile

    def _token(self, request, name, expected, optional=False):
        value = _text(request, MEDIA, name)
        if value is None and optional:
            return
        if value != expected:
            detail = "NoProfile" if name == "ProfileToken" else "NoConfig"
            raise _Fault("Unknown media token", "InvalidArgVal", detail)

    def _configuration(self, parent, name, token):
        result = _tt(parent, name, token=token)
        _tt(result, "Name", name)
        _tt(result, "UseCount", 1)
        return result

    def _video_source_config(self, parent, profile):
        result = self._configuration(parent, "VideoSourceConfiguration", VIDEO_SOURCE_CONFIG)
        _tt(result, "SourceToken", VIDEO_SOURCE)
        _tt(result, "Bounds", x=0, y=0, width=profile.width, height=profile.height)
        return result

    def _multicast(self, parent):
        multicast = _tt(parent, "Multicast")
        address = _tt(multicast, "Address")
        _tt(address, "Type", "IPv4")
        _tt(address, "IPv4Address", "0.0.0.0")
        _tt(multicast, "Port", 0)
        _tt(multicast, "TTL", 0)
        _tt(multicast, "AutoStart", "false")
        _tt(parent, "SessionTimeout", "PT60S")

    def _video_encoder_config(self, parent, profile):
        result = self._configuration(parent, "VideoEncoderConfiguration", VIDEO_ENCODER)
        _tt(result, "Encoding", profile.video_encoding)
        resolution = _tt(result, "Resolution")
        _tt(resolution, "Width", profile.width)
        _tt(resolution, "Height", profile.height)
        _tt(result, "Quality", 0)  # required schema field; no adjustable encoder quality
        if profile.frame_rate and profile.video_bitrate and float(profile.frame_rate).is_integer():
            rate = _tt(result, "RateControl")
            _tt(rate, "FrameRateLimit", int(profile.frame_rate))
            _tt(rate, "EncodingInterval", 1)
            _tt(rate, "BitrateLimit", profile.video_bitrate)
        if profile.gop and profile.h264_profile:
            h264 = _tt(result, "H264")
            _tt(h264, "GovLength", profile.gop)
            _tt(h264, "H264Profile", profile.h264_profile)
        self._multicast(result)
        return result

    def _audio_source_config(self, parent, profile):
        result = self._configuration(parent, "AudioSourceConfiguration", AUDIO_SOURCE_CONFIG)
        _tt(result, "SourceToken", AUDIO_SOURCE)
        return result

    def _audio_encoder_config(self, parent, profile):
        result = self._configuration(parent, "AudioEncoderConfiguration", AUDIO_ENCODER)
        _tt(result, "Encoding", profile.audio_encoding)
        _tt(result, "Bitrate", profile.audio_bitrate)
        _tt(result, "SampleRate", profile.audio_sample_rate // 1000)
        self._multicast(result)
        return result

    def _media(self, request, action, result):
        supported = {"GetProfiles", "GetProfile", "GetStreamUri", "GetSnapshotUri", "GetVideoSources", "GetAudioSources"}
        kinds = {"VideoSource": (VIDEO_SOURCE_CONFIG, self._video_source_config),
                 "VideoEncoder": (VIDEO_ENCODER, self._video_encoder_config),
                 "AudioSource": (AUDIO_SOURCE_CONFIG, self._audio_source_config),
                 "AudioEncoder": (AUDIO_ENCODER, self._audio_encoder_config)}
        for kind in kinds:
            supported.update((f"Get{kind}Configuration", f"Get{kind}Configurations",
                              f"Get{kind}ConfigurationOptions", f"GetCompatible{kind}Configurations"))
        if action not in supported:
            raise _Fault()
        profile = self._profile()
        if action in ("GetProfile", "GetStreamUri", "GetSnapshotUri"):
            self._token(request, "ProfileToken", PROFILE)
        if action in ("GetProfiles", "GetProfile"):
            item = _add(result, MEDIA, "Profiles" if action == "GetProfiles" else "Profile", token=PROFILE, fixed="true")
            _tt(item, "Name", self.config.name)
            self._video_source_config(item, profile)
            if profile.audio_encoding:
                self._audio_source_config(item, profile)
            self._video_encoder_config(item, profile)
            if profile.audio_encoding:
                self._audio_encoder_config(item, profile)
        elif action in ("GetStreamUri", "GetSnapshotUri"):
            if action == "GetStreamUri":
                setup = request.find(f"{{{MEDIA}}}StreamSetup")
                if setup is None:
                    raise _Fault("StreamSetup is required", "InvalidArgVal")
                stream = _text(setup, SCHEMA, "Stream")
                transport = setup.find(f"{{{SCHEMA}}}Transport")
                protocol = _text(transport, SCHEMA, "Protocol") if transport is not None else None
                allowed = ("RTSP", "UDP") if self.config.supports_rtsp_udp else ("RTSP",)
                if stream != "RTP-Unicast" or protocol not in allowed or transport.find(f"{{{SCHEMA}}}Tunnel") is not None:
                    raise _Fault("Unsupported stream transport", "InvalidArgVal", "InvalidStreamSetup")
                uri = self.rtsp_url
            else:
                if self.snapshot_provider is None:
                    raise _Fault()
                uri = self.snapshot_url
            media_uri = _add(result, MEDIA, "MediaUri")
            _tt(media_uri, "Uri", uri)
            _tt(media_uri, "InvalidAfterConnect", "false")
            _tt(media_uri, "InvalidAfterReboot", "false")
            _tt(media_uri, "Timeout", "PT0S")
        elif action == "GetVideoSources":
            if profile.frame_rate is None:
                raise _Fault("Video frame rate is not ready", "Action", receiver=True)
            source = _add(result, MEDIA, "VideoSources", token=VIDEO_SOURCE)
            _tt(source, "Framerate", format(profile.frame_rate, ".8g"))
            resolution = _tt(source, "Resolution")
            _tt(resolution, "Width", profile.width)
            _tt(resolution, "Height", profile.height)
        elif action == "GetAudioSources":
            if profile.audio_encoding:
                _tt(_add(result, MEDIA, "AudioSources", token=AUDIO_SOURCE), "Channels", profile.audio_channels)
        else:
            for kind, (token, builder) in kinds.items():
                if kind in action:
                    audio = kind.startswith("Audio")
                    options = action.endswith("Options")
                    multiple = action.endswith("Configurations")
                    compatible = action.startswith("GetCompatible")
                    self._token(request, "ProfileToken", PROFILE, optional=not compatible)
                    self._token(request, "ConfigurationToken", token, optional=multiple or options)
                    if audio and not profile.audio_encoding:
                        if multiple:
                            return
                        raise _Fault("Audio configuration is unavailable", "InvalidArgVal", "NoConfig")
                    if options:
                        self._options(result, kind, profile)
                    else:
                        temporary = ET.Element("temporary")
                        element = builder(temporary, profile)
                        element.tag = f"{{{MEDIA}}}{'Configurations' if multiple else 'Configuration'}"
                        result.append(element)
                    return

    def _options(self, result, kind, profile):
        options = _add(result, MEDIA, "Options")
        if kind == "VideoSource":
            bounds = _tt(options, "BoundsRange")
            for name, value in (("XRange", 0), ("YRange", 0), ("WidthRange", profile.width), ("HeightRange", profile.height)):
                _range(bounds, name, value)
            _tt(options, "VideoSourceTokensAvailable", VIDEO_SOURCE)
        elif kind == "AudioSource":
            _tt(options, "InputTokensAvailable", AUDIO_SOURCE)
        elif kind == "AudioEncoder":
            item = _tt(options, "Options")
            _tt(item, "Encoding", profile.audio_encoding)
            _tt(_tt(item, "BitrateList"), "Items", profile.audio_bitrate)
            _tt(_tt(item, "SampleRateList"), "Items", profile.audio_sample_rate // 1000)
        else:
            _range(options, "QualityRange", 0)
            # H264Options requires GOP, fps and profile together. Omit unknowns.
            if profile.gop and profile.frame_rate and profile.h264_profile and float(profile.frame_rate).is_integer():
                h264 = _tt(options, "H264")
                resolution = _tt(h264, "ResolutionsAvailable")
                _tt(resolution, "Width", profile.width)
                _tt(resolution, "Height", profile.height)
                _range(h264, "GovLengthRange", profile.gop)
                _range(h264, "FrameRateRange", int(profile.frame_rate))
                _range(h264, "EncodingIntervalRange", 1)
                _tt(h264, "H264ProfilesSupported", profile.h264_profile)
