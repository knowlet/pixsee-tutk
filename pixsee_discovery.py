"""Small IPv4 WS-Discovery target for the opt-in Pixsee ONVIF adapter.

Uses SOAP 1.2, WS-Addressing 2004/08 and WS-Discovery 2005/04. This is
an interoperability subset, not an ONVIF Profile conformance claim. Callers
must persist the device UUID and increment ``instance_id`` on every restart;
the timestamp default is convenient for standalone/local use but cannot
guarantee ordering across same-second restarts or a backward clock change.

Standards: https://specs.xmlsoap.org/ws/2005/04/discovery/ws-discovery.pdf
and https://www.onvif.org/specs/core/ONVIF-Core-Specification.pdf section 7.
No third-party server templates or implementation code are used.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
import heapq
import io
import ipaddress
import random
import re
import select
import socket
import threading
import time
from typing import Sequence
from urllib.parse import unquote, urlsplit
import uuid
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape


SOAP = "http://www.w3.org/2003/05/soap-envelope"
ADDRESSING = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
DISCOVERY = "http://schemas.xmlsoap.org/ws/2005/04/discovery"
DEVICE = "http://www.onvif.org/ver10/device/wsdl"
NETWORK = "http://www.onvif.org/ver10/network/wsdl"
DISCOVERY_TO = "urn:schemas-xmlsoap-org:ws:2005:04:discovery"
ANONYMOUS = ADDRESSING + "/role/anonymous"
MULTICAST_GROUP = "239.255.255.250"
DISCOVERY_PORT = 3702
MAX_DATAGRAM = 8192
_MAX_QUEUE = 64
_MAX_RECENT = 256
_MAX_PEERS = 64
_TYPES = frozenset({(DEVICE, "Device"), (NETWORK, "NetworkVideoTransmitter")})
_MATCH_RULES = frozenset(DISCOVERY + "/" + value for value in
                         ("rfc2396", "rfc3986", "strcmp0"))


def _tag(namespace: str, local: str) -> str:
    return "{" + namespace + "}" + local


def _uri(value: str, limit: int = 1024) -> bool:
    return (isinstance(value, str) and 0 < len(value) <= limit
            and re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", value) is not None
            and not any(ord(char) <= 32 or ord(char) >= 127 for char in value)
            and re.search(r"%(?![0-9A-Fa-f]{2})", value) is None)


def _ipv4(value: str, *, unspecified: bool = False) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        raise ValueError("discovery requires a literal IPv4 address") from None
    if address.is_multicast or address.is_reserved or (
        address.is_unspecified and not unspecified
    ):
        raise ValueError("discovery requires a unicast IPv4 address")
    return str(address)


def _scope_match(probe: str, advertised: str, rule: str) -> bool:
    if not _uri(probe) or rule not in _MATCH_RULES:
        return False
    if rule == DISCOVERY + "/strcmp0":
        return probe == advertised
    try:
        left, right = urlsplit(probe), urlsplit(advertised)
        # Split before unescaping: an escaped slash is data within a segment.
        left_path = [unquote(part, errors="strict") for part in left.path.split("/")]
        right_path = [unquote(part, errors="strict") for part in right.path.split("/")]
        if any(part in (".", "..") for part in left_path + right_path):
            return False
        if not left.path:
            left_path = []
        return (left.scheme.lower() == right.scheme.lower()
                and left.netloc.lower() == right.netloc.lower()
                and right_path[:len(left_path)] == left_path)
    except (ValueError, UnicodeError):
        return False


def _parse_packet(data: bytes) -> tuple[ET.Element, dict[int, dict[str, str]]]:
    """Bound tree work and preserve in-scope prefixes for QName-valued Types."""
    if not data or len(data) > MAX_DATAGRAM or b"\x00" in data:
        raise ValueError("invalid discovery packet size or encoding")
    text = data.decode("utf-8-sig")
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("discovery DTDs are not supported")
    stack: list[dict[str, str]] = []
    pending: dict[str, str] = {}
    namespaces: dict[int, dict[str, str]] = {}
    count = 0
    parser = ET.iterparse(io.StringIO(text), events=("start-ns", "start", "end"))
    for event, item in parser:
        if event == "start-ns":
            pending[item[0]] = item[1]
        elif event == "start":
            count += 1
            if count > 128 or len(stack) >= 24:
                raise ValueError("discovery XML exceeds structural limits")
            current = dict(stack[-1]) if stack else {}
            current.update(pending)
            pending.clear()
            stack.append(current)
            if item.tag == _tag(DISCOVERY, "Types"):
                namespaces[id(item)] = current
        else:
            stack.pop()
    return parser.root, namespaces


def _single(parent: ET.Element, name: str, *, required: bool = False):
    values = parent.findall(name)
    if len(values) > 1 or (required and not values):
        raise ValueError("missing or repeated discovery field")
    return values[0] if values else None


def _text(element: ET.Element | None) -> str:
    if element is None:
        return ""
    if len(element):
        raise ValueError("nested discovery text field")
    return (element.text or "").strip()


@dataclass(order=True)
class _Transmission:
    due: float
    order: int
    destination: tuple[str, int] = field(compare=False)
    kind: str = field(compare=False)
    relates_to: str = field(default="", compare=False)
    remaining: int = field(default=2, compare=False)
    interval: float = field(default=0.0, compare=False)
    payload: bytes | None = field(default=None, compare=False)


class DiscoveryService:
    """Single-use, explicitly configured IPv4 discovery service.

    ``interface_ip`` must be the same literal IPv4 address used in ``xaddr``.
    ``scopes`` are supplied by the adapter; no profiles, PTZ or audio capability
    are invented here. Construction has no network effects; ``start`` opts in.
    For local tests use 127.0.0.1, a custom multicast group and ``port=0``.
    ``close`` sends best-effort Bye retransmissions and releases the socket in
    at most two seconds under normal OS operation. It is safe to repeat.
    """

    def __init__(self, *, interface_ip: str, device_uuid: str | uuid.UUID,
                 xaddr: str, scopes: Sequence[str], port: int = DISCOVERY_PORT,
                 multicast_group: str = MULTICAST_GROUP, bind_ip: str = "0.0.0.0",
                 instance_id: int | None = None, metadata_version: int = 1):
        self.interface_ip = _ipv4(interface_ip)
        self.bind_ip = _ipv4(bind_ip, unspecified=True)
        if self.bind_ip not in ("0.0.0.0", self.interface_ip):
            raise ValueError("discovery bind address must match its interface")
        try:
            self.endpoint = uuid.UUID(str(device_uuid)).urn
        except (ValueError, TypeError, AttributeError):
            raise ValueError("device_uuid must be a stable UUID") from None
        if not _uri(xaddr):
            raise ValueError("xaddr must be an absolute HTTP IPv4 URL")
        try:
            url = urlsplit(xaddr)
            if (url.scheme not in ("http", "https") or url.hostname != self.interface_ip
                    or url.username is not None or url.password is not None
                    or url.fragment or url.port == 0):
                raise ValueError
        except ValueError:
            raise ValueError("xaddr must advertise the explicit discovery interface") from None
        if isinstance(scopes, str) or len(scopes) > 16 or any(not _uri(s, 256) for s in scopes):
            raise ValueError("scopes must contain at most 16 bounded absolute URIs")
        if sum(len(s) for s in scopes) > 2048:
            raise ValueError("discovery scopes are too large")
        # A valid URI can contain '&'; XML escaping must also fit the UDP cap.
        if sum(len(escape(value)) for value in (xaddr, *scopes)) > 4096:
            raise ValueError("discovery advertisement is too large after XML escaping")
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("discovery port must be 0 to 65535")
        try:
            group = ipaddress.IPv4Address(multicast_group)
            if not group.is_multicast:
                raise ValueError
        except (ValueError, TypeError):
            raise ValueError("discovery multicast_group must be IPv4 multicast") from None
        self.instance_id = int(time.time()) if instance_id is None else instance_id
        for value in (self.instance_id, metadata_version):
            if type(value) is not int or not 1 <= value <= 0xFFFFFFFF:
                raise ValueError("discovery sequence versions must be positive uint32 values")
        self.xaddr, self.scopes = xaddr, tuple(scopes)
        self.port, self.multicast_group = port, str(group)
        self.metadata_version = metadata_version
        self.error: OSError | None = None
        self._socket: socket.socket | None = None
        self._address: tuple[str, int] | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._closed = False
        self._sequence_id = uuid.uuid4().urn
        self._message_number = 0
        self._queue: list[_Transmission] = []
        self._order = 0
        self._recent: OrderedDict[tuple[str, str], float] = OrderedDict()
        self._peers: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._global_bucket = (20.0, time.monotonic())

    @property
    def address(self) -> tuple[str, int] | None:
        return self._address

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stop.is_set()

    def start(self) -> DiscoveryService:
        with self._lock:
            if self.running:
                return self
            if self._closed or self._thread is not None:
                raise RuntimeError("create a new discovery service after closing")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, "SO_REUSEPORT"):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                sock.bind((self.bind_ip, self.port))
                membership = socket.inet_aton(self.multicast_group) + socket.inet_aton(self.interface_ip)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                                socket.inet_aton(self.interface_ip))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
                sock.setblocking(False)
                self._address = sock.getsockname()
                self._socket = sock
                self._thread = threading.Thread(target=self._run, name="pixsee-discovery", daemon=True)
                self._thread.start()
            except BaseException:
                sock.close()
                self._socket = None
                raise
        return self

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._stop.set()
            if self._thread is not None:
                self._thread.join(timeout=2.0)
                if self._thread.is_alive():
                    raise RuntimeError("discovery service did not stop")

    def __enter__(self) -> DiscoveryService:
        return self.start()

    def __exit__(self, *args) -> None:
        self.close()

    def _message(self, kind: str, relates_to: str = "") -> bytes:
        self._message_number += 1
        root = ET.Element("s:Envelope", {
            "xmlns:s": SOAP, "xmlns:a": ADDRESSING, "xmlns:d": DISCOVERY,
            "xmlns:tds": DEVICE, "xmlns:tdn": NETWORK,
        })
        header = ET.SubElement(root, "s:Header")
        ET.SubElement(header, "a:Action").text = DISCOVERY + "/" + kind
        ET.SubElement(header, "a:MessageID").text = uuid.uuid4().urn
        if relates_to:
            ET.SubElement(header, "a:RelatesTo").text = relates_to
        ET.SubElement(header, "a:To").text = ANONYMOUS if relates_to else DISCOVERY_TO
        ET.SubElement(header, "d:AppSequence", {
            "InstanceId": str(self.instance_id), "SequenceId": self._sequence_id,
            "MessageNumber": str(self._message_number),
        })
        body = ET.SubElement(root, "s:Body")
        record = ET.SubElement(body, "d:" + kind)
        if kind in ("ProbeMatches", "ResolveMatches"):
            record = ET.SubElement(record, "d:" + kind[:-2])
        epr = ET.SubElement(record, "a:EndpointReference")
        ET.SubElement(epr, "a:Address").text = self.endpoint
        if kind != "Bye":
            ET.SubElement(record, "d:Types").text = "tds:Device tdn:NetworkVideoTransmitter"
            ET.SubElement(record, "d:Scopes").text = " ".join(self.scopes)
            ET.SubElement(record, "d:XAddrs").text = self.xaddr
            ET.SubElement(record, "d:MetadataVersion").text = str(self.metadata_version)
        return ET.tostring(root, encoding="utf-8", xml_declaration=True)

    def _request(self, data: bytes) -> tuple[str, str] | None:
        try:
            root, namespaces = _parse_packet(data)
            if root.tag != _tag(SOAP, "Envelope"):
                return None
            header = _single(root, _tag(SOAP, "Header"), required=True)
            body = _single(root, _tag(SOAP, "Body"), required=True)
            if len(body) != 1:
                return None
            operation = body[0]
            kind = { _tag(DISCOVERY, "Probe"): "Probe",
                     _tag(DISCOVERY, "Resolve"): "Resolve" }.get(operation.tag)
            if kind is None:
                return None
            action = _text(_single(header, _tag(ADDRESSING, "Action"), required=True))
            message_id = _text(_single(header, _tag(ADDRESSING, "MessageID"), required=True))
            to = _text(_single(header, _tag(ADDRESSING, "To"), required=True))
            if (action != DISCOVERY + "/" + kind or not _uri(message_id, 256)
                    or to != DISCOVERY_TO):
                return None
            reply = _single(header, _tag(ADDRESSING, "ReplyTo"))
            if reply is not None and _text(_single(reply, _tag(ADDRESSING, "Address"),
                                                  required=True)) != ANONYMOUS:
                return None
            if kind == "Resolve":
                epr = _single(operation, _tag(ADDRESSING, "EndpointReference"), required=True)
                if _text(_single(epr, _tag(ADDRESSING, "Address"), required=True)) != self.endpoint:
                    return None
                properties = _single(epr, _tag(ADDRESSING, "ReferenceProperties"))
                if properties is not None and (len(properties) or (properties.text or "").strip()):
                    return None
            else:
                types = _single(operation, _tag(DISCOVERY, "Types"))
                for token in _text(types).split():
                    prefix, separator, local = token.partition(":")
                    prefix, local = (prefix, local) if separator else ("", prefix)
                    if (namespaces.get(id(types), {}).get(prefix, ""), local) not in _TYPES:
                        return None
                scopes = _single(operation, _tag(DISCOVERY, "Scopes"))
                if scopes is not None:
                    rule = scopes.get("MatchBy", DISCOVERY + "/rfc2396")
                    if rule not in _MATCH_RULES:
                        return None
                    for scope in _text(scopes).split():
                        if not any(_scope_match(scope, own, rule) for own in self.scopes):
                            return None
            return kind + "Matches", message_id
        except (ET.ParseError, ValueError, UnicodeError):
            return None

    def _allow(self, peer: str, now: float) -> bool:
        global_tokens, updated = self._global_bucket
        global_tokens = min(20.0, global_tokens + (now - updated) * 20.0)
        self._global_bucket = (max(0.0, global_tokens - 1.0), now)
        if global_tokens < 1.0:
            return False
        tokens, updated = self._peers.pop(peer, (5.0, now))
        tokens = min(5.0, tokens + (now - updated) * 5.0)
        self._peers[peer] = (max(0.0, tokens - 1.0), now)
        while len(self._peers) > _MAX_PEERS:
            self._peers.popitem(last=False)
        return tokens >= 1.0

    def _schedule(self, kind: str, destination: tuple[str, int], relates_to: str = "") -> None:
        if len(self._queue) >= _MAX_QUEUE:
            return
        self._order += 1
        heapq.heappush(self._queue, _Transmission(
            time.monotonic() + random.uniform(0.0, 0.5), self._order,
            destination, kind, relates_to, 2 if relates_to else 4,
            random.uniform(0.05, 0.25)))

    def _send(self, payload: bytes, destination: tuple[str, int]) -> None:
        try:
            self._socket.sendto(payload, destination)
        except OSError as error:
            self.error = error

    def _run(self) -> None:
        multicast = (self.multicast_group, self._address[1])
        try:
            self._schedule("Hello", multicast)
            while not self._stop.is_set():
                now = time.monotonic()
                while self._queue and self._queue[0].due <= now:
                    item = heapq.heappop(self._queue)
                    if item.payload is None:
                        item.payload = self._message(item.kind, item.relates_to)
                    self._send(item.payload, item.destination)
                    item.remaining -= 1
                    if item.remaining:
                        item.due = now + item.interval
                        item.interval = min(item.interval * 2, 0.5)
                        heapq.heappush(self._queue, item)
                readable, _, _ = select.select([self._socket], [], [], 0.05)
                if not readable:
                    continue
                data, peer = self._socket.recvfrom(MAX_DATAGRAM + 1)
                try:
                    _ipv4(peer[0])
                except ValueError:
                    continue
                if not peer[1] or not self._allow(peer[0], time.monotonic()):
                    continue
                request = self._request(data)
                if request is None:
                    continue
                kind, message_id = request
                now = time.monotonic()
                while self._recent and next(iter(self._recent.values())) < now - 10.0:
                    self._recent.popitem(last=False)
                key = (peer[0], message_id)
                if key in self._recent:
                    continue
                self._recent[key] = now
                while len(self._recent) > _MAX_RECENT:
                    self._recent.popitem(last=False)
                self._schedule(kind, peer, message_id)
            self._queue.clear()
            bye = self._message("Bye")
            delay = random.uniform(0.05, 0.25)
            for attempt in range(4):
                self._send(bye, multicast)
                if attempt < 3:
                    time.sleep(delay)
                    delay = min(delay * 2, 0.5)
        except OSError as error:
            self.error = error
        finally:
            self._socket.close()
            self._socket = None
