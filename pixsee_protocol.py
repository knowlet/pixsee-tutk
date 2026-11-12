"""Pixsee SDK 4.3.8.1 LAN discovery, session, and DTLS packet framing.

Static sources: libIOTCAPIs.so builder 0x14124, sender 0xdb10,
AddLanSearchTask callback 0x15398, and response builder 0x1d414.
Session sources: IOTC_Session_Write_Data_And_Datatype 0x13a48,
IOTC_Session_Write_DTLS 0x13e26, close builder 0x1312c, alive loop 0x1fe98.
This module encodes packets only; it does not open sockets or authenticate AV.
"""

from dataclasses import dataclass, field
import struct
from typing import Optional, Union

from cuboai_pure import _CLIENT_FINGERPRINT, inv_transcode, transcode


class PixseeProtocolError(ValueError):
    """A packet or caller-supplied identity does not match the LAN protocol."""


@dataclass(frozen=True)
class DiscoveryReply:
    uid: str = field(repr=False)
    device_name: str
    sdk_version: str
    nonce: int
    fingerprint: bytes = field(repr=False)
    status: int
    protocol_version: int
    flags: int


def _uid_bytes(uid: str) -> bytes:
    if not isinstance(uid, str):
        raise PixseeProtocolError("UID must be an ASCII string")
    try:
        value = uid.encode("ascii")
    except UnicodeEncodeError as exc:
        raise PixseeProtocolError("UID must be ASCII") from exc
    if not 1 <= len(value) <= 20 or not value.isalnum():
        raise PixseeProtocolError("UID must contain 1 to 20 ASCII letters/digits")
    return value


def _fingerprint_bytes(value: Optional[bytes]) -> bytes:
    if value is None:
        value = _CLIENT_FINGERPRINT
    if not isinstance(value, bytes) or len(value) != 6:
        raise PixseeProtocolError("Fingerprint must contain exactly 6 bytes")
    return value


def _session_identity(nonce: int, fingerprint: Optional[bytes]) -> bytes:
    if type(nonce) is not int or not 1 <= nonce <= 0xFFFE:
        raise PixseeProtocolError("Connection nonce must be in 1..65534")
    return struct.pack("<H", nonce) + _fingerprint_bytes(fingerprint)


def _validate_iotc_header(plain: bytes) -> None:
    if len(plain) < 16 or plain[:2] != b"\x04\x02":
        raise PixseeProtocolError("Invalid IOTC packet header")
    if struct.unpack_from("<H", plain, 4)[0] != len(plain) - 16:
        raise PixseeProtocolError("Invalid IOTC packet payload length")


def encode_iotc_packet(plain: bytes) -> bytes:
    """Apply native iotc_SendMessage encoding, including partial encryption.

    Flag bit 0 selects the first 64 bytes, not just the 16/28-byte header.
    The remainder is copied unchanged. Native always sets flag bit 1.
    """
    if not isinstance(plain, bytes):
        raise PixseeProtocolError("IOTC plaintext must be bytes")
    _validate_iotc_header(plain)
    packet = bytearray(plain)
    packet[3] |= 2
    limit = min(len(packet), 64) if packet[3] & 1 else len(packet)
    return transcode(bytes(packet[:limit]), swap_tail=True) + bytes(packet[limit:])


def decode_iotc_packet(wire: bytes) -> bytes:
    """Decode a complete native datagram without transforming a clear suffix."""
    if not isinstance(wire, bytes) or len(wire) < 16:
        raise PixseeProtocolError("IOTC datagram must contain at least 16 bytes")
    header = inv_transcode(wire[:16])
    if header[:2] != b"\x04\x02" or not header[3] & 2:
        raise PixseeProtocolError("Invalid encoded IOTC packet header")
    limit = min(len(wire), 64) if header[3] & 1 else len(wire)
    plain = inv_transcode(wire[:limit]) + wire[limit:]
    _validate_iotc_header(plain)
    return plain


def build_dtls_data(payload: bytes, nonce: int, sequence: int,
                    fingerprint: Optional[bytes] = None, channel: int = 0) -> bytes:
    """Wrap one DTLS datagram in the native 28-byte LAN client data header.

    Sequence is the caller's per-channel IOTC sequence (modulo 65536), separate
    from DTLS record sequence numbers. Payload is at most 1388 bytes.
    """
    identity = _session_identity(nonce, fingerprint)
    if not isinstance(payload, bytes) or len(payload) > 0x56C:
        raise PixseeProtocolError("DTLS payload must be at most 1388 bytes")
    if type(sequence) is not int or not 0 <= sequence <= 0xFFFF:
        raise PixseeProtocolError("IOTC sequence must be in 0..65535")
    if type(channel) is not int or not 0 <= channel <= 31:
        raise PixseeProtocolError("IOTC channel must be in 0..31")
    packet = bytearray(28 + len(payload))
    struct.pack_into("<BBBBHHHHHBBI", packet, 0,
                     4, 2, 0x1D, 0x0B, 12 + len(payload), sequence,
                     0x0407, 0x21, nonce, channel, 1, 12)
    packet[20:28] = identity
    packet[28:] = payload
    return encode_iotc_packet(bytes(packet))


def parse_dtls_data(wire: bytes, expected_nonce: int, channel: int = 0, *,
                    expected_fingerprint: Optional[bytes] = None) -> bytes:
    """Return a camera DTLS payload after validating its complete session identity.

    Header MID is deliberately not compared: the camera may choose it separately.
    Caller must validate socket source IP/port and process DTLS authentication.
    """
    identity = _session_identity(expected_nonce, expected_fingerprint)
    if type(channel) is not int or not 0 <= channel <= 31:
        raise PixseeProtocolError("IOTC channel must be in 0..31")
    plain = decode_iotc_packet(wire)
    if len(plain) < 28 or len(plain) > 28 + 0x56C:
        raise PixseeProtocolError("Invalid DTLS session packet length")
    if plain[2] != 0x1D or plain[3] not in (0x0A, 0x0B):
        raise PixseeProtocolError("Unexpected DTLS session protocol flags")
    if struct.unpack_from("<HH", plain, 8) != (0x0408, 0x12):
        raise PixseeProtocolError("Unexpected camera DTLS message type")
    if plain[14] != channel or plain[15] != 1:
        raise PixseeProtocolError("Unexpected DTLS channel or datatype")
    if struct.unpack_from("<I", plain, 16)[0] != 12:
        raise PixseeProtocolError("Invalid DTLS session extension")
    if plain[20:28] != identity:
        raise PixseeProtocolError("DTLS packet session identity does not match")
    return plain[28:]


def build_talk_data(payload: bytes, nonce: int, sequence: int) -> bytes:
    """Native avServStart3 talk data on channel 1, datatype 0 (not DTLS).

    The authenticated channel-0 command explicitly enables this separate
    channel. The native app uses unencrypted AV here; do not label it secure.
    """
    plain = bytearray(decode_iotc_packet(build_dtls_data(payload, nonce, sequence, channel=1)))
    plain[15] = 0
    return encode_iotc_packet(bytes(plain))


def parse_talk_data(wire: bytes, expected_nonce: int) -> bytes:
    """Validate a talk-channel datagram from the already pinned camera peer."""
    plain = bytearray(decode_iotc_packet(wire))
    if len(plain) < 28 or plain[14:16] != bytes((1, 0)):
        raise PixseeProtocolError("Unexpected talk channel or datatype")
    plain[15] = 1
    return parse_dtls_data(encode_iotc_packet(bytes(plain)), expected_nonce, channel=1)


def keepalive_reply(wire: bytes, expected_nonce: int, *,
                    expected_fingerprint: Optional[bytes] = None) -> Optional[bytes]:
    """Reply to a valid camera alive-check, or return None for other packets."""
    identity = _session_identity(expected_nonce, expected_fingerprint)
    plain = decode_iotc_packet(wire)
    if struct.unpack_from("<H", plain, 8)[0] != 0x0428:
        return None
    if (len(plain) != 24 or plain[:4] != bytes.fromhex("04021d0a")
            or plain[6:16] != bytes.fromhex("00002804120000000000")):
        raise PixseeProtocolError("Invalid camera keepalive packet")
    if plain[16:24] != identity:
        raise PixseeProtocolError("Keepalive session identity does not match")
    packet = bytes.fromhex("04021d0a080000002704210000000000") + plain[16:24]
    return encode_iotc_packet(packet)


def build_session_close(nonce: int, fingerprint: Optional[bytes] = None) -> bytes:
    """Build the native client LAN close packet for this exact session identity."""
    packet = bytes.fromhex("04021d0a080000001704210000000000")
    return encode_iotc_packet(packet + _session_identity(nonce, fingerprint))


def _search_plaintext(discovery: bool) -> bytearray:
    packet = bytearray(88)
    # iotc_SendMessage sets bit 1 of byte 3 before encoding the native builder.
    packet[:16] = bytes.fromhex("04021d02480000000106210000000000")
    packet[15] = int(discovery)
    packet[52:56] = bytes((1, 8, 3, 4))
    return packet


def build_discovery_probe(retry_index: int = 0) -> bytes:
    """Build a UID-less discovery request suitable for unicast to one camera.

    Native search cycles retry_index through 0..15. A nonzero index switches
    the request to 0x0603; no connection ACK or AV login is performed here.
    """
    if type(retry_index) is not int or not 0 <= retry_index <= 15:
        raise PixseeProtocolError("Discovery retry index must be in 0..15")
    packet = _search_plaintext(discovery=True)
    if retry_index:
        struct.pack_into("<H", packet, 8, 0x0603)
        struct.pack_into("<I", packet, 68, retry_index)
    return transcode(bytes(packet), swap_tail=True)


def _connect_packet(uid: str, nonce: int, auth_key: Union[str, bytes],
                    fingerprint: Optional[bytes], operation: int) -> bytes:
    uid_value = _uid_bytes(uid)
    if type(nonce) is not int or not 1 <= nonce <= 0xFFFE:
        raise PixseeProtocolError("Connection nonce must be in 1..65534")
    identity = _fingerprint_bytes(fingerprint)
    if isinstance(auth_key, str):
        try:
            auth_key = auth_key.encode("ascii")
        except UnicodeEncodeError as exc:
            raise PixseeProtocolError("Auth key must be 8 ASCII bytes") from exc
    if not isinstance(auth_key, bytes) or len(auth_key) != 8 or b"\0" in auth_key:
        raise PixseeProtocolError("Auth key must contain exactly 8 non-NUL bytes")
    packet = _search_plaintext(discovery=False)
    packet[16:16 + len(uid_value)] = uid_value
    struct.pack_into("<H", packet, 56, nonce)
    packet[58:64] = identity
    struct.pack_into("<I", packet, 64, operation)
    packet[74:82] = auth_key
    # The last two auth-key bytes cross the full-block boundary. Native Swap
    # is required here; using Cubo's pre-session no-swap path corrupts the key.
    return transcode(bytes(packet), swap_tail=True)


def build_connect_probe(uid: str, nonce: int, auth_key: Union[str, bytes],
                        fingerprint: Optional[bytes] = None) -> bytes:
    """Build a known-UID LAN connection precheck (operation 1)."""
    return _connect_packet(uid, nonce, auth_key, fingerprint, 1)


def build_connect_ack(uid: str, nonce: int, auth_key: Union[str, bytes],
                      fingerprint: Optional[bytes] = None) -> bytes:
    """Acknowledge an accepted precheck with the same identity (operation 2)."""
    return _connect_packet(uid, nonce, auth_key, fingerprint, 2)


def parse_discovery_reply(wire: bytes, *, expected_uid: Optional[str] = None,
                          expected_nonce: Optional[int] = None,
                          expected_fingerprint: Optional[bytes] = None) -> DiscoveryReply:
    """Decode this SDK's 200-byte 0x0602 reply and validate optional identity.

    Source IP/port validation belongs to the socket receiver. Status 0 means
    discovery, 1/7 are connection-precheck grants, and other values are not
    accepted here as authentication success. AV authentication is separate.
    """
    if not isinstance(wire, bytes) or len(wire) != 200:
        raise PixseeProtocolError("Expected a 200-byte Pixsee discovery reply")
    plain = inv_transcode(wire)
    if plain[:2] != b"\x04\x02":
        raise PixseeProtocolError("Invalid IOTC discovery header")
    if struct.unpack_from("<H", plain, 4)[0] != 184:
        raise PixseeProtocolError("Invalid discovery payload length")
    if struct.unpack_from("<H", plain, 8)[0] != 0x0602:
        raise PixseeProtocolError("Unexpected IOTC discovery message type")
    uid_field = plain[16:36]
    uid_value, separator, padding = uid_field.partition(b"\0")
    if separator and padding.strip(b"\0"):
        raise PixseeProtocolError("Invalid UID padding")
    try:
        uid = uid_value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise PixseeProtocolError("Invalid discovery UID encoding") from exc
    _uid_bytes(uid)
    nonce = struct.unpack_from("<H", plain, 188)[0]
    fingerprint = plain[190:196]
    if expected_uid is not None and _uid_bytes(expected_uid) != uid_value:
        raise PixseeProtocolError("Discovery reply UID does not match")
    if expected_nonce is not None:
        if type(expected_nonce) is not int or not 1 <= expected_nonce <= 0xFFFE:
            raise PixseeProtocolError("Expected nonce must be in 1..65534")
        if expected_nonce != nonce:
            raise PixseeProtocolError("Discovery reply nonce does not match")
    if expected_fingerprint is not None:
        if _fingerprint_bytes(expected_fingerprint) != fingerprint:
            raise PixseeProtocolError("Discovery reply fingerprint does not match")
    return DiscoveryReply(
        uid=uid,
        device_name=plain[52:181].split(b"\0", 1)[0].decode("utf-8", "replace"),
        sdk_version=".".join(str(part) for part in reversed(plain[184:188])),
        nonce=nonce,
        fingerprint=fingerprint,
        status=struct.unpack_from("<I", plain, 196)[0],
        protocol_version=plain[2],
        flags=plain[3],
    )
