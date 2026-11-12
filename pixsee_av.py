"""Plaintext Pixsee AV login messages carried inside the IOTC DTLS session.

Recovered from the APK's ARM libAVAPIs.so 4.3.8.1: assemblePackHead (0xed98),
clientConnect (0x1e57c), GetOpCodeSupportCurrent (0x15360), grant dispatch
(0x11d22/0x20280), and PSK helpers (0x1dfb0/0x1dff4/0x18408).
Offsets here start at the AV application header, excluding the 28-byte IOTC
envelope. These functions perform no network access or device setting changes.
"""

from dataclasses import dataclass, field
import hashlib
import struct


AV_PROTOCOL_VERSION = 12
AV_HEADER_SIZE = 24
AV_CAPABILITIES = struct.pack("<5I", 4, 0x001F07FB, 0, 0, 0x00030000)


class AVProtocolError(ValueError):
    """Invalid AV application message or unsupported input."""


def _text_bytes(value: str, name: str, limit: int = 255) -> bytes:
    if not isinstance(value, str) or not value or "\0" in value:
        raise AVProtocolError(f"{name} must be nonempty text without NUL bytes")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise AVProtocolError(f"{name} must contain valid UTF-8 text") from None
    if len(encoded) > limit:
        raise AVProtocolError(f"{name} must be at most {limit} UTF-8 bytes")
    return encoded


def _token(value: int) -> int:
    if type(value) is not int or not 1 <= value <= 0xFFFFFFFF:
        raise AVProtocolError("AV token must be an integer in 1..4294967295")
    return value


def derive_psk(account: str, password: str) -> tuple[bytes, bytes]:
    """Return the native auth_type=0 DTLS identity and 32-byte PSK.

    The native identity uses snprintf(buffer, 120, "AUTHPWD_%s", account),
    so only its first 119 bytes survive. Its SHA-256 result is copied with
    strncpy rather than memcpy: the first zero byte zero-fills the remainder.
    The PSK callback still returns length 32, including that zero padding.
    """
    account_bytes = _text_bytes(account, "account", 120)
    password_bytes = _text_bytes(password, "password")
    digest = hashlib.sha256(password_bytes).digest()
    key = digest.split(b"\0", 1)[0].ljust(32, b"\0")
    return (b"AUTHPWD_" + account_bytes)[:119], key


def build_av_login(account: str, password: str, token: int, *,
                   resend: bool = False) -> bytes:
    """Build the normal (570-byte) or resend-negotiation (572-byte) login.

    Both messages advertise resend support, matching the Pixsee app. Send the
    normal packet and then its resend-negotiation companion. ``token`` is the
    shared base token: the companion carries token+1, including byte carries.
    Audio/video-on-connect are zero, as in the app; no stream is requested here.
    The returned bytes contain credentials and must never be logged.
    """
    account_bytes = _text_bytes(account, "account")
    password_bytes = _text_bytes(password, "password")
    base = _token(token)
    if type(resend) is not bool:
        raise AVProtocolError("resend must be a bool")
    if resend and base == 0xFFFFFFFF:
        raise AVProtocolError("AV base token leaves no room for resend token")
    packet = bytearray(572 if resend else 570)
    packet[1] = 0x20 if resend else 0
    struct.pack_into("<H", packet, 2, AV_PROTOCOL_VERSION)
    struct.pack_into("<H", packet, 16, len(packet) - AV_HEADER_SIZE)
    packet[18] = 0 if resend else 1
    struct.pack_into("<I", packet, 20, base + int(resend))
    packet[24:24 + len(account_bytes)] = account_bytes
    packet[281:281 + len(password_bytes)] = password_bytes
    packet[538] = 1
    packet[542:562] = AV_CAPABILITIES
    # auth_type=0 at 562; native internal connect config flag=1 at 566.
    packet[566] = 1
    return bytes(packet)


@dataclass(frozen=True)
class AvGrant:
    status: int
    opcode: int
    protocol_version: int
    token: int = field(repr=False)
    server_word: int = field(repr=False)
    resend_supported: bool
    capabilities: tuple[int, ...]

    @property
    def authenticated(self) -> bool:
        return self.status == 0


def parse_av_grant(application: bytes, expected_token: int) -> AvGrant:
    """Validate one decrypted grant, including its exact echoed wire token.

    For a resend grant (opcode 0x21), pass the transmitted base token + 1.
    Nonzero authentication status is returned faithfully, never as success.
    Transport source/session validation and DTLS authentication belong to the
    caller. This parser does not accept an encrypted record or IOTC envelope.
    """
    expected_token = _token(expected_token)
    if not isinstance(application, bytes) or len(application) < 36:
        raise AVProtocolError("Truncated AV grant")
    opcode = application[1]
    if application[0] != 0 or opcode not in (0x01, 0x14, 0x21):
        raise AVProtocolError("Unexpected AV grant opcode")
    version, = struct.unpack_from("<H", application, 2)
    if not 1 <= version <= AV_PROTOCOL_VERSION:
        raise AVProtocolError("Unsupported AV grant protocol version")
    body_size, = struct.unpack_from("<H", application, 16)
    if len(application) != AV_HEADER_SIZE + body_size:
        raise AVProtocolError("Invalid AV grant payload length")
    minimum = 36 if opcode == 0x01 else 56
    if opcode == 0x21:
        minimum = 62 if version >= 12 else 60
    if len(application) < minimum:
        raise AVProtocolError("Truncated AV grant fields")
    token, = struct.unpack_from("<I", application, 20)
    if token != expected_token:
        raise AVProtocolError("AV grant token does not match")
    capabilities = ()
    if opcode != 0x01:
        count, = struct.unpack_from("<I", application, 36)
        if count > 4:
            raise AVProtocolError("Invalid AV grant capability count")
        capabilities = struct.unpack_from(f"<{count}I", application, 40)
    return AvGrant(
        status=application[24], opcode=opcode, protocol_version=version,
        token=token, server_word=struct.unpack_from("<I", application, 4)[0],
        resend_supported=bool(application[32]), capabilities=capabilities,
    )
