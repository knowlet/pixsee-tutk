"""Pixsee PCM receive and reverse AV talk-channel application messages.

The app's AudioThreadRunnable/AudioSpeaker use signed PCM16, mono, 8 kHz.
AudioSpeaker sends 640-byte (40 ms) chunks. TUTKClient starts an AV server on
channel 1; the camera connects with empty account/password, independently of
the authenticated main channel. Callers must validate the IOTC peer/session
and enable this handler only while a user-requested talk session is active.

Builders here return AV application bytes only, without the IOTC envelope.
No vendor binary is loaded and these helpers perform no network access.
"""

from dataclasses import dataclass, field
import struct

from pixsee_av import AV_CAPABILITIES, AV_HEADER_SIZE, AV_PROTOCOL_VERSION, AVProtocolError


PCM_CODEC_ID = 0x008C
PCM_SAMPLE_RATE = 8000
PCM_CHANNELS = 1
PCM_SAMPLE_WIDTH = 2
PCM_FRAMEINFO_SIZE = 16
TALK_CHUNK_BYTES = 640
TALK_CHUNK_SECONDS = TALK_CHUNK_BYTES / (PCM_SAMPLE_RATE * PCM_SAMPLE_WIDTH)
TALK_MAX_PCM_BYTES = 1024 - PCM_FRAMEINFO_SIZE
TALK_SERVICE_TYPE = 60
SPEAKER_START = 0x0350
SPEAKER_STOP = 0x0351


def _counter(value: int, name: str) -> int:
    if type(value) is not int or value < 0:
        raise AVProtocolError(f"{name} must be a nonnegative integer")
    return value


def parse_pcm_audio_unit(unit: bytes, *, complete: bool = True) -> tuple[bytes, dict]:
    """Strip the 16-byte FRAMEINFO from one complete camera PCM access unit.

    The caller supplies the transport's completeness result. Timestamp is the
    camera's unsigned millisecond clock at FRAMEINFO offset 12, as with video.
    Unknown codecs and partial 16-bit samples are rejected rather than emitted
    as noise. Sample format follows the active app path, not guessed bit flags.
    """
    if type(complete) is not bool or not complete:
        raise AVProtocolError("Incomplete PCM audio access unit")
    if not isinstance(unit, bytes) or len(unit) <= PCM_FRAMEINFO_SIZE:
        raise AVProtocolError("Truncated PCM audio access unit")
    pcm, info = unit[:-PCM_FRAMEINFO_SIZE], unit[-PCM_FRAMEINFO_SIZE:]
    if len(pcm) % PCM_SAMPLE_WIDTH:
        raise AVProtocolError("PCM audio has an incomplete 16-bit sample")
    if struct.unpack_from("<H", info)[0] != PCM_CODEC_ID:
        raise AVProtocolError("Unsupported Pixsee audio codec")
    return pcm, {
        "codec": "pcm_s16le", "codec_id": PCM_CODEC_ID,
        "sample_rate": PCM_SAMPLE_RATE, "channels": PCM_CHANNELS,
        "sample_width": PCM_SAMPLE_WIDTH, "complete": True,
        "timestamp_ms": struct.unpack_from("<I", info, 12)[0],
    }


@dataclass(frozen=True)
class TalkLogin:
    opcode: int
    protocol_version: int
    token: int = field(repr=False)
    header: bytes = field(repr=False)
    capabilities: tuple[int, ...]

    @property
    def resend(self) -> bool:
        return self.opcode == 0x20


def parse_talk_login(application: bytes) -> TalkLogin:
    """Validate the known version-12 camera-to-host talk login.

    This is a structural parser, not authentication. Empty credentials match
    avServStart3(..., NULL, NULL, ..., channel=1) in the app and this firmware's
    reverse connection. Main-channel peer/session checks remain mandatory.
    The input is not retained, preventing accidental credential logging.
    """
    if not isinstance(application, bytes) or len(application) not in (570, 572):
        raise AVProtocolError("Invalid Pixsee talk login length")
    opcode = application[1]
    if application[0] != 0 or opcode not in (0, 0x20):
        raise AVProtocolError("Unexpected Pixsee talk login opcode")
    expected_size = 572 if opcode == 0x20 else 570
    version, = struct.unpack_from("<H", application, 2)
    if version != AV_PROTOCOL_VERSION:
        raise AVProtocolError("Unsupported Pixsee talk protocol version")
    body_size, = struct.unpack_from("<H", application, 16)
    if len(application) != expected_size or body_size != expected_size - AV_HEADER_SIZE:
        raise AVProtocolError("Invalid Pixsee talk login payload length")
    token, = struct.unpack_from("<I", application, 20)
    if token == 0:
        raise AVProtocolError("Invalid Pixsee talk login token")
    if any(application[24:538]) or any(application[562:570]):
        raise AVProtocolError("Unsupported Pixsee talk authentication mode")
    if application[538:542] != b"\x01\0\0\0":
        raise AVProtocolError("Pixsee talk login requires resend support")
    expected_flag = 0 if opcode == 0x20 else 1
    if application[18:20] != bytes((expected_flag, 0)):
        raise AVProtocolError("Invalid Pixsee talk resend negotiation")
    if opcode == 0x20 and application[570:] != b"\0\0":
        raise AVProtocolError("Unexpected media-on-connect request")
    count, = struct.unpack_from("<I", application, 542)
    if not 1 <= count <= 4:
        raise AVProtocolError("Invalid Pixsee talk capability count")
    capabilities = struct.unpack_from(f"<{count}I", application, 546)
    return TalkLogin(opcode, version, token, application[:AV_HEADER_SIZE], capabilities)


def build_talk_grant(login: TalkLogin, server_word: int = TALK_SERVICE_TYPE) -> bytes:
    """Accept a validated resend companion with the native 62-byte grant.

    Native grant builder 0x12548 ignores the primary's resend-negotiation flag
    and responds to its 0x20 companion. Echo its full 32-bit token; a fresh
    token would make the camera reject the grant. ``server_word`` is the local
    AV service type: the app passes 60 to avServStart3. It is not the camera's
    main-channel service type or its capability bitmap.
    """
    if not isinstance(login, TalkLogin) or not login.resend:
        raise AVProtocolError("Wait for the talk resend companion before granting")
    if (len(login.header) != AV_HEADER_SIZE or login.header[:4] != b"\0\x20\x0c\0"
            or login.token == 0 or struct.unpack_from("<I", login.header, 20)[0] != login.token):
        raise AVProtocolError("Invalid parsed Pixsee talk login")
    if type(server_word) is not int or not 0 <= server_word <= 0xFFFFFFFF:
        raise AVProtocolError("server_word must be an unsigned 32-bit integer")
    packet = bytearray(62)
    packet[:AV_HEADER_SIZE] = login.header
    packet[1] = 0x21
    struct.pack_into("<I", packet, 4, server_word)
    struct.pack_into("<H", packet, 16, len(packet) - AV_HEADER_SIZE)
    packet[28:32] = b"\0\x01\0\x01"
    packet[32] = 1
    packet[36:56] = AV_CAPABILITIES
    # status=0 at 24; auth/config at 56..59 and AV-on-connect results at 60..61
    # stay zero, matching the app's unauthenticated reverse AV server.
    return bytes(packet)


def build_talk_audio(pcm: bytes, relseq: int, frame_number: int, *,
                     timestamp_ms: int = 0) -> bytes:
    """Build one native non-FEC audio AV packet, with a single complete frame.

    The 8-byte AV header and 20-byte frame header follow _sendAVFrameFifo
    (0x13078) / avPutDataToAVFrameFifo (0x13dbc), without optional FEC parity.
    A 16-byte codec-0x8c/flags-2 FRAMEINFO follows PCM, as in the app. At most
    1008 PCM bytes fit the native 1024-byte fragment; use 640-byte chunks at
    40 ms intervals to match AudioSpeaker. Native app talk timestamps are zero.

    Counters are zero-based host counters; only their wire widths wrap. The
    global frame number starts at zero, while the audio frame number starts
    at one. Native initialization (0x1ff4e) seeds the global counter with -1
    before its first increment; the receiver waits for global frame zero.
    Resends must reuse the original frame_number while incrementing relseq.
    """
    if (not isinstance(pcm, bytes) or not pcm or len(pcm) % PCM_SAMPLE_WIDTH
            or len(pcm) > TALK_MAX_PCM_BYTES):
        raise AVProtocolError("Talk PCM must contain 1..504 complete 16-bit samples")
    relseq = _counter(relseq, "relseq")
    frame_number = _counter(frame_number, "frame_number")
    if type(timestamp_ms) is not int or not 0 <= timestamp_ms <= 0xFFFFFFFF:
        raise AVProtocolError("timestamp_ms must be an unsigned 32-bit integer")
    info = bytearray(PCM_FRAMEINFO_SIZE)
    struct.pack_into("<HB", info, 0, PCM_CODEC_ID, 2)
    struct.pack_into("<I", info, 12, timestamp_ms)
    payload = pcm + info
    packet = bytearray(28 + len(payload))
    # Audio subtype 3; last fragment and end-of-current-send-batch flags (1|4).
    struct.pack_into("<BBHHH", packet, 0, 3, 5, AV_PROTOCOL_VERSION,
                     relseq & 0xFFFF, 0)
    struct.pack_into("<BBHHHHHII", packet, 8, 3, 1, frame_number & 0xFFFF,
                     1, PCM_FRAMEINFO_SIZE, len(payload), 0,
                     frame_number & 0xFFFFFFFF,
                     (frame_number + 1) & 0xFFFFFFFF)
    packet[28:] = payload
    return bytes(packet)
