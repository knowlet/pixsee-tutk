"""Managed Pixsee producer -> FFmpeg -> MediaMTX protocol gateway.

MediaMTX 1.21.3 is the supported API/configuration contract. No camera session
is created by import or configuration validation. Credentials never enter argv.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from fractions import Fraction
import fcntl
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from urllib.request import ProxyHandler, Request, build_opener
import uuid

from pixsee_config import PixseeCredentials


def _viewer_pair(username, password):
    if username is None and password is None:
        return None, None
    if (not isinstance(username, str) or
            not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username) or username == "any"):
        raise ValueError("viewer username must be 1-64 ASCII letters, digits, dots, dashes or underscores")
    try:
        valid = (isinstance(password, str) and 1 <= len(password.encode("utf-8")) <= 256
                 and all(ord(c) >= 32 and ord(c) != 127 for c in password))
    except UnicodeError:
        valid = False
    if not valid:
        raise ValueError("viewer password must be 1-256 UTF-8 bytes without control characters")
    return username, password


def _json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("invalid JSON constant")

    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


def load_viewer_credentials(path=None, environ=None):
    """Return (username, password); an explicit JSON file takes precedence.

    No partial merge of a file and environment is performed. Errors omit values.
    """
    env = os.environ if environ is None else environ
    if path is not None:
        try:
            with open(path, "rb") as handle:
                data = handle.read(4097)
            if len(data) > 4096:
                raise ValueError()
            value = _json(data)
            if not isinstance(value, dict) or set(value) != {"username", "password"}:
                raise ValueError()
        except (OSError, ValueError, UnicodeError):
            raise ValueError("viewer credential file must contain only username and password") from None
        return _viewer_pair(value["username"], value["password"])
    return _viewer_pair(env.get("PIXSEE_GATEWAY_USERNAME"), env.get("PIXSEE_GATEWAY_PASSWORD"))


def _ipv4(value, label):
    try:
        if not isinstance(value, str):
            raise ValueError()
        address = ipaddress.IPv4Address(value)
        if address.is_unspecified or address.is_multicast or int(address) == 0xffffffff:
            raise ValueError()
    except (ValueError, TypeError):
        raise ValueError(f"{label} must be a unicast IPv4 address") from None
    return address


@dataclass(frozen=True)
class GatewayConfig:
    camera_ip: str
    camera_credentials: PixseeCredentials = field(repr=False)
    bind_host: str = "127.0.0.1"
    advertised_host: str | None = None
    rtsp_port: int = 8554
    onvif_port: int = 8080
    hls_port: int = 8888
    rtp_port: int = 8000
    rtcp_port: int = 8001
    api_port: int = 9997
    stream_path: str = "pixsee"
    username: str | None = None
    password: str | None = field(default=None, repr=False)
    discovery: bool = False
    with_audio: bool = True
    hls: bool = True
    mediamtx: str = "mediamtx"
    ffmpeg: str = "ffmpeg"
    ffprobe: str = "ffprobe"
    state_path: str = ".pixsee-gateway-state.json"
    camera_timeout: float = 20
    media_timeout: float = 15
    startup_timeout: float = 30
    duration: float | None = None
    openssl_library: str | None = None
    verbose: bool = False

    def __post_init__(self):
        _ipv4(self.camera_ip, "camera_ip")
        if not isinstance(self.camera_credentials, PixseeCredentials):
            raise ValueError("camera_credentials must be validated PixseeCredentials")
        for name in ("discovery", "with_audio", "hls", "verbose"):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name} must be a boolean")
        if self.bind_host not in ("127.0.0.1", "0.0.0.0"):
            raise ValueError("bind_host must be 127.0.0.1 or 0.0.0.0")
        _viewer_pair(self.username, self.password)
        if self.bind_host == "0.0.0.0":
            if self.advertised_host is None:
                raise ValueError("LAN binding requires an explicit advertised_host")
            if _ipv4(self.advertised_host, "advertised_host").is_loopback:
                raise ValueError("LAN advertised_host must not be loopback")
            if self.username is None:
                raise ValueError("LAN binding requires viewer username and password")
        elif self.advertised_host not in (None, "127.0.0.1"):
            raise ValueError("loopback binding can only advertise 127.0.0.1")
        if self.discovery and self.bind_host != "0.0.0.0":
            raise ValueError("discovery requires LAN binding and an explicit advertised_host")
        ports = [self.rtsp_port, self.onvif_port, self.hls_port, self.rtp_port,
                 self.rtcp_port, self.api_port]
        if any(type(p) is not int or not 1024 <= p <= 65535 for p in ports):
            raise ValueError("gateway ports must be integers between 1024 and 65535")
        # MediaMTX v1.21.3 uses gortsplib v5.6.7 Server.Start: an even RTP
        # listener followed immediately by its RTCP listener is mandatory.
        if self.rtp_port % 2 or self.rtcp_port != self.rtp_port + 1:
            raise ValueError("RTP port must be even and RTCP port must equal RTP port + 1")
        if len(set(ports)) != len(ports) or (self.discovery and 3702 in ports):
            raise ValueError("gateway ports must be distinct, including discovery")
        if not isinstance(self.stream_path, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", self.stream_path):
            raise ValueError("stream_path must contain 1-64 ASCII letters, digits, underscores or dashes")
        for name in ("camera_timeout", "media_timeout", "startup_timeout", "duration"):
            value = getattr(self, name)
            if name == "duration" and value is None:
                continue
            if (type(value) not in (int, float) or not math.isfinite(value) or
                    not 0 < value <= 86400):
                raise ValueError(f"{name} must be finite and between 0 and 86400 seconds")
        if self.camera_timeout > 120:
            raise ValueError("camera_timeout must not exceed 120 seconds")
        for name in ("mediamtx", "ffmpeg", "ffprobe", "state_path"):
            value = getattr(self, name)
            if not isinstance(value, (str, os.PathLike)) or not os.fspath(value) or "\x00" in os.fspath(value):
                raise ValueError(f"{name} must be a nonempty path")
        if self.openssl_library is not None and (not isinstance(self.openssl_library, str)
                                                or not self.openssl_library or "\x00" in self.openssl_library):
            raise ValueError("openssl_library must be a nonempty path")

    @property
    def host(self):
        return self.advertised_host or "127.0.0.1"

    @property
    def local_rtsp_url(self):
        return f"rtsp://127.0.0.1:{self.rtsp_port}/{self.stream_path}"


def mediamtx_config(config):
    """Generate the pinned backend contract; returned dict contains a secret."""
    users = [{"user": "any", "ips": ["127.0.0.1", "::1"], "permissions": [
        {"action": "publish", "path": config.stream_path},
        {"action": "read", "path": config.stream_path}, {"action": "api"}]}]
    if config.username is not None:
        users.append({"user": config.username, "pass": config.password, "permissions": [
            {"action": "read", "path": config.stream_path}]})
    return {"logLevel": "warn", "logDestinations": ["stdout"],
            "authMethod": "internal", "authInternalUsers": users,
            "api": True, "apiAddress": f"127.0.0.1:{config.api_port}",
            "rtsp": True, "rtspAddress": f"{config.bind_host}:{config.rtsp_port}",
            "rtspTransports": ["tcp", "udp"], "rtspAuthMethods": ["basic", "digest"],
            "rtpAddress": f"{config.bind_host}:{config.rtp_port}",
            "rtcpAddress": f"{config.bind_host}:{config.rtcp_port}",
            "hls": config.hls, "hlsAddress": f"{config.bind_host}:{config.hls_port}",
            "hlsVariant": "mpegts", "hlsAllowOrigins": [],
            "rtmp": False, "webrtc": False, "srt": False, "moq": False,
            "playback": False, "metrics": False, "pprof": False,
            "paths": {config.stream_path: {"source": "publisher", "overridePublisher": False}}}


def _base_env():
    return {key: value for key, value in os.environ.items()
            if not key.startswith("PIXSEE_") and not key.startswith("MTX_")}


def producer_command(config):
    command = [sys.executable, "-m", "pixsee", "stream", "--profile", "custom",
               "--camera-ip", config.camera_ip, "--timeout", str(config.camera_timeout)]
    if config.with_audio:
        command.append("--audio")
    if config.openssl_library:
        command.extend(["--openssl-library", config.openssl_library])
    return command


def publisher_command(config, ffmpeg):
    command = [ffmpeg, "-hide_banner", "-loglevel", "warning", "-nostdin",
               "-f", "mpegts", "-i", "pipe:0", "-map", "0:v:0"]
    if config.with_audio:
        # RTSP writes AAC configuration before packets; ADTS stream-copy lacks
        # that extradata even with aac_adtstoasc. Re-encode only the audio.
        command.extend(["-map", "0:a:0", "-c:a", "aac", "-ar", "8000",
                        "-ac", "1", "-b:a", "24k"])
    command.extend(["-c:v", "copy", "-f", "rtsp", "-rtsp_transport", "tcp",
                    "-muxdelay", "0.1", config.local_rtsp_url])
    return command


class _Process:
    """Own an entire child group; drain diagnostics without retaining secrets."""
    def __init__(self, command, *, env=None, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL):
        self.auth_rejected = threading.Event()
        self._drain_stop = threading.Event()
        self.stopped = False
        self.process = subprocess.Popen(command, stdin=stdin, stdout=stdout,
                                        stderr=subprocess.PIPE, env=env or _base_env(),
                                        start_new_session=True)
        os.set_blocking(self.process.stderr.fileno(), False)
        self.thread = threading.Thread(target=self._drain, daemon=True)
        self.thread.start()

    def _read_stderr_chunk(self):
        return os.read(self.process.stderr.fileno(), 4096)

    def _drain(self):
        # Only retain a bounded window to recognize our producer's explicit
        # credential rejection. No raw diagnostic text is stored or surfaced.
        tail = b""
        try:
            while not self._drain_stop.is_set():
                readable, _, _ = select.select([self.process.stderr], [], [], 0.1)
                if not readable:
                    continue
                try:
                    chunk = self._read_stderr_chunk()
                except BlockingIOError:
                    continue
                if not chunk:
                    break
                tail = (tail + chunk)[-8192:]
                if any(marker in tail for marker in (
                    b"Camera rejected the IOTC auth key", b"Camera rejected AV login",
                    b"DTLS authentication timed out; check the selected device password",
                )):
                    self.auth_rejected.set()
        except (OSError, ValueError):
            pass

    def stop(self):
        if self.stopped:
            return
        # On macOS an exited, unreaped group leader can make killpg raise EPERM.
        # Reap it first, while still signalling any surviving descendants.
        self.process.poll()
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(self.process.pid, sig)
            except ProcessLookupError:
                break
            except PermissionError:
                # The leader may have exited between poll and killpg. Only
                # forgive that race after both reaping and proving group absence.
                self.process.poll()
                if self.process.returncode is None:
                    raise
                try:
                    os.killpg(self.process.pid, 0)
                except ProcessLookupError:
                    break
                raise
            try:
                self.process.wait(timeout=1)
                # A parent may have exited while a descendant still owns pipes.
                if sig != signal.SIGKILL:
                    try:
                        os.killpg(self.process.pid, 0)
                    except ProcessLookupError:
                        break
                else:
                    break
            except subprocess.TimeoutExpired:
                continue
        self.process.wait(timeout=2)
        # A descendant outside the original group can retain a pipe writer.
        # Cancel raw reads before closing streams; buffered close can otherwise
        # wait indefinitely for a reader holding its internal lock.
        self._drain_stop.set()
        self.thread.join(timeout=1)
        if self.thread.is_alive():
            raise RuntimeError("media diagnostic reader did not stop")
        for stream in (self.process.stdout, self.process.stderr):
            if stream is not None:
                stream.close()
        self.stopped = True


def _capture(command, timeout, max_bytes=1024 * 1024):
    child = _Process(command, stdout=subprocess.PIPE)
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        descriptor = child.process.stdout.fileno()
        os.set_blocking(descriptor, False)
        eof = False
        # The deadline covers pipe EOF as well as the group leader: an exited
        # helper does not prove that all inherited output writers have closed.
        while not eof or child.process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("media helper exceeded its output or time limit")
            if eof:
                time.sleep(min(0.03, remaining))
                continue
            readable, _, _ = select.select([descriptor], [], [], min(0.03, remaining))
            if not readable:
                continue
            try:
                part = os.read(descriptor, 65536)
            except BlockingIOError:
                continue
            if not part:
                eof = True
            elif len(output) + len(part) > max_bytes:
                raise RuntimeError("media helper exceeded its output or time limit")
            else:
                output.extend(part)
        if child.process.returncode != 0:
            raise RuntimeError("media helper did not complete successfully")
        return bytes(output)
    finally:
        child.stop()


def probe_profile(config, ffprobe, *, timeout=None):
    from pixsee_onvif import MediaProfile

    limit = min(10, config.startup_timeout) if timeout is None else timeout
    wire = _capture([ffprobe, "-v", "error", "-rtsp_transport", "tcp", "-show_streams",
                     "-of", "json", config.local_rtsp_url], limit)
    try:
        streams = _json(wire)["streams"]
        video = next(s for s in streams if s.get("codec_type") == "video")
        if video.get("codec_name") != "h264":
            raise ValueError()
        width, height = int(video["width"]), int(video["height"])
        if not 1 <= width <= 16384 or not 1 <= height <= 16384:
            raise ValueError()
        fps = None
        for key in ("avg_frame_rate", "r_frame_rate"):
            try:
                value = float(Fraction(video.get(key, "0/0")))
                if math.isfinite(value) and 0 < value <= 240:
                    fps = value
                    break
            except (ValueError, ZeroDivisionError, TypeError):
                continue
        if fps is None:
            # Media1 GetVideoSources requires this; announcing a profile without
            # it would fail node-onvif/Scrypted bootstrap after a false ready.
            raise ValueError()
        audio_args = {}
        if config.with_audio:
            audio = next(s for s in streams if s.get("codec_type") == "audio")
            if audio.get("codec_name") != "aac":
                raise ValueError()
            rate, channels = int(audio["sample_rate"]), int(audio["channels"])
            if rate != 8000 or channels != 1:
                raise ValueError()
            # The owned publisher encodes AAC at a fixed 24 kbit/s target.
            audio_args = dict(audio_encoding="AAC", audio_sample_rate=rate,
                              audio_channels=channels, audio_bitrate=24)
        return MediaProfile(width=width, height=height, frame_rate=fps, **audio_args)
    except (ValueError, KeyError, TypeError, StopIteration, UnicodeError):
        raise RuntimeError("RTSP media metadata does not match the expected H.264/AAC producer") from None


class _Snapshots:
    def __init__(self, config, ffmpeg, healthy):
        self.config, self.ffmpeg, self.healthy = config, ffmpeg, healthy
        self.lock = threading.Lock()
        self.cached = None
        self.expires = 0

    def clear(self):
        with self.lock:
            self.cached = None
            self.expires = 0

    def __call__(self):
        if not self.healthy() or not self.lock.acquire(timeout=0.1):
            raise RuntimeError("snapshot is temporarily unavailable")
        try:
            if not self.healthy():
                raise RuntimeError("snapshot is temporarily unavailable")
            if self.cached is not None and time.monotonic() < self.expires:
                return self.cached
            data = _capture([self.ffmpeg, "-hide_banner", "-loglevel", "error", "-nostdin",
                             "-rtsp_transport", "tcp", "-i", self.config.local_rtsp_url,
                             "-map", "0:v:0", "-frames:v", "1", "-f", "image2pipe",
                             "-c:v", "mjpeg", "pipe:1"], 8, max_bytes=16 * 1024 * 1024)
            if not data.startswith(b"\xff\xd8") or not data.endswith(b"\xff\xd9"):
                raise RuntimeError("snapshot encoder returned an invalid JPEG")
            if not self.healthy():
                raise RuntimeError("snapshot source is no longer available")
            self.cached, self.expires = data, time.monotonic() + 1
            return data
        finally:
            self.lock.release()


@contextmanager
def _identity(path):
    path = Path(path).absolute()
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    lock = os.open(str(path) + ".lock", flags, 0o600)
    try:
        os.fchmod(lock, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("gateway state is already in use") from None
        if path.is_symlink():
            raise ValueError("gateway state must not be a symbolic link")
        if path.exists():
            try:
                with path.open("rb") as handle:
                    raw = handle.read(4097)
                if len(raw) > 4096:
                    raise ValueError()
                state = _json(raw)
                device_uuid = str(uuid.UUID(state["device_uuid"]))
                previous = state["instance_id"]
                if type(previous) is not int or not 0 <= previous < 4294967295:
                    raise ValueError()
                instance = previous + 1
            except (OSError, ValueError, TypeError, KeyError, UnicodeError):
                raise ValueError("gateway state file is invalid; preserve it for recovery") from None
        else:
            device_uuid, instance = str(uuid.uuid4()), 1
        state = {"device_uuid": device_uuid, "instance_id": instance}
        fd, temporary = tempfile.mkstemp(prefix=".pixsee-state-", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                os.fchmod(handle.fileno(), 0o600)
                json.dump(state, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        yield state
    finally:
        os.close(lock)


@contextmanager
def _signals(stop):
    previous = {}
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.getsignal(sig)
            signal.signal(sig, lambda *_: stop.set())
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def _api(config, endpoint):
    request = Request(f"http://127.0.0.1:{config.api_port}/v3/{endpoint}")
    with build_opener(ProxyHandler({})).open(request, timeout=1) as response:
        raw = response.read(262145)
    if len(raw) > 262144:
        raise ValueError("backend API response exceeded its limit")
    return _json(raw)


def _check_ports(config):
    """Fail before a camera child if a requested listener is already occupied."""
    listeners = [(socket.SOCK_STREAM, config.bind_host, config.rtsp_port),
                 (socket.SOCK_STREAM, config.bind_host, config.onvif_port),
                 (socket.SOCK_STREAM, "127.0.0.1", config.api_port),
                 (socket.SOCK_DGRAM, config.bind_host, config.rtp_port),
                 (socket.SOCK_DGRAM, config.bind_host, config.rtcp_port)]
    if config.hls:
        listeners.append((socket.SOCK_STREAM, config.bind_host, config.hls_port))
    sockets = []
    try:
        for kind, host, port in listeners:
            listener = socket.socket(socket.AF_INET, kind)
            sockets.append(listener)
            if kind == socket.SOCK_STREAM:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((host, port))
    except OSError:
        raise RuntimeError("a requested gateway port is already in use or unavailable") from None
    finally:
        for listener in sockets:
            listener.close()


def _ingress(data, with_audio):
    if not isinstance(data, dict) or data.get("online") is not True or data.get("available") is not True:
        return None
    tracks = data.get("tracks2", [])
    if not isinstance(tracks, list):
        return None
    codecs = {t.get("codec") for t in tracks if isinstance(t, dict)}
    if "H264" not in codecs or (with_audio and "MPEG-4 Audio" not in codecs):
        return None
    count = data.get("inboundBytes")
    if type(count) is not int or count < 0:
        return None
    source = data.get("source")
    if not isinstance(source, dict) or not isinstance(source.get("id"), str):
        return None
    return source["id"], count


def _start_pair(config, binaries):
    creds = config.camera_credentials
    env = _base_env()
    env.update(PIXSEE_ACCOUNT=creds.account, PIXSEE_PASSWORD=creds.password,
               PIXSEE_AUTH_KEY=creds.auth_key, PIXSEE_FFMPEG=binaries["ffmpeg"])
    if creds.uid is not None:
        env["PIXSEE_UID"] = creds.uid
    env["PATH"] = str(Path(binaries["ffmpeg"]).parent) + os.pathsep + env.get("PATH", "")
    producer = _Process(producer_command(config), env=env, stdout=subprocess.PIPE)
    try:
        publisher = _Process(publisher_command(config, binaries["ffmpeg"]),
                             stdin=producer.process.stdout)
    except BaseException:
        producer.stop()
        raise
    finally:
        producer.process.stdout.close()
    return producer, publisher


def run_gateway(config, *, stop_event=None, on_ready=None):
    """Run until stopped/duration; announce once only after verified ingestion.

    All child diagnostics are consumed privately. Caller owns user-facing JSON.
    The on_ready callback and return value contain no embedded URL credentials.
    """
    if not isinstance(config, GatewayConfig):
        raise ValueError("config must be GatewayConfig")
    config.__post_init__()
    if stop_event is not None and stop_event.is_set():
        return {"ready": False, "status": "stopped", "restarts": 0}
    from pixsee_onvif import OnvifConfig, OnvifServer

    binaries = {}
    for name in ("mediamtx", "ffmpeg", "ffprobe"):
        found = shutil.which(os.fspath(getattr(config, name)))
        if found is None:
            raise RuntimeError(f"required executable is unavailable: {name}")
        binaries[name] = found
    version = _capture([binaries["mediamtx"], "--version"], 5, max_bytes=4096).decode("utf-8", "replace").strip()
    if version != "v1.21.3":
        raise RuntimeError("this gateway requires MediaMTX v1.21.3")
    _check_ports(config)
    stop = stop_event if stop_event is not None else threading.Event()
    started = time.monotonic()
    result = {"ready": False, "status": "stopped", "restarts": 0}
    shared = {"profile": None, "healthy": False}
    snapshots = _Snapshots(config, binaries["ffmpeg"], lambda: shared["healthy"] and not stop.is_set())
    backend = producer = publisher = onvif = discovery = None
    backoff, retry_at, pair_started = 0.5, started, started
    last_ingress, last_progress = None, started

    def stopping():
        if stop.is_set():
            return True
        elapsed = time.monotonic() - started
        if config.duration is not None and elapsed >= config.duration:
            if not result["ready"]:
                raise RuntimeError("gateway duration expired before verified media was available")
            return True
        if not result["ready"] and elapsed >= config.startup_timeout:
            raise RuntimeError("gateway startup timed out before verified media was available")
        return False

    with _signals(stop), _identity(config.state_path) as identity, tempfile.TemporaryDirectory(prefix="pixsee-gateway-") as directory:
        config_path = Path(directory) / "mediamtx.json"
        fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(mediamtx_config(config), handle)
        _capture([binaries["mediamtx"], "--validate-conf", str(config_path)], 5)
        try:
            while not stopping():
                now = time.monotonic()
                if backend is None:
                    if now < retry_at:
                        stop.wait(min(0.2, retry_at - now))
                        continue
                    backend = _Process([binaries["mediamtx"], str(config_path)])
                backend_alive = backend.process.poll() is None
                pair_alive = (producer is not None and producer.process.poll() is None
                              and publisher.process.poll() is None)
                if producer is not None and producer.process.poll() is not None:
                    producer.thread.join(timeout=0.1)
                if producer is not None and producer.auth_rejected.is_set():
                    raise RuntimeError("camera authentication was rejected; verify the selected credentials")
                data = None
                if backend_alive:
                    try:
                        data = _api(config, "paths/get/" + config.stream_path)
                    except (OSError, ValueError):
                        pass
                ingress = _ingress(data, config.with_audio)
                progressed = False
                if ingress is not None:
                    if last_ingress is not None and ingress[0] != last_ingress[0]:
                        shared.update(healthy=False, profile=None)
                        snapshots.clear()
                    if last_ingress is not None and ingress[0] == last_ingress[0] and ingress[1] > last_ingress[1]:
                        last_progress, progressed = now, True
                    last_ingress = ingress
                else:
                    shared["healthy"] = False
                if progressed and shared["profile"] is not None:
                    shared["healthy"] = True
                stall_limit = (config.media_timeout if last_ingress is not None else
                               config.camera_timeout + config.media_timeout)
                pair_failed = producer is not None and (not pair_alive or now - last_progress > stall_limit)
                if not backend_alive or pair_failed:
                    shared.update(healthy=False, profile=None)
                    snapshots.clear()
                    for process in (publisher, producer):
                        if process is not None:
                            process.stop()
                    publisher = producer = None
                    last_ingress = None
                    if not backend_alive:
                        backend.stop()
                        backend = None
                    result["restarts"] += 1
                    retry_at = time.monotonic() + backoff
                    backoff = min(8, backoff * 2)
                    continue
                if producer is None and now >= retry_at:
                    try:
                        _api(config, "info")
                    except (OSError, ValueError):
                        stop.wait(0.2)
                        continue
                    producer, publisher = _start_pair(config, binaries)
                    pair_started = last_progress = time.monotonic()
                    last_ingress = None
                if progressed and pair_alive and shared["profile"] is None:
                    remaining = [10.0]
                    elapsed = time.monotonic() - started
                    if not result["ready"]:
                        remaining.append(config.startup_timeout - elapsed)
                    if config.duration is not None:
                        remaining.append(config.duration - elapsed)
                    if stopping():
                        break
                    try:
                        profile = probe_profile(config, binaries["ffprobe"], timeout=min(remaining))
                    except RuntimeError:
                        stop.wait(0.2)
                        continue
                    # Probing can block. Never announce stale metadata after a
                    # stop/deadline, process exit, or replacement of the source.
                    if stopping():
                        break
                    try:
                        current = _ingress(_api(config, "paths/get/" + config.stream_path), config.with_audio)
                    except (OSError, ValueError):
                        current = None
                    if stopping():
                        break
                    if (backend.process.poll() is not None or producer.process.poll() is not None
                            or publisher.process.poll() is not None or current is None
                            or current[0] != ingress[0] or current[1] <= ingress[1]):
                        shared.update(profile=None, healthy=False)
                        last_ingress = current
                        stop.wait(0.2)
                        continue
                    last_ingress, last_progress = current, time.monotonic()
                    shared.update(profile=profile, healthy=True)
                    if onvif is None:
                        onvif = OnvifServer(OnvifConfig(
                            device_uuid=identity["device_uuid"], serial_number=identity["device_uuid"],
                            bind_host=config.bind_host, port=config.onvif_port, advertised_host=config.host,
                            rtsp_port=config.rtsp_port, rtsp_path=config.stream_path,
                            username=config.username, password=config.password, discoverable=config.discovery),
                            profile_provider=lambda: shared["profile"] if shared["healthy"] else None,
                            snapshot_provider=snapshots)
                        onvif.start()
                        if config.discovery:
                            from pixsee_discovery import DiscoveryService
                            discovery = DiscoveryService(interface_ip=config.host,
                                device_uuid=identity["device_uuid"], xaddr=onvif.device_url,
                                scopes=["onvif://www.onvif.org/type/video_encoder",
                                        "onvif://www.onvif.org/name/Pixsee"],
                                instance_id=identity["instance_id"])
                            discovery.start()
                    if stopping():
                        break
                    result.update(ready=True, status="ready", rtsp_url=onvif.rtsp_url, onvif_url=onvif.device_url,
                                  snapshot_url=onvif.snapshot_url,
                                  hls_url=(f"http://{config.host}:{config.hls_port}/{config.stream_path}/index.m3u8" if config.hls else None),
                                  authentication_required=config.username is not None,
                                  discovery=config.discovery, metadata=asdict(profile))
                    if on_ready is not None:
                        callback, on_ready = on_ready, None
                        callback(dict(result))
                if progressed and time.monotonic() - pair_started >= config.media_timeout:
                    backoff = 0.5
                if discovery is not None and (not discovery.running or discovery.error is not None):
                    raise RuntimeError("discovery service stopped unexpectedly")
                stop.wait(0.2)
        finally:
            pending_error = sys.exc_info()[0] is not None
            cleanup_failed = False
            result["healthy_at_stop"] = shared["healthy"]
            shared.update(healthy=False, profile=None)
            stop.set()
            for service in (discovery, onvif):
                if service is not None:
                    try:
                        service.close()
                    except Exception:
                        cleanup_failed = True
            try:
                snapshots.clear()
            except Exception:
                cleanup_failed = True
            for process in (publisher, producer, backend):
                if process is not None:
                    try:
                        process.stop()
                    except Exception:
                        cleanup_failed = True
            if cleanup_failed and not pending_error:
                raise RuntimeError("gateway shutdown could not confirm complete cleanup")
    result["status"] = "stopped"
    return result
