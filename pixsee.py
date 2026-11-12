#!/usr/bin/env python3
"""Pixsee LAN discovery, authenticated streaming, audio recording and talk.

Examples (put options after the subcommand):
  python3 pixsee.py discover --camera-ip 192.168.0.7
  python3 pixsee.py probe --camera-ip 192.168.0.7 --profile legacy
  python3 pixsee.py stream --camera-ip 192.168.0.7 --profile legacy > live.ts

Custom credentials come from --credentials JSON or PIXSEE_PASSWORD/PIXSEE_AUTH_KEY;
passwords and keys are deliberately not accepted on the command line. The default
profile is custom. --firmware explicitly opts into an APK-based profile suggestion;
--profile overrides it. Firmware alone does not prove which credentials a device
uses (the tested 1.006.25 camera requires the explicit legacy profile).

Streaming defaults to H.264 video; --audio adds AAC using FFmpeg. Talk plays the
selected local audio through the camera speaker and must be explicitly invoked.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager, redirect_stdout, ExitStack
from itertools import chain
import ipaddress
import json
import math
import os
import re
import sys
import tempfile
import time

from cuboai_mpegts import TSMuxer
from pixsee_config import load_credentials, profile_for_firmware
from pixsee_media import AACEncoder, MediaClock, PCMTimeline, pcm_input, validate_pcm, wav_writer
from pixsee_session import PixseeConnectionError, PixseeSession, discover


def _seconds(value):
    try:
        result = float(value)
    except (ValueError, TypeError):
        raise argparse.ArgumentTypeError("must be a number of seconds") from None
    if not math.isfinite(result) or not 0 < result <= 120:
        raise argparse.ArgumentTypeError("must be greater than 0 and at most 120 seconds")
    return result


def _ip(value):
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        raise argparse.ArgumentTypeError("must be an IPv4 address") from None
    if address.is_multicast or address.is_unspecified or str(address) == "255.255.255.255":
        raise argparse.ArgumentTypeError("must identify one camera, not a broadcast/multicast address")
    return str(address)


def build_parser():
    parser = argparse.ArgumentParser(description="Connect to your Pixsee camera over the LAN.")
    commands = parser.add_subparsers(dest="command", required=True)
    discovery = commands.add_parser("discover", help="identify one camera without logging in")
    probe = commands.add_parser("probe", help="authenticate and require at least one video frame")
    stream = commands.add_parser("stream", help="write MPEG-TS or raw H.264; optionally include audio")
    audio = commands.add_parser("audio", help="record camera audio as WAV or PCM16LE mono 8 kHz")
    talk = commands.add_parser("talk", help="play an audio input through the camera speaker")
    for command in (discovery, probe, stream, audio, talk):
        command.add_argument("--camera-ip", type=_ip, default=os.environ.get("PIXSEE_CAMERA_IP"),
                             help="camera IPv4 address (or PIXSEE_CAMERA_IP)")
        command.add_argument("--timeout", type=_seconds,
                             default=3.0 if command is discovery else 20.0,
                             help="connection/discovery timeout in seconds (maximum 120)")
        command.add_argument("--verbose", action="store_true", help="write diagnostic messages to stderr")
    discovery.add_argument("--show-uid", action="store_true", help="include the full device UID in JSON")
    for command in (probe, stream, audio, talk):
        command.add_argument("--profile", choices=("custom", "legacy", "current"),
                             help="choose one profile; default custom; overrides --firmware")
        command.add_argument("--firmware", help="suggest a profile using APK firmware rules; --profile wins")
        command.add_argument("--pixsee-play", action="store_true", help="use Pixsee Play firmware thresholds")
        command.add_argument("--credentials", metavar="JSON", help="private credential JSON file")
        command.add_argument("--uid", help="device UID; otherwise discover it (or PIXSEE_UID)")
        command.add_argument("--account", help="AV account (default admin, or PIXSEE_ACCOUNT)")
        command.add_argument("--openssl-library", metavar="PATH", help="installed OpenSSL 3.2+ libssl path")
        command.add_argument("--duration", type=_seconds,
                             default=5.0 if command is probe else None,
                             help="duration in seconds (probe default 5; otherwise until stopped/input ends)")
    stream.add_argument("--format", choices=("mpegts", "h264"), default="mpegts",
                        help="video container (default mpegts)")
    stream.add_argument("--audio", action="store_true", help="add camera audio as AAC (MPEG-TS only; requires FFmpeg)")
    audio.add_argument("--format", choices=("wav", "s16le"), default="wav",
                       help="audio format (default wav); PCM is 8000 Hz, mono, 16-bit little-endian")
    for command in (stream, audio):
        command.add_argument("--output", metavar="FILE", default="-", help="output file, or - for stdout (default)")
        command.add_argument("--overwrite", action="store_true", help="allow replacing the selected output file")
    talk.add_argument("--input", metavar="FILE", required=True, help="audio file, or - for stdin")
    talk.add_argument("--input-format", choices=("auto", "s16le"), default="auto",
                      help="auto uses FFmpeg; s16le accepts PCM16LE mono 8000 Hz directly")
    return parser


def _credentials(args):
    profile = args.profile
    if profile is None:
        profile = (profile_for_firmware(args.firmware, is_pixsee_play=args.pixsee_play)
                   if args.firmware is not None else "custom")
    return load_credentials(profile=profile, config_path=args.credentials,
                            uid=args.uid, account=args.account)


def _safe_error(error, credentials=None):
    message = str(error) or type(error).__name__
    if credentials is not None:
        for value in (credentials.password, credentials.auth_key, credentials.uid):
            if value:
                message = message.replace(value, "[redacted]")
    return message


def _json_result(value):
    print(json.dumps(value, ensure_ascii=True, sort_keys=True))


def _run_discover(args):
    try:
        with redirect_stdout(sys.stderr):
            reply, peer = discover(args.camera_ip, timeout=args.timeout)
        result = {"ok": True, "camera_ip": peer[0], "port": peer[1],
                  "device_name": reply.device_name, "sdk_version": reply.sdk_version,
                  "uid": reply.uid if args.show_uid else "[redacted]"}
        # Device labels are untrusted and may happen to contain the UID as text.
        if not args.show_uid and reply.uid:
            result["device_name"] = result["device_name"].replace(reply.uid, "[redacted]")
        _json_result(result)
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        _json_result({"ok": False, "camera_ip": args.camera_ip, "error": str(error)})
        return 1


def _run_probe(args, credentials):
    result = {"ok": False, "camera_ip": args.camera_ip, "authenticated": False,
              "video_frames": 0, "video_bytes": 0, "video_codec": "h264", "audio": False}
    session = None
    try:
        with redirect_stdout(sys.stderr):
            session = PixseeSession(args.camera_ip, credentials, verbose=args.verbose,
                                    openssl_library=args.openssl_library)
            session.connect(timeout=args.timeout)
            result["authenticated"] = bool(session.authenticated)
            if not result["authenticated"]:
                raise PixseeConnectionError("AV authentication was not confirmed")
            for frame, _ in session.video_frames_timed(duration=args.duration, max_frames=1):
                if frame:
                    result["video_frames"] += 1
                    result["video_bytes"] += len(frame)
        if result["video_frames"] == 0:
            result["error"] = "Authenticated, but no video frame arrived before the probe ended"
        else:
            result["ok"] = True
    except (OSError, ValueError, RuntimeError) as error:
        result["error"] = _safe_error(error, credentials)
    finally:
        if session is not None:
            with redirect_stdout(sys.stderr):
                session.disconnect()
    _json_result(result)
    return 0 if result["ok"] else 1


@contextmanager
def _media_output(args):
    if args.output == "-":
        output = getattr(sys.stdout, "buffer", None)
        if output is None:
            raise ValueError("stdout must support binary media output")
        yield output
        output.flush()
        return
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if args.overwrite else os.O_EXCL)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(args.output, flags, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        yield output


class _VideoClock:
    """Prefer camera millisecond deltas; use elapsed time for missing/bad values."""
    def __init__(self):
        self.previous_timestamp = None
        self.previous_arrival = None
        self.pts_ms = 0.0

    def feed(self, metadata):
        now = time.monotonic() * 1000.0
        timestamp = (metadata or {}).get("timestamp_ms")
        if type(timestamp) is not int or not 0 <= timestamp <= 0xffffffff:
            timestamp = None
        if self.previous_arrival is not None:
            delta = max(1.0, now - self.previous_arrival)
            if timestamp is not None and self.previous_timestamp is not None:
                camera_delta = (timestamp - self.previous_timestamp) & 0xffffffff
                if 0 < camera_delta <= 10000:
                    delta = camera_delta
            self.pts_ms += delta
        self.previous_timestamp = timestamp
        self.previous_arrival = now
        return round(self.pts_ms * 90)


_NAL_HEADER = re.compile(b"\x00\x00(?:\x00)?\x01(.)", re.DOTALL)


def _keyframe(frame, metadata):
    if metadata is not None and "keyframe" in metadata:
        return bool(metadata["keyframe"])
    return any((match.group(1)[0] & 0x1f) in (5, 7, 8)
               for match in _NAL_HEADER.finditer(frame))


def _run_stream(args, credentials):
    session = None
    count = 0
    # Opening the output precedes any networking, including existing-file errors.
    with ExitStack() as resources:
        output = resources.enter_context(_media_output(args))
        resources.enter_context(redirect_stdout(sys.stderr))
        encoder = AACEncoder() if args.audio else None
        if encoder is not None:
            resources.callback(encoder.close)
        try:
            session = PixseeSession(args.camera_ip, credentials, verbose=args.verbose,
                                    openssl_library=args.openssl_library)
            session.connect(timeout=args.timeout)
            if not session.authenticated:
                raise PixseeConnectionError("AV authentication was not confirmed")
            mux = TSMuxer(codec="h264", audio_codec="aac" if args.audio else None) if args.format == "mpegts" else None
            clock = MediaClock() if args.audio else _VideoClock()
            audio_count = 0
            frames = (session.av_frames_timed(duration=args.duration) if args.audio else
                      (("video", frame, metadata) for frame, metadata in session.video_frames_timed(duration=args.duration)))
            for kind, frame, metadata in frames:
                if not frame:
                    continue
                if kind == "audio":
                    validate_pcm(frame, metadata)
                    pts = clock.feed(kind, metadata, len(frame) // 2)
                    for adts, audio_pts in encoder.feed(frame, pts):
                        output.write(mux.mux_audio_au(adts, audio_pts, now_ms=audio_pts / 90))
                    output.flush()
                    audio_count += 1
                    continue
                if mux is None:
                    data = frame
                else:
                    pts = clock.feed(kind, metadata) if args.audio else clock.feed(metadata)
                    data = mux.mux_au(frame, pts, keyframe=_keyframe(frame, metadata), now_ms=pts / 90)
                output.write(data)
                output.flush()
                count += 1
            if encoder is not None and audio_count:
                for adts, pts in encoder.finish():
                    output.write(mux.mux_audio_au(adts, pts, now_ms=pts / 90))
                output.flush()
            if count == 0:
                raise PixseeConnectionError("Authenticated, but no video frames were received")
            if args.audio and audio_count == 0:
                raise PixseeConnectionError("Authenticated, but no audio frames were received")
            if args.verbose:
                print(f"[pixsee] delivered_video_frames={count} "
                      f"dropped_video_frames={session.video_dropped}", file=sys.stderr)
        finally:
            if session is not None:
                session.disconnect()
    return 0


def _run_audio(args, credentials):
    session = None
    count = 0
    with ExitStack() as resources:
        output = resources.enter_context(_media_output(args))
        resources.enter_context(redirect_stdout(sys.stderr))
        # WAV needs the final byte count in its header. A stdout pipe cannot be
        # rewound, so finite captures spool locally before emitting a valid file.
        destination = output
        if args.format == "wav" and args.output == "-":
            destination = resources.enter_context(tempfile.TemporaryFile(mode="w+b"))
        writer = wav_writer(destination) if args.format == "wav" else None
        clock, timeline = MediaClock(), PCMTimeline()

        def emit(pcm):
            if writer is None:
                output.write(pcm)
                output.flush()
            else:
                writer.writeframesraw(pcm)

        try:
            session = PixseeSession(args.camera_ip, credentials, verbose=args.verbose,
                                    openssl_library=args.openssl_library)
            session.connect(timeout=args.timeout)
            if not session.authenticated:
                raise PixseeConnectionError("AV authentication was not confirmed")
            try:
                for pcm, metadata in session.audio_frames_timed(duration=args.duration):
                    if not pcm:
                        continue
                    validate_pcm(pcm, metadata)
                    pts = clock.feed("audio", metadata, len(pcm) // 2)
                    for block, _ in timeline.feed(pcm, pts):
                        emit(block)
                    count += 1
                for block, _ in timeline.finish():
                    emit(block)
            finally:
                if writer is not None:
                    writer.close()
                    writer = None
            if not count:
                raise PixseeConnectionError("Authenticated, but no audio frames were received")
            if destination is not output:
                destination.seek(0)
                while block := destination.read(65536):
                    output.write(block)
                output.flush()
            if args.verbose:
                print(f"[pixsee] delivered_audio_frames={count}", file=sys.stderr)
        finally:
            if writer is not None:
                writer.close()
            if session is not None:
                session.disconnect()
    return 0


def _run_talk(args, credentials):
    session = None
    with pcm_input(args.input, args.input_format, args.duration) as chunks:
        first = next(chunks, None)
        if not first:
            raise ValueError("Audio input contains no playable samples")
        try:
            with redirect_stdout(sys.stderr):
                session = PixseeSession(args.camera_ip, credentials, verbose=args.verbose,
                                        openssl_library=args.openssl_library)
                session.connect(timeout=args.timeout)
                if not session.authenticated:
                    raise PixseeConnectionError("AV authentication was not confirmed")
                result = session.talk_pcm(chain((first,), chunks), timeout=min(args.timeout, 8),
                                          duration=args.duration)
        finally:
            if session is not None:
                with redirect_stdout(sys.stderr):
                    session.disconnect()
    _json_result({"ok": True, **result})
    return 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.camera_ip is None:
        parser.error("--camera-ip or PIXSEE_CAMERA_IP is required")
    if args.command == "stream" and args.audio and args.format != "mpegts":
        parser.error("--audio requires --format mpegts")
    if args.command == "audio" and args.format == "wav" and args.output == "-" and args.duration is None:
        parser.error("WAV output to stdout requires --duration; use --format s16le for continuous audio")
    if args.command == "discover":
        return _run_discover(args)
    credentials = None
    try:
        credentials = _credentials(args)
        if args.command == "probe":
            return _run_probe(args, credentials)
        if args.command == "audio":
            return _run_audio(args, credentials)
        if args.command == "talk":
            return _run_talk(args, credentials)
        return _run_stream(args, credentials)
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        # The viewer closed its pipe. Avoid both traceback and interpreter flush.
        if args.command in ("stream", "audio") and args.output == "-":
            try:
                replacement = os.open(os.devnull, os.O_WRONLY)
                os.dup2(replacement, sys.stdout.fileno())
                os.close(replacement)
            except (OSError, AttributeError):
                pass
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        message = _safe_error(error, credentials)
        if args.command == "probe":
            _json_result({"ok": False, "authenticated": False, "error": message})
        elif args.command == "talk":
            _json_result({"ok": False, "error": message})
        else:
            print(f"pixsee: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
