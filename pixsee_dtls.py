"""A socket-free DTLS 1.2 PSK client backed by installed OpenSSL >= 3.2.

Each returned bytes object is one complete UDP payload. Feed one received UDP
payload at a time; the datagram BIO pair preserves boundaries, including flights
containing several records. The caller owns addressing, I/O and overall timeout.
Call handle_timeout() when timeout_seconds expires, even without incoming data.
Use this object from one thread, and close it when finished.

OpenSSL references (checked against installed 3.5.9 headers):
https://docs.openssl.org/3.5/man3/BIO_s_dgram_pair/
https://docs.openssl.org/3.0/man3/SSL_CTX_set_psk_client_callback/
https://docs.openssl.org/3.5/man3/SSL_get_error/
https://docs.openssl.org/3.5/man3/DTLSv1_handle_timeout/
"""

from __future__ import annotations

import ctypes as C
import ctypes.util
from pathlib import Path
from typing import List, Optional


DEFAULT_CIPHERS = "PSK-AES128-GCM-SHA256:PSK-AES128-CBC-SHA256:PSK-AES128-CBC-SHA"
_DTLS_1_2 = 0xFEFD
_WANT_READ, _WANT_WRITE, _ZERO_RETURN = 2, 3, 6
_PSK_CALLBACK = C.CFUNCTYPE(C.c_uint, C.c_void_p, C.c_char_p,
                          C.c_void_p, C.c_uint, C.c_void_p, C.c_uint)


class DtlsError(RuntimeError):
    """DTLS failed without exposing identities, keys, or plaintext."""


class _Timeval(C.Structure):
    _fields_ = [("tv_sec", C.c_long), ("tv_usec", C.c_long)]


def _library_path(explicit: Optional[str]) -> str:
    if explicit:
        return str(explicit)
    for path in ("/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib",
                 "/usr/local/opt/openssl@3/lib/libssl.3.dylib"):
        if Path(path).is_file():
            return path
    found = ctypes.util.find_library("ssl")
    if found:
        return found
    raise DtlsError("OpenSSL 3.2 or newer is required")


class _OpenSSL:
    def __init__(self, library_path: Optional[str]):
        try:
            self.lib = C.CDLL(_library_path(library_path))
            # libssl's linked libcrypto symbols are available through this handle.
            signatures = {
                "OpenSSL_version_num": (C.c_ulong, []),
                "DTLS_client_method": (C.c_void_p, []),
                "SSL_CTX_new": (C.c_void_p, [C.c_void_p]),
                "SSL_CTX_free": (None, [C.c_void_p]),
                "SSL_CTX_ctrl": (C.c_long, [C.c_void_p, C.c_int, C.c_long, C.c_void_p]),
                "SSL_CTX_set_cipher_list": (C.c_int, [C.c_void_p, C.c_char_p]),
                "SSL_CTX_set_psk_client_callback": (None, [C.c_void_p, _PSK_CALLBACK]),
                "SSL_new": (C.c_void_p, [C.c_void_p]),
                "SSL_free": (None, [C.c_void_p]),
                "SSL_set_bio": (None, [C.c_void_p, C.c_void_p, C.c_void_p]),
                "SSL_set_connect_state": (None, [C.c_void_p]),
                "SSL_set_options": (C.c_uint64, [C.c_void_p, C.c_uint64]),
                "SSL_ctrl": (C.c_long, [C.c_void_p, C.c_int, C.c_long, C.c_void_p]),
                "SSL_do_handshake": (C.c_int, [C.c_void_p]),
                "SSL_is_init_finished": (C.c_int, [C.c_void_p]),
                "SSL_get_error": (C.c_int, [C.c_void_p, C.c_int]),
                "SSL_read": (C.c_int, [C.c_void_p, C.c_void_p, C.c_int]),
                "SSL_write": (C.c_int, [C.c_void_p, C.c_void_p, C.c_int]),
                "DTLS_get_data_mtu": (C.c_size_t, [C.c_void_p]),
                "BIO_new_bio_dgram_pair": (C.c_int, [C.POINTER(C.c_void_p), C.c_size_t,
                                                        C.POINTER(C.c_void_p), C.c_size_t]),
                "BIO_free": (C.c_int, [C.c_void_p]),
                "BIO_ctrl": (C.c_long, [C.c_void_p, C.c_int, C.c_long, C.c_void_p]),
                "BIO_read": (C.c_int, [C.c_void_p, C.c_void_p, C.c_int]),
                "BIO_write": (C.c_int, [C.c_void_p, C.c_void_p, C.c_int]),
                "ERR_clear_error": (None, []),
            }
            for name, (restype, argtypes) in signatures.items():
                function = getattr(self.lib, name)
                function.restype, function.argtypes = restype, argtypes
            if not 0x30200000 <= self.lib.OpenSSL_version_num() < 0x40000000:
                raise DtlsError("OpenSSL 3.2 or newer within version 3 is required")
        except (OSError, AttributeError):
            raise DtlsError("Could not load OpenSSL 3.2+ with datagram BIO support") from None


class DtlsPskClient:
    """DTLS client; identity is a NUL-free byte string and psk is binary key bytes.

    ``mtu`` limits the DTLS UDP payload, excluding outer TUTK/IP/UDP headers.
    No certificate modes are enabled: authentication requires the supplied PSK.
    """

    def __init__(self, identity: bytes, psk: bytes, library_path=None, mtu=1200,
                 *, ciphers: str = DEFAULT_CIPHERS):
        if not isinstance(identity, bytes) or not identity or b"\0" in identity or len(identity) > 255:
            raise ValueError("DTLS identity must be 1 to 255 NUL-free bytes")
        if not isinstance(psk, bytes) or not 1 <= len(psk) <= 512:
            raise ValueError("DTLS PSK must be 1 to 512 bytes")
        if isinstance(mtu, bool) or not isinstance(mtu, int) or not 256 <= mtu <= 16384:
            raise ValueError("DTLS MTU must be an integer from 256 to 16384")
        if not isinstance(ciphers, str) or not ciphers or "\0" in ciphers:
            raise ValueError("DTLS cipher list must be a nonempty string")
        try:
            cipher_bytes = ciphers.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("DTLS cipher list must use ASCII") from None
        # Restrict to PSK authentication: no ALL/DEFAULT/certificate cipher fallback.
        if any(not item.startswith("PSK-") or any(c in item for c in "!+@")
               for item in ciphers.split(":")):
            raise ValueError("DTLS cipher list must contain only explicit PSK suites")
        self.mtu = mtu
        self._ssl = self._ctx = self._network_bio = None
        self._closed = self._failed = self._started = False
        self._peer_closed = False
        self._application = []
        self._identity = C.create_string_buffer(identity)
        self._psk = C.create_string_buffer(psk, len(psk))
        self._identity_length, self._psk_length = len(identity), len(psk)
        self._openssl = _OpenSSL(library_path)
        self._lib = self._openssl.lib
        self._callback = _PSK_CALLBACK(self._provide_psk)
        ssl_bio = C.c_void_p()
        network_bio = C.c_void_p()
        try:
            self._ctx = self._lib.SSL_CTX_new(self._lib.DTLS_client_method())
            if not self._ctx:
                raise DtlsError("Could not create DTLS context")
            for command in (123, 124):  # SSL_CTRL_SET_MIN/MAX_PROTO_VERSION
                if self._lib.SSL_CTX_ctrl(self._ctx, command, _DTLS_1_2, None) != 1:
                    raise DtlsError("Could not restrict DTLS to version 1.2")
            if self._lib.SSL_CTX_set_cipher_list(self._ctx, cipher_bytes) != 1:
                raise DtlsError("No supported DTLS PSK cipher was selected")
            self._lib.SSL_CTX_set_psk_client_callback(self._ctx, self._callback)
            self._ssl = self._lib.SSL_new(self._ctx)
            if not self._ssl:
                raise DtlsError("Could not create DTLS session")
            if self._lib.BIO_new_bio_dgram_pair(C.byref(ssl_bio), 262144,
                                               C.byref(network_bio), 262144) != 1:
                raise DtlsError("Could not create DTLS datagram buffers")
            self._network_bio = network_bio.value
            # No-truncate on both halves; each read buffer also uses full UDP size.
            for bio in (ssl_bio.value, self._network_bio):
                self._lib.BIO_ctrl(bio, 89, 1, None)  # BIO_CTRL_DGRAM_SET_NO_TRUNC
                self._lib.BIO_ctrl(bio, 42, mtu, None)  # BIO_CTRL_DGRAM_SET_MTU
            self._lib.SSL_set_bio(self._ssl, ssl_bio.value, ssl_bio.value)
            ssl_bio = C.c_void_p()  # SSL now owns this endpoint (one shared reference).
            self._lib.SSL_set_options(self._ssl, 1 << 12)  # SSL_OP_NO_QUERY_MTU
            if self._lib.SSL_ctrl(self._ssl, 17, mtu, None) <= 0:  # SSL_set_mtu
                raise DtlsError("Could not configure DTLS MTU")
            self._lib.SSL_set_connect_state(self._ssl)
        except Exception:
            if ssl_bio.value:
                self._lib.BIO_free(ssl_bio.value)
            self.close()
            raise

    def _provide_psk(self, ssl, hint, identity, max_identity, psk, max_psk):
        if self._identity_length + 1 > max_identity or self._psk_length > max_psk:
            return 0
        C.memmove(identity, self._identity, self._identity_length + 1)
        C.memmove(psk, self._psk, self._psk_length)
        return self._psk_length

    def _check_open(self):
        if self._closed:
            raise DtlsError("DTLS client is closed")
        if self._failed:
            raise DtlsError("DTLS session has failed")
        if self._peer_closed:
            raise DtlsError("DTLS peer closed the session")

    def _check_result(self, result, operation):
        if result > 0:
            return True
        error = self._lib.SSL_get_error(self._ssl, result)
        if error in (_WANT_READ, _WANT_WRITE):
            return False
        if error == _ZERO_RETURN:
            self._peer_closed = True
            return False
        self._failed = True
        raise DtlsError(f"DTLS {operation} failed (SSL error {error})")

    def _drain_outbound(self):
        datagrams = []
        buffer = C.create_string_buffer(65535)
        while self._lib.BIO_ctrl(self._network_bio, 10, 0, None) > 0:
            size = self._lib.BIO_read(self._network_bio, buffer, len(buffer))
            if size <= 0:
                raise DtlsError("Could not read an outbound DTLS datagram")
            if size > self.mtu:
                self._failed = True
                raise DtlsError("OpenSSL emitted a DTLS datagram exceeding the MTU")
            datagrams.append(buffer.raw[:size])
        return datagrams

    def _advance(self):
        if not self.handshake_complete:
            self._lib.ERR_clear_error()
            result = self._lib.SSL_do_handshake(self._ssl)
            self._check_result(result, "handshake")
        if self.handshake_complete:
            buffer = C.create_string_buffer(65535)
            while True:
                self._lib.ERR_clear_error()
                size = self._lib.SSL_read(self._ssl, buffer, len(buffer))
                if not self._check_result(size, "read"):
                    break
                self._application.append(buffer.raw[:size])
                if len(self._application) > 1024:
                    self._failed = True
                    raise DtlsError("DTLS application receive queue is full")

    @property
    def handshake_complete(self):
        return bool(not self._closed and not self._failed and not self._peer_closed
                    and self._ssl and self._lib.SSL_is_init_finished(self._ssl))

    @property
    def data_mtu(self):
        """Maximum application record size after cipher negotiation, or zero."""
        return int(self._lib.DTLS_get_data_mtu(self._ssl)) if self.handshake_complete else 0

    @property
    def timeout_seconds(self):
        """Seconds until the next retransmit timer, or None if none is pending."""
        self._check_open()
        timeout = _Timeval()
        if self._lib.SSL_ctrl(self._ssl, 73, 0, C.byref(timeout)) <= 0:
            return None
        return max(0.0, timeout.tv_sec + timeout.tv_usec / 1_000_000)

    def start(self) -> List[bytes]:
        self._check_open()
        if self._started:
            raise DtlsError("DTLS handshake already started")
        self._started = True
        self._advance()
        return self._drain_outbound()

    def feed_datagram(self, data: bytes) -> List[bytes]:
        self._check_open()
        if not self._started:
            raise DtlsError("Start the DTLS handshake before feeding datagrams")
        if not isinstance(data, bytes) or not 1 <= len(data) <= 65507:
            raise ValueError("DTLS input must be a nonempty UDP payload of at most 65507 bytes")
        buffer = C.create_string_buffer(data, len(data))
        if self._lib.BIO_write(self._network_bio, buffer, len(data)) != len(data):
            self._failed = True
            raise DtlsError("DTLS input buffer is full")
        self._advance()
        return self._drain_outbound()

    def send_application(self, data: bytes) -> List[bytes]:
        self._check_open()
        if not self.handshake_complete:
            raise DtlsError("DTLS handshake is not complete")
        if not isinstance(data, bytes) or not data:
            raise ValueError("DTLS application data must be nonempty bytes")
        if len(data) > self.data_mtu:
            raise ValueError("DTLS application data exceeds the negotiated data MTU")
        buffer = C.create_string_buffer(data, len(data))
        self._lib.ERR_clear_error()
        size = self._lib.SSL_write(self._ssl, buffer, len(data))
        self._check_result(size, "write")
        if size != len(data):
            self._failed = True
            raise DtlsError("DTLS application write did not complete")
        return self._drain_outbound()

    def receive_application(self) -> List[bytes]:
        self._check_open()
        result, self._application = self._application, []
        return result

    def handle_timeout(self) -> List[bytes]:
        self._check_open()
        self._lib.ERR_clear_error()
        if self._lib.SSL_ctrl(self._ssl, 74, 0, None) < 0:
            self._failed = True
            raise DtlsError("DTLS retransmission failed")
        return self._drain_outbound()

    def close(self):
        """Release native state; caller handles enclosing session teardown."""
        if self._closed:
            return
        self._closed = True
        if self._ssl:
            self._lib.SSL_free(self._ssl)
            self._ssl = None
        if self._network_bio:
            self._lib.BIO_free(self._network_bio)
            self._network_bio = None
        if self._ctx:
            self._lib.SSL_CTX_free(self._ctx)
            self._ctx = None
        C.memset(self._psk, 0, self._psk_length)
        C.memset(self._identity, 0, self._identity_length + 1)
        self._application.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
