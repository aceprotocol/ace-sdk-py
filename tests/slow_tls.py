"""A local TLS server that drips its reply one byte at a time (total-deadline tests)."""

from __future__ import annotations

import datetime
import socket
import ssl
import tempfile
import threading
from contextlib import contextmanager

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _self_signed(dirname: str) -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.DNSName("ace.test")]),
            False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = f"{dirname}/cert.pem", f"{dirname}/key.pem"
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    return cert_path, key_path


@contextmanager
def slow_drip_server(monkeypatch, disc, reply: bytes, interval: float = 0.1):
    """Serve ``reply`` one byte per ``interval`` to every connection on 127.0.0.1; patch
    ``disc`` so that ``localhost`` resolves there, is not blocked, and the self-signed
    certificate is trusted. Yields the port."""
    with tempfile.TemporaryDirectory() as d:
        cert, key = _self_signed(d)
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(cert, key)
        listener = socket.create_server(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        stop = threading.Event()

        def serve(conn: socket.socket) -> None:
            try:
                with server_ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.settimeout(0.05)
                    for b in reply:
                        try:  # drain the request without blocking the drip
                            tls.recv(65536)
                        except (TimeoutError, ssl.SSLError):
                            pass
                        if stop.wait(interval):
                            return
                        tls.sendall(bytes([b]))
                    stop.wait(30)
            except OSError:
                pass

        def accept() -> None:
            listener.settimeout(0.1)
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except (TimeoutError, OSError):
                    continue
                threading.Thread(target=serve, args=(conn,), daemon=True).start()

        threading.Thread(target=accept, daemon=True).start()

        monkeypatch.setattr(disc, "_ssl_context", lambda: ssl.create_default_context(cafile=cert))
        monkeypatch.setattr(disc, "is_blocked_address", lambda ip: False)
        monkeypatch.setattr(
            disc,
            "_getaddrinfo",
            lambda host, p, *a, **k: [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", p))
            ],
        )
        try:
            yield port
        finally:
            stop.set()
            listener.close()
