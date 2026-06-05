#!/usr/bin/env python3
import argparse
import os
import signal
import socket
import ssl
import sys
import tempfile
import threading
from pathlib import Path

TLS_VERSION_CHOICES = ("default", "TLS1.2", "TLS1.3")


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def build_fullchain(server_crt: Path, chain_pem: Path) -> str:
    data = server_crt.read_text(encoding="ascii")
    if chain_pem.exists() and chain_pem.stat().st_size > 0:
        extra = chain_pem.read_text(encoding="ascii").strip()
        # chain1 intentionally has no intermediates. Ignore empty/newline-only files
        # and any file that does not actually contain a PEM certificate block.
        if extra and "-----BEGIN CERTIFICATE-----" in extra:
            data += "\n" + extra + "\n"
    fd, path = tempfile.mkstemp(prefix="tlsbench_fullchain_", suffix=".pem")
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(data)
    return path


def configure_tls_version(context: ssl.SSLContext, tls_version: str) -> None:
    if tls_version == "TLS1.2":
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    elif tls_version == "TLS1.3":
        if not hasattr(ssl.TLSVersion, "TLSv1_3"):
            raise RuntimeError("This Python/OpenSSL build does not support TLS 1.3")
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
    else:
        # Backwards-compatible default from earlier repo versions.
        context.minimum_version = ssl.TLSVersion.TLSv1_2


def handle_client(conn, addr):
    try:
        # Complete handshake happens before this function receives conn because wrap_socket is called in accept loop.
        try:
            conn.settimeout(2.0)
            data = conn.recv(4096)
            if data:
                conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
        except Exception:
            pass
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(description="Tiny TLS server for Raspberry Pi benchmark. Uses Python ssl/OpenSSL backend and OpenSSL-generated certificates.")
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--chain", default="")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--tls-version", choices=TLS_VERSION_CHOICES, default="default")
    parser.add_argument("--cipher-string", default="", help="TLS 1.2-and-below OpenSSL cipher string")
    args = parser.parse_args()

    server_crt = Path(args.cert)
    server_key = Path(args.key)
    chain_pem = Path(args.chain) if args.chain else Path("__missing_chain.pem")
    if not server_crt.exists():
        raise FileNotFoundError(f"Missing certificate: {server_crt}")
    if not server_key.exists():
        raise FileNotFoundError(f"Missing key: {server_key}")

    fullchain_path = build_fullchain(server_crt, chain_pem)
    stop = threading.Event()

    def _signal_handler(signum, frame):
        stop.set()

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=fullchain_path, keyfile=str(server_key))
    configure_tls_version(context, args.tls_version)
    if args.cipher_string:
        # Python ssl controls TLS 1.2 and older ciphers through set_ciphers.
        # TLS 1.3 ciphers are controlled with OpenSSL s_server in experimental mode.
        context.set_ciphers(args.cipher_string)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(256)
    sock.settimeout(0.5)
    log(f"READY host={args.host} port={args.port} pid={os.getpid()} cert={server_crt} tls_version={args.tls_version} cipher_string={args.cipher_string or 'default'}")

    try:
        while not stop.is_set():
            try:
                raw_conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                tls_conn = context.wrap_socket(raw_conn, server_side=True)
            except Exception as exc:
                log(f"handshake_failed addr={addr} err={type(exc).__name__}: {exc}")
                try:
                    raw_conn.close()
                except Exception:
                    pass
                continue
            t = threading.Thread(target=handle_client, args=(tls_conn, addr), daemon=True)
            t.start()
    finally:
        try:
            sock.close()
        except Exception:
            pass
        try:
            os.remove(fullchain_path)
        except Exception:
            pass
        log("STOPPED")


if __name__ == "__main__":
    main()
