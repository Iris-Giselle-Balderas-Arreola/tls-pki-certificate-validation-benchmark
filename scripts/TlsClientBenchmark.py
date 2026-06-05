#!/usr/bin/env python3
"""TLS client benchmark that emits one rich JSON row per benchmark run.

The output is intentionally ML-friendly: every execution produces one JSON object
with throughput targets plus latency, protocol, cipher, byte-count, failure and
environment features. It also supports controlled experiments for TLS version
and TLS 1.2 cipher strings without changing the old default behavior.
"""

import argparse
import json
import platform
import socket
import ssl
import statistics
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

REQUEST_BYTES = b"GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"
TLS_VERSION_CHOICES = ("default", "TLS1.2", "TLS1.3")


def percentile(values: List[float], pct: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    k = (len(ordered) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(ordered) - 1)
    if f == c:
        return ordered[f]
    return ordered[f] + (ordered[c] - ordered[f]) * (k - f)


def safe_stdev(values: List[float]) -> Optional[float]:
    if len(values) < 2:
        return 0.0 if len(values) == 1 else None
    return statistics.stdev(values)


def summarize(values: List[float], prefix: str) -> Dict[str, Optional[float]]:
    return {
        f"mean_{prefix}_ms": statistics.mean(values) if values else None,
        f"median_{prefix}_ms": statistics.median(values) if values else None,
        f"p90_{prefix}_ms": percentile(values, 90),
        f"p95_{prefix}_ms": percentile(values, 95),
        f"p99_{prefix}_ms": percentile(values, 99),
        f"min_{prefix}_ms": min(values) if values else None,
        f"max_{prefix}_ms": max(values) if values else None,
        f"std_{prefix}_ms": safe_stdev(values),
    }


def most_common(values: Iterable[Any]) -> Any:
    cleaned = [v for v in values if v not in (None, "")]
    if not cleaned:
        return None
    return Counter(cleaned).most_common(1)[0][0]


def summarize_failure(exc: BaseException) -> str:
    text = f"{type(exc).__name__}: {exc}"
    return text[:500]


def ssl_version_name(value: Any) -> str:
    if value is None:
        return "default"
    return getattr(value, "name", str(value))


def configure_tls_version(context: ssl.SSLContext, tls_version: str) -> Tuple[str, str]:
    """Apply the requested TLS version while preserving the old default.

    default = minimum TLS 1.2, maximum left to OpenSSL/Python default.
    TLS1.2 = force exactly TLS 1.2.
    TLS1.3 = force exactly TLS 1.3.
    """
    if tls_version not in TLS_VERSION_CHOICES:
        raise ValueError(f"Unsupported TLS version requested: {tls_version}")

    if tls_version == "TLS1.2":
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    elif tls_version == "TLS1.3":
        if not hasattr(ssl.TLSVersion, "TLSv1_3"):
            raise RuntimeError("This Python/OpenSSL build does not support TLS 1.3")
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
    else:
        # Backwards-compatible floor used by the previous repo version.
        context.minimum_version = ssl.TLSVersion.TLSv1_2

    return ssl_version_name(getattr(context, "minimum_version", None)), ssl_version_name(getattr(context, "maximum_version", None))


def one_connection(args: argparse.Namespace, context: ssl.SSLContext) -> Dict[str, Any]:
    """Open one TCP connection, perform TLS handshake, send a tiny request.

    Timings are split so the resulting CSV can distinguish network TCP setup,
    cryptographic TLS work, and the small application request/response probe.
    """
    raw_sock: Optional[socket.socket] = None
    tls_sock: Optional[ssl.SSLSocket] = None
    start_total = time.perf_counter()

    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(args.timeout)

        tcp_start = time.perf_counter()
        raw_sock.connect((args.host, args.port))
        tcp_connect_ms = (time.perf_counter() - tcp_start) * 1000.0

        tls_sock = context.wrap_socket(
            raw_sock,
            server_hostname=args.server_name,
            do_handshake_on_connect=False,
        )
        # Ownership has moved to tls_sock. Avoid closing raw_sock twice.
        raw_sock = None

        tls_start = time.perf_counter()
        tls_sock.do_handshake()
        tls_handshake_ms = (time.perf_counter() - tls_start) * 1000.0
        handshake_ms = (time.perf_counter() - start_total) * 1000.0

        cipher = tls_sock.cipher() or (None, None, None)
        app_bytes_sent = 0
        app_bytes_received = 0
        request_response_ms = None

        try:
            rr_start = time.perf_counter()
            tls_sock.sendall(REQUEST_BYTES)
            app_bytes_sent = len(REQUEST_BYTES)
            chunk = tls_sock.recv(4096)
            request_response_ms = (time.perf_counter() - rr_start) * 1000.0
            app_bytes_received = len(chunk or b"")
        except Exception:
            # The benchmark target is the handshake. Application probing is useful
            # but should not invalidate a successful verified TLS connection.
            pass

        total_connection_ms = (time.perf_counter() - start_total) * 1000.0

        return {
            "tcp_connect_ms": tcp_connect_ms,
            "tls_handshake_ms": tls_handshake_ms,
            "handshake_ms": handshake_ms,  # TCP connect + TLS handshake, backwards-compatible concept.
            "request_response_ms": request_response_ms,
            "total_connection_ms": total_connection_ms,
            "tls_version": tls_sock.version(),
            "cipher_name": cipher[0],
            "cipher_protocol": cipher[1],
            "cipher_bits": cipher[2],
            "compression": tls_sock.compression(),
            "alpn_protocol": tls_sock.selected_alpn_protocol(),
            "session_reused": bool(getattr(tls_sock, "session_reused", False)),
            "app_bytes_sent": app_bytes_sent,
            "app_bytes_received": app_bytes_received,
        }
    finally:
        if tls_sock is not None:
            try:
                tls_sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                tls_sock.close()
            except Exception:
                pass
        if raw_sock is not None:
            try:
                raw_sock.close()
            except Exception:
                pass


def emit_setup_failure(args: argparse.Namespace, stage: str, exc: BaseException) -> None:
    result = {
        "host": getattr(args, "host", ""),
        "port": getattr(args, "port", ""),
        "server_name": getattr(args, "server_name", ""),
        "requested_duration_seconds": getattr(args, "duration", ""),
        "duration_seconds": getattr(args, "duration", ""),
        "tls_version_requested": getattr(args, "tls_version", ""),
        "cipher_profile_requested": getattr(args, "cipher_profile", ""),
        "client_cipher_string_requested": getattr(args, "cipher_string", ""),
        "client_os": platform.platform(),
        "client_python_version": sys.version.split()[0],
        "client_ssl_library": "python-ssl",
        "client_openssl_version": ssl.OPENSSL_VERSION,
        "actual_elapsed_seconds": 0,
        "connection_attempts": 0,
        "success_count": 0,
        "failure_count": 1,
        "success_rate": 0,
        "failure_rate": 1,
        "connections_per_sec": 0,
        "sample_failures": [summarize_failure(exc)],
        "stage": stage,
    }
    print(json.dumps(result, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser(description="Repeated TCP+TLS client benchmark with certificate verification.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cafile", required=True)
    parser.add_argument("--duration", type=float, default=3.0)
    parser.add_argument("--server-name", default="localhost", help="TLS SNI/hostname used for certificate verification")
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--warmup-timeout", type=float, default=8.0)
    parser.add_argument("--tls-version", choices=TLS_VERSION_CHOICES, default="default", help="default keeps old TLS 1.2+ behavior; TLS1.2/TLS1.3 force one version")
    parser.add_argument("--cipher-profile", default="default", help="Metadata label for the experiment profile requested by PowerShell")
    parser.add_argument("--cipher-string", default="", help="OpenSSL cipher string applied by the Python client for TLS 1.2 and below")
    args = parser.parse_args()

    cafile = Path(args.cafile)
    if not cafile.exists():
        raise FileNotFoundError(f"CA file not found: {cafile}")

    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(cafile))
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        min_version, max_version = configure_tls_version(context, args.tls_version)
        if args.cipher_string:
            # Python's ssl.set_ciphers controls TLS 1.2 and older cipher suites.
            # TLS 1.3 cipher suites are normally controlled server-side in this repo.
            context.set_ciphers(args.cipher_string)
    except Exception as exc:
        emit_setup_failure(args, "client_context_setup", exc)
        raise SystemExit(2)

    base_result: Dict[str, Any] = {
        "host": args.host,
        "port": args.port,
        "server_name": args.server_name,
        "requested_duration_seconds": args.duration,
        "duration_seconds": args.duration,  # backwards-compatible field name.
        "tls_version_requested": args.tls_version,
        "cipher_profile_requested": args.cipher_profile,
        "client_cipher_string_requested": args.cipher_string,
        "client_os": platform.platform(),
        "client_python_version": sys.version.split()[0],
        "client_ssl_library": "python-ssl",
        "client_openssl_version": ssl.OPENSSL_VERSION,
        "tls_min_version_configured": min_version,
        "tls_max_version_configured": max_version,
    }

    # Warm-up: wait until the server is reachable and able to complete verified TLS.
    warmup_failures: List[str] = []
    warmup_deadline = time.perf_counter() + max(args.warmup_timeout, 0.1)
    while True:
        try:
            one_connection(args, context)
            break
        except Exception as exc:
            warmup_failures.append(summarize_failure(exc))
            if time.perf_counter() >= warmup_deadline:
                result = {
                    **base_result,
                    "actual_elapsed_seconds": 0,
                    "connection_attempts": len(warmup_failures),
                    "success_count": 0,
                    "failure_count": len(warmup_failures),
                    "success_rate": 0,
                    "failure_rate": 1,
                    "connections_per_sec": 0,
                    "sample_failures": warmup_failures[-5:],
                    "stage": "warmup_connect_to_server",
                }
                print(json.dumps(result, ensure_ascii=False))
                raise SystemExit(2)
            time.sleep(0.15)

    successes: List[Dict[str, Any]] = []
    failures: List[str] = []
    bench_start = time.perf_counter()
    deadline = bench_start + max(args.duration, 0.1)

    while time.perf_counter() < deadline:
        try:
            successes.append(one_connection(args, context))
        except Exception as exc:
            failures.append(summarize_failure(exc))
            time.sleep(0.02)

    actual_elapsed_seconds = max(time.perf_counter() - bench_start, 0.000001)
    success_count = len(successes)
    failure_count = len(failures)
    attempts = success_count + failure_count

    handshake_ms = [r["handshake_ms"] for r in successes]
    tcp_connect_ms = [r["tcp_connect_ms"] for r in successes]
    tls_handshake_ms = [r["tls_handshake_ms"] for r in successes]
    request_response_ms = [r["request_response_ms"] for r in successes if r.get("request_response_ms") is not None]
    total_connection_ms = [r["total_connection_ms"] for r in successes]

    session_reused_count = sum(1 for r in successes if r.get("session_reused"))
    total_app_bytes_sent = sum(int(r.get("app_bytes_sent") or 0) for r in successes)
    total_app_bytes_received = sum(int(r.get("app_bytes_received") or 0) for r in successes)

    result: Dict[str, Any] = {
        **base_result,
        "actual_elapsed_seconds": actual_elapsed_seconds,
        "connection_attempts": attempts,
        "success_count": success_count,
        "failure_count": failure_count,
        "success_rate": (success_count / attempts) if attempts else None,
        "failure_rate": (failure_count / attempts) if attempts else None,
        "connections_per_sec": success_count / actual_elapsed_seconds,
        "session_reused_count": session_reused_count,
        "session_reused_rate": (session_reused_count / success_count) if success_count else None,
        "tls_version_observed": most_common(r.get("tls_version") for r in successes),
        "cipher_name": most_common(r.get("cipher_name") for r in successes),
        "cipher_protocol": most_common(r.get("cipher_protocol") for r in successes),
        "cipher_bits": most_common(r.get("cipher_bits") for r in successes),
        "compression": most_common(r.get("compression") for r in successes),
        "alpn_protocol": most_common(r.get("alpn_protocol") for r in successes),
        "total_app_bytes_sent": total_app_bytes_sent,
        "total_app_bytes_received": total_app_bytes_received,
        "mean_app_bytes_received": (total_app_bytes_received / success_count) if success_count else None,
        "sample_failures": failures[:5],
        "stage": "benchmark",
    }

    # Backwards-compatible latency names: handshake_ms means TCP connect + TLS handshake.
    result.update(summarize(handshake_ms, "handshake"))
    result.update(summarize(tcp_connect_ms, "tcp_connect"))
    result.update(summarize(tls_handshake_ms, "tls_handshake"))
    result.update(summarize(request_response_ms, "request_response"))
    result.update(summarize(total_connection_ms, "total_connection"))

    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(0 if success_count > 0 else 2)


if __name__ == "__main__":
    main()
