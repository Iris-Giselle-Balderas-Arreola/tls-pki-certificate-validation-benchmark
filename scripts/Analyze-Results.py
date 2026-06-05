#!/usr/bin/env python3
import argparse
from pathlib import Path
from typing import Iterable, List

import pandas as pd
import matplotlib.pyplot as plt


NON_MODEL_COLUMNS = {
    "raw_output_log",
    "failure_examples",
    "cert_sha256_fingerprint",
    "cert_not_before",
    "cert_not_after",
    "timestamp",
}

CATEGORICAL_HINTS = [
    "algorithm",
    "key_family",
    "ec_curve",
    "signature_algorithm",
    "public_key_algorithm",
    "test_mode",
    "server_mode",
    "tls_version_requested",
    "cipher_profile_requested",
    "cipher_family",
    "cipher_bulk",
    "cipher_mode",
    "tls_version_observed",
    "cipher_name",
    "cipher_protocol",
    "compression",
    "alpn_protocol",
    "client_ssl_library",
]


NUMERIC_COLS: List[str] = [
    "algorithm_encoded", "key_size_bits", "chain_length", "intermediates_sent_count", "certs_sent_count",
    "validation_chain_cert_count", "root_cert_in_trust_store", "run", "requested_duration_seconds",
    "actual_elapsed_seconds", "port", "tls_version_requested_encoded", "cipher_profile_encoded",
    "is_cipher_restricted", "is_tls13_cipher_suite", "session_reused_count", "session_reused_rate",
    "connection_attempts", "success_count", "failure_count", "success_rate", "failure_rate", "connections_per_sec",
    "total_connections", "mean_handshake_ms", "median_handshake_ms", "p90_handshake_ms", "p95_handshake_ms",
    "p99_handshake_ms", "min_handshake_ms", "max_handshake_ms", "std_handshake_ms", "mean_tcp_connect_ms",
    "median_tcp_connect_ms", "p95_tcp_connect_ms", "mean_tls_handshake_ms", "median_tls_handshake_ms",
    "p95_tls_handshake_ms", "mean_request_response_ms", "median_request_response_ms", "p95_request_response_ms",
    "mean_total_connection_ms", "median_total_connection_ms", "p95_total_connection_ms", "p99_total_connection_ms",
    "min_total_connection_ms", "max_total_connection_ms", "std_total_connection_ms", "total_app_bytes_sent",
    "total_app_bytes_received", "mean_app_bytes_received", "server_cert_bytes", "chain_pem_bytes", "root_cert_bytes",
    "sent_chain_pem_bytes", "total_cert_material_bytes", "cert_material_kb", "cert_validity_days", "cipher_bits",
    "exit_code",
    # Backwards-compatible columns from earlier versions:
    "time_seconds",
]


def save_no_data_chart(path: Path, title: str, message: str) -> None:
    plt.figure(figsize=(10, 5))
    plt.title(title)
    plt.text(0.5, 0.5, message, ha="center", va="center", wrap=True)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(path, dpi=200)
    plt.close()


def coerce_numeric(df: pd.DataFrame, columns: Iterable[str]) -> None:
    for col in columns:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")


def ensure_new_columns(df: pd.DataFrame) -> None:
    """Keep old CSVs compatible with the new experiment schema."""
    defaults = {
        "tls_version_requested": "default",
        "tls_version_requested_encoded": 0,
        "cipher_profile_requested": "default",
        "cipher_profile_encoded": 0,
        "cipher_family": "default",
        "cipher_bulk": "default",
        "cipher_mode": "default",
        "is_cipher_restricted": 0,
        "is_tls13_cipher_suite": 0,
        "client_cipher_string_requested": "",
        "server_cipher_string_requested": "",
        "server_ciphersuites_requested": "",
        "tls_max_version_configured": "default",
    }
    for col, value in defaults.items():
        if col not in df.columns:
            df[col] = value

    if "experiment_id" not in df.columns:
        if "algorithm" in df.columns and "chain_length" in df.columns:
            df["experiment_id"] = (
                df["algorithm"].astype(str)
                + "-chain"
                + pd.to_numeric(df["chain_length"], errors="coerce").astype("Int64").astype(str)
                + "-"
                + df["tls_version_requested"].astype(str)
                + "-"
                + df["cipher_profile_requested"].astype(str)
            )
        else:
            df["experiment_id"] = "unknown"


def make_config_label(df: pd.DataFrame) -> pd.Series:
    alg = df.get("algorithm", pd.Series("unknown", index=df.index)).astype(str)
    chain = pd.to_numeric(df.get("chain_length", pd.Series(0, index=df.index)), errors="coerce").astype("Int64").astype(str)
    tls = df.get("tls_version_requested", pd.Series("default", index=df.index)).astype(str)
    profile = df.get("cipher_profile_requested", pd.Series("default", index=df.index)).astype(str)
    return alg + "-c" + chain + "-" + tls + "-" + profile


def make_ml_ready(df: pd.DataFrame) -> pd.DataFrame:
    """Create a compact ML table: one row per benchmark run.

    Keeps useful numeric features and one-hot encodes stable categorical fields.
    Drops logs, fingerprints, free text and failed/warmup-only rows.
    """
    ml = df.copy()

    if "stage" in ml.columns:
        ml = ml[ml["stage"].fillna("").astype(str).eq("benchmark")].copy()
    if "connections_per_sec" in ml.columns:
        ml = ml[pd.to_numeric(ml["connections_per_sec"], errors="coerce").notna()].copy()

    drop_cols = [c for c in NON_MODEL_COLUMNS if c in ml.columns]
    # Host, free-text cipher strings and environment are useful for debugging, but they can leak
    # machine identity/noise or become high-cardinality text features. Keep encoded/profile fields instead.
    drop_cols += [
        c for c in [
            "target_host", "pi_host", "server_name", "client_os", "client_python_version",
            "client_openssl_version", "openssl_cli_version", "stage", "experiment_id",
            "client_cipher_string_requested", "server_cipher_string_requested", "server_ciphersuites_requested",
        ] if c in ml.columns
    ]
    ml = ml.drop(columns=drop_cols, errors="ignore")

    categorical_cols = [c for c in CATEGORICAL_HINTS if c in ml.columns]
    if categorical_cols:
        ml = pd.get_dummies(ml, columns=categorical_cols, dummy_na=False)

    for col in ml.columns:
        if ml[col].dtype == "object":
            ml[col] = pd.to_numeric(ml[col], errors="coerce")

    # Move target columns to the front for easier training.
    front = [
        c for c in [
            "connections_per_sec", "success_count", "failure_count", "success_rate", "failure_rate",
            "mean_handshake_ms", "mean_tls_handshake_ms", "tls_version_requested_encoded", "cipher_profile_encoded",
            "is_cipher_restricted", "is_tls13_cipher_suite",
        ] if c in ml.columns
    ]
    rest = [c for c in ml.columns if c not in front]
    return ml[front + rest]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to raw_results.csv")
    parser.add_argument("--output", required=True, help="Output directory")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not input_path.exists():
        raise FileNotFoundError(f"Input CSV not found: {input_path}")

    df = pd.read_csv(input_path)
    if df.empty:
        raise ValueError("Input CSV is empty. Run the benchmark first.")

    ensure_new_columns(df)
    coerce_numeric(df, NUMERIC_COLS)

    if "requested_duration_seconds" not in df.columns and "time_seconds" in df.columns:
        df["requested_duration_seconds"] = df["time_seconds"]

    df["config"] = make_config_label(df)

    if "total_cert_material_bytes" not in df.columns:
        df["total_cert_material_bytes"] = (
            df.get("server_cert_bytes", 0).fillna(0)
            + df.get("chain_pem_bytes", 0).fillna(0)
            + df.get("root_cert_bytes", 0).fillna(0)
        )

    valid = df[(df.get("connections_per_sec", pd.Series(dtype=float)).notna()) & (df["connections_per_sec"] > 0)].copy()
    failure_report = df[df.get("connections_per_sec", pd.Series(dtype=float)).isna() | (df["connections_per_sec"] <= 0)].copy()
    if not failure_report.empty:
        failure_report.to_csv(output_dir / "failed_or_empty_runs.csv", index=False)

    ml_ready = make_ml_ready(df)
    ml_ready.to_csv(output_dir / "ml_ready_results.csv", index=False)

    if valid.empty:
        df.to_csv(output_dir / "summary_by_config.csv", index=False)
        msg = "No successful TLS client runs were found. Open failed_or_empty_runs.csv and client_*.log files."
        save_no_data_chart(output_dir / "throughput_by_config.png", "TLS benchmark: mean connections per second", msg)
        save_no_data_chart(output_dir / "handshake_latency_by_config.png", "TLS benchmark: mean TCP+TLS handshake latency", msg)
        save_no_data_chart(output_dir / "tls_only_latency_by_config.png", "TLS-only handshake latency", msg)
        save_no_data_chart(output_dir / "chain_size_by_config.png", "Certificate material size by configuration", msg)
        save_no_data_chart(output_dir / "throughput_vs_chain_length.png", "Mean TLS throughput vs chain length", msg)
        print(msg)
        print(f"Wrote ML-ready table to {output_dir / 'ml_ready_results.csv'}")
        return

    group_cols = ["algorithm", "chain_length", "tls_version_requested", "cipher_profile_requested", "server_mode"]
    summary = (
        valid.groupby(group_cols, dropna=False)
        .agg(
            runs=("run", "count"),
            successful_connections=("success_count", "sum"),
            failed_connections=("failure_count", "sum"),
            mean_connections_per_sec=("connections_per_sec", "mean"),
            median_connections_per_sec=("connections_per_sec", "median"),
            std_connections_per_sec=("connections_per_sec", "std"),
            mean_tcp_tls_handshake_ms=("mean_handshake_ms", "mean"),
            median_tcp_tls_handshake_ms=("median_handshake_ms", "median"),
            p95_tcp_tls_handshake_ms=("p95_handshake_ms", "mean"),
            mean_tls_only_handshake_ms=("mean_tls_handshake_ms", "mean"),
            p95_tls_only_handshake_ms=("p95_tls_handshake_ms", "mean"),
            mean_tcp_connect_ms=("mean_tcp_connect_ms", "mean"),
            mean_request_response_ms=("mean_request_response_ms", "mean"),
            mean_total_connections=("total_connections", "mean"),
            server_cert_bytes=("server_cert_bytes", "mean"),
            chain_pem_bytes=("chain_pem_bytes", "mean"),
            root_cert_bytes=("root_cert_bytes", "mean"),
            sent_chain_pem_bytes=("sent_chain_pem_bytes", "mean"),
            total_cert_material_bytes=("total_cert_material_bytes", "mean"),
            certs_sent_count=("certs_sent_count", "mean"),
            validation_chain_cert_count=("validation_chain_cert_count", "mean"),
            key_size_bits=("key_size_bits", "mean"),
            cipher_bits=("cipher_bits", "mean"),
            is_cipher_restricted=("is_cipher_restricted", "max"),
            is_tls13_cipher_suite=("is_tls13_cipher_suite", "max"),
        )
        .reset_index()
    )

    summary["config"] = make_config_label(summary)
    summary.to_csv(output_dir / "summary_by_config.csv", index=False)

    plot_df = summary.copy().sort_values(["algorithm", "chain_length", "tls_version_requested", "cipher_profile_requested"])

    width = max(12, min(24, 0.45 * len(plot_df) + 8))
    plt.figure(figsize=(width, 6))
    plt.bar(plot_df["config"], plot_df["mean_connections_per_sec"])
    plt.title("TLS benchmark: mean successful connections per second")
    plt.xlabel("Configuration")
    plt.ylabel("Mean successful connections per second")
    plt.xticks(rotation=65, ha="right")
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_dir / "throughput_by_config.png", dpi=200)
    plt.close()

    plt.figure(figsize=(width, 6))
    plt.bar(plot_df["config"], plot_df["mean_tcp_tls_handshake_ms"])
    plt.title("TLS benchmark: mean TCP+TLS handshake latency")
    plt.xlabel("Configuration")
    plt.ylabel("Mean TCP+TLS latency per connection (ms)")
    plt.xticks(rotation=65, ha="right")
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_dir / "handshake_latency_by_config.png", dpi=200)
    plt.close()

    plt.figure(figsize=(width, 6))
    plt.bar(plot_df["config"], plot_df["mean_tls_only_handshake_ms"])
    plt.title("TLS benchmark: mean TLS-only handshake latency")
    plt.xlabel("Configuration")
    plt.ylabel("Mean TLS-only latency per connection (ms)")
    plt.xticks(rotation=65, ha="right")
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_dir / "tls_only_latency_by_config.png", dpi=200)
    plt.close()

    plt.figure(figsize=(width, 6))
    plt.bar(plot_df["config"], plot_df["sent_chain_pem_bytes"])
    plt.title("Estimated certificate bytes sent by server")
    plt.xlabel("Configuration")
    plt.ylabel("PEM bytes: leaf + intermediates")
    plt.xticks(rotation=65, ha="right")
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_dir / "chain_size_by_config.png", dpi=200)
    plt.close()

    plt.figure(figsize=(10, 6))
    for algorithm in sorted(plot_df["algorithm"].dropna().unique()):
        subset = plot_df[
            (plot_df["algorithm"] == algorithm)
            & (plot_df["tls_version_requested"].astype(str) == "default")
            & (plot_df["cipher_profile_requested"].astype(str) == "default")
        ].sort_values("chain_length")
        if subset.empty:
            subset = plot_df[plot_df["algorithm"] == algorithm].sort_values("chain_length")
        plt.plot(subset["chain_length"], subset["mean_connections_per_sec"], marker="o", label=algorithm)
    plt.title("Mean TLS throughput vs certificate chain length")
    plt.xlabel("Chain length parameter")
    plt.ylabel("Mean successful connections per second")
    plt.xticks(sorted(plot_df["chain_length"].dropna().unique()))
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(output_dir / "throughput_vs_chain_length.png", dpi=200)
    plt.close()

    print(f"Wrote summary to {output_dir / 'summary_by_config.csv'}")
    print(f"Wrote ML-ready table to {output_dir / 'ml_ready_results.csv'}")
    print(f"Wrote charts to {output_dir}")


if __name__ == "__main__":
    main()
