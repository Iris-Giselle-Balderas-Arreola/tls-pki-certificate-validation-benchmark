#!/usr/bin/env bash
set -euo pipefail

ALGORITHM="${1:?Use: ./Start-TlsServer.sh RSA|ECDSA chainLength port [python|openssl] [tlsVersion] [cipherProfile] [serverCipherString] [serverCipherSuites]}"
CHAIN_LENGTH="${2:?Use: ./Start-TlsServer.sh RSA|ECDSA chainLength port [python|openssl] [tlsVersion] [cipherProfile] [serverCipherString] [serverCipherSuites]}"
PORT="${3:?Use: ./Start-TlsServer.sh RSA|ECDSA chainLength port [python|openssl] [tlsVersion] [cipherProfile] [serverCipherString] [serverCipherSuites]}"
MODE="${4:-python}"
TLS_VERSION="${5:-default}"
CIPHER_PROFILE="${6:-default}"
SERVER_CIPHER_STRING="${7:-}"
SERVER_CIPHER_SUITES="${8:-}"

ALG_DIR="$(echo "$ALGORITHM" | tr '[:upper:]' '[:lower:]')"
CONFIG_DIR="certs/${ALG_DIR}/chain${CHAIN_LENGTH}"

pem_has_certificates() {
  local pem_file="$1"
  [[ -f "$pem_file" ]] && grep -q -- "-----BEGIN CERTIFICATE-----" "$pem_file"
}

SERVER_CRT="${CONFIG_DIR}/server.crt"
SERVER_KEY="${CONFIG_DIR}/server.key"
CHAIN_PEM="${CONFIG_DIR}/chain.pem"

if [[ ! -f "$SERVER_CRT" ]]; then
  echo "Missing $SERVER_CRT" >&2
  exit 1
fi

if [[ ! -f "$SERVER_KEY" ]]; then
  echo "Missing $SERVER_KEY" >&2
  exit 1
fi

if [[ "$MODE" == "openssl" ]]; then
  # OpenSSL mode is best for experimental TLS-version/cipher-suite matrices.
  ARGS=(s_server -4 -accept "0.0.0.0:${PORT}" -cert "$SERVER_CRT" -key "$SERVER_KEY" -www)
  if pem_has_certificates "$CHAIN_PEM"; then
    # Only pass -cert_chain when the file actually contains certificates.
    # chain1 intentionally has no intermediates; an empty/newline-only chain.pem
    # makes openssl s_server fail with:
    # "Could not find certificates of server certificate chain".
    ARGS+=(-cert_chain "$CHAIN_PEM")
  fi

  case "$TLS_VERSION" in
    TLS1.2) ARGS+=(-tls1_2) ;;
    TLS1.3) ARGS+=(-tls1_3) ;;
    default|"") ;;
    *) echo "Unsupported TLS version: $TLS_VERSION" >&2; exit 2 ;;
  esac

  if [[ -n "$SERVER_CIPHER_STRING" ]]; then
    ARGS+=(-cipher "$SERVER_CIPHER_STRING")
  fi
  if [[ -n "$SERVER_CIPHER_SUITES" ]]; then
    ARGS+=(-ciphersuites "$SERVER_CIPHER_SUITES")
  fi

  echo "Starting OpenSSL s_server: ${ALGORITHM} chain${CHAIN_LENGTH} on 0.0.0.0:${PORT} tls=${TLS_VERSION} profile=${CIPHER_PROFILE}" >&2
  exec openssl "${ARGS[@]}"
else
  echo "Starting Python TLS server using Python ssl/OpenSSL backend: ${ALGORITHM} chain${CHAIN_LENGTH} on 0.0.0.0:${PORT} tls=${TLS_VERSION} profile=${CIPHER_PROFILE}" >&2
  exec python3 scripts/raspberry/TlsPythonServer.py \
    --host 0.0.0.0 \
    --port "$PORT" \
    --cert "$SERVER_CRT" \
    --key "$SERVER_KEY" \
    --chain "$CHAIN_PEM" \
    --tls-version "$TLS_VERSION" \
    --cipher-string "$SERVER_CIPHER_STRING"
fi
