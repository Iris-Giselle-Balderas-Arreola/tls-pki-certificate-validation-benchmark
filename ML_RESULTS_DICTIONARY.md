# Diccionario de resultados para entrenamiento ML

Este repositorio ahora guarda un `results/raw_results.csv` con una fila por corrida/configuración. La variable objetivo principal para modelar rendimiento es:

- `connections_per_sec`: conexiones TLS exitosas por segundo durante la ventana de medición real.

También se genera `results/analysis/ml_ready_results.csv` al correr `Analyze-Results.py`. Ese archivo elimina columnas de texto largo y hace one-hot encoding de variables categóricas estables para que sea más fácil usarlo en scikit-learn, TensorFlow, PyTorch, etc.

## Columnas principales

### Identificación de la prueba

- `timestamp`: fecha/hora de la corrida.
- `test_mode`: `remote_raspberry` si el servidor corre en Raspberry Pi; `local_windows` si corre local.
- `algorithm`: algoritmo de llave/certificado probado: `RSA` o `ECDSA`.
- `algorithm_encoded`: codificación simple para ML: `0 = RSA`, `1 = ECDSA`.
- `run`: número de repetición para esa configuración.
- `requested_duration_seconds`: duración solicitada para la medición.
- `actual_elapsed_seconds`: duración real medida por el cliente.
- `port`, `target_host`, `pi_host`, `server_name`, `server_mode`: datos de conectividad y modo del servidor.

### Atributos criptográficos y de certificados

- `key_family`: familia de llave (`RSA` o `EC`).
- `key_size_bits`: tamaño de la llave pública del certificado servidor. En este repo normalmente `2048` para RSA y `256` para ECDSA prime256v1.
- `ec_curve`: curva usada para EC/ECDSA, por ejemplo `prime256v1`.
- `signature_algorithm`: algoritmo de firma del certificado, por ejemplo `sha256WithRSAEncryption` o `ecdsa-with-SHA256`.
- `public_key_algorithm`: algoritmo de llave pública reportado por OpenSSL.
- `chain_length`: parámetro experimental del repo. `1` significa servidor + root, `2` agrega 1 intermedio, `3` agrega 2 intermedios.
- `intermediates_sent_count`: cuántos certificados intermedios manda el servidor.
- `certs_sent_count`: certificados enviados por el servidor: leaf/server + intermedios.
- `validation_chain_cert_count`: certificados que el cliente valida conceptualmente: leaf/server + intermedios + root de confianza.
- `root_cert_in_trust_store`: `1` cuando el root se usa como CA confiable del cliente.
- `server_cert_bytes`: tamaño en bytes del certificado leaf/server en PEM.
- `chain_pem_bytes`: tamaño en bytes del archivo de intermedios.
- `root_cert_bytes`: tamaño en bytes del root usado por el cliente.
- `sent_chain_pem_bytes`: bytes aproximados enviados por servidor en PEM: server + intermedios.
- `total_cert_material_bytes`: server + intermedios + root.
- `cert_material_kb`: `total_cert_material_bytes` convertido a KB.
- `cert_validity_days`, `cert_not_before`, `cert_not_after`: ventana de validez del certificado servidor.
- `cert_sha256_fingerprint`: fingerprint para trazabilidad. No se recomienda usarlo como feature predictiva.

### TLS negociado

- `tls_min_version_configured`: versión mínima configurada en el cliente Python.
- `tls_version_observed`: versión TLS negociada más común en la corrida.
- `cipher_name`: cipher suite más común.
- `cipher_protocol`: protocolo reportado por el cipher.
- `cipher_bits`: bits del cipher suite negociado.
- `compression`: compresión TLS negociada; normalmente vacío/null.
- `alpn_protocol`: protocolo ALPN negociado; normalmente vacío si no se configura HTTP/2.
- `session_reused_count`: número de conexiones que reutilizaron sesión TLS.
- `session_reused_rate`: proporción de conexiones con session reuse.

### Métricas de rendimiento

- `connection_attempts`: intentos totales, exitosos + fallidos.
- `success_count`: conexiones TLS verificadas exitosamente.
- `failure_count`: fallas durante la corrida.
- `success_rate`: `success_count / connection_attempts`.
- `failure_rate`: `failure_count / connection_attempts`.
- `connections_per_sec`: throughput observado. Es la columna más útil como variable objetivo.
- `total_connections`: alias de `success_count` por compatibilidad.

### Latencia

- `mean_handshake_ms`, `median_handshake_ms`, `p90_handshake_ms`, `p95_handshake_ms`, `p99_handshake_ms`, `min_handshake_ms`, `max_handshake_ms`, `std_handshake_ms`: latencia TCP + handshake TLS. Esta es la métrica comparable con la versión anterior del repo.
- `mean_tcp_connect_ms`, `median_tcp_connect_ms`, `p95_tcp_connect_ms`: tiempo de conexión TCP solamente.
- `mean_tls_handshake_ms`, `median_tls_handshake_ms`, `p95_tls_handshake_ms`: tiempo del handshake TLS criptográfico, después de establecer TCP.
- `mean_request_response_ms`, `median_request_response_ms`, `p95_request_response_ms`: tiempo para mandar una petición HTTP mínima y recibir el primer bloque de respuesta.
- `mean_total_connection_ms`, `median_total_connection_ms`, `p95_total_connection_ms`, `p99_total_connection_ms`, `min_total_connection_ms`, `max_total_connection_ms`, `std_total_connection_ms`: tiempo end-to-end aproximado de la conexión completa medida por el cliente.

### Bytes de aplicación y diagnóstico

- `total_app_bytes_sent`: bytes de petición enviados por el cliente durante conexiones exitosas.
- `total_app_bytes_received`: bytes de respuesta recibidos.
- `mean_app_bytes_received`: promedio de bytes recibidos por conexión exitosa.
- `exit_code`: código de salida del cliente benchmark.
- `stage`: `benchmark` si la medición corrió; `warmup_connect_to_server` si falló antes.
- `failure_examples`: ejemplos compactos de errores.
- `raw_output_log`: JSON/log crudo de la corrida. Útil para debugging; no se recomienda como feature de entrenamiento.

## Recomendación de modelado

Para predecir `connections_per_sec`, empieza con estas features:

- `algorithm_encoded`
- `key_size_bits`
- `chain_length`
- `intermediates_sent_count`
- `certs_sent_count`
- `validation_chain_cert_count`
- `sent_chain_pem_bytes`
- `total_cert_material_bytes`
- `cipher_bits`
- `mean_tcp_connect_ms`
- `mean_tls_handshake_ms`
- `p95_tls_handshake_ms`
- `failure_rate`
- one-hot de `cipher_name`, `tls_version_observed`, `signature_algorithm`, `ec_curve`, `server_mode`

Evita entrenar con columnas de trazabilidad como `timestamp`, `cert_sha256_fingerprint`, `raw_output_log`, `target_host` o `client_os` salvo que quieras modelar específicamente diferencias entre máquinas/redes.

## Nuevas columnas de matriz experimental

Estas columnas sirven para entrenar modelos con variaciones de protocolo y cipher suite:

- `experiment_id`: nombre legible de la configuración, por ejemplo `RSA-chain1-TLS1.3-tls13_aes128_gcm`.
- `tls_version_requested`: versión pedida al cliente y al servidor. Valores: `default`, `TLS1.2`, `TLS1.3`.
- `tls_version_requested_encoded`: codificación numérica para ML. `0 = default`, `12 = TLS1.2`, `13 = TLS1.3`.
- `tls_max_version_configured`: versión máxima configurada en el cliente Python. En `TLS1.2` y `TLS1.3`, coincide con la versión forzada.
- `cipher_profile_requested`: perfil experimental solicitado.
- `cipher_profile_encoded`: codificación numérica estable del perfil. Ejemplos: `12128 = TLS 1.2 AES128-GCM`, `13256 = TLS 1.3 AES256-GCM`.
- `cipher_family`: familia general del cipher, como `AES`, `CHACHA20` o `default`.
- `cipher_bulk`: tamaño/tipo del cifrado de datos, como `AES128`, `AES256`, `CHACHA20`.
- `cipher_mode`: modo AEAD, como `GCM` o `POLY1305`.
- `is_cipher_restricted`: `1` si el experimento restringe explícitamente el cipher/ciphersuite; `0` si usa defaults de OpenSSL.
- `is_tls13_cipher_suite`: `1` si el perfil corresponde a una cipher suite de TLS 1.3.
- `client_cipher_string_requested`: cipher string aplicado en el cliente Python para TLS 1.2.
- `server_cipher_string_requested`: cipher string aplicado del lado servidor para TLS 1.2.
- `server_ciphersuites_requested`: cipher suite aplicada del lado servidor para TLS 1.3.

Para modelado, normalmente conviene usar las columnas codificadas y one-hot de `ml_ready_results.csv`, no las cadenas crudas de cipher.
