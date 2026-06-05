# Cómo correr y obtener resultados extendidos

## Raspberry Pi remoto

Desde la carpeta del repo en Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\Quick-Run-Raspberry.ps1 -PiHost TU_IP_DE_RASPBERRY -Runs 10 -TimeSeconds 3
```

El CSV principal queda en:

```text
results\raw_results.csv
```

Cada fila del CSV representa una corrida de una configuración específica: algoritmo, longitud de cadena y repetición.

## Generar tablas y gráficas

```powershell
python .\scripts\Analyze-Results.py --input results\raw_results.csv --output results\analysis
```

Esto genera:

- `results\analysis\summary_by_config.csv`: resumen agregado por RSA/ECDSA y chain length.
- `results\analysis\ml_ready_results.csv`: tabla más limpia para entrenamiento de modelos.
- `throughput_by_config.png`: TLS/s promedio por configuración.
- `handshake_latency_by_config.png`: latencia TCP+TLS promedio.
- `tls_only_latency_by_config.png`: latencia TLS-only promedio.
- `chain_size_by_config.png`: tamaño aproximado de certificados enviados.
- `throughput_vs_chain_length.png`: throughput vs longitud de cadena.

## Variable objetivo sugerida

Usa `connections_per_sec` como target para predecir cuántas conexiones TLS por segundo logra una configuración.

## Importante

`mean_handshake_ms` mide TCP + TLS handshake, para mantener compatibilidad con el CSV anterior. Si quieres aislar la parte criptográfica, usa `mean_tls_handshake_ms`.

## Matriz experimental TLS/cipher

Esta versión agrega una capa opcional de experimentos. Si corres el comando normal, el comportamiento sigue igual que antes:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\Quick-Run-Raspberry.ps1 -PiHost TU_IP_DE_RASPBERRY -Runs 10 -TimeSeconds 3
```

Para generar más datos variando versión TLS y cipher suites, usa:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\Quick-Run-Raspberry.ps1 -PiHost TU_IP_DE_RASPBERRY -Runs 10 -TimeSeconds 3 -BasePort 50000 -ExperimentalMatrix
```

Con `-ExperimentalMatrix`, el repo prueba por cada algoritmo y longitud de cadena:

- `default/default`: comportamiento anterior, TLS 1.2+ sin restringir cipher.
- `TLS1.2/default`: fuerza TLS 1.2 sin restringir cipher.
- `TLS1.2/tls12_aes128_gcm`: fuerza TLS 1.2 con AES-128-GCM.
- `TLS1.2/tls12_aes256_gcm`: fuerza TLS 1.2 con AES-256-GCM.
- `TLS1.2/tls12_chacha20`: fuerza TLS 1.2 con ChaCha20-Poly1305.
- `TLS1.3/default`: fuerza TLS 1.3 sin restringir cipher suite.
- `TLS1.3/tls13_aes128_gcm`: fuerza TLS 1.3 con TLS_AES_128_GCM_SHA256.
- `TLS1.3/tls13_aes256_gcm`: fuerza TLS 1.3 con TLS_AES_256_GCM_SHA384.
- `TLS1.3/tls13_chacha20`: fuerza TLS 1.3 con TLS_CHACHA20_POLY1305_SHA256.

Para una prueba manual de una sola configuración:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\Invoke-TlsBenchmark-Remote.ps1 `
  -Algorithm RSA `
  -ChainLength 1 `
  -Run 1 `
  -PiHost TU_IP_DE_RASPBERRY `
  -SshKeyPath "$env:USERPROFILE\.ssh\raspberry_tls_bench_ed25519" `
  -Port 50001 `
  -ServerMode openssl `
  -TlsVersion TLS1.3 `
  -CipherProfile tls13_aes128_gcm
```

Nota: cuando `-ExperimentalMatrix` está activado, el runner remoto usa `openssl s_server` automáticamente aunque el default normal sea el servidor Python. Esto permite restringir cipher suites de TLS 1.3 de forma más confiable.
