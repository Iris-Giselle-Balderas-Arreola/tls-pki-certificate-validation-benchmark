# TLS PKI Benchmark con Raspberry Pi 4

Arquitectura:

- Windows = cliente de medición
- Raspberry Pi = servidor TLS
- OpenSSL = generación de certificados X.509 RSA/ECDSA y material criptográfico
- Servidor TLS por defecto = Python `ssl`, que usa el backend OpenSSL de Python. Esto evita bloqueos de `openssl s_server` en corridas automatizadas.
- Modo opcional: `openssl s_server` sigue disponible desde `Start-TlsServer.sh` si se quiere comparar manualmente.

## 1. Entrar al repo

```powershell
cd "C:\Users\arreo\Downloads\tls-pki-benchmark-repo-raspberry-v9\tls-pki-benchmark-repo-raspberry-v9"
```

## 2. Limpiar llave vieja y configurar SSH sin contraseña repetida

```powershell
Remove-Item "$env:USERPROFILE\.ssh\raspberry_tls_bench_ed25519*" -Force -ErrorAction SilentlyContinue
powershell -ExecutionPolicy Bypass -File .\scripts\windows\Setup-SshKey.ps1 -PiHost 192.168.100.136 -PiUser pi -ForceRecreate
```

Debe pedir la contraseña de la Raspberry una sola vez.

Validación:

```powershell
ssh -i "$env:USERPROFILE\.ssh\raspberry_tls_bench_ed25519" -o IdentitiesOnly=yes -o BatchMode=yes pi@192.168.100.136 "hostname && openssl version && python3 --version"
```

## 3. Prueba pequeña

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\Quick-Run-Raspberry.ps1 -PiHost 192.168.100.136 -PiUser pi -Runs 3 -TimeSeconds 2 -RegenerateCerts
```

## 4. Prueba formal

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\Quick-Run-Raspberry.ps1 -PiHost 192.168.100.136 -PiUser pi -Runs 30 -TimeSeconds 3 -RegenerateCerts
```

## 5. Resultados

Abrir:

```powershell
explorer .\results
```

Archivos principales:

- `raw_results.csv`
- `summary_by_config.csv`
- `throughput_by_config.png`
- `handshake_latency_by_config.png`
- `chain_size_by_config.png`
- `throughput_vs_chain_length.png`

Las columnas que deben estar mayores a cero son:

- `connections_per_sec`
- `success_count`
- `mean_handshake_ms`
- `median_handshake_ms`
- `p95_handshake_ms`

Si salen ceros, revisar `failed_or_empty_runs.csv` y `results\client_*.out.log`.


## v10 fix

This version fixes the remote port check. Older versions treated `not_listening` as success because the text contains `listening`; v10 requires exact `LISTENING` before running the Windows client. If the server fails, the PowerShell error now prints Raspberry stdout/stderr so the real startup error is visible.


## v11 fix

This version fixes remote server startup. Previous versions used `pkill -f 'TlsPythonServer.py...'` inside the same SSH command. On Raspberry/Linux, `pkill -f` can match the SSH shell command itself and kill it before the server starts. v11 uses bracketed patterns (`[T]lsPythonServer.py`) so the cleanup command does not kill itself.

Recommended test port base:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\Quick-Run-Raspberry.ps1 -PiHost 192.168.100.136 -PiUser pi -Runs 3 -TimeSeconds 2 -RegenerateCerts -BasePort 50000
```

Formal run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\Quick-Run-Raspberry.ps1 -PiHost 192.168.100.136 -PiUser pi -Runs 30 -TimeSeconds 3 -RegenerateCerts -BasePort 50000
```

## Resultados extendidos para entrenar modelos

Después de correr `Quick-Run-Raspberry.ps1`, revisa:

```text
results\raw_results.csv
```

Ahora cada fila incluye muchas más variables útiles para entrenar una red neuronal o un modelo de regresión: algoritmo, tamaño de llave, longitud de cadena, cantidad de intermedios, bytes de certificados, versión TLS, cipher suite, TLS/s, tasa de éxito/falla y latencias separadas.

Para generar un dataset más limpio:

```powershell
python .\scripts\Analyze-Results.py --input results\raw_results.csv --output results\analysis
```

El archivo recomendado para iniciar modelado es:

```text
results\analysis\ml_ready_results.csv
```

La variable objetivo sugerida es `connections_per_sec`.

## v13 experimental matrix: TLS 1.2, TLS 1.3 y cipher suites

El comando normal sigue funcionando igual:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\Quick-Run-Raspberry.ps1 -PiHost 192.168.100.136 -PiUser pi -Runs 3 -TimeSeconds 2 -RegenerateCerts -BasePort 50000
```

Para generar más datos para ML, corre la matriz experimental:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\Quick-Run-Raspberry.ps1 -PiHost 192.168.100.136 -PiUser pi -Runs 3 -TimeSeconds 2 -RegenerateCerts -BasePort 50000 -ExperimentalMatrix
```

Esto multiplica las filas porque prueba RSA/ECDSA, chain length 1/2/3, TLS 1.2/TLS 1.3 y varios perfiles de cipher. El CSV final conserva `connections_per_sec` como target principal y agrega `tls_version_requested`, `cipher_profile_requested`, `cipher_family`, `cipher_bulk`, `cipher_mode`, `is_cipher_restricted`, `tls_version_observed` y `cipher_name`.

## v14 fix

This version fixes a PowerShell parser error in `scripts\windows\Invoke-TlsBenchmark-Remote.ps1` caused by Bash quote escaping inside the `Quote-BashArg` helper. The behavior is the same as v13, but the remote benchmark script now parses correctly on Windows PowerShell.


## Fix included in v15: chain1 + OpenSSL s_server

If you previously saw this error:

```text
Could not find certificates of server certificate chain from certs/rsa/chain1/chain.pem
```

that happened because `chain1` has no intermediate certificates, so its `chain.pem` is intentionally empty. v15 fixes the server startup logic so OpenSSL only receives `-cert_chain` when `chain.pem` actually contains PEM certificate blocks.

Run with `-RegenerateCerts` once if you want to rebuild all certificates cleanly:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\windows\Quick-Run-Raspberry.ps1 -PiHost raspberrypi.local -Runs 1 -TimeSeconds 2 -BasePort 50000 -RegenerateCerts
```


## Resuming a long run

If a long run fails after many iterations, do not rerun the same command immediately because the default behavior starts fresh and recreates `results\raw_results.csv`. First back up your partial file, then resume with `-SkipExisting` and, preferably, the real Raspberry Pi IP instead of `raspberrypi.local`:

```powershell
Copy-Item .\results\raw_results.csv .\results\raw_results_partial_backup.csv -Force

powershell -ExecutionPolicy Bypass -File .\scripts\windows\Quick-Run-Raspberry.ps1 -PiHost 192.168.X.X -Runs 100 -TimeSeconds 3 -BasePort 50000 -ExperimentalMatrix -SkipExisting -RetriesPerRun 5 -RetryDelaySeconds 15
```

`-SkipExisting` skips completed `experiment_id + run` rows and continues with the missing measurements.
