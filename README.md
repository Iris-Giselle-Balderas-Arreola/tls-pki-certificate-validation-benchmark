# PKI clásica en TLS — costo de verificación de certificados

Repositorio reproducible para medir el costo operativo de verificar certificados X.509 en TLS bajo las siguientes condiciones:

- RSA vs ECDSA
- Cadenas `chain1`, `chain2`, `chain3`
- N corridas por combinación
- Exportación a CSV y gráficas comparativas

## Correr prueba pequeña

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Run-Project.ps1 -Runs 3 -TimeSeconds 2
```

## Correr prueba completa

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Run-Project.ps1 -Runs 100 -TimeSeconds 3
```

## Resultados esperados

```text
results/raw_results.csv
results/summary_by_config.csv
results/throughput_by_config.png
results/chain_size_by_config.png
results/throughput_vs_chain_length.png
```

## Nota de compatibilidad

Esta versión evita `ProcessStartInfo.ArgumentList` porque no siempre está disponible en Windows PowerShell clásico.
La captura de `openssl s_time` se hace con `Start-Process` y archivos temporales.

## Resultados extendidos para ML

Esta versión guarda resultados más completos en `results/raw_results.csv`, incluyendo atributos criptográficos, longitud de cadena, tamaños de certificados, versión TLS, cipher suite, tasas de éxito/falla y latencias separadas de TCP, TLS-only y conexión total.

Después de correr el benchmark puedes generar una tabla lista para modelado con:

```powershell
python .\scripts\Analyze-Results.py --input results\raw_results.csv --output results\analysis
```

Consulta `ML_RESULTS_DICTIONARY.md` para entender cada columna y `README_ML_RESULTS.md` para el flujo recomendado.
