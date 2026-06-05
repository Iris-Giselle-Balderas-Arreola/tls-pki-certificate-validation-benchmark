# Classical PKI in TLS — Certificate Verification Cost

Reproducible repository for measuring the operational cost of verifying X.509 certificates in TLS under the following conditions:

* RSA vs ECDSA
* `chain1`, `chain2`, `chain3` certificate chains
* N runs per configuration
* CSV export and comparative plots

## Run a Small Test

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Run-Project.ps1 -Runs 3 -TimeSeconds 2
```

## Run the Full Test

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Run-Project.ps1 -Runs 100 -TimeSeconds 3
```

## Expected Results

```text
results/raw_results.csv
results/summary_by_config.csv
results/throughput_by_config.png
results/chain_size_by_config.png
results/throughput_vs_chain_length.png
```

## Compatibility Note

This version avoids `ProcessStartInfo.ArgumentList` because it is not always available in classic Windows PowerShell.

The `openssl s_time` output is captured using `Start-Process` and temporary files.

## Extended Results for Machine Learning

This version stores more complete results in `results/raw_results.csv`, including cryptographic attributes, certificate chain length, certificate sizes, TLS version, cipher suite, success/failure rates, and separated TCP, TLS-only, and total connection latencies.

After running the benchmark, you can generate a modeling-ready table with:

```powershell
python .\scripts\Analyze-Results.py --input results\raw_results.csv --output results\analysis
```

See `ML_RESULTS_DICTIONARY.md` to understand each column and `README_ML_RESULTS.md` for the recommended workflow.
