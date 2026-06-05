# Resume after interruption

If a long run stops because of Wi-Fi, SSH, mDNS, or `raspberrypi.local` resolution, do not delete `results\raw_results.csv`.

Recommended recovery:

```powershell
# 1) Keep a backup of the partial data
Copy-Item .\results\raw_results.csv .\results\raw_results_partial_backup.csv -Force

# 2) Resume using the Raspberry Pi real IP instead of raspberrypi.local
powershell -ExecutionPolicy Bypass -File .\scripts\windows\Quick-Run-Raspberry.ps1 `
  -PiHost 192.168.X.X `
  -Runs 100 `
  -TimeSeconds 3 `
  -BasePort 50000 `
  -ExperimentalMatrix `
  -SkipExisting `
  -RetriesPerRun 5 `
  -RetryDelaySeconds 15
```

`-SkipExisting` keeps the existing CSV and skips rows already present by `experiment_id + run`.

If you rerun without `-SkipExisting`, the script intentionally starts a fresh run and deletes `results\raw_results.csv`.
