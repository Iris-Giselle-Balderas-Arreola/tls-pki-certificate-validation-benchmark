param(
    [int]$Runs = 100,
    [int]$TimeSeconds = 3
)

$ErrorActionPreference = "Stop"

Write-Host "=== Step 1/3: Generating certificates ==="
powershell -ExecutionPolicy Bypass -File ".\scripts\New-TlsCertChains.ps1"
if ($LASTEXITCODE -ne 0) {
    throw "Certificate generation failed."
}

Write-Host ""
Write-Host "=== Step 2/3: Running benchmarks ==="
powershell -ExecutionPolicy Bypass -File ".\scripts\Run-AllBenchmarks.ps1" -Runs $Runs -TimeSeconds $TimeSeconds
if ($LASTEXITCODE -ne 0) {
    throw "Benchmark step failed."
}

Write-Host ""
Write-Host "=== Step 3/3: Generating analysis ==="

$pythonCmd = "python"

try {
    & $pythonCmd --version | Out-Host
}
catch {
    $pythonCmd = "py"
}

& $pythonCmd -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    throw "pip install failed."
}

& $pythonCmd ".\scripts\Analyze-Results.py" --input "results\raw_results.csv" --output "results"
if ($LASTEXITCODE -ne 0) {
    throw "Python analysis failed."
}

Write-Host ""
Write-Host "Done. Open results with: explorer .\results"
