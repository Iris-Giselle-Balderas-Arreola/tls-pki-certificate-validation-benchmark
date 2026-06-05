param(
    [Parameter(Mandatory = $true)]
    [string]$PiHost,

    [string]$PiUser = "pi",

    [string]$PiRepoPath = "~/tls-pki-benchmark",

    [string]$SshKeyPath = "",

    [int]$Runs = 100,

    [int]$TimeSeconds = 3,

    [int]$BasePort = 44330,

    [ValidateSet("python", "openssl")]
    [string]$ServerMode = "python",

    [switch]$ExperimentalMatrix,

    [switch]$RegenerateCerts,

    [switch]$SkipExisting,

    [int]$RetriesPerRun = 2,

    [int]$RetryDelaySeconds = 10
)

$ErrorActionPreference = "Stop"

Write-Host "=== Step 1/4: Preparing certificates locally ==="
if ($RegenerateCerts -or -not (Test-Path "certs\rsa\chain1\server.crt") -or -not (Test-Path "certs\ecdsa\chain3\server.crt")) {
    Write-Host "Generating certificates..."
    powershell -ExecutionPolicy Bypass -File ".\scripts\New-TlsCertChains.ps1"
    if ($LASTEXITCODE -ne 0) { throw "Certificate generation failed." }
} else {
    Write-Host "Certificates already exist. Skipping generation. Use -RegenerateCerts to rebuild them."
}

Write-Host ""
Write-Host "=== Step 2/4: Syncing certificates/scripts to Raspberry Pi ==="
$syncArgs = @("-ExecutionPolicy", "Bypass", "-File", ".\scripts\windows\Sync-ToRaspberry.ps1", "-PiHost", $PiHost, "-PiUser", $PiUser, "-PiRepoPath", $PiRepoPath)
if (-not [string]::IsNullOrWhiteSpace($SshKeyPath)) { $syncArgs += @("-SshKeyPath", $SshKeyPath) }
powershell @syncArgs
if ($LASTEXITCODE -ne 0) { throw "Raspberry Pi sync failed." }

Write-Host ""
Write-Host "=== Step 3/4: Running remote benchmarks ==="
$benchArgs = @(
    "-ExecutionPolicy", "Bypass", "-File", ".\scripts\windows\Run-AllBenchmarks-Remote.ps1",
    "-PiHost", $PiHost,
    "-PiUser", $PiUser,
    "-PiRepoPath", $PiRepoPath,
    "-Runs", $Runs,
    "-TimeSeconds", $TimeSeconds,
    "-BasePort", $BasePort,
    "-ServerMode", $ServerMode
)
if (-not [string]::IsNullOrWhiteSpace($SshKeyPath)) { $benchArgs += @("-SshKeyPath", $SshKeyPath) }
if ($ExperimentalMatrix) { $benchArgs += @("-ExperimentalMatrix") }
if ($SkipExisting) { $benchArgs += @("-SkipExisting") }
$benchArgs += @("-RetriesPerRun", $RetriesPerRun, "-RetryDelaySeconds", $RetryDelaySeconds)
powershell @benchArgs
if ($LASTEXITCODE -ne 0) { throw "Remote benchmark step failed." }

Write-Host ""
Write-Host "=== Step 4/4: Generating analysis locally ==="

$pythonCmd = "python"
try { & $pythonCmd --version | Out-Host } catch { $pythonCmd = "py" }

& $pythonCmd -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "pip install failed." }

& $pythonCmd ".\scripts\Analyze-Results.py" --input "results\raw_results.csv" --output "results"
if ($LASTEXITCODE -ne 0) { throw "Python analysis failed." }

Write-Host ""
Write-Host "Done. Open results with: explorer .\results"
