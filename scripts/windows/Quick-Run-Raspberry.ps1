param(
    [Parameter(Mandatory = $true)]
    [string]$PiHost,

    [string]$PiUser = "pi",

    [string]$SshKeyPath = "$env:USERPROFILE\.ssh\raspberry_tls_bench_ed25519",

    [int]$Runs = 10,

    [int]$TimeSeconds = 3,

    [int]$BasePort = 50000,

    [ValidateSet("python", "openssl")]
    [string]$ServerMode = "python",

    [switch]$ExperimentalMatrix,

    [switch]$RegenerateCerts,

    # Resume helper: do not delete existing raw_results.csv; skip rows already present.
    [switch]$SkipExisting,

    [int]$RetriesPerRun = 2,

    [int]$RetryDelaySeconds = 10
)

$ErrorActionPreference = "Stop"

function Test-KeyWorksWithoutPrompt {
    param([string]$KeyPath, [string]$PiUser, [string]$PiHost)
    if (-not (Test-Path $KeyPath)) { return $false }

    # Do NOT call ssh without BatchMode here; if the key is wrong, we want a fast failure, not 50 prompts.
    ssh -i $KeyPath -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$PiUser@$PiHost" "echo ok" *> $null
    return ($LASTEXITCODE -eq 0)
}

if (-not (Test-KeyWorksWithoutPrompt -KeyPath $SshKeyPath -PiUser $PiUser -PiHost $PiHost)) {
    Write-Host "SSH key is missing, encrypted, or not accepted. Recreating it WITHOUT passphrase..."
    powershell -ExecutionPolicy Bypass -File ".\scripts\windows\Setup-SshKey.ps1" -PiHost $PiHost -PiUser $PiUser -KeyPath $SshKeyPath -ForceRecreate
    if ($LASTEXITCODE -ne 0) { throw "SSH key setup failed." }
}

Write-Host "Testing passwordless SSH before running benchmark..."
ssh -i $SshKeyPath -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$PiUser@$PiHost" "echo ok && hostname && openssl version" | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "Passwordless SSH is not working. Run Setup-SshKey.ps1 with -ForceRecreate."
}

$runArgs = @(
    "-ExecutionPolicy", "Bypass", "-File", ".\scripts\windows\Run-RemoteProject.ps1",
    "-PiHost", $PiHost,
    "-PiUser", $PiUser,
    "-Runs", $Runs,
    "-TimeSeconds", $TimeSeconds,
    "-BasePort", $BasePort,
    "-SshKeyPath", $SshKeyPath,
    "-ServerMode", $ServerMode
)
if ($ExperimentalMatrix) { $runArgs += @("-ExperimentalMatrix") }
if ($RegenerateCerts) { $runArgs += @("-RegenerateCerts") }
if ($SkipExisting) { $runArgs += @("-SkipExisting") }
$runArgs += @("-RetriesPerRun", $RetriesPerRun, "-RetryDelaySeconds", $RetryDelaySeconds)

powershell @runArgs
