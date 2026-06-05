param(
    [Parameter(Mandatory = $true)]
    [string]$PiHost,

    [string]$PiUser = "pi",

    [string]$KeyPath = "$env:USERPROFILE\.ssh\raspberry_tls_bench_ed25519",

    [switch]$ForceRecreate
)

$ErrorActionPreference = "Stop"

function Assert-CommandExists {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command not found in PATH: $Name"
    }
}

function Invoke-CmdLine {
    param(
        [Parameter(Mandatory=$true)][string]$Line,
        [switch]$Quiet
    )

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $env:ComSpec
    $psi.Arguments = "/d /s /c `"$Line`""
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    if (-not $Quiet) {
        if ($stdout) { Write-Host $stdout }
        if ($stderr) { Write-Host $stderr }
    }
    return $p.ExitCode
}

function Quote-CmdPath {
    param([string]$Path)
    return '"' + ($Path -replace '"','\"') + '"'
}

function Test-KeyWorksWithoutPassphrase {
    param([string]$PrivateKey)
    if (-not (Test-Path $PrivateKey)) { return $false }

    # Use cmd.exe because Windows PowerShell sometimes drops/blocks empty-string
    # arguments like -P "" or -N "" when passed through functions.
    $quotedKey = Quote-CmdPath $PrivateKey
    $line = "ssh-keygen -y -P `"`" -f $quotedKey"
    $code = Invoke-CmdLine -Line $line -Quiet
    return ($code -eq 0)
}

Assert-CommandExists "ssh"
Assert-CommandExists "scp"
Assert-CommandExists "ssh-keygen"

$sshDir = Split-Path $KeyPath
New-Item -ItemType Directory -Force -Path $sshDir | Out-Null
$pubPath = "$KeyPath.pub"

if ($ForceRecreate -or (Test-Path $KeyPath) -or (Test-Path $pubPath)) {
    Write-Host "Removing old benchmark SSH key so we can create a clean key WITHOUT passphrase..."
    Remove-Item -Force $KeyPath -ErrorAction SilentlyContinue
    Remove-Item -Force $pubPath -ErrorAction SilentlyContinue
}

if (-not (Test-Path $KeyPath)) {
    Write-Host "Creating SSH key WITHOUT passphrase: $KeyPath"
    $quotedKey = Quote-CmdPath $KeyPath
    # Important: -N "" means NO passphrase. This is intentional for an automated
    # local lab benchmark; do not reuse this key for anything sensitive.
    $line = "ssh-keygen -t ed25519 -f $quotedKey -C `"raspberry-tls-benchmark`" -N `"`" -q"
    $exit = Invoke-CmdLine -Line $line
    if ($exit -ne 0) {
        throw "ssh-keygen failed. Delete $KeyPath and $pubPath, then rerun this script."
    }
}

if (-not (Test-Path $pubPath)) {
    throw "Public key not found after generation: $pubPath"
}

if (-not (Test-KeyWorksWithoutPassphrase -PrivateKey $KeyPath)) {
    throw "The SSH key still requires a passphrase or cannot be read. Delete it and rerun with -ForceRecreate."
}

Write-Host "Copying public key to Raspberry Pi. Enter the Raspberry password ONE time if asked."
$publicKey = (Get-Content -Raw -Path $pubPath).Trim()
# Escape single quotes defensively, although OpenSSH public keys normally do not contain them.
$escapedPublicKey = $publicKey.Replace("'", "'\''")
$remoteCmd = "mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && grep -qxF '$escapedPublicKey' ~/.ssh/authorized_keys || echo '$escapedPublicKey' >> ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys"
& ssh -o StrictHostKeyChecking=accept-new "$PiUser@$PiHost" $remoteCmd
if ($LASTEXITCODE -ne 0) {
    throw "Could not copy SSH public key to Raspberry Pi. Check PiHost/PiUser/password."
}

Write-Host "Testing passwordless SSH..."
& ssh -i $KeyPath -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$PiUser@$PiHost" "echo SSH key OK && hostname && openssl version"
if ($LASTEXITCODE -ne 0) {
    throw "Passwordless SSH test failed. The key was copied, but SSH did not accept it."
}

Write-Host ""
Write-Host "Done. Future runs will use this key automatically:"
Write-Host $KeyPath
