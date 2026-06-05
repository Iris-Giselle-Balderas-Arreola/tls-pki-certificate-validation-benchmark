param(
    [Parameter(Mandatory = $true)]
    [string]$PiHost,

    [string]$PiUser = "pi",

    [string]$PiRepoPath = "~/tls-pki-benchmark",

    [string]$SshKeyPath = ""
)

$ErrorActionPreference = "Stop"

function Get-CommonSshArgs {
    $args = @("-o", "StrictHostKeyChecking=accept-new")
    if (-not [string]::IsNullOrWhiteSpace($SshKeyPath)) {
        $args += @("-i", $SshKeyPath, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes")
    }
    return $args
}

function Invoke-SshCommand {
    param([Parameter(Mandatory=$true)][string]$Command)
    $sshArgs = Get-CommonSshArgs
    $sshArgs += @("$PiUser@$PiHost", $Command)
    & ssh @sshArgs
}

function Invoke-ScpCopy {
    param([Parameter(Mandatory=$true)][string]$Source, [Parameter(Mandatory=$true)][string]$Destination)
    $scpArgs = @("-r") + (Get-CommonSshArgs)
    $scpArgs += @($Source, $Destination)
    & scp @scpArgs
}

Write-Host "Preparing Raspberry Pi directory: $PiRepoPath"
Invoke-SshCommand -Command "mkdir -p $PiRepoPath/certs $PiRepoPath/scripts $PiRepoPath/results"
if ($LASTEXITCODE -ne 0) { throw "SSH failed while preparing Raspberry directory. Run Setup-SshKey.ps1 first." }

Write-Host "Copying certificates..."
Invoke-ScpCopy -Source "certs" -Destination "$PiUser@$PiHost`:$PiRepoPath/"
if ($LASTEXITCODE -ne 0) { throw "SCP failed while copying certs." }

Write-Host "Copying scripts..."
Invoke-ScpCopy -Source "scripts" -Destination "$PiUser@$PiHost`:$PiRepoPath/"
if ($LASTEXITCODE -ne 0) { throw "SCP failed while copying scripts." }

Write-Host "Ensuring OpenSSL exists on Raspberry Pi..."
Invoke-SshCommand -Command "openssl version || (sudo apt update && sudo apt install -y openssl)"
if ($LASTEXITCODE -ne 0) { throw "Could not validate/install OpenSSL on Raspberry Pi." }

Write-Host "Sync completed. Raspberry Pi repo path: $PiRepoPath"
