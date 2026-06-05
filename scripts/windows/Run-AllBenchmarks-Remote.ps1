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

    [ValidateSet("default", "TLS1.2", "TLS1.3")]
    [string[]]$TlsVersions = @("default"),

    [ValidateSet("default", "tls12_aes128_gcm", "tls12_aes256_gcm", "tls12_chacha20", "tls13_aes128_gcm", "tls13_aes256_gcm", "tls13_chacha20")]
    [string[]]$CipherProfiles = @("default"),

    [switch]$ExperimentalMatrix,

    # Resume helper: keep existing raw_results.csv and skip rows that already exist.
    [switch]$SkipExisting,

    # Retry transient SSH / mDNS / network hiccups before failing the whole experiment.
    [int]$RetriesPerRun = 2,

    [int]$RetryDelaySeconds = 10
)

$ErrorActionPreference = "Stop"

function New-ExperimentPairs {
    param([switch]$UseFullMatrix, [string[]]$Versions, [string[]]$Profiles)

    $pairs = @()
    if ($UseFullMatrix) {
        # Curated valid pairs. It intentionally avoids invalid combos such as TLS1.3 + TLS1.2 cipher strings.
        $pairs += [pscustomobject]@{ TlsVersion = "default"; CipherProfile = "default" }
        $pairs += [pscustomobject]@{ TlsVersion = "TLS1.2"; CipherProfile = "default" }
        $pairs += [pscustomobject]@{ TlsVersion = "TLS1.2"; CipherProfile = "tls12_aes128_gcm" }
        $pairs += [pscustomobject]@{ TlsVersion = "TLS1.2"; CipherProfile = "tls12_aes256_gcm" }
        $pairs += [pscustomobject]@{ TlsVersion = "TLS1.2"; CipherProfile = "tls12_chacha20" }
        $pairs += [pscustomobject]@{ TlsVersion = "TLS1.3"; CipherProfile = "default" }
        $pairs += [pscustomobject]@{ TlsVersion = "TLS1.3"; CipherProfile = "tls13_aes128_gcm" }
        $pairs += [pscustomobject]@{ TlsVersion = "TLS1.3"; CipherProfile = "tls13_aes256_gcm" }
        $pairs += [pscustomobject]@{ TlsVersion = "TLS1.3"; CipherProfile = "tls13_chacha20" }
        return $pairs
    }

    foreach ($version in $Versions) {
        foreach ($profile in $Profiles) {
            $pairs += [pscustomobject]@{ TlsVersion = $version; CipherProfile = $profile }
        }
    }
    return $pairs
}

New-Item -ItemType Directory -Force -Path "results" | Out-Null
if ($SkipExisting) {
    Write-Host "Resume mode enabled: keeping existing results\raw_results.csv and skipping completed rows."
} else {
    Remove-Item "results\raw_results.csv" -Force -ErrorAction SilentlyContinue
    Remove-Item "results\*.log" -Force -ErrorAction SilentlyContinue
}

$existingKeys = @{}
if ($SkipExisting -and (Test-Path "results\raw_results.csv")) {
    try {
        Import-Csv "results\raw_results.csv" | ForEach-Object {
            if (-not [string]::IsNullOrWhiteSpace($_.experiment_id) -and -not [string]::IsNullOrWhiteSpace($_.run)) {
                $existingKeys["$($_.experiment_id)|$($_.run)"] = $true
            }
        }
        Write-Host "Loaded $($existingKeys.Count) completed result rows for resume/skip."
    } catch {
        Write-Warning "Could not read existing results for resume mode. The file may be partially written or malformed. Error: $($_.Exception.Message)"
    }
}

if (-not (Test-Path "certs\rsa\chain1\server.crt")) {
    Write-Host "Certificates not found. Generating certificates first..."
    powershell -ExecutionPolicy Bypass -File ".\scripts\New-TlsCertChains.ps1"
    if ($LASTEXITCODE -ne 0) { throw "Certificate generation failed." }
}

$experimentPairs = New-ExperimentPairs -UseFullMatrix:$ExperimentalMatrix -Versions $TlsVersions -Profiles $CipherProfiles
$effectiveServerMode = $ServerMode
if ($ExperimentalMatrix -and $ServerMode -eq "python") {
    $effectiveServerMode = "openssl"
    Write-Host "Experimental matrix enabled: using OpenSSL server mode so TLS 1.3 ciphersuite restrictions are enforceable."
}

$configIndex = 0

foreach ($Algorithm in @("RSA", "ECDSA")) {
    foreach ($ChainLength in @(1, 2, 3)) {
        foreach ($pair in $experimentPairs) {
            $configIndex += 1
            $port = $BasePort + $configIndex

            Write-Host ""
            Write-Host "Running remote benchmark: $Algorithm chain$ChainLength tls=$($pair.TlsVersion) cipherProfile=$($pair.CipherProfile) mode=$effectiveServerMode port=$port"

            $experimentId = "$Algorithm-chain$ChainLength-$($pair.TlsVersion)-$($pair.CipherProfile)"

            for ($Run = 1; $Run -le $Runs; $Run++) {
                $resumeKey = "$experimentId|$Run"
                if ($SkipExisting -and $existingKeys.ContainsKey($resumeKey)) {
                    Write-Host "Skipping completed result: $experimentId run $Run"
                    continue
                }

                $invokeArgs = @(
                    "-ExecutionPolicy", "Bypass", "-File", ".\scripts\windows\Invoke-TlsBenchmark-Remote.ps1",
                    "-Algorithm", $Algorithm,
                    "-ChainLength", $ChainLength,
                    "-Run", $Run,
                    "-PiHost", $PiHost,
                    "-PiUser", $PiUser,
                    "-PiRepoPath", $PiRepoPath,
                    "-TimeSeconds", $TimeSeconds,
                    "-Port", $port,
                    "-ServerMode", $effectiveServerMode,
                    "-TlsVersion", $pair.TlsVersion,
                    "-CipherProfile", $pair.CipherProfile,
                    "-ResultsPath", "results\raw_results.csv"
                )
                if (-not [string]::IsNullOrWhiteSpace($SshKeyPath)) { $invokeArgs += @("-SshKeyPath", $SshKeyPath) }

                $success = $false
                $maxAttempts = [math]::Max(1, $RetriesPerRun + 1)
                for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
                    if ($attempt -gt 1) {
                        Write-Warning "Retrying $experimentId run $Run. Attempt $attempt of $maxAttempts after $RetryDelaySeconds seconds..."
                        Start-Sleep -Seconds $RetryDelaySeconds
                    }

                    powershell @invokeArgs
                    if ($LASTEXITCODE -eq 0) {
                        $success = $true
                        if ($SkipExisting) { $existingKeys[$resumeKey] = $true }
                        break
                    }

                    Write-Warning "Attempt $attempt failed for $experimentId run $Run with exit code $LASTEXITCODE."
                }

                if (-not $success) {
                    throw "Remote benchmark failed for $Algorithm chain$ChainLength tls=$($pair.TlsVersion) cipher=$($pair.CipherProfile) run $Run after $maxAttempts attempt(s)"
                }
            }
        }
    }
}

if (-not (Test-Path "results\raw_results.csv")) { throw "Benchmark did not produce results\raw_results.csv" }

$lineCount = (Get-Content "results\raw_results.csv").Count
if ($lineCount -le 1) { throw "Benchmark CSV has only header or is empty. Check logs in results." }

Write-Host ""
Write-Host "All remote benchmarks completed. Results: results\raw_results.csv"
