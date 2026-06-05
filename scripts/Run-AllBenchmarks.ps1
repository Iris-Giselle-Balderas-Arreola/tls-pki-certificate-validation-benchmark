param(
    [int]$Runs = 100,
    [int]$TimeSeconds = 3,
    [int]$BasePort = 44330,

    [ValidateSet("default", "TLS1.2", "TLS1.3")]
    [string[]]$TlsVersions = @("default"),

    [ValidateSet("default", "tls12_aes128_gcm", "tls12_aes256_gcm", "tls12_chacha20", "tls13_aes128_gcm", "tls13_aes256_gcm", "tls13_chacha20")]
    [string[]]$CipherProfiles = @("default"),

    [switch]$ExperimentalMatrix
)

$ErrorActionPreference = "Stop"

function New-ExperimentPairs {
    param([switch]$UseFullMatrix, [string[]]$Versions, [string[]]$Profiles)

    $pairs = @()
    if ($UseFullMatrix) {
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
Remove-Item "results\raw_results.csv" -Force -ErrorAction SilentlyContinue
Remove-Item "results\*.log" -Force -ErrorAction SilentlyContinue

if (-not (Test-Path "certs\rsa\chain1\server.crt")) {
    Write-Host "Certificates not found. Generating certificates first..."
    powershell -ExecutionPolicy Bypass -File ".\scripts\New-TlsCertChains.ps1"
    if ($LASTEXITCODE -ne 0) {
        throw "Certificate generation failed."
    }
}

$experimentPairs = New-ExperimentPairs -UseFullMatrix:$ExperimentalMatrix -Versions $TlsVersions -Profiles $CipherProfiles
$configIndex = 0

foreach ($Algorithm in @("RSA", "ECDSA")) {
    foreach ($ChainLength in @(1, 2, 3)) {
        foreach ($pair in $experimentPairs) {
            $configIndex += 1
            $port = $BasePort + $configIndex

            Write-Host ""
            Write-Host "Running benchmark: $Algorithm chain$ChainLength tls=$($pair.TlsVersion) cipherProfile=$($pair.CipherProfile) on port $port"

            for ($Run = 1; $Run -le $Runs; $Run++) {
                powershell -ExecutionPolicy Bypass -File ".\scripts\Invoke-TlsBenchmark.ps1" `
                    -Algorithm $Algorithm `
                    -ChainLength $ChainLength `
                    -Run $Run `
                    -TimeSeconds $TimeSeconds `
                    -Port $port `
                    -TlsVersion $($pair.TlsVersion) `
                    -CipherProfile $($pair.CipherProfile) `
                    -ResultsPath "results\raw_results.csv"

                if ($LASTEXITCODE -ne 0) {
                    throw "Benchmark failed for $Algorithm chain$ChainLength tls=$($pair.TlsVersion) cipher=$($pair.CipherProfile) run $Run"
                }
            }
        }
    }
}

if (-not (Test-Path "results\raw_results.csv")) {
    throw "Benchmark did not produce results\raw_results.csv"
}

$lineCount = (Get-Content "results\raw_results.csv").Count
if ($lineCount -le 1) {
    throw "Benchmark CSV has only header or is empty. Check OpenSSL output logs in results."
}

Write-Host ""
Write-Host "All benchmarks completed. Results: results\raw_results.csv"
