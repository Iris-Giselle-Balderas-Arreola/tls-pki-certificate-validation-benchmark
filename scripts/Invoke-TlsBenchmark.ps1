param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("RSA", "ECDSA")]
    [string]$Algorithm,

    [Parameter(Mandatory = $true)]
    [int]$ChainLength,

    [Parameter(Mandatory = $true)]
    [int]$Run,

    [int]$TimeSeconds = 3,

    [int]$Port = 44330,

    [ValidateSet("default", "TLS1.2", "TLS1.3")]
    [string]$TlsVersion = "default",

    [ValidateSet("default", "tls12_aes128_gcm", "tls12_aes256_gcm", "tls12_chacha20", "tls13_aes128_gcm", "tls13_aes256_gcm", "tls13_chacha20")]
    [string]$CipherProfile = "default",

    [string]$ResultsPath = "results\raw_results.csv"
)

$ErrorActionPreference = "Stop"

function Assert-FileExists {
    param([string]$Path, [string]$Label)
    if (-not (Test-Path $Path)) { throw "$Label not found: $Path" }
}

function Get-FileSizeBytes {
    param([string]$Path)
    if (Test-Path $Path) { return (Get-Item $Path).Length }
    return 0
}

function Escape-Csv {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    $text = [string]$Value
    $text = $text.Replace('"', '""')
    if ($text.Contains(",") -or $text.Contains('"') -or $text.Contains("`n") -or $text.Contains("`r")) { return '"' + $text + '"' }
    return $text
}

function Get-SafeName {
    param([string]$Value)
    return ([regex]::Replace($Value, "[^A-Za-z0-9_-]", "_"))
}

function Get-PythonCommand {
    $candidates = @("python", "py")
    foreach ($candidate in $candidates) {
        try {
            & $candidate --version *> $null
            if ($LASTEXITCODE -eq 0) { return $candidate }
        } catch { }
    }
    throw "Python not found on Windows. Install Python or make sure 'python' is in PATH."
}

function Count-CertificatesInPem {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return 0 }
    $text = Get-Content $Path -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($text)) { return 0 }
    return ([regex]::Matches($text, "-----BEGIN CERTIFICATE-----")).Count
}

function Get-OpenSslVersionText {
    try { return ((& openssl version 2>$null) -join " ").Trim() } catch { return "" }
}

function Get-CertFeatureMap {
    param([string]$CertPath)

    $features = @{
        public_key_algorithm = ""
        public_key_bits = ""
        ec_curve = ""
        signature_algorithm = ""
        cert_validity_days = ""
        cert_not_before = ""
        cert_not_after = ""
        cert_sha256_fingerprint = ""
    }

    if (-not (Test-Path $CertPath)) { return $features }

    try {
        $text = ((& openssl x509 -in $CertPath -noout -text 2>$null) -join "`n")
        if ($text -match "Public Key Algorithm:\s*([^`r`n]+)") { $features.public_key_algorithm = $Matches[1].Trim() }
        if ($text -match "Public-Key:\s*\((\d+) bit\)") { $features.public_key_bits = $Matches[1].Trim() }
        if ($text -match "ASN1 OID:\s*([^`r`n]+)") { $features.ec_curve = $Matches[1].Trim() }
        if ($text -match "Signature Algorithm:\s*([^`r`n]+)") { $features.signature_algorithm = $Matches[1].Trim() }
    } catch { }

    try {
        $dates = ((& openssl x509 -in $CertPath -noout -dates 2>$null) -join "`n")
        if ($dates -match "notBefore=([^`r`n]+)") { $features.cert_not_before = $Matches[1].Trim() }
        if ($dates -match "notAfter=([^`r`n]+)") { $features.cert_not_after = $Matches[1].Trim() }
        if (-not [string]::IsNullOrWhiteSpace($features.cert_not_before) -and -not [string]::IsNullOrWhiteSpace($features.cert_not_after)) {
            try {
                $nb = [DateTime]::Parse($features.cert_not_before, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal)
                $na = [DateTime]::Parse($features.cert_not_after, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal)
                $features.cert_validity_days = [math]::Round(($na - $nb).TotalDays, 2)
            } catch { }
        }
    } catch { }

    try {
        $fp = ((& openssl x509 -in $CertPath -noout -fingerprint -sha256 2>$null) -join "`n")
        if ($fp -match "SHA256 Fingerprint=(.+)") { $features.cert_sha256_fingerprint = $Matches[1].Trim() }
    } catch { }

    return $features
}

function Get-JsonValue {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return "" }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -ne $prop) { return $prop.Value }
    return ""
}

function Convert-JsonArrayToCompactText {
    param($Value)
    if ($null -eq $Value) { return "" }
    try { return (($Value | ConvertTo-Json -Compress -Depth 4) -replace "`r", " " -replace "`n", " ") } catch { return [string]$Value }
}

function Get-CipherExperimentSettings {
    param(
        [ValidateSet("RSA", "ECDSA")][string]$Algorithm,
        [ValidateSet("default", "TLS1.2", "TLS1.3")][string]$TlsVersion,
        [string]$CipherProfile
    )

    if ($CipherProfile -ne "default" -and $TlsVersion -eq "default") {
        throw "CipherProfile '$CipherProfile' requires explicit -TlsVersion TLS1.2 or TLS1.3."
    }
    if ($CipherProfile.StartsWith("tls12_") -and $TlsVersion -ne "TLS1.2") { throw "CipherProfile '$CipherProfile' must be used with -TlsVersion TLS1.2." }
    if ($CipherProfile.StartsWith("tls13_") -and $TlsVersion -ne "TLS1.3") { throw "CipherProfile '$CipherProfile' must be used with -TlsVersion TLS1.3." }

    $auth = if ($Algorithm -eq "RSA") { "RSA" } else { "ECDSA" }
    $settings = @{
        client_cipher_string = ""
        server_cipher_string = ""
        server_ciphersuites = ""
        cipher_profile_encoded = 0
        tls_version_requested_encoded = 0
        cipher_family = "default"
        cipher_bulk = "default"
        cipher_mode = "default"
        is_cipher_restricted = 0
        is_tls13_cipher_suite = 0
    }

    if ($TlsVersion -eq "TLS1.2") { $settings.tls_version_requested_encoded = 12 }
    elseif ($TlsVersion -eq "TLS1.3") { $settings.tls_version_requested_encoded = 13 }

    switch ($CipherProfile) {
        "tls12_aes128_gcm" {
            $value = "ECDHE-$auth-AES128-GCM-SHA256"
            $settings.client_cipher_string = $value; $settings.server_cipher_string = $value
            $settings.cipher_profile_encoded = 12128; $settings.cipher_family = "AES"; $settings.cipher_bulk = "AES128"; $settings.cipher_mode = "GCM"; $settings.is_cipher_restricted = 1
        }
        "tls12_aes256_gcm" {
            $value = "ECDHE-$auth-AES256-GCM-SHA384"
            $settings.client_cipher_string = $value; $settings.server_cipher_string = $value
            $settings.cipher_profile_encoded = 12256; $settings.cipher_family = "AES"; $settings.cipher_bulk = "AES256"; $settings.cipher_mode = "GCM"; $settings.is_cipher_restricted = 1
        }
        "tls12_chacha20" {
            $value = "ECDHE-$auth-CHACHA20-POLY1305"
            $settings.client_cipher_string = $value; $settings.server_cipher_string = $value
            $settings.cipher_profile_encoded = 12200; $settings.cipher_family = "CHACHA20"; $settings.cipher_bulk = "CHACHA20"; $settings.cipher_mode = "POLY1305"; $settings.is_cipher_restricted = 1
        }
        "tls13_aes128_gcm" {
            $settings.server_ciphersuites = "TLS_AES_128_GCM_SHA256"
            $settings.cipher_profile_encoded = 13128; $settings.cipher_family = "AES"; $settings.cipher_bulk = "AES128"; $settings.cipher_mode = "GCM"; $settings.is_cipher_restricted = 1; $settings.is_tls13_cipher_suite = 1
        }
        "tls13_aes256_gcm" {
            $settings.server_ciphersuites = "TLS_AES_256_GCM_SHA384"
            $settings.cipher_profile_encoded = 13256; $settings.cipher_family = "AES"; $settings.cipher_bulk = "AES256"; $settings.cipher_mode = "GCM"; $settings.is_cipher_restricted = 1; $settings.is_tls13_cipher_suite = 1
        }
        "tls13_chacha20" {
            $settings.server_ciphersuites = "TLS_CHACHA20_POLY1305_SHA256"
            $settings.cipher_profile_encoded = 13200; $settings.cipher_family = "CHACHA20"; $settings.cipher_bulk = "CHACHA20"; $settings.cipher_mode = "POLY1305"; $settings.is_cipher_restricted = 1; $settings.is_tls13_cipher_suite = 1
        }
        default { }
    }
    return $settings
}

$settings = Get-CipherExperimentSettings -Algorithm $Algorithm -TlsVersion $TlsVersion -CipherProfile $CipherProfile
$experimentId = "$Algorithm-chain$ChainLength-$TlsVersion-$CipherProfile"
$safeExperiment = Get-SafeName $experimentId

$CsvHeaders = @(
    "timestamp", "test_mode", "experiment_id", "algorithm", "algorithm_encoded", "key_family", "key_size_bits", "ec_curve",
    "signature_algorithm", "public_key_algorithm", "chain_length", "intermediates_sent_count", "certs_sent_count",
    "validation_chain_cert_count", "root_cert_in_trust_store", "run", "requested_duration_seconds", "actual_elapsed_seconds",
    "port", "target_host", "pi_host", "server_name", "server_mode", "tls_version_requested", "tls_version_requested_encoded",
    "cipher_profile_requested", "cipher_profile_encoded", "cipher_family", "cipher_bulk", "cipher_mode", "is_cipher_restricted", "is_tls13_cipher_suite",
    "client_cipher_string_requested", "server_cipher_string_requested", "server_ciphersuites_requested",
    "client_os", "client_python_version", "client_ssl_library", "client_openssl_version", "openssl_cli_version",
    "tls_min_version_configured", "tls_max_version_configured", "tls_version_observed", "cipher_name",
    "cipher_protocol", "cipher_bits", "compression", "alpn_protocol", "session_reused_count", "session_reused_rate",
    "connection_attempts", "success_count", "failure_count", "success_rate", "failure_rate", "connections_per_sec", "total_connections",
    "mean_handshake_ms", "median_handshake_ms", "p90_handshake_ms", "p95_handshake_ms", "p99_handshake_ms", "min_handshake_ms",
    "max_handshake_ms", "std_handshake_ms", "mean_tcp_connect_ms", "median_tcp_connect_ms", "p95_tcp_connect_ms",
    "mean_tls_handshake_ms", "median_tls_handshake_ms", "p95_tls_handshake_ms", "mean_request_response_ms",
    "median_request_response_ms", "p95_request_response_ms", "mean_total_connection_ms", "median_total_connection_ms",
    "p95_total_connection_ms", "p99_total_connection_ms", "min_total_connection_ms", "max_total_connection_ms", "std_total_connection_ms",
    "total_app_bytes_sent", "total_app_bytes_received", "mean_app_bytes_received", "server_cert_bytes", "chain_pem_bytes",
    "root_cert_bytes", "sent_chain_pem_bytes", "total_cert_material_bytes", "cert_material_kb", "cert_validity_days", "cert_not_before",
    "cert_not_after", "cert_sha256_fingerprint", "exit_code", "stage", "failure_examples", "raw_output_log"
)

$algDirName = $Algorithm.ToLowerInvariant()
$configDir = Join-Path "certs" (Join-Path $algDirName "chain$ChainLength")

$serverCrt = Join-Path $configDir "server.crt"
$serverKey = Join-Path $configDir "server.key"
$chainPem = Join-Path $configDir "chain.pem"
$rootCrt = Join-Path $configDir "root.crt"

Assert-FileExists -Path $serverCrt -Label "Server certificate"
Assert-FileExists -Path $serverKey -Label "Server key"
Assert-FileExists -Path $rootCrt -Label "Root certificate"
Assert-FileExists -Path ".\scripts\TlsClientBenchmark.py" -Label "Python TLS client benchmark"

New-Item -ItemType Directory -Force -Path (Split-Path $ResultsPath) | Out-Null
$headerLine = ($CsvHeaders -join ",")
if (Test-Path $ResultsPath) {
    $existingHeader = Get-Content $ResultsPath -First 1 -ErrorAction SilentlyContinue
    if ($existingHeader -ne $headerLine) {
        $backupPath = "$ResultsPath.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Move-Item -Force $ResultsPath $backupPath
        Write-Warning "Existing CSV header was from an older schema. Moved it to $backupPath and started a new raw_results.csv."
    }
}
if (-not (Test-Path $ResultsPath)) { $headerLine | Set-Content -Encoding utf8 $ResultsPath }

$serverArgs = @("s_server", "-accept", "$Port", "-cert", $serverCrt, "-key", $serverKey, "-quiet", "-www")
if ((Test-Path $chainPem) -and ((Get-Item $chainPem).Length -gt 5)) { $serverArgs += @("-cert_chain", $chainPem) }
if ($TlsVersion -eq "TLS1.2") { $serverArgs += @("-tls1_2") }
elseif ($TlsVersion -eq "TLS1.3") { $serverArgs += @("-tls1_3") }
if (-not [string]::IsNullOrWhiteSpace($settings.server_cipher_string)) { $serverArgs += @("-cipher", $settings.server_cipher_string) }
if (-not [string]::IsNullOrWhiteSpace($settings.server_ciphersuites)) { $serverArgs += @("-ciphersuites", $settings.server_ciphersuites) }

$serverOut = Join-Path "results" "server_${safeExperiment}_run${Run}.out.log"
$serverErr = Join-Path "results" "server_${safeExperiment}_run${Run}.err.log"
Remove-Item $serverOut -Force -ErrorAction SilentlyContinue
Remove-Item $serverErr -Force -ErrorAction SilentlyContinue

$serverProcess = Start-Process -FilePath "openssl" -ArgumentList $serverArgs -PassThru -WindowStyle Hidden -RedirectStandardOutput $serverOut -RedirectStandardError $serverErr
Start-Sleep -Milliseconds 1200

if ($serverProcess.HasExited) {
    $errText = ""
    if (Test-Path $serverErr) { $errText = Get-Content $serverErr -Raw -ErrorAction SilentlyContinue }
    throw "OpenSSL server exited before client test. Port may be busy, certificate may be invalid, or cipher/TLS profile may be unsupported. Server stderr: $errText"
}

$clientOut = Join-Path "results" "client_${safeExperiment}_run${Run}.out.log"
$clientErr = Join-Path "results" "client_${safeExperiment}_run${Run}.err.log"
Remove-Item $clientOut -Force -ErrorAction SilentlyContinue
Remove-Item $clientErr -Force -ErrorAction SilentlyContinue

$pythonCmd = Get-PythonCommand
$clientArgs = @(
    ".\scripts\TlsClientBenchmark.py", "--host", "127.0.0.1", "--port", "$Port", "--cafile", $rootCrt,
    "--duration", "$TimeSeconds", "--server-name", "localhost", "--timeout", "3.0", "--warmup-timeout", "12.0",
    "--tls-version", $TlsVersion, "--cipher-profile", $CipherProfile
)
if (-not [string]::IsNullOrWhiteSpace($settings.client_cipher_string)) { $clientArgs += @("--cipher-string", $settings.client_cipher_string) }

$clientOutput = ""
$exitCode = 999
try {
    $clientLines = & $pythonCmd @clientArgs 2>&1
    $exitCode = $LASTEXITCODE
    $clientOutput = ($clientLines -join "`n")
    Set-Content -Encoding utf8 -Path $clientOut -Value $clientOutput
}
catch {
    $clientOutput = $_ | Out-String
    Set-Content -Encoding utf8 -Path $clientErr -Value $clientOutput
    $exitCode = 998
}
finally {
    if ($null -ne $serverProcess -and -not $serverProcess.HasExited) { Stop-Process -Id $serverProcess.Id -Force -ErrorAction SilentlyContinue }
}

$jsonLine = (($clientOutput -split "`n") | Where-Object { $_.Trim().StartsWith("{") } | Select-Object -Last 1)
$parsed = $null
if ($null -ne $jsonLine) { try { $parsed = $jsonLine | ConvertFrom-Json } catch { $parsed = $null } }

$timestamp = (Get-Date).ToString("s")
$serverCertBytes = Get-FileSizeBytes $serverCrt
$chainPemBytes = Get-FileSizeBytes $chainPem
$rootCertBytes = Get-FileSizeBytes $rootCrt
$intermediatesSentCount = Count-CertificatesInPem $chainPem
$certsSentCount = 1 + $intermediatesSentCount
$validationChainCertCount = $certsSentCount + 1
$totalCertMaterialBytes = $serverCertBytes + $chainPemBytes + $rootCertBytes
$sentChainPemBytes = $serverCertBytes + $chainPemBytes
$certMaterialKb = [math]::Round($totalCertMaterialBytes / 1024.0, 4)
$certFeatures = Get-CertFeatureMap $serverCrt
$keyFamily = if ($Algorithm -eq "ECDSA") { "EC" } else { "RSA" }
$keySizeBits = if (-not [string]::IsNullOrWhiteSpace($certFeatures.public_key_bits)) { $certFeatures.public_key_bits } elseif ($Algorithm -eq "RSA") { "2048" } else { "256" }
$algorithmEncoded = if ($Algorithm -eq "RSA") { 0 } else { 1 }
$rawOneLine = ([string]$clientOutput).Trim() -replace "`r", " " -replace "`n", " | "

$rowMap = @{
    timestamp = $timestamp; test_mode = "local_windows"; experiment_id = $experimentId; algorithm = $Algorithm; algorithm_encoded = $algorithmEncoded; key_family = $keyFamily;
    key_size_bits = $keySizeBits; ec_curve = $certFeatures.ec_curve; signature_algorithm = $certFeatures.signature_algorithm;
    public_key_algorithm = $certFeatures.public_key_algorithm; chain_length = $ChainLength; intermediates_sent_count = $intermediatesSentCount;
    certs_sent_count = $certsSentCount; validation_chain_cert_count = $validationChainCertCount; root_cert_in_trust_store = 1; run = $Run;
    requested_duration_seconds = $TimeSeconds; actual_elapsed_seconds = (Get-JsonValue $parsed "actual_elapsed_seconds"); port = $Port;
    target_host = "127.0.0.1"; pi_host = ""; server_name = "localhost"; server_mode = "openssl";
    tls_version_requested = $TlsVersion; tls_version_requested_encoded = $settings.tls_version_requested_encoded;
    cipher_profile_requested = $CipherProfile; cipher_profile_encoded = $settings.cipher_profile_encoded; cipher_family = $settings.cipher_family; cipher_bulk = $settings.cipher_bulk; cipher_mode = $settings.cipher_mode;
    is_cipher_restricted = $settings.is_cipher_restricted; is_tls13_cipher_suite = $settings.is_tls13_cipher_suite;
    client_cipher_string_requested = $settings.client_cipher_string; server_cipher_string_requested = $settings.server_cipher_string; server_ciphersuites_requested = $settings.server_ciphersuites;
    client_os = (Get-JsonValue $parsed "client_os"); client_python_version = (Get-JsonValue $parsed "client_python_version");
    client_ssl_library = (Get-JsonValue $parsed "client_ssl_library"); client_openssl_version = (Get-JsonValue $parsed "client_openssl_version");
    openssl_cli_version = (Get-OpenSslVersionText); tls_min_version_configured = (Get-JsonValue $parsed "tls_min_version_configured"); tls_max_version_configured = (Get-JsonValue $parsed "tls_max_version_configured");
    tls_version_observed = (Get-JsonValue $parsed "tls_version_observed"); cipher_name = (Get-JsonValue $parsed "cipher_name"); cipher_protocol = (Get-JsonValue $parsed "cipher_protocol");
    cipher_bits = (Get-JsonValue $parsed "cipher_bits"); compression = (Get-JsonValue $parsed "compression"); alpn_protocol = (Get-JsonValue $parsed "alpn_protocol");
    session_reused_count = (Get-JsonValue $parsed "session_reused_count"); session_reused_rate = (Get-JsonValue $parsed "session_reused_rate"); connection_attempts = (Get-JsonValue $parsed "connection_attempts");
    success_count = (Get-JsonValue $parsed "success_count"); failure_count = (Get-JsonValue $parsed "failure_count"); success_rate = (Get-JsonValue $parsed "success_rate"); failure_rate = (Get-JsonValue $parsed "failure_rate");
    connections_per_sec = (Get-JsonValue $parsed "connections_per_sec"); total_connections = (Get-JsonValue $parsed "success_count");
    mean_handshake_ms = (Get-JsonValue $parsed "mean_handshake_ms"); median_handshake_ms = (Get-JsonValue $parsed "median_handshake_ms"); p90_handshake_ms = (Get-JsonValue $parsed "p90_handshake_ms");
    p95_handshake_ms = (Get-JsonValue $parsed "p95_handshake_ms"); p99_handshake_ms = (Get-JsonValue $parsed "p99_handshake_ms"); min_handshake_ms = (Get-JsonValue $parsed "min_handshake_ms");
    max_handshake_ms = (Get-JsonValue $parsed "max_handshake_ms"); std_handshake_ms = (Get-JsonValue $parsed "std_handshake_ms"); mean_tcp_connect_ms = (Get-JsonValue $parsed "mean_tcp_connect_ms");
    median_tcp_connect_ms = (Get-JsonValue $parsed "median_tcp_connect_ms"); p95_tcp_connect_ms = (Get-JsonValue $parsed "p95_tcp_connect_ms"); mean_tls_handshake_ms = (Get-JsonValue $parsed "mean_tls_handshake_ms");
    median_tls_handshake_ms = (Get-JsonValue $parsed "median_tls_handshake_ms"); p95_tls_handshake_ms = (Get-JsonValue $parsed "p95_tls_handshake_ms"); mean_request_response_ms = (Get-JsonValue $parsed "mean_request_response_ms");
    median_request_response_ms = (Get-JsonValue $parsed "median_request_response_ms"); p95_request_response_ms = (Get-JsonValue $parsed "p95_request_response_ms"); mean_total_connection_ms = (Get-JsonValue $parsed "mean_total_connection_ms");
    median_total_connection_ms = (Get-JsonValue $parsed "median_total_connection_ms"); p95_total_connection_ms = (Get-JsonValue $parsed "p95_total_connection_ms"); p99_total_connection_ms = (Get-JsonValue $parsed "p99_total_connection_ms");
    min_total_connection_ms = (Get-JsonValue $parsed "min_total_connection_ms"); max_total_connection_ms = (Get-JsonValue $parsed "max_total_connection_ms"); std_total_connection_ms = (Get-JsonValue $parsed "std_total_connection_ms");
    total_app_bytes_sent = (Get-JsonValue $parsed "total_app_bytes_sent"); total_app_bytes_received = (Get-JsonValue $parsed "total_app_bytes_received"); mean_app_bytes_received = (Get-JsonValue $parsed "mean_app_bytes_received");
    server_cert_bytes = $serverCertBytes; chain_pem_bytes = $chainPemBytes; root_cert_bytes = $rootCertBytes; sent_chain_pem_bytes = $sentChainPemBytes; total_cert_material_bytes = $totalCertMaterialBytes; cert_material_kb = $certMaterialKb;
    cert_validity_days = $certFeatures.cert_validity_days; cert_not_before = $certFeatures.cert_not_before; cert_not_after = $certFeatures.cert_not_after; cert_sha256_fingerprint = $certFeatures.cert_sha256_fingerprint;
    exit_code = $exitCode; stage = (Get-JsonValue $parsed "stage"); failure_examples = (Convert-JsonArrayToCompactText (Get-JsonValue $parsed "sample_failures")); raw_output_log = $rawOneLine
}

$row = $CsvHeaders | ForEach-Object { Escape-Csv $rowMap[$_] }
Add-Content -Encoding utf8 -Path $ResultsPath -Value ($row -join ",")

if ($exitCode -ne 0) { Write-Warning "Client benchmark returned exit code $exitCode for $experimentId run $Run. Check $clientOut and $clientErr" }
Write-Host "Completed local test: $experimentId run $Run TLS/sec=$($rowMap.connections_per_sec) observed=$($rowMap.tls_version_observed)/$($rowMap.cipher_name) mean_tls_only_ms=$($rowMap.mean_tls_handshake_ms)"
