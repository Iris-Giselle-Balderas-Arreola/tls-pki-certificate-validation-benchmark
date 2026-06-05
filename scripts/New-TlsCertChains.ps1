param(
    [int[]]$ChainLengths = @(1, 2, 3),
    [int]$Days = 3650
)

$ErrorActionPreference = "Stop"

function Invoke-OpenSSL {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & openssl @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "OpenSSL failed: openssl $($Arguments -join ' ')"
    }
}

function New-TlsBenchKey {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("RSA", "ECDSA")]
        [string]$Algorithm,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    if ($Algorithm -eq "RSA") {
        Invoke-OpenSSL -Arguments @("genrsa", "-out", $OutputPath, "2048")
    }
    else {
        Invoke-OpenSSL -Arguments @("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", $OutputPath)
    }
}

function Write-ExtensionFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet("CA", "SERVER")]
        [string]$Kind
    )

    if ($Kind -eq "CA") {
@"
basicConstraints=critical,CA:TRUE,pathlen:5
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
"@ | Set-Content -Encoding ascii $Path
    }
    else {
@"
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
"@ | Set-Content -Encoding ascii $Path
    }
}

Write-Host "Cleaning previous certificates..."
Remove-Item -Recurse -Force "certs" -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path "certs" | Out-Null

foreach ($Algorithm in @("RSA", "ECDSA")) {
    $algDirName = $Algorithm.ToLowerInvariant()

    foreach ($ChainLength in $ChainLengths) {
        $dir = Join-Path "certs" (Join-Path $algDirName "chain$ChainLength")
        New-Item -ItemType Directory -Force -Path $dir | Out-Null

        $caExt = Join-Path $dir "ca_ext.cnf"
        $serverExt = Join-Path $dir "server_ext.cnf"

        Write-ExtensionFile -Path $caExt -Kind "CA"
        Write-ExtensionFile -Path $serverExt -Kind "SERVER"

        $rootKey = Join-Path $dir "root.key"
        $rootCrt = Join-Path $dir "root.crt"

        New-TlsBenchKey -Algorithm $Algorithm -OutputPath $rootKey

        Invoke-OpenSSL -Arguments @(
            "req", "-x509", "-new", "-nodes",
            "-key", $rootKey,
            "-sha256",
            "-days", "$Days",
            "-out", $rootCrt,
            "-subj", "/CN=TLS Bench $Algorithm Root chain$ChainLength",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:5",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash"
        )

        $issuerCrt = $rootCrt
        $issuerKey = $rootKey
        $intermediateCerts = @()

        $numIntermediates = $ChainLength - 1

        for ($i = 1; $i -le $numIntermediates; $i++) {
            $intKey = Join-Path $dir "int$i.key"
            $intCsr = Join-Path $dir "int$i.csr"
            $intCrt = Join-Path $dir "int$i.crt"

            New-TlsBenchKey -Algorithm $Algorithm -OutputPath $intKey

            Invoke-OpenSSL -Arguments @(
                "req", "-new",
                "-key", $intKey,
                "-out", $intCsr,
                "-subj", "/CN=TLS Bench $Algorithm Intermediate $i chain$ChainLength"
            )

            Invoke-OpenSSL -Arguments @(
                "x509", "-req",
                "-in", $intCsr,
                "-CA", $issuerCrt,
                "-CAkey", $issuerKey,
                "-CAcreateserial",
                "-out", $intCrt,
                "-days", "$Days",
                "-sha256",
                "-extfile", $caExt
            )

            $issuerCrt = $intCrt
            $issuerKey = $intKey
            $intermediateCerts += $intCrt
        }

        $serverKey = Join-Path $dir "server.key"
        $serverCsr = Join-Path $dir "server.csr"
        $serverCrt = Join-Path $dir "server.crt"

        New-TlsBenchKey -Algorithm $Algorithm -OutputPath $serverKey

        Invoke-OpenSSL -Arguments @(
            "req", "-new",
            "-key", $serverKey,
            "-out", $serverCsr,
            "-subj", "/CN=localhost"
        )

        Invoke-OpenSSL -Arguments @(
            "x509", "-req",
            "-in", $serverCsr,
            "-CA", $issuerCrt,
            "-CAkey", $issuerKey,
            "-CAcreateserial",
            "-out", $serverCrt,
            "-days", "$Days",
            "-sha256",
            "-extfile", $serverExt
        )

        $chainFile = Join-Path $dir "chain.pem"
        if ($intermediateCerts.Count -gt 0) {
            # TLS servers must send intermediates starting with the certificate
            # that signed the leaf, then moving upward toward the root.
            # For chain3 that means int2, int1 (not int1, int2).
            $chainContent = @()
            $orderedIntermediates = [object[]]$intermediateCerts.Clone()
            [array]::Reverse($orderedIntermediates)
            foreach ($cert in $orderedIntermediates) {
                $chainContent += Get-Content $cert
            }
            $chainContent | Set-Content -Encoding ascii $chainFile
        }
        else {
            # chain1 has no intermediates. Create a true zero-byte file so OpenSSL
            # s_server will not try to load an empty certificate chain.
            New-Item -ItemType File -Force -Path $chainFile | Out-Null
        }

        if ($intermediateCerts.Count -gt 0) {
            Invoke-OpenSSL -Arguments @("verify", "-CAfile", $rootCrt, "-untrusted", $chainFile, $serverCrt)
        }
        else {
            Invoke-OpenSSL -Arguments @("verify", "-CAfile", $rootCrt, $serverCrt)
        }

        Write-Host "Generated $Algorithm chain$ChainLength at $dir"
    }
}

Write-Host "Certificate generation completed."
