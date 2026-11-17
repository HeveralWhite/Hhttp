# ============================================================
# Hhttp TLS (HTTPS / WSS) verification -- OpenSSL backend
#
#   powershell -ExecutionPolicy Bypass -File tests\run-tls-tests.ps1
#
# Covers:
#   - HTTPS requests / keep-alive / POST body over TLS
#   - HTTP.get.isHttps() / scheme() / tlsProtocol()
#   - multi-certificate SNI selection (PFX)
#   - WebSocket over TLS (WSS handshake + echo)
#   - garbage on the TLS port must not break the listener
#   - PEM certificate configuration (cert_file + key_file)
# Exit code = number of failed checks.
# ============================================================

param(
    [switch]$NoStart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$exe = Join-Path $repo "build\Hhttp.exe"
if (-not (Test-Path $exe)) { $exe = Join-Path $repo "build\Release\Hhttp.exe" }
$verifyDir = $PSScriptRoot
$scriptDir = Join-Path $verifyDir "scripts"
$pfxConfig = Join-Path $verifyDir "config-tls.json"
$pemConfig = Join-Path $verifyDir "config-tls-pem.json"
$httpsPort = 18443
$pemPort = 18444
$httpPort = 18099

$latin1 = [System.Text.Encoding]::GetEncoding(28591)
$utf8 = [System.Text.UTF8Encoding]::new($false)

$script:pass = 0
$script:fail = 0
$script:failures = @()

function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = "")
    if ($Condition) {
        $script:pass++
        Write-Host ("PASS  {0}" -f $Name) -ForegroundColor Green
    } else {
        $script:fail++
        $script:failures += ("{0} {1}" -f $Name, $Detail).Trim()
        Write-Host ("FAIL  {0}  {1}" -f $Name, $Detail) -ForegroundColor Red
    }
}

function Read-UntilMarker {
    param($Stream, [byte[]]$Marker, [int]$Limit = 1048576)
    $ms = New-Object System.IO.MemoryStream
    $one = [byte[]]::new(1)
    while ($ms.Length -lt $Limit) {
        try { $n = $Stream.Read($one, 0, 1) } catch { $n = 0 }
        if ($n -le 0) { break }
        $ms.WriteByte($one[0])
        if ($ms.Length -ge $Marker.Length) {
            $buf = $ms.GetBuffer()
            $start = [int]$ms.Length - $Marker.Length
            $hit = $true
            for ($i = 0; $i -lt $Marker.Length; $i++) {
                if ($buf[$start + $i] -ne $Marker[$i]) { $hit = $false; break }
            }
            if ($hit) { break }
        }
    }
    return $ms.ToArray()
}

function Read-ExactBytes {
    param($Stream, [int]$Count)
    $out = New-Object System.IO.MemoryStream
    $buf = [byte[]]::new(8192)
    while ($out.Length -lt $Count) {
        $want = [Math]::Min($buf.Length, $Count - $out.Length)
        try { $n = $Stream.Read($buf, 0, $want) } catch { $n = 0 }
        if ($n -le 0) { break }
        $out.Write($buf, 0, $n)
    }
    return $out.ToArray()
}

function Read-Response {
    param($Stream, [switch]$HeadOnly)
    $head = Read-UntilMarker -Stream $Stream -Marker ([byte[]](13, 10, 13, 10))
    if ($head.Length -eq 0) { return $null }
    $lines = $latin1.GetString($head) -split "`r`n"
    if ($lines[0] -notmatch '^HTTP/(\d\.\d) (\d{3})') { throw "bad status line: $($lines[0])" }
    $status = [int]$Matches[2]
    $headers = @{}
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -eq "") { continue }
        $colon = $line.IndexOf(":")
        if ($colon -lt 0) { continue }
        $headers[$line.Substring(0, $colon).Trim().ToLowerInvariant()] = $line.Substring($colon + 1).Trim()
    }
    $body = [byte[]]::new(0)
    if (-not $HeadOnly) {
        if ($headers.ContainsKey("content-length")) {
            $len = [int]$headers["content-length"]
            if ($len -gt 0) { $body = Read-ExactBytes -Stream $Stream -Count $len }
        } elseif ($headers.ContainsKey("transfer-encoding") -and $headers["transfer-encoding"] -match "chunked") {
            $ms = New-Object System.IO.MemoryStream
            while ($true) {
                $sizeLine = Read-UntilMarker -Stream $Stream -Marker ([byte[]](13, 10))
                if ($sizeLine.Length -eq 0) { break }
                $sizeText = $latin1.GetString($sizeLine).TrimEnd([char]13, [char]10)
                $semi = $sizeText.IndexOf(";")
                if ($semi -ge 0) { $sizeText = $sizeText.Substring(0, $semi) }
                $size = [Convert]::ToInt32($sizeText.Trim(), 16)
                if ($size -eq 0) {
                    [void](Read-UntilMarker -Stream $Stream -Marker ([byte[]](13, 10)) -Limit 64)
                    break
                }
                $chunk = Read-ExactBytes -Stream $Stream -Count $size
                $ms.Write($chunk, 0, $chunk.Length)
                [void](Read-ExactBytes -Stream $Stream -Count 2)
            }
            $body = $ms.ToArray()
        }
    }
    return New-Object psobject -Property @{
        Status  = $status
        Headers = $headers
        Body    = $body
        Text    = $utf8.GetString($body)
    }
}

function New-TlsStream {
    param([int]$Port, [string]$Target, [int]$TimeoutMs = 6000)
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.NoDelay = $true
    $tcp.Connect("127.0.0.1", $Port)
    $tcp.ReceiveTimeout = $TimeoutMs
    $callback = [System.Net.Security.RemoteCertificateValidationCallback] {
        param($sender, $cert, $chain, $errors)
        return $true # accept the self-signed test certificate
    }
    $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $callback)
    $ssl.ReadTimeout = $TimeoutMs
    $ssl.WriteTimeout = $TimeoutMs
    $ssl.AuthenticateAsClient($Target)
    return @{ Tcp = $tcp; Ssl = $ssl }
}

function Send-StreamText {
    param($Stream, [string]$Text)
    $bytes = $latin1.GetBytes($Text)
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush()
}

function Close-TlsStream {
    param($Pair)
    try { $Pair.Ssl.Dispose() } catch { }
    try { $Pair.Tcp.Dispose() } catch { }
}

function Start-Server {
    param([string]$ConfigPath, [int]$Port)
    $stdinFile = Join-Path $env:TEMP ("hhttp-tls-in-{0}.txt" -f ([guid]::NewGuid().ToString("N")))
    [System.IO.File]::WriteAllText($stdinFile, "", $utf8)
    $outFile = Join-Path $env:TEMP ("hhttp-tls-out-{0}.log" -f ([guid]::NewGuid().ToString("N")))
    $proc = Start-Process -FilePath $exe `
        -ArgumentList @("--config", $ConfigPath, "--dir", $scriptDir) `
        -WorkingDirectory $repo `
        -RedirectStandardInput $stdinFile `
        -RedirectStandardOutput $outFile `
        -RedirectStandardError ([System.IO.Path]::ChangeExtension($outFile, ".err")) `
        -PassThru
    for ($i = 0; $i -lt 150; $i++) {
        try {
            $probe = New-Object System.Net.Sockets.TcpClient
            $probe.Connect("127.0.0.1", $Port)
            $probe.Dispose()
            return @{ Proc = $proc; In = $stdinFile; Out = $outFile }
        } catch {
            if ($proc.HasExited) {
                Write-Host "server exited during startup; log:" -ForegroundColor Red
                Get-Content $outFile -ErrorAction SilentlyContinue | Select-Object -Last 25
                exit 1
            }
            Start-Sleep -Milliseconds 100
        }
    }
    throw "server did not start on port $Port"
}

function Stop-Server {
    param($Server)
    if ($null -ne $Server -and $null -ne $Server.Proc -and -not $Server.Proc.HasExited) {
        try { $Server.Proc.Kill(); [void]$Server.Proc.WaitForExit(5000) } catch { }
    }
    if ($null -ne $Server) {
        Remove-Item $Server.In -ErrorAction SilentlyContinue
        Remove-Item $Server.Out -ErrorAction SilentlyContinue
        Remove-Item ([System.IO.Path]::ChangeExtension($Server.Out, ".err")) -ErrorAction SilentlyContinue
    }
}

if (-not (Test-Path $exe)) { Write-Error "missing $exe (build first)"; exit 1 }

$server = $null
try {
    # ================= PFX + multi-cert SNI =================
    $server = if ($NoStart) { $null } else { Start-Server -ConfigPath $pfxConfig -Port $httpsPort }

    # ---- basic HTTPS ----
    $tls = New-TlsStream -Port $httpsPort -Target "localhost"
    try {
        Assert-True "TLS handshake (localhost)" ($tls.Ssl.SslProtocol -match "Tls1[23]") "proto=$($tls.Ssl.SslProtocol)"
        Send-StreamText -Stream $tls.Ssl -Text "GET /echo HTTP/1.1`r`nHost: localhost`r`n`r`n"
        $r = Read-Response -Stream $tls.Ssl
        Assert-True "HTTPS GET /echo -> 200" ($r.Status -eq 200) "status=$($r.Status)"
        $json = $null
        try { $json = $r.Text | ConvertFrom-Json } catch { }
        Assert-True "HTTPS response is JSON" ($null -ne $json) $r.Text
        if ($null -ne $json) {
            Assert-True "isHttps() = true" ($json.https -eq $true) "https=$($json.https)"
            Assert-True "scheme() = https" ($json.scheme -eq "https") "scheme=$($json.scheme)"
            Assert-True "tlsProtocol() reports a version" ("$($json.tls)" -match "^TLS [0-9]") "tls=$($json.tls)"
        }

        # ---- keep-alive over TLS ----
        Send-StreamText -Stream $tls.Ssl -Text "GET /static/ HTTP/1.1`r`nHost: localhost`r`n`r`n"
        $r = Read-Response -Stream $tls.Ssl
        Assert-True "HTTPS keep-alive GET /static/" ($r.Status -eq 200 -and $r.Text -eq "hello-static") "status=$($r.Status) body=$($r.Text)"

        # ---- POST body over TLS ----
        Send-StreamText -Stream $tls.Ssl -Text "POST /echo HTTP/1.1`r`nHost: localhost`r`nContent-Length: 8`r`nConnection: close`r`n`r`ntls-body"
        $r = Read-Response -Stream $tls.Ssl
        $json = $null
        try { $json = $r.Text | ConvertFrom-Json } catch { }
        Assert-True "HTTPS POST body echoed" ($null -ne $json -and $json.body -eq "tls-body") "body=$($json.body)"
    } finally {
        Close-TlsStream $tls
    }

    # ---- SNI: localhost certificate ----
    $tls = New-TlsStream -Port $httpsPort -Target "localhost"
    try {
        $subject = ""
        if ($null -ne $tls.Ssl.RemoteCertificate) { $subject = $tls.Ssl.RemoteCertificate.Subject }
        Assert-True "SNI localhost serves localhost cert" ($subject -match "CN=localhost") "subject=$subject"
    } finally {
        Close-TlsStream $tls
    }

    # ---- SNI: alt.localhost certificate + host-specific route ----
    $tls = New-TlsStream -Port $httpsPort -Target "alt.localhost"
    try {
        $subject = ""
        if ($null -ne $tls.Ssl.RemoteCertificate) { $subject = $tls.Ssl.RemoteCertificate.Subject }
        Assert-True "SNI alt.localhost serves alt cert" ($subject -match "CN=alt.localhost") "subject=$subject"
        Send-StreamText -Stream $tls.Ssl -Text "GET /alt/ HTTP/1.1`r`nHost: alt.localhost`r`nConnection: close`r`n`r`n"
        $r = Read-Response -Stream $tls.Ssl
        Assert-True "alt host route over HTTPS" ($r.Status -eq 200 -and $r.Text -eq "hello-alt") "status=$($r.Status) body=$($r.Text)"
    } finally {
        Close-TlsStream $tls
    }

    # ---- WSS ----
    $tls = New-TlsStream -Port $httpsPort -Target "localhost"
    try {
        $key = "dGhlIHNhbXBsZSBub25jZQ=="
        Send-StreamText -Stream $tls.Ssl -Text ("GET /ws HTTP/1.1`r`nHost: localhost`r`nUpgrade: websocket`r`nConnection: Upgrade`r`nSec-WebSocket-Key: {0}`r`nSec-WebSocket-Version: 13`r`n`r`n" -f $key)
        $resp = Read-Response -Stream $tls.Ssl -HeadOnly
        Assert-True "WSS handshake 101" ($resp.Status -eq 101) "status=$($resp.Status)"

        $h = Read-ExactBytes -Stream $tls.Ssl -Count 2
        $len = $h[1] -band 0x7F
        if ($len -eq 126) {
            $ext = Read-ExactBytes -Stream $tls.Ssl -Count 2
            $len = ($ext[0] -shl 8) -bor $ext[1]
        }
        $payload = [byte[]]::new(0)
        if ($len -gt 0) { $payload = Read-ExactBytes -Stream $tls.Ssl -Count $len }
        Assert-True "WSS welcome frame" ($utf8.GetString($payload) -eq "hello") "payload=$($utf8.GetString($payload))"

        $msg = [System.Text.Encoding]::UTF8.GetBytes("wss-ping")
        $mask = [byte[]](0x11, 0x22, 0x33, 0x44)
        $frame = New-Object System.Collections.Generic.List[byte]
        $frame.Add([byte]0x81)
        $frame.Add([byte](0x80 -bor $msg.Length))
        $frame.AddRange($mask)
        for ($i = 0; $i -lt $msg.Length; $i++) { $frame.Add([byte]($msg[$i] -bxor $mask[$i % 4])) }
        $tls.Ssl.Write($frame.ToArray(), 0, $frame.Count)
        $tls.Ssl.Flush()

        $h = Read-ExactBytes -Stream $tls.Ssl -Count 2
        $len = $h[1] -band 0x7F
        if ($len -eq 126) {
            $ext = Read-ExactBytes -Stream $tls.Ssl -Count 2
            $len = ($ext[0] -shl 8) -bor $ext[1]
        }
        $payload = [byte[]]::new(0)
        if ($len -gt 0) { $payload = Read-ExactBytes -Stream $tls.Ssl -Count $len }
        Assert-True "WSS echo" ($utf8.GetString($payload) -eq "echo:wss-ping") "payload=$($utf8.GetString($payload))"
    } finally {
        Close-TlsStream $tls
    }

    # ---- large body over TLS (exercises write backpressure) ----
    $tls = New-TlsStream -Port $httpsPort -Target "localhost"
    try {
        $big = "y" * 200000
        Send-StreamText -Stream $tls.Ssl -Text ("POST /echo HTTP/1.1`r`nHost: localhost`r`nContent-Length: {0}`r`nConnection: close`r`n`r`n{1}" -f $big.Length, $big)
        $r = Read-Response -Stream $tls.Ssl
        $json = $null
        try { $json = $r.Text | ConvertFrom-Json } catch { }
        Assert-True "HTTPS large body echoed (200KB)" ($null -ne $json -and $json.bodyLen -eq $big.Length) "bodyLen=$($json.bodyLen) expected=$($big.Length)"
    } finally {
        Close-TlsStream $tls
    }

    # ---- handshake timeout: a client that connects and sends nothing ----
    $silent = New-Object System.Net.Sockets.TcpClient
    $silent.Connect("127.0.0.1", $httpsPort)
    $silent.ReceiveTimeout = 15000
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $closed = $false
    try {
        $buf = [byte[]]::new(64)
        $n = $silent.GetStream().Read($buf, 0, $buf.Length)
        $closed = ($n -le 0)
    } catch {
        $closed = $true
    }
    $sw.Stop()
    Assert-True "silent TLS client is dropped" $closed "elapsed=$($sw.ElapsedMilliseconds)ms"
    Assert-True "handshake timeout is bounded (<= 15s)" ($sw.Elapsed.TotalSeconds -le 15) "elapsed=$($sw.Elapsed.TotalSeconds)s"
    $silent.Dispose()

    # ---- plain HTTP listener still works next to HTTPS ----
    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.Connect("127.0.0.1", $httpPort)
    $tcp.ReceiveTimeout = 5000
    $stream = $tcp.GetStream()
    Send-StreamText -Stream $stream -Text "GET /echo HTTP/1.1`r`nHost: localhost`r`nConnection: close`r`n`r`n"
    $r = Read-Response -Stream $stream
    $json = $null
    try { $json = $r.Text | ConvertFrom-Json } catch { }
    Assert-True "plain HTTP listener still works" ($r.Status -eq 200 -and $json.scheme -eq "http") "status=$($r.Status) scheme=$($json.scheme)"
    $tcp.Dispose()

    # ---- garbage on the TLS port must not break the listener ----
    $raw = New-Object System.Net.Sockets.TcpClient
    $raw.Connect("127.0.0.1", $httpsPort)
    $raw.ReceiveTimeout = 8000
    $garbage = $latin1.GetBytes("THIS-IS-NOT-TLS`r`n`r`n")
    $raw.GetStream().Write($garbage, 0, $garbage.Length)
    $raw.GetStream().Flush()
    $closed = $false
    try {
        $buf = [byte[]]::new(16)
        $n = $raw.GetStream().Read($buf, 0, $buf.Length)
        $closed = ($n -le 0)
    } catch {
        $closed = $true
    }
    Assert-True "garbage ClientHello is dropped" $closed ""
    $raw.Dispose()

    $tls = New-TlsStream -Port $httpsPort -Target "localhost"
    try {
        Send-StreamText -Stream $tls.Ssl -Text "GET /static/ HTTP/1.1`r`nHost: localhost`r`nConnection: close`r`n`r`n"
        $r = Read-Response -Stream $tls.Ssl
        Assert-True "TLS listener healthy after garbage" ($r.Status -eq 200 -and $r.Text -eq "hello-static") "status=$($r.Status)"
    } finally {
        Close-TlsStream $tls
    }

    Stop-Server $server
    $server = $null

    # ================= PEM certificate =================
    $server = if ($NoStart) { $null } else { Start-Server -ConfigPath $pemConfig -Port $pemPort }
    $tls = New-TlsStream -Port $pemPort -Target "localhost"
    try {
        Send-StreamText -Stream $tls.Ssl -Text "GET /static/ HTTP/1.1`r`nHost: localhost`r`nConnection: close`r`n`r`n"
        $r = Read-Response -Stream $tls.Ssl
        Assert-True "PEM cert HTTPS request" ($r.Status -eq 200 -and $r.Text -eq "hello-static") "status=$($r.Status) body=$($r.Text)"
    } finally {
        Close-TlsStream $tls
    }

} finally {
    Stop-Server $server
}

Write-Host ""
Write-Host ("{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor ($(if ($script:fail -eq 0) { "Green" } else { "Red" }))
if ($script:fail -gt 0) {
    Write-Host "failed checks:" -ForegroundColor Red
    $script:failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
}
exit $script:fail
