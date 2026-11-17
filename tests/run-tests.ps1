param(
    [string]$Exe = "",
    [switch]$Loose,
    [switch]$NoStart
)

# -Loose: keep going after a failed parse / assertion (used to survey an old
# build where responses may not be what the assertions expect).
if ($Loose) {
    Set-StrictMode -Off
    $ErrorActionPreference = "Continue"
} else {
    Set-StrictMode -Version Latest
    $ErrorActionPreference = "Stop"
}

# ============================================================
# Hhttp behavior verification
#
# Usage (from the repository root, after building):
#   powershell -ExecutionPolicy Bypass -File tests\run-tests.ps1
#   powershell -ExecutionPolicy Bypass -File tests\run-tests.ps1 -Exe build\Hhttp.exe
#
# Covers: HTTP parsing / security limits, keep-alive, pipelining, HEAD,
#         chunked requests and responses, file & SQLite permission
#         boundaries, response-header injection, cookies, WebSocket
#         handshake and echo.
# Exit code = number of failed checks (0 = all passed).
# ============================================================

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($Exe)) {
    $exe = Join-Path $repo "build\Hhttp.exe"
    # 多配置生成器(Visual Studio / Ninja Multi-Config)把产物放在 build\<Config> 下
    if (-not (Test-Path $exe)) { $exe = Join-Path $repo "build\Release\Hhttp.exe" }
} else { $exe = (Resolve-Path $Exe).Path }
$config = Join-Path $PSScriptRoot "config.json"
$scriptDir = Join-Path $PSScriptRoot "scripts"
$port = 18099
$latin1 = [System.Text.Encoding]::GetEncoding(28591)
$utf8 = [System.Text.UTF8Encoding]::new($false)

$script:pass = 0
$script:fail = 0
$script:failures = @()

function From-JsonSafe {
    param([string]$Text)
    try { return ($Text | ConvertFrom-Json) } catch { return $null }
}

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

# ---------------- raw TCP client ----------------
function New-Conn {
    param([int]$TimeoutMs = 5000)
    $c = New-Object System.Net.Sockets.TcpClient
    $c.NoDelay = $true
    $c.Connect("127.0.0.1", $port)
    $c.ReceiveTimeout = $TimeoutMs
    return $c
}

function Send-RawText {
    param($Conn, [string]$Text)
    $bytes = $latin1.GetBytes($Text)
    $Conn.GetStream().Write($bytes, 0, $bytes.Length)
    $Conn.GetStream().Flush()
}

function Send-RawBytes {
    param($Conn, [byte[]]$Bytes)
    $Conn.GetStream().Write($Bytes, 0, $Bytes.Length)
    $Conn.GetStream().Flush()
}

function Read-UntilMarker {
    param($Stream, [byte[]]$Marker, [int]$Limit = 1048576)
    $ms = New-Object System.IO.MemoryStream
    $one = [byte[]]::new(1)
    while ($ms.Length -lt $Limit) {
        $n = $Stream.Read($one, 0, 1)
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
        $n = $Stream.Read($buf, 0, $want)
        if ($n -le 0) { break }
        $out.Write($buf, 0, $n)
    }
    return $out.ToArray()
}

function Read-Response {
    param($Stream, [switch]$HeadOnly)

    $marker = [byte[]](13, 10, 13, 10)
    $headBytes = Read-UntilMarker -Stream $Stream -Marker $marker
    if ($headBytes.Length -eq 0) { return $null }
    $headText = $latin1.GetString($headBytes)
    $lines = $headText -split "`r`n"
    if ($lines.Count -lt 1 -or $lines[0] -eq "") { return $null }

    $statusLine = $lines[0]
    if ($statusLine -notmatch '^HTTP/(\d\.\d) (\d{3})(?: (.*))?$') {
        throw "bad status line: $statusLine"
    }
    $status = [int]$Matches[2]
    $reason = ""
    if ($Matches.Count -gt 3) { $reason = $Matches[3] }

    $headers = @{}
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -eq "") { continue }
        $colon = $line.IndexOf(":")
        if ($colon -lt 0) { continue }
        $name = $line.Substring(0, $colon).Trim().ToLowerInvariant()
        $value = $line.Substring($colon + 1).Trim()
        if ($headers.ContainsKey($name)) {
            $headers[$name] = $headers[$name] + ", " + $value
        } else {
            $headers[$name] = $value
        }
    }

    $body = [byte[]]::new(0)
    if (-not $HeadOnly) {
        if ($headers.ContainsKey("transfer-encoding") -and $headers["transfer-encoding"] -match "chunked") {
            $ms = New-Object System.IO.MemoryStream
            while ($true) {
                $sizeLine = Read-UntilMarker -Stream $Stream -Marker ([byte[]](13, 10))
                if ($sizeLine.Length -eq 0) { break }
                $sizeText = $latin1.GetString($sizeLine)
                $sizeText = $sizeText.TrimEnd([char]13, [char]10)
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
        } elseif ($headers.ContainsKey("content-length")) {
            $len = [int]$headers["content-length"]
            if ($len -gt 0) { $body = Read-ExactBytes -Stream $Stream -Count $len }
        } else {
            $ms = New-Object System.IO.MemoryStream
            $buf = [byte[]]::new(8192)
            while ($true) {
                $n = $Stream.Read($buf, 0, $buf.Length)
                if ($n -le 0) { break }
                $ms.Write($buf, 0, $n)
            }
            $body = $ms.ToArray()
        }
    }

    return New-Object psobject -Property @{
        Status  = $status
        Reason  = $reason
        Headers = $headers
        Body    = $body
        Text    = $utf8.GetString($body)
    }
}

function Invoke-Request {
    param(
        [string]$Raw,
        [switch]$HeadOnly,
        [int]$TimeoutMs = 5000
    )
    $conn = New-Conn -TimeoutMs $TimeoutMs
    try {
        Send-RawText -Conn $conn -Text $Raw
        return Read-Response -Stream $conn.GetStream() -HeadOnly:$HeadOnly
    } finally {
        $conn.Dispose()
    }
}

function Get-Header {
    param($Response, [string]$Name)
    if ($null -eq $Response) { return $null }
    $key = $Name.ToLowerInvariant()
    if ($Response.Headers.ContainsKey($key)) { return $Response.Headers[$key] }
    return $null
}

function Test-HeaderPresent {
    param($Response, [string]$Name)
    return ($null -ne (Get-Header -Response $Response -Name $Name))
}

function Read-WsFrame {
    param($Stream)
    $h = Read-ExactBytes -Stream $Stream -Count 2
    if ($h.Length -lt 2) { return $null }
    $len = $h[1] -band 0x7F
    if ($len -eq 126) {
        $ext = Read-ExactBytes -Stream $Stream -Count 2
        $len = ($ext[0] -shl 8) -bor $ext[1]
    } elseif ($len -eq 127) {
        $ext = Read-ExactBytes -Stream $Stream -Count 8
        $len = 0
        for ($i = 0; $i -lt 8; $i++) { $len = ($len -shl 8) -bor $ext[$i] }
    }
    $masked = ($h[1] -band 0x80) -ne 0
    $mask = $null
    if ($masked) { $mask = Read-ExactBytes -Stream $Stream -Count 4 }
    $payload = [byte[]]::new(0)
    if ($len -gt 0) { $payload = Read-ExactBytes -Stream $Stream -Count $len }
    if ($masked) {
        for ($i = 0; $i -lt $payload.Length; $i++) { $payload[$i] = $payload[$i] -bxor $mask[$i % 4] }
    }
    return New-Object psobject -Property @{
        Opcode  = ($h[0] -band 0x0F)
        Fin     = (($h[0] -band 0x80) -ne 0)
        Payload = $payload
    }
}

function New-WsFrame {
    param([int]$Opcode, [string]$Text = "", [bool]$Fin = $true)
    $payload = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $mask = [byte[]](0x11, 0x22, 0x33, 0x44)
    $list = New-Object System.Collections.Generic.List[byte]
    $b0 = $Opcode
    if ($Fin) { $b0 = $b0 -bor 0x80 }
    $list.Add([byte]$b0)
    if ($payload.Length -lt 126) {
        $list.Add([byte](0x80 -bor $payload.Length))
    } else {
        $list.Add([byte](0x80 -bor 126))
        $list.Add([byte](($payload.Length -shr 8) -band 0xFF))
        $list.Add([byte]($payload.Length -band 0xFF))
    }
    $list.AddRange($mask)
    for ($i = 0; $i -lt $payload.Length; $i++) {
        $list.Add([byte]($payload[$i] -bxor $mask[$i % 4]))
    }
    return $list.ToArray()
}

# Open a WebSocket connection and consume the server's welcome frame.
function Connect-Ws {
    $c = New-Conn
    Send-RawText -Conn $c -Text ("GET /ws HTTP/1.1`r`nHost: h`r`nUpgrade: websocket`r`nConnection: Upgrade`r`nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==`r`nSec-WebSocket-Version: 13`r`n`r`n")
    $resp = Read-Response -Stream $c.GetStream() -HeadOnly
    if ($resp.Status -ne 101) {
        $c.Dispose()
        return $null
    }
    [void](Read-WsFrame -Stream $c.GetStream()) # welcome
    return $c
}

# ============================================================
# start the server
# ============================================================
if (-not $NoStart -and -not (Test-Path $exe)) { Write-Error "missing $exe (build first)"; exit 1 }

$dataDir = Join-Path $scriptDir "data"
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
$tmpDir = Join-Path $scriptDir "tmp"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
[System.IO.File]::WriteAllText((Join-Path $dataDir "small.txt"), "hello-file", $utf8)
[System.IO.File]::WriteAllText((Join-Path $dataDir "big.txt"), ("x" * 2000000), $utf8)

$stdinFile = Join-Path $env:TEMP ("hhttp-stdin-{0}.txt" -f ([guid]::NewGuid().ToString("N")))
[System.IO.File]::WriteAllText($stdinFile, "", $utf8)
$stdoutFile = Join-Path $env:TEMP ("hhttp-out-{0}.log" -f ([guid]::NewGuid().ToString("N")))
$stderrFile = Join-Path $env:TEMP ("hhttp-err-{0}.log" -f ([guid]::NewGuid().ToString("N")))

$proc = $null
if (-not $NoStart) {
    $proc = Start-Process -FilePath $exe `
        -ArgumentList @("--config", $config, "--dir", $scriptDir) `
        -WorkingDirectory $repo `
        -RedirectStandardInput $stdinFile `
        -RedirectStandardOutput $stdoutFile `
        -RedirectStandardError $stderrFile `
        -PassThru
}

try {
    if (-not $NoStart) {
        $ready = $false
        for ($i = 0; $i -lt 100; $i++) {
            try {
                $probe = New-Object System.Net.Sockets.TcpClient
                $probe.Connect("127.0.0.1", $port)
                $probe.Dispose()
                $ready = $true
                break
            } catch {
                Start-Sleep -Milliseconds 100
            }
        }
        if (-not $ready) {
            Write-Host "server did not start; log tail:" -ForegroundColor Red
            Get-Content $stdoutFile -ErrorAction SilentlyContinue | Select-Object -Last 40
            Get-Content $stderrFile -ErrorAction SilentlyContinue | Select-Object -Last 40
            exit 1
        }
    }

    # ---------------- basic request ----------------
    $r = Invoke-Request "GET /echo?x=1&y=2 HTTP/1.1`r`nHost: example.com`r`nConnection: close`r`n`r`n"
    Assert-True "GET /echo -> 200" ($r.Status -eq 200) "status=$($r.Status)"
    $json = $null
    try { $json = From-JsonSafe $r.Text } catch { }
    Assert-True "GET /echo JSON body" ($null -ne $json) $r.Text
    if ($null -ne $json) {
        Assert-True "method=GET" ($json.method -eq "GET") "method=$($json.method)"
        Assert-True "url=/echo" ($json.url -eq "/echo") "url=$($json.url)"
        Assert-True "rawUrl keeps query" ($json.rawUrl -eq "/echo?x=1&y=2") "rawUrl=$($json.rawUrl)"
        Assert-True "query.x=1" ($json.query.x -eq "1") "x=$($json.query.x)"
        Assert-True "query.y=2" ($json.query.y -eq "2") "y=$($json.query.y)"
        Assert-True "version=HTTP/1.1" ($json.version -eq "HTTP/1.1") "v=$($json.version)"
        Assert-True "host header" ($json.headerHost -eq "example.com") "host=$($json.headerHost)"
        Assert-True "scheme=http" ($json.scheme -eq "http") "scheme=$($json.scheme)"
    }

    # ---------------- HEAD ----------------
    $conn = New-Conn
    try {
        # fixed-length /static/ body so GET and HEAD must agree
        Send-RawText -Conn $conn -Text "GET /static/ HTTP/1.1`r`nHost: h`r`n`r`n"
        $getr = Read-Response -Stream $conn.GetStream()
        Send-RawText -Conn $conn -Text "HEAD /static/ HTTP/1.1`r`nHost: h`r`n`r`n"
        $head = Read-Response -Stream $conn.GetStream() -HeadOnly
        Assert-True "HEAD -> 200" ($head.Status -eq 200) "status=$($head.Status)"
        Assert-True "HEAD has no body" ($head.Body.Length -eq 0) "len=$($head.Body.Length)"
        $cl = Get-Header -Response $head -Name "content-length"
        Assert-True "HEAD Content-Length equals GET body" ("$cl" -eq "$($getr.Body.Length)") "head=$cl get=$($getr.Body.Length)"
        Send-RawText -Conn $conn -Text "GET /static/ HTTP/1.1`r`nHost: h`r`n`r`n"
        $second = Read-Response -Stream $conn.GetStream()
        Assert-True "GET after HEAD on same connection" ($second.Status -eq 200) "status=$($second.Status)"
    } finally {
        $conn.Dispose()
    }

    # ---------------- keep-alive + pipelining ----------------
    $conn = New-Conn
    try {
        Send-RawText -Conn $conn -Text "GET /echo HTTP/1.1`r`nHost: h`r`n`r`nGET /echo HTTP/1.1`r`nHost: h`r`n`r`nGET /echo HTTP/1.1`r`nHost: h`r`nConnection: close`r`n`r`n"
        $r1 = Read-Response -Stream $conn.GetStream()
        $r2 = Read-Response -Stream $conn.GetStream()
        $r3 = Read-Response -Stream $conn.GetStream()
        Assert-True "pipelining response 1" ($r1.Status -eq 200) "status=$($r1.Status)"
        Assert-True "pipelining response 2" ($r2.Status -eq 200) "status=$($r2.Status)"
        Assert-True "pipelining response 3" ($r3.Status -eq 200) "status=$($r3.Status)"
        Assert-True "Connection: keep-alive" ((Get-Header -Response $r1 -Name "connection") -match "keep-alive") "conn=$(Get-Header -Response $r1 -Name 'connection')"
        Assert-True "Connection: close honored" ((Get-Header -Response $r3 -Name "connection") -match "close") "conn=$(Get-Header -Response $r3 -Name 'connection')"
    } finally {
        $conn.Dispose()
    }

    # ---------------- request bodies ----------------
    $r = Invoke-Request "POST /echo HTTP/1.1`r`nHost: h`r`nContent-Length: 5`r`nConnection: close`r`n`r`nhello"
    $json = From-JsonSafe $r.Text
    Assert-True "Content-Length body" ($json.body -eq "hello") "body=$($json.body)"

    $r = Invoke-Request "POST /echo HTTP/1.1`r`nHost: h`r`nTransfer-Encoding: chunked`r`nConnection: close`r`n`r`n4`r`nWiki`r`n5`r`npedia`r`n0`r`n`r`n"
    $json = From-JsonSafe $r.Text
    Assert-True "chunked body" ($json.body -eq "Wikipedia") "body=$($json.body)"

    # ---------------- smuggling / malformed requests ----------------
    $r = Invoke-Request "POST /echo HTTP/1.1`r`nHost: h`r`nContent-Length: 5`r`nTransfer-Encoding: chunked`r`nConnection: close`r`n`r`n0`r`n`r`n"
    Assert-True "CL+TE rejected (400)" ($r.Status -eq 400) "status=$($r.Status)"

    $r = Invoke-Request "POST /echo HTTP/1.1`r`nHost: h`r`nContent-Length: 5`r`nContent-Length: 6`r`nConnection: close`r`n`r`nhello!"
    Assert-True "duplicate Content-Length rejected (400)" ($r.Status -eq 400) "status=$($r.Status)"

    $r = Invoke-Request "POST /echo HTTP/1.1`r`nHost: h`r`nContent-Length: 5abc`r`nConnection: close`r`n`r`nhello"
    Assert-True "invalid Content-Length rejected (400)" ($r.Status -eq 400) "status=$($r.Status)"

    $r = Invoke-Request "POST /echo HTTP/1.1`r`nHost: h`r`nContent-Length: +5`r`nConnection: close`r`n`r`nhello"
    Assert-True "signed Content-Length rejected (400)" ($r.Status -eq 400) "status=$($r.Status)"

    $r = Invoke-Request "GET /echo HTTP/1.1`r`nHost: h`r`nX-Test : v`r`nConnection: close`r`n`r`n"
    Assert-True "space before colon rejected (400)" ($r.Status -eq 400) "status=$($r.Status)"

    $r = Invoke-Request "GET /echo HTTP/1.1`r`nHost: h`r`nNoColonHeader`r`nConnection: close`r`n`r`n"
    Assert-True "header without colon rejected (400)" ($r.Status -eq 400) "status=$($r.Status)"

    $r = Invoke-Request "GET /echo`r`nHost: h`r`n`r`n"
    Assert-True "request line without version rejected (400)" ($r.Status -eq 400) "status=$($r.Status)"

    $longPath = "GET /echo?" + ("a" * 9000) + " HTTP/1.1`r`nHost: h`r`n`r`n"
    $r = Invoke-Request $longPath
    Assert-True "oversized URI -> 414" ($r.Status -eq 414) "status=$($r.Status)"

    $many = "GET /echo HTTP/1.1`r`nHost: h`r`n"
    for ($i = 0; $i -lt 120; $i++) { $many += "X-H${i}: v`r`n" }
    $many += "`r`n"
    $r = Invoke-Request $many
    Assert-True "too many headers -> 431" ($r.Status -eq 431) "status=$($r.Status)"

    $r = Invoke-Request "POST /echo HTTP/1.1`r`nHost: h`r`nContent-Length: 9000000`r`nConnection: close`r`n`r`n"
    Assert-True "oversized body -> 413" ($r.Status -eq 413) "status=$($r.Status)"

    $r = Invoke-Request "GET /nope HTTP/1.1`r`nHost: h`r`nConnection: close`r`n`r`n"
    Assert-True "unmatched path -> 404" ($r.Status -eq 404) "status=$($r.Status)"

    # ---------------- chunked trailers / transfer-coding variants ----------------
    $conn = New-Conn
    try {
        # A chunked body with a trailer field, followed by a pipelined request.
        # The trailer must be consumed; otherwise the next request is misparsed
        # (request smuggling / connection desync).
        $raw = "POST /echo HTTP/1.1`r`nHost: h`r`nTransfer-Encoding: chunked`r`n`r`n" +
        "5`r`nhello`r`n0`r`nX-Trailer: v`r`n`r`n" +
        "POST /echo HTTP/1.1`r`nHost: h`r`nContent-Length: 3`r`nConnection: close`r`n`r`nabc"
        Send-RawText -Conn $conn -Text $raw
        $r1 = Read-Response -Stream $conn.GetStream()
        $j1 = From-JsonSafe $r1.Text
        Assert-True "chunked body with trailer parsed" ($r1.Status -eq 200 -and $j1.body -eq "hello") "status=$($r1.Status) body=$($j1.body)"
        try {
            $r2 = Read-Response -Stream $conn.GetStream()
            $j2 = From-JsonSafe $r2.Text
            Assert-True "request after trailer still parsed" ($r2.Status -eq 200 -and $j2.body -eq "abc") "status=$($r2.Status) body=$($r2.Text)"
        } catch {
            # The old implementation left the trailer for the next request, so the
            # following bytes are not even an HTTP response.
            Assert-True "request after trailer still parsed" $false $_.Exception.Message
        }
    } finally {
        $conn.Dispose()
    }

    $r = Invoke-Request "POST /echo HTTP/1.1`r`nHost: h`r`nTransfer-Encoding: gzip, chunked`r`nConnection: close`r`n`r`n0`r`n`r`n"
    Assert-True "unsupported transfer coding -> 501" ($r.Status -eq 501) "status=$($r.Status)"

    $r = Invoke-Request "POST /echo HTTP/1.1`r`nHost: h`r`nTransfer-Encoding: gzip`r`nConnection: close`r`n`r`n"
    Assert-True "non-chunked transfer coding -> 400" ($r.Status -eq 400) "status=$($r.Status)"

    $r = Invoke-Request "POST /echo HTTP/1.1`r`nHost: h`r`nTransfer-Encoding: chunked, chunked`r`nConnection: close`r`n`r`n0`r`n`r`n"
    Assert-True "double chunked -> 501" ($r.Status -eq 501) "status=$($r.Status)"

    # HTTP/1.0 with an explicit keep-alive request
    $conn = New-Conn
    try {
        Send-RawText -Conn $conn -Text "GET /static/ HTTP/1.0`r`nHost: h`r`nConnection: keep-alive`r`n`r`n"
        $r1 = Read-Response -Stream $conn.GetStream()
        Send-RawText -Conn $conn -Text "GET /static/ HTTP/1.0`r`nHost: h`r`nConnection: close`r`n`r`n"
        $r2 = Read-Response -Stream $conn.GetStream()
        Assert-True "HTTP/1.0 keep-alive first response" ($r1.Status -eq 200) "status=$($r1.Status)"
        Assert-True "HTTP/1.0 keep-alive second response" ($r2.Status -eq 200) "status=$($r2.Status)"
    } finally {
        $conn.Dispose()
    }

    # ---------------- response header injection ----------------
    $r = Invoke-Request "GET /inject/?v=a%0d%0aX-Evil:%201 HTTP/1.1`r`nHost: h`r`nConnection: close`r`n`r`n"
    Assert-True "header injection blocked (no X-Evil)" (-not (Test-HeaderPresent -Response $r -Name "X-Evil")) ""
    Assert-True "injection request still succeeds" ($r.Status -eq 200 -and $r.Text -eq "ok") "status=$($r.Status) body=$($r.Text)"

    $r = Invoke-Request "GET /inject/?reason=why%0d%0aX-Evil:%201 HTTP/1.1`r`nHost: h`r`nConnection: close`r`n`r`n"
    Assert-True "reason-phrase injection blocked (no X-Evil)" (-not (Test-HeaderPresent -Response $r -Name "X-Evil")) ""
    Assert-True "reason-phrase injection keeps 200" ($r.Status -eq 200) "status=$($r.Status)"

    $r = Invoke-Request "GET /inject/?h=a%0d%0aX-Evil&v=1 HTTP/1.1`r`nHost: h`r`nConnection: close`r`n`r`n"
    Assert-True "header-name injection blocked (no X-Evil)" (-not (Test-HeaderPresent -Response $r -Name "X-Evil")) ""
    Assert-True "header-name injection request succeeds" ($r.Status -eq 200) "status=$($r.Status)"

    # ---------------- streaming response ----------------
    $r = Invoke-Request "GET /stream/?n=3 HTTP/1.1`r`nHost: h`r`nConnection: close`r`n`r`n"
    Assert-True "streaming response is chunked" ((Get-Header -Response $r -Name "transfer-encoding") -match "chunked") "te=$(Get-Header -Response $r -Name 'transfer-encoding')"
    Assert-True "streaming response body" ($r.Text -eq "chunk-0;chunk-1;chunk-2;") "body=$($r.Text)"

    # res.file(): fixed -length streaming download
    $r = Invoke-Request "GET /download/ HTTP/1.1`r`nHost: h`r`nConnection: close`r`n`r`n"
    Assert-True "download status 200" ($r.Status -eq 200) "status=$($r.Status)"
    Assert-True "download Content-Length" ((Get-Header -Response $r -Name "content-length") -eq "$($r.Body.Length)") "cl=$(Get-Header -Response $r -Name 'content-length') len=$($r.Body.Length)"
    Assert-True "download body" ($r.Text -eq "hello-file") "body=$($r.Text)"
    Assert-True "download is not chunked" ($null -eq (Get-Header -Response $r -Name "transfer-encoding")) "te=$(Get-Header -Response $r -Name 'transfer-encoding')"

    # ---------------- large request body (exercises the read path) ----------------
    $big = "x" * 200000
    $r = Invoke-Request ("POST /echo HTTP/1.1`r`nHost: h`r`nContent-Length: {0}`r`nConnection: close`r`n`r`n{1}" -f $big.Length, $big) -TimeoutMs 20000
    $json = From-JsonSafe $r.Text
    Assert-True "large body echoed completely" ($json.bodyLen -eq $big.Length) "bodyLen=$($json.bodyLen) expected=$($big.Length)"

    # ---------------- file access / permissions ----------------
    $r = Invoke-Request "GET /file/?name=data/small.txt HTTP/1.1`r`nHost: h`r`nConnection: close`r`n`r`n"
    $json = From-JsonSafe $r.Text
    Assert-True "read inside allowed dir" ($json.text -eq "hello-file") "text=$($json.text)"

    $r = Invoke-Request "GET /file/?name=../config.json HTTP/1.1`r`nHost: h`r`nConnection: close`r`n`r`n"
    $json = From-JsonSafe $r.Text
    Assert-True "read outside allowed dir denied" ($null -ne $json.error) "json=$($r.Text)"

    $r = Invoke-Request "GET /file/?name=data/big.txt HTTP/1.1`r`nHost: h`r`nConnection: close`r`n`r`n"
    $json = From-JsonSafe $r.Text
    Assert-True "read above file_max_size denied" ($null -ne $json.error) "json=$($r.Text.Substring(0, [Math]::Min(120, $r.Text.Length)))"

    # ---------------- cookies ----------------
    $r = Invoke-Request "GET /cookie/?v=abc123 HTTP/1.1`r`nHost: h`r`nCookie: sid=old`r`nConnection: close`r`n`r`n"
    $sc = Get-Header -Response $r -Name "set-cookie"
    Assert-True "Set-Cookie emitted" ($sc -match "sid=abc123") "set-cookie=$sc"
    Assert-True "Set-Cookie HttpOnly" ($sc -match "HttpOnly") "set-cookie=$sc"
    $json = From-JsonSafe $r.Text
    Assert-True "request cookie parsed" ($json.read -eq "old") "read=$($json.read)"

    # ---------------- SQLite ----------------
    $r = Invoke-Request "GET /sql/ HTTP/1.1`r`nHost: h`r`nConnection: close`r`n`r`n"
    $json = From-JsonSafe $r.Text
    Assert-True "sqlite read/write on allowed db" (@($json.rows)[0].k -eq "k1") "$($r.Text)"
    Assert-True "sqlite column names" ((@($json.columns) -join ",") -eq "k,v") "$($r.Text)"
    Assert-True "sqlite other db denied" ($json.denied -ne "opened") "denied=$($json.denied)"

    # ---------------- JS permission context across Global.call ----------------
    $r = Invoke-Request "GET /escalate/ HTTP/1.1`r`nHost: h`r`nConnection: close`r`n`r`n"
    $json = From-JsonSafe $r.Text
    Assert-True "business script has no file access" ($json.canReadBefore -eq $false) "canReadBefore=$($json.canReadBefore)"
    Assert-True "global script call succeeded" ($json.call.canSeeFile -eq $true) "call=$($r.Text)"
    Assert-True "global store works from global script" ($json.call.stored -eq $true) "call=$($r.Text)"
    Assert-True "no privilege leak after Global.call" ($json.canReadAfter -eq $false) "canReadAfter=$($json.canReadAfter)"
    Assert-True "file read still denied after Global.call" ("$($json.readAfter)" -like "denied:*") "readAfter=$($json.readAfter)"

    # ---------------- security filter (check()) ----------------
    $r = Invoke-Request "GET /echo HTTP/1.1`r`nHost: h`r`nConnection: close`r`n`r`n"
    Assert-True "security filter allows normal request" ($r.Status -eq 200) "status=$($r.Status)"

    $r = Invoke-Request "GET /forbidden HTTP/1.1`r`nHost: h`r`nConnection: close`r`n`r`n"
    Assert-True "security filter blocks with status" ($r.Status -eq 403) "status=$($r.Status)"
    Assert-True "security filter custom header" ((Get-Header -Response $r -Name "x-blocked") -eq "1") "headers=$($r.Headers.Keys -join ',')"
    Assert-True "security filter custom message" ($r.Text -eq "blocked by policy") "body=$($r.Text)"

    $r = Invoke-Request "GET /teapot HTTP/1.1`r`nHost: h`r`nConnection: close`r`n`r`n"
    Assert-True "security filter numeric status" ($r.Status -eq 418) "status=$($r.Status)"

    $conn = New-Conn
    try {
        Send-RawText -Conn $conn -Text "GET /drop HTTP/1.1`r`nHost: h`r`n`r`n"
        $closed = $false
        $got = [byte[]]::new(0)
        try {
            $stream = $conn.GetStream()
            $stream.ReadTimeout = 3000
            $buf = [byte[]]::new(256)
            $n = $stream.Read($buf, 0, $buf.Length)
            $closed = ($n -le 0)
            if ($n -gt 0) { $got = $buf[0..($n - 1)] }
        } catch { $closed = $true }
        Assert-True "security filter -1 closes silently" $closed ("got=" + ($got.Length))
    } finally {
        $conn.Dispose()
    }

    # ---------------- RST storm must not stop the acceptor ----------------
    for ($i = 0; $i -lt 80; $i++) {
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $c.LingerState = New-Object System.Net.Sockets.LingerOption($true, 0)
            $c.Connect("127.0.0.1", $port)
            $c.Client.Close()
            $c.Dispose()
        } catch { }
    }
    Start-Sleep -Milliseconds 300
    $r = Invoke-Request "GET /echo HTTP/1.1`r`nHost: h`r`nConnection: close`r`n`r`n"
    Assert-True "server still serves after RST storm" ($r.Status -eq 200) "status=$($r.Status)"

    # ---------------- WebSocket ----------------
    $wsKey = "dGhlIHNhbXBsZSBub25jZQ=="
    $conn = New-Conn
    try {
        Send-RawText -Conn $conn -Text ("GET /ws HTTP/1.1`r`nHost: h`r`nUpgrade: websocket`r`nConnection: Upgrade`r`nSec-WebSocket-Key: {0}`r`nSec-WebSocket-Version: 13`r`n`r`n" -f $wsKey)
        $resp = Read-Response -Stream $conn.GetStream() -HeadOnly
        Assert-True "WebSocket handshake 101" ($resp.Status -eq 101) "status=$($resp.Status)"
        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        $expected = [Convert]::ToBase64String($sha1.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($wsKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")))
        Assert-True "Sec-WebSocket-Accept correct" ((Get-Header -Response $resp -Name "sec-websocket-accept") -eq $expected) "got=$(Get-Header -Response $resp -Name 'sec-websocket-accept') expect=$expected"

        $frame = Read-WsFrame -Stream $conn.GetStream()
        Assert-True "WebSocket first frame is text" ($frame.Opcode -eq 1) "op=$($frame.Opcode)"
        Assert-True "WebSocket welcome payload" ($utf8.GetString($frame.Payload) -eq "hello") "payload=$($utf8.GetString($frame.Payload))"

        $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes("ping")
        $maskKey = [byte[]](0x11, 0x22, 0x33, 0x44)
        $frameBytes = New-Object System.Collections.Generic.List[byte]
        $frameBytes.Add(0x81)
        $frameBytes.Add([byte](0x80 -bor $payloadBytes.Length))
        $frameBytes.AddRange($maskKey)
        for ($i = 0; $i -lt $payloadBytes.Length; $i++) {
            $frameBytes.Add([byte]($payloadBytes[$i] -bxor $maskKey[$i % 4]))
        }
        Send-RawBytes -Conn $conn -Bytes $frameBytes.ToArray()
        $echoFrame = Read-WsFrame -Stream $conn.GetStream()
        Assert-True "WebSocket echo" ($utf8.GetString($echoFrame.Payload) -eq "echo:ping") "payload=$($utf8.GetString($echoFrame.Payload))"

        $closeFrame = [byte[]](0x88, 0x82, 0x11, 0x22, 0x33, 0x44, (0x03 -bxor 0x11), (0xE8 -bxor 0x22))
        Send-RawBytes -Conn $conn -Bytes $closeFrame
        $reply = Read-WsFrame -Stream $conn.GetStream()
        Assert-True "WebSocket close frame answered" ($null -ne $reply -and $reply.Opcode -eq 8) "op=$($reply.Opcode)"
    } finally {
        $conn.Dispose()
    }

    # fragmented application message must still be reassembled
    $conn = Connect-Ws
    try {
        Send-RawBytes -Conn $conn -Bytes (New-WsFrame -Opcode 1 -Text "he" -Fin $false)
        Send-RawBytes -Conn $conn -Bytes (New-WsFrame -Opcode 0 -Text "llo" -Fin $true)
        $f = Read-WsFrame -Stream $conn.GetStream()
        Assert-True "fragmented message reassembled" ($null -ne $f -and $utf8.GetString($f.Payload) -eq "echo:hello") "payload=$($utf8.GetString($f.Payload))"
    } finally {
        $conn.Dispose()
    }

    # unmasked client frame is a protocol error: the server must close
    $conn = Connect-Ws
    try {
        Send-RawBytes -Conn $conn -Bytes ([byte[]](0x81, 0x01, 0x78))
        $f = Read-WsFrame -Stream $conn.GetStream()
        Assert-True "unmasked client frame rejected" ($null -eq $f -or $f.Opcode -eq 8) "op=$($f.Opcode)"
    } finally {
        $conn.Dispose()
    }

    # oversized control frame (ping payload > 125 bytes) is a protocol error
    $conn = Connect-Ws
    try {
        $big = "p" * 200
        Send-RawBytes -Conn $conn -Bytes (New-WsFrame -Opcode 9 -Text $big)
        $f = Read-WsFrame -Stream $conn.GetStream()
        Assert-True "oversized ping rejected" ($null -eq $f -or $f.Opcode -eq 8) "op=$($f.Opcode)"
    } finally {
        $conn.Dispose()
    }

    # ---------------- HTTP/1.0 ----------------
    $conn = New-Conn
    try {
        Send-RawText -Conn $conn -Text "GET /echo HTTP/1.0`r`nHost: h`r`n`r`n"
        $r = Read-Response -Stream $conn.GetStream()
        Assert-True "HTTP/1.0 request succeeds" ($r.Status -eq 200) "status=$($r.Status)"
        Assert-True "HTTP/1.0 gets Connection: close" ((Get-Header -Response $r -Name "connection") -match "close") "conn=$(Get-Header -Response $r -Name 'connection')"
        $closed = $false
        try {
            $stream = $conn.GetStream()
            $stream.ReadTimeout = 2000
            $b = [byte[]]::new(1)
            $n = $stream.Read($b, 0, 1)
            $closed = ($n -le 0)
        } catch { $closed = $true }
        Assert-True "HTTP/1.0 connection closed after response" $closed ""
    } finally {
        $conn.Dispose()
    }

} finally {
    if ($null -ne $proc -and -not $proc.HasExited) {
        try { $proc.Kill() } catch { }
        Start-Sleep -Milliseconds 200
    }
    if (Test-Path $stdoutFile) {
        $log = Get-Content $stdoutFile -ErrorAction SilentlyContinue
        if ($null -ne $log -and $log.Count -gt 0) {
            Write-Host "`n---- server log (tail 30) ----" -ForegroundColor DarkGray
            $log | Select-Object -Last 30 | ForEach-Object { Write-Host "$_" -ForegroundColor DarkGray }
        }
    }
    if (Test-Path $stderrFile) {
        $err = Get-Content $stderrFile -ErrorAction SilentlyContinue
        if ($null -ne $err -and $err.Count -gt 0) {
            Write-Host "`n---- server stderr (tail 20) ----" -ForegroundColor DarkYellow
            $err | Select-Object -Last 20 | ForEach-Object { Write-Host "$_" -ForegroundColor DarkYellow }
        }
    }
    Remove-Item $stdinFile, $stdoutFile, $stderrFile -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host ("{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor ($(if ($script:fail -eq 0) { "Green" } else { "Red" }))
if ($script:fail -gt 0) {
    Write-Host "failed checks:" -ForegroundColor Red
    $script:failures | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
}
exit $script:fail
