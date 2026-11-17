param(
    [string]$Exe = "",
    [switch]$NoStart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================
# Hhttp routing regression tests
#
# Usage (from the repository root, after building):
#   powershell -ExecutionPolicy Bypass -File tests\run-routing-tests.ps1
#
# Covers:
#   - the same path can serve HTTP and WebSocket at once (no silent overwrite)
#   - path matched but request type unsupported -> typed fallback handler
#   - undefine_roter can handle WebSocket requests (was dead config)
#   - wildcard host tables: the most specific (*.wild.test) wins over (*.test)
#   - exact host table shadows wildcard tables
#   - default table still serves hosts without a dedicated table
# Exit code = number of failed checks (0 = all passed).
# ============================================================

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($Exe)) {
    $exe = Join-Path $repo "build\Hhttp.exe"
    if (-not (Test-Path $exe)) { $exe = Join-Path $repo "build\Release\Hhttp.exe" }
} else { $exe = (Resolve-Path $Exe).Path }
$config = Join-Path $PSScriptRoot "config-routing.json"
$scriptDir = Join-Path $PSScriptRoot "scripts"
$port = 18101
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
    $ms = New-Object System.IO.MemoryStream
    $one = [byte[]]::new(1)
    while ($ms.Length -lt 65536) {
        $n = $Stream.Read($one, 0, 1)
        if ($n -le 0) { break }
        $ms.WriteByte($one[0])
        if ($ms.Length -ge $marker.Length) {
            $buf = $ms.GetBuffer()
            $start = [int]$ms.Length - $marker.Length
            $hit = $true
            for ($i = 0; $i -lt $marker.Length; $i++) {
                if ($buf[$start + $i] -ne $marker[$i]) { $hit = $false; break }
            }
            if ($hit) { break }
        }
    }
    if ($ms.Length -eq 0) { return $null }

    $headText = $latin1.GetString($ms.ToArray())
    $lines = $headText -split "`r`n"
    if ($lines[0] -notmatch '^HTTP/(\d\.\d) (\d{3})(?: (.*))?$') {
        throw "bad status line: $($lines[0])"
    }
    $status = [int]$Matches[2]

    $headers = @{}
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -eq "") { continue }
        $colon = $line.IndexOf(":")
        if ($colon -lt 0) { continue }
        $name = $line.Substring(0, $colon).Trim().ToLowerInvariant()
        $headers[$name] = $line.Substring($colon + 1).Trim()
    }

    $body = [byte[]]::new(0)
    if (-not $HeadOnly -and $status -ne 101) {
        if ($headers.ContainsKey("content-length")) {
            $len = [int]$headers["content-length"]
            if ($len -gt 0) { $body = Read-ExactBytes -Stream $Stream -Count $len }
        } else {
            # 没有 Content-Length:读到连接关闭(测试脚本只用在 404 之类的小响应上)
            $out = New-Object System.IO.MemoryStream
            $buf = [byte[]]::new(8192)
            while ($true) {
                $n = $Stream.Read($buf, 0, $buf.Length)
                if ($n -le 0) { break }
                $out.Write($buf, 0, $n)
            }
            $body = $out.ToArray()
        }
    }

    return New-Object psobject -Property @{
        Status  = $status
        Headers = $headers
        Text    = $utf8.GetString($body)
    }
}

function Invoke-Request {
    param([string]$Raw, [switch]$HeadOnly, [int]$TimeoutMs = 5000)
    $conn = New-Conn -TimeoutMs $TimeoutMs
    try {
        Send-RawText -Conn $conn -Text $Raw
        return Read-Response -Stream $conn.GetStream() -HeadOnly:$HeadOnly
    } finally {
        $conn.Dispose()
    }
}

function Get-Http {
    param([string]$Path, [string]$HostName = "plain.example")
    return Invoke-Request ("GET {0} HTTP/1.1`r`nHost: {1}`r`nConnection: close`r`n`r`n" -f $Path, $HostName)
}

function Assert-HttpBody {
    param([string]$Name, [string]$Path, [string]$HostName, [int]$Status, [string]$Body)
    $r = Get-Http -Path $Path -HostName $HostName
    $ok = ($null -ne $r -and $r.Status -eq $Status -and $r.Text -eq $Body)
    $detail = if ($null -eq $r) { "no response" } else { "status=$($r.Status) body=$($r.Text)" }
    Assert-True $Name $ok $detail
}

# ---------------- WebSocket ----------------
function New-WsFrame {
    param([int]$Opcode, [string]$Text = "", [bool]$Fin = $true)
    $payload = $utf8.GetBytes($Text)
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
        Payload = $payload
    }
}

# 连接 WebSocket 并读出服务端发来的欢迎帧;失败时返回 $null
function Connect-Ws {
    param([string]$Path, [string]$HostName = "plain.example")
    $c = New-Conn
    Send-RawText -Conn $c -Text ("GET {0} HTTP/1.1`r`nHost: {1}`r`nUpgrade: websocket`r`nConnection: Upgrade`r`nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==`r`nSec-WebSocket-Version: 13`r`n`r`n" -f $Path, $HostName)
    $resp = Read-Response -Stream $c.GetStream() -HeadOnly
    if ($null -eq $resp -or $resp.Status -ne 101) {
        $c.Dispose()
        $status = if ($null -eq $resp) { 0 } else { $resp.Status }
        return New-Object psobject -Property @{ Conn = $null; Status = $status; Welcome = $null }
    }
    $frame = Read-WsFrame -Stream $c.GetStream()
    $welcome = if ($null -eq $frame) { "" } else { $utf8.GetString($frame.Payload) }
    return New-Object psobject -Property @{ Conn = $c; Status = 101; Welcome = $welcome }
}

function Assert-WsWelcome {
    param([string]$Name, [string]$Path, [string]$HostName, [string]$Expected)
    $ws = Connect-Ws -Path $Path -HostName $HostName
    try {
        $ok = ($null -ne $ws.Conn -and $ws.Welcome -eq $Expected)
        $detail = if ($null -eq $ws.Conn) { "status=$($ws.Status)" } else { "welcome=$($ws.Welcome)" }
        Assert-True $Name $ok $detail
    } finally {
        if ($null -ne $ws.Conn) { $ws.Conn.Dispose() }
    }
}

# ============================================================
# start the server
# ============================================================
if (-not $NoStart -and -not (Test-Path $exe)) { Write-Error "missing $exe (build first)"; exit 1 }

$stdinFile = Join-Path $env:TEMP ("hhttp-routing-stdin-{0}.txt" -f ([guid]::NewGuid().ToString("N")))
[System.IO.File]::WriteAllText($stdinFile, "", $utf8)
$stdoutFile = Join-Path $env:TEMP ("hhttp-routing-out-{0}.log" -f ([guid]::NewGuid().ToString("N")))
$stderrFile = Join-Path $env:TEMP ("hhttp-routing-err-{0}.log" -f ([guid]::NewGuid().ToString("N")))

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

    # ---- 同一路径:HTTP 与 WebSocket 处理器共存 ----
    Assert-HttpBody "same path: HTTP handler" "/both" "plain.example" 200 "http-route"
    Assert-HttpBody "same path: HTTP handler on unregistered host" "/both" "other.example" 200 "http-route"
    Assert-WsWelcome "same path: WebSocket handler" "/both" "plain.example" "ws-route"

    # WebSocket echo on the same path still works (handler, not just handshake)
    $ws = Connect-Ws -Path "/both" -HostName "plain.example"
    try {
        if ($null -ne $ws.Conn) {
            Send-RawBytes -Conn $ws.Conn -Bytes (New-WsFrame -Opcode 1 -Text "ping")
            $f = Read-WsFrame -Stream $ws.Conn.GetStream()
            Assert-True "same path: WebSocket echo" ($null -ne $f -and $utf8.GetString($f.Payload) -eq "echo:ping") "payload=$(if ($null -ne $f) { $utf8.GetString($f.Payload) } else { '<none>' })"
        } else {
            Assert-True "same path: WebSocket echo" $false "handshake failed (status=$($ws.Status))"
        }
    } finally {
        if ($null -ne $ws.Conn) { $ws.Conn.Dispose() }
    }

    # ---- 请求类型判定:Upgrade / Connection 是逗号分隔 token 列表 ----
    $conn = New-Conn
    try {
        Send-RawText -Conn $conn -Text ("GET /both HTTP/1.1`r`nHost: plain.example`r`nUpgrade: h2c, websocket`r`nConnection: keep-alive, Upgrade`r`nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==`r`nSec-WebSocket-Version: 13`r`n`r`n")
        $resp = Read-Response -Stream $conn.GetStream() -HeadOnly
        $ok = ($null -ne $resp -and $resp.Status -eq 101)
        $detail = if ($null -eq $resp) { "no response" } else { "status=$($resp.Status)" }
        Assert-True "websocket: multi-token upgrade headers" $ok $detail
        if ($ok) {
            $frame = Read-WsFrame -Stream $conn.GetStream()
            Assert-True "websocket: multi-token upgrade routed to handler" ($null -ne $frame -and $utf8.GetString($frame.Payload) -eq "ws-route") ""
        }
    } finally {
        $conn.Dispose()
    }

    # ---- 路径命中但请求类型不匹配 -> 交给对应类型的兜底处理器 ----
    Assert-HttpBody "type mismatch: HTTP request falls back" "/ws-only" "plain.example" 418 "fallback-http"
    Assert-WsWelcome "type mismatch: WebSocket request falls back" "/http-only" "plain.example" "fallback-ws"

    # ---- 完全不存在的路径 -> 兜底处理器(HTTP 与 WebSocket 各自生效) ----
    Assert-HttpBody "no route: HTTP fallback" "/nope" "plain.example" 418 "fallback-http"
    Assert-WsWelcome "no route: WebSocket fallback" "/nope" "plain.example" "fallback-ws"
    Assert-HttpBody "no route: host table fallback" "/missing" "a.wild.test" 418 "fallback-http"
    Assert-WsWelcome "no route: host table WebSocket fallback" "/missing" "a.wild.test" "fallback-ws"

    # ---- 通配子域:更具体(*.wild.test)优先于更宽(*.test) ----
    Assert-HttpBody "wildcard: most specific host table wins" "/pick/x" "a.wild.test" 200 "route-deep"
    Assert-HttpBody "wildcard: broader host table still works" "/pick/x" "a.test" 200 "route-parent"
    Assert-HttpBody "wildcard: host with port is normalized" "/pick/x" "a.wild.test:18101" 200 "route-deep"
    Assert-HttpBody "wildcard: host is case-insensitive" "/pick/x" "A.WILD.TEST" 200 "route-deep"
    Assert-HttpBody "wildcard: trailing dot is ignored" "/pick/x" "a.wild.test." 200 "route-deep"

    # ---- 精确域名表优先于通配,且精确 / 前缀匹配规则不变 ----
    Assert-HttpBody "exact host: exact path" "/name" "exact.test" 200 "exact-route"
    Assert-HttpBody "exact host: prefix route" "/other" "exact.test" 200 "route-prefix"
    Assert-HttpBody "exact host shadows wildcard" "/pick/x" "exact.test" 200 "route-prefix"

    # ---- WebSocket 兜底处理器需要支持 WebSocket 才接管 ----
    Assert-WsWelcome "unmatched deeper path: WebSocket fallback" "/http-only/deeper" "plain.example" "fallback-ws"

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
