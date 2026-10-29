$ErrorActionPreference = 'Stop'
$base = 'http://127.0.0.1:8787'
$tokenFile = Join-Path $PSScriptRoot '.proxy-token'

$token = $env:PROXY_TOKEN
if (-not $token -and (Test-Path $tokenFile)) {
    $token = (Get-Content -Raw $tokenFile).Trim()
}
if (-not $token) {
    Write-Host 'FAIL: no PROXY_TOKEN env var and no .proxy-token file. Start the server first.' -ForegroundColor Red
    exit 1
}

$pass = 0
$fail = 0
function Check($name, $ok, $detail) {
    if ($ok) { Write-Host "PASS: $name" -ForegroundColor Green; $script:pass++ }
    else { Write-Host "FAIL: $name - $detail" -ForegroundColor Red; $script:fail++ }
}

function HttpGet($url, $cookieJar = $null) {
    $args = @('-s', '-o', 'NUL', '-w', '%{http_code}|%{header_json}', $url)
    if ($cookieJar) { $args = @('-s', '-o', 'NUL', '-w', '%{http_code}|%{header_json}', '-b', $cookieJar, $url) }
    $raw = & curl.exe @args
    $parts = $raw -split '\|', 2
    return @{ Status = [int]$parts[0]; Headers = ($parts[1] | ConvertFrom-Json) }
}

Write-Host "`n=== R1 acceptance test ===" -ForegroundColor Cyan
Write-Host "Base: $base`n"

# Test 1: no cookie -> 401
$r = HttpGet "$base/stream/state"
Check 'Test 1: no cookie -> 401' ($r.Status -eq 401) "got $($r.Status)"
Check 'Test 1: WWW-Authenticate present' ($r.Headers.'www-authenticate' -match 'Bearer realm="pv"') "got $($r.Headers.'www-authenticate')"
Check 'Test 1: X-Request-Id present' ([bool]$r.Headers.'x-request-id') "got $($r.Headers.'x-request-id')"

# Test 2: master token -> 302 + Set-Cookie
$jar = Join-Path $env:TEMP "pv-r1-$([guid]::NewGuid()).jar"
$raw = & curl.exe -s -c $jar -o NUL -w '%{http_code}|%{redirect_url}|%{header_json}' "$base/?k=$token"
$parts = $raw -split '\|', 3
$status2 = [int]$parts[0]
$redirect = $parts[1]
$headers2 = $parts[2] | ConvertFrom-Json
Check 'Test 2: master token -> 302' ($status2 -eq 302) "got $status2"
Check 'Test 2: Location is /' ($redirect -match '/$' -and $redirect -notmatch '__pv|k=') "got $redirect"
Check 'Test 2: __pv_auth cookie set' ((Get-Content -Raw $jar) -match '__pv_auth') 'cookie jar empty'
Check 'Test 2: cookie is HttpOnly' ($headers2.'set-cookie' -match 'HttpOnly') "got $($headers2.'set-cookie')"

# Test 3: with cookie -> 200 or 404
$r = HttpGet "$base/stream/state" $jar
Check 'Test 3: authed /stream/state -> 200 or 404' ($r.Status -eq 200 -or $r.Status -eq 404) "got $($r.Status)"

# Test 4: wrong master -> 401, no Set-Cookie
$raw = & curl.exe -s -o NUL -w '%{http_code}|%{header_json}' "$base/?k=definitely-wrong"
$parts = $raw -split '\|', 2
$status4 = [int]$parts[0]
$headers4 = $parts[1] | ConvertFrom-Json
Check 'Test 4: wrong master -> 401' ($status4 -eq 401) "got $status4"
Check 'Test 4: no Set-Cookie on failure' (-not $headers4.'set-cookie') "got $($headers4.'set-cookie')"

# Test 5: logout -> 204, then 401
$raw = & curl.exe -s -b $jar -X POST -o NUL -w '%{http_code}' "$base/logout"
Check 'Test 5: logout -> 204' ([int]$raw -eq 204) "got $raw"
$r = HttpGet "$base/stream/state" $jar
Check 'Test 5: post-logout /stream/state -> 401' ($r.Status -eq 401) "got $($r.Status)"

# Test 6: token not in stream-diagnostics.log
$diag = Join-Path $PSScriptRoot 'stream-diagnostics.log'
if (Test-Path $diag) {
    $hit = Select-String -Path $diag -SimpleMatch $token -Quiet
    Check 'Test 6: token not in stream-diagnostics.log' (-not $hit) 'token found in log'
} else {
    Write-Host 'SKIP: Test 6 - stream-diagnostics.log not yet created' -ForegroundColor Yellow
}

Write-Host "`n$pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })

# Test 7 (manual): the master token must appear in the server console only once,
# on the single "Launcher token: <token>" line. Scroll the PowerShell window and
# confirm no other line contains it. Also confirm no log line contains a /p/<token>
# path or a __pv_auth/__pv_proxy cookie value.
Write-Host "`nManual check: scroll the server console. The token must appear only on the single 'Launcher token:' line." -ForegroundColor Yellow

Remove-Item $jar -ErrorAction SilentlyContinue