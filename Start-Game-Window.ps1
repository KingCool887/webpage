$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $MyInvocation.MyCommand.Path
$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) {
    throw 'Node.js is required. Install the current Node.js LTS version, then run this file again.'
}

Set-Location -LiteralPath $project
Write-Host 'Keep this PowerShell window open while using the launcher.'
Write-Host ''
Write-Host 'Open the launcher in your browser with one of your keys, for example:'
Write-Host '  http://localhost:8787/?key=Colin_4587'
Write-Host ''
Write-Host '(The first visit sets a session cookie; after that the plain URL works.)'
Write-Host ''
Write-Host 'Proxy logs appear below. They show method, status, elapsed, and content-type only —'
Write-Host 'the target host and path are not printed.'
& $node.Source (Join-Path $project 'server.js')