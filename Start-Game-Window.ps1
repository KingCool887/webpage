$ErrorActionPreference = 'Stop'
$project = Split-Path -Parent $MyInvocation.MyCommand.Path
$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) {
    throw 'Node.js is required. Install the current Node.js LTS version, then run this file again.'
}

Set-Location -LiteralPath $project
Write-Host 'Keep this PowerShell window open while using the launcher.'
Write-Host 'Open the launcher URL printed by the server (it includes your launcher token).'
Write-Host 'If no URL was printed, read the token from .proxy-token and open:'
Write-Host '  http://launcher.localhost:8787/?k=<token>'
Write-Host 'Proxy request logs appear below. They include site paths but omit query strings and cookies.'
& $node.Source (Join-Path $project 'server.js')