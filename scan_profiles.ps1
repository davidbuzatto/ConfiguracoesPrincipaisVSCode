[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
node "$scriptDir\scan_profiles.js" "$scriptDir"
