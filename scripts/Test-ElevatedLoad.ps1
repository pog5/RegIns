param([Parameter(Mandatory)][string]$Workspace)
$ErrorActionPreference = 'Stop'
$results = @()
foreach ($relative in @('artifacts/acceptance/synthetic.hive', 'test-or-mess-with-on-this-hive/SYSTEM', 'artifacts/acceptance/SYSTEM.recovered-v3', 'artifacts/acceptance/diag-uniform-security.hive')) {
    $source = Join-Path $Workspace $relative
    $id = [Guid]::NewGuid().ToString('N')
    $directory = Join-Path $Workspace ('artifacts/acceptance/elevated-' + $id)
    $null = New-Item -ItemType Directory -Path $directory
    $copy = Join-Path $directory 'SYSTEM'
    Copy-Item -LiteralPath $source -Destination $copy
    $mount = 'HKLM\RI' + $id.Substring(0, 6)
    $loaded = $false
    try {
        $ErrorActionPreference = 'Continue'
        $message = & "$env:WINDIR\System32\reg.exe" load $mount $copy 2>&1 | Out-String
        $code = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
        $loaded = $code -eq 0
        $appResult = & (Join-Path $Workspace 'scripts/Test-NativeLoad.ps1') -Hive $source -OutputDirectory $directory -SystemLoad | ConvertFrom-Json
        $results += [pscustomobject]@{Source=$relative;Loaded=$loaded;ExitCode=$code;Message=$message;Copy=$copy;AppLoadCode=$appResult.LoadCode;AppLoaded=$appResult.Loaded}
    } finally {
        if ($loaded) { & reg.exe unload $mount | Out-Null; if ($LASTEXITCODE -ne 0) { throw "Could not unload $mount" } }
    }
}
$results | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $Workspace 'artifacts/acceptance/elevated-native-results.json')
