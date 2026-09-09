param([string]$Dotnet = 'dotnet')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
    $bundle = Join-Path $root 'artifacts/release/RegIns-1.0.0'
    foreach ($rid in @('win-x64', 'linux-x64', 'linux-musl-x64')) {
        foreach ($app in @('Gui', 'Cli')) {
            & $Dotnet publish "src/RegIns.$app" -c Release -r $rid --self-contained true -o "$bundle/$rid"
            if ($LASTEXITCODE -ne 0) { throw "Publish failed: $rid $app" }
        }
    }
    & $Dotnet pack src/RegIns.Core -c Release -o "$bundle/library"
    if ($LASTEXITCODE -ne 0) { throw 'Pack failed' }
    Copy-Item src/RegIns.Core/bin/Release/net11.0/RegIns.Core.dll "$bundle/library/"
    Copy-Item README.md "$bundle/ENGINE-README.md"
    Copy-Item docs/support.md "$bundle/SUPPORT.md"
    Copy-Item docs/release-readme.txt "$bundle/README.txt"
    $entries = Get-ChildItem $bundle -Recurse -File | Where-Object Name -ne 'SHA256SUMS.txt' | Sort-Object FullName | ForEach-Object {
        $relative = [IO.Path]::GetRelativePath($bundle, $_.FullName).Replace('\', '/')
        "{0}  {1}" -f (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $relative
    }
    $entries | Set-Content "$bundle/SHA256SUMS.txt" -Encoding ascii
    $zip = Join-Path $root 'artifacts/release/RegIns-1.0.0.zip'
    Compress-Archive -LiteralPath $bundle -DestinationPath $zip -CompressionLevel Optimal -Force
    (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash | Set-Content "$zip.sha256" -Encoding ascii
} finally { Pop-Location }
