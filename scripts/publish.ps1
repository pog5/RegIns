param([string]$Dotnet = 'dotnet')
$ErrorActionPreference = 'Stop'
foreach ($rid in @('win-x64','linux-x64')) {
    foreach ($app in @('Cli','Gui')) {
        & $Dotnet publish "src/RegIns.$app/RegIns.$app.csproj" -c Release -r $rid --self-contained true -o "artifacts/publish/$rid/$app"
        if ($LASTEXITCODE -ne 0) { throw "Publish failed: $rid $app" }
    }
}
& $Dotnet pack src/RegIns.Core/RegIns.Core.csproj -c Release -o artifacts/packages
if ($LASTEXITCODE -ne 0) { throw 'Package failed' }
