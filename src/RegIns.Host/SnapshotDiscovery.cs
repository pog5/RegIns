using System.Diagnostics;
using System.Text.Json;
namespace RegIns;

public sealed record SnapshotRoot(string Id, string Path, string? Created, string Origin);
public static class SnapshotDiscovery
{
    // Optional host discovery adapter. Registry parsing never calls this adapter.
    // Linux/offline users supply mounted or extracted snapshot roots directly.
    public static async Task<IReadOnlyList<SnapshotRoot>> EnumerateHostAsync(CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Supply mounted/extracted VSS roots on Linux. Raw VSS store parsing is not implemented.");
        var info = new ProcessStartInfo("powershell.exe") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        info.ArgumentList.Add("-NoProfile"); info.ArgumentList.Add("-NonInteractive"); info.ArgumentList.Add("-Command");
        info.ArgumentList.Add("$ErrorActionPreference='Stop'; @(Get-CimInstance Win32_ShadowCopy | Select-Object ID,DeviceObject,@{n='Created';e={$_.InstallDate.ToString('o')}}) | ConvertTo-Json -Compress");
        using var process = Process.Start(info) ?? throw new IOException("Could not start snapshot discovery.");
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); timeout.CancelAfter(TimeSpan.FromSeconds(30));
        try
        {
            var outputTask = process.StandardOutput.ReadToEndAsync(timeout.Token); var errorTask = process.StandardError.ReadToEndAsync(timeout.Token);
            await process.WaitForExitAsync(timeout.Token); string output = await outputTask, error = await errorTask;
            if (process.ExitCode != 0) throw new IOException("Snapshot enumeration failed: " + error.Trim());
            if (string.IsNullOrWhiteSpace(output)) return [];
            using var doc = JsonDocument.Parse(output);
            var entries = doc.RootElement.ValueKind == JsonValueKind.Array ? doc.RootElement.EnumerateArray().ToArray() : [doc.RootElement];
            return entries.Select(e => new SnapshotRoot(e.GetProperty("ID").GetString()!, e.GetProperty("DeviceObject").GetString()! + "\\", e.GetProperty("Created").GetString(), "Windows-host-VSS")).ToList();
        }
        catch (OperationCanceledException) { if (!process.HasExited) process.Kill(true); throw; }
    }
}
