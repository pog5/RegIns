param([Parameter(Mandatory)][string]$Hive, [Parameter(Mandatory)][string]$OutputDirectory, [switch]$SystemLoad)
$ErrorActionPreference = 'Stop'
# Test oracle only. Never used by the recovery engine. Load a disposable copy.
$null = New-Item -ItemType Directory -Force -Path $OutputDirectory
$copy = Join-Path ([IO.Path]::GetFullPath($OutputDirectory)) ('oracle-' + [Guid]::NewGuid().ToString('N') + '.hive')
Copy-Item -LiteralPath $Hive -Destination $copy
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class RegInsNativeOracle {
 [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] public static extern int RegLoadAppKey(string file, out IntPtr key, uint access, uint options, uint reserved);
 [DllImport("advapi32.dll")] public static extern int RegCloseKey(IntPtr key);
 [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] public static extern int RegLoadKey(IntPtr key, string subkey, string file);
 [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] public static extern int RegUnLoadKey(IntPtr key, string subkey);
 [StructLayout(LayoutKind.Sequential, Pack=1)] public struct Privilege { public uint Count; public long Luid; public uint Attributes; }
 [DllImport("advapi32.dll", SetLastError=true)] public static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
 [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern bool LookupPrivilegeValue(string system, string name, out long luid);
 [DllImport("advapi32.dll", SetLastError=true)] public static extern bool AdjustTokenPrivileges(IntPtr token, bool disable, ref Privilege privilege, uint length, IntPtr previous, IntPtr returned);
 [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
 public static int Enable(string name) { IntPtr t; if(!OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle,0x28,out t)) return Marshal.GetLastWin32Error(); try { long luid; if(!LookupPrivilegeValue(null,name,out luid)) return Marshal.GetLastWin32Error(); var p=new Privilege { Count=1,Luid=luid,Attributes=2 }; AdjustTokenPrivileges(t,false,ref p,0,IntPtr.Zero,IntPtr.Zero); return Marshal.GetLastWin32Error(); } finally { CloseHandle(t); } }
}
'@
if ($SystemLoad) {
    $backup = [RegInsNativeOracle]::Enable('SeBackupPrivilege')
    $restore = [RegInsNativeOracle]::Enable('SeRestorePrivilege')
    $name = 'RI' + [Guid]::NewGuid().ToString('N').Substring(0,8)
    $hklm = [IntPtr]::new(-2147483646)
    $code = [RegInsNativeOracle]::RegLoadKey($hklm,$name,$copy)
    try { [pscustomobject]@{Input=$Hive;Copy=$copy;LoadCode=$code;Message=([ComponentModel.Win32Exception]::new($code)).Message;Loaded=($code -eq 0);BackupPrivilege=$backup;RestorePrivilege=$restore} | ConvertTo-Json }
    finally { if ($code -eq 0) { $unload = [RegInsNativeOracle]::RegUnLoadKey($hklm,$name); if ($unload -ne 0) { throw "Unload failed for HKLM\$name : $unload" } } }
    return
}
$handle = [IntPtr]::Zero
$code = [RegInsNativeOracle]::RegLoadAppKey($copy, [ref]$handle, 0x20019, 1, 0)
try { [pscustomobject]@{Input=[IO.Path]::GetFullPath($Hive); Copy=$copy; LoadCode=$code; Message=([ComponentModel.Win32Exception]::new($code)).Message; Loaded=($code -eq 0)} | ConvertTo-Json }
finally { if ($handle -ne [IntPtr]::Zero) { $null = [RegInsNativeOracle]::RegCloseKey($handle) } }
