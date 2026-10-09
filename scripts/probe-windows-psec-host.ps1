# Read-only native capability report. No Node, MSVC, ACL changes or agent launch.
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'This diagnostic requires Windows.' }

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class AgentkeeperPsecHost {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern IntPtr LoadLibraryExW(string name, IntPtr file, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true)]
    public static extern IntPtr GetProcAddress(IntPtr module, string name);
    [DllImport("kernel32.dll", ExactSpelling = true)]
    public static extern bool FreeLibrary(IntPtr module);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int VersionQuery(uint major, out byte available, out uint minor);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    public delegate int SupportQuery(out ulong flags);
}
'@

$registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::LocalMachine,
    [Microsoft.Win32.RegistryView]::Registry64)
$osKey = $registry.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion')
$productKey = $registry.OpenSubKey('SYSTEM\CurrentControlSet\Control\ProductOptions')
try {
    [uint32]$installedBuild = $osKey.GetValue('CurrentBuildNumber')
    [uint32]$revision = $osKey.GetValue('UBR')
    $workstation = $productKey.GetValue('ProductType') -eq 'WinNT'
} finally {
    if ($null -ne $osKey) { $osKey.Dispose() }
    if ($null -ne $productKey) { $productKey.Dispose() }
    $registry.Dispose()
}

# Resolve the module from System32 only, including when the script's directory
# contains a DLL with the same filename.
$nativeModule = [AgentkeeperPsecHost]::LoadLibraryExW('processmodel.dll', [IntPtr]::Zero, 0x800)
[byte]$available = 0
[uint32]$minor = 0
[uint64]$supportFlags = 0
$versionSucceeded = $false
$supportSucceeded = $false
$complete = $false
try {
    if ($nativeModule -ne [IntPtr]::Zero) {
        $addresses = @{}
        foreach ($name in @('CreateProcessSecurityEnvironment', 'CloseProcessSecurityEnvironment',
                'IsProcessSecurityEnvironmentVersionSupported', 'QueryProcessSecurityEnvironmentSupport')) {
            $addresses[$name] = [AgentkeeperPsecHost]::GetProcAddress($nativeModule, $name)
        }
        $complete = @($addresses.Values | Where-Object { $_ -eq [IntPtr]::Zero }).Count -eq 0
        $versionAddress = $addresses['IsProcessSecurityEnvironmentVersionSupported']
        if ($versionAddress -ne [IntPtr]::Zero) {
            $query = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
                $versionAddress, [AgentkeeperPsecHost+VersionQuery])
            $versionSucceeded = $query.Invoke(1, [ref]$available, [ref]$minor) -ge 0
        }
        $supportAddress = $addresses['QueryProcessSecurityEnvironmentSupport']
        if ($supportAddress -ne [IntPtr]::Zero) {
            $query = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
                $supportAddress, [AgentkeeperPsecHost+SupportQuery])
            $supportSucceeded = $query.Invoke([ref]$supportFlags) -ge 0
        }
    }
} finally {
    if ($nativeModule -ne [IntPtr]::Zero) { [void][AgentkeeperPsecHost]::FreeLibrary($nativeModule) }
}

[ordered]@{
    kind = 'agentkeeper.psec-host.v1'
    os = [ordered]@{ build = $installedBuild; revision = $revision; workstation = $workstation }
    psec = [ordered]@{
        exportsAvailable = $complete
        versionQuerySucceeded = $versionSucceeded
        supportQuerySucceeded = $supportSucceeded
        available = $available -ne 0
        major = 1
        minor = $minor
        supportFlags = '0x{0:x}' -f $supportFlags
    }
} | ConvertTo-Json -Depth 4 -Compress
