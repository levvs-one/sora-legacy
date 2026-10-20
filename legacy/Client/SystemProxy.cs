using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Microsoft.Win32;
using Newtonsoft.Json.Linq;

namespace Sora.Legacy.Client;

// Restores the per-user system proxy for the installer's --restore-proxy
// contract ([UninstallRun] in Sora.iss). The semantics are the shipped
// client's (v2rayN SysProxyHandle.ResetIEProxy): before Sora changes the
// system proxy it records the user's own settings in user-wininet.json
// next to the executable; restoring replays that record and deletes it.
// No record means Sora never changed the proxy, so there is nothing to
// restore and the call succeeds. A damaged record is a failure (exit
// code 1 for the uninstaller), never a silent guess.
//
// The replay is native instead of shelling out to the sysproxy.exe the
// old client bundles: the recorded flags are the WinINet per-connection
// flags, mapped onto the HKCU Internet Settings values, and the named
// values (proxy on/off, server, bypass list, PAC URL) are restored
// exactly — including for the numeric flag form the recorder actually
// writes ("5" = DIRECT|AUTO_PROXY_URL restores the PAC URL).
// Two honest degradations:
//  - the PROXY_TYPE_AUTO_DETECT bit is not restored: it lives only in
//    the binary DefaultConnectionSettings blob, which this restore
//    deliberately does not rewrite;
//  - the replay covers only the default (LAN) connection values under
//    HKCU Internet Settings. sysproxy.exe also applies settings to RAS
//    connections; per-connection RAS entries are not replayed here.
internal static class SystemProxy
{
    private const string InternetSettingsPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const string BackupFileName = "user-wininet.json";

    // WinINet per-connection flags (INTERNET_PER_CONN_FLAGS). The
    // values are the ones the reference client declares in
    // v2rayN/Handler/ProxySetting.cs (PerConnFlags); that enum is the
    // source of truth — do not re-derive the bits here.
    private const int FlagDirect = 1;
    private const int FlagProxy = 2;
    private const int FlagAutoProxyUrl = 4;
    private const int FlagAutoDetect = 8;

    private const int InternetOptionSettingsChanged = 39;
    private const int InternetOptionRefresh = 37;

    [DllImport("wininet.dll", SetLastError = true)]
    private static extern bool InternetSetOption(IntPtr internet, int option, IntPtr buffer, int bufferLength);

    public static bool Restore()
    {
        try
        {
            var backupPath = Path.Combine(Application.StartupPath, BackupFileName);
            if (!File.Exists(backupPath)) return true;
            var backup = JObject.Parse(File.ReadAllText(backupPath));
            if ((bool?)backup["UserSettingsRecorded"] != true) return true;
            var flags = ParseFlags((string?)backup["Flags"]);
            if (flags == null) return false;
            var proxyServer = Normalize((string?)backup["ProxyServer"]);
            var bypassList = Normalize((string?)backup["BypassList"]);
            var pacUrl = Normalize((string?)backup["PacUrl"]);

            using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsPath, writable: true)
                ?? Registry.CurrentUser.CreateSubKey(InternetSettingsPath);
            if (key == null) return false;
            key.SetValue("ProxyEnable", (flags.Value & FlagProxy) != 0 ? 1 : 0, RegistryValueKind.DWord);
            key.SetValue("ProxyServer", proxyServer, RegistryValueKind.String);
            key.SetValue("ProxyOverride", bypassList, RegistryValueKind.String);
            if ((flags.Value & FlagAutoProxyUrl) != 0 && pacUrl.Length > 0)
                key.SetValue("AutoConfigURL", pacUrl, RegistryValueKind.String);
            else
                key.DeleteValue("AutoConfigURL", throwOnMissingValue: false);
            NotifySettingsChanged();
            File.Delete(backupPath);
            return true;
        }
        catch (Exception exception)
        {
            System.Diagnostics.Trace.WriteLine("Legacy client proxy restore: " + exception.GetType().Name);
            return false;
        }
    }

    // The recorder stores the numeric bitmask ("1" for direct). Accept
    // the PROXY_TYPE_* token form too, so a record written by another
    // build of the shipped client still restores instead of failing.
    // Internal, not private, so the ClientInterop pin tests can hold
    // the numeric vectors (and the flag values above) to the standard.
    internal static int? ParseFlags(string? raw)
    {
        if (raw == null) return FlagDirect;
        raw = raw.Trim();
        if (raw.Length == 0) return FlagDirect;
        if (int.TryParse(raw, out var numeric)) return numeric;
        var flags = 0;
        var any = false;
        foreach (var token in raw.Split('|'))
        {
            var value = token.Trim() switch
            {
                "PROXY_TYPE_DIRECT" => FlagDirect,
                "PROXY_TYPE_PROXY" => FlagProxy,
                "PROXY_TYPE_AUTO_DETECT" => FlagAutoDetect,
                "PROXY_TYPE_AUTO_PROXY_URL" => FlagAutoProxyUrl,
                _ => 0
            };
            if (value == 0) return null;
            flags |= value;
            any = true;
        }
        return any ? flags : null;
    }

    // The recorder writes "(null)" for empty query results.
    private static string Normalize(string? value) =>
        string.Equals(value?.Trim(), "(null)", StringComparison.OrdinalIgnoreCase) ? "" : value ?? "";

    private static void NotifySettingsChanged()
    {
        // Best effort: the registry values are already written; a failed
        // notification only means running programs notice on restart.
        // wininet.dll ships with every supported Windows (Win7+).
        try
        {
            InternetSetOption(IntPtr.Zero, InternetOptionSettingsChanged, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, InternetOptionRefresh, IntPtr.Zero, 0);
        }
        catch (DllNotFoundException) { }
        catch (EntryPointNotFoundException) { }
    }

}
