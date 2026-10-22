using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Sora.Ancient
{
    // Per-user system proxy (HKCU Internet Settings) with the project's
    // snapshot/restore contract, reduced to what net40 offers: before the
    // first change, the user's own values are recorded to a snapshot
    // file; restore replays them exactly and deletes the snapshot. No
    // snapshot means Sora never touched the proxy — restore is a no-op.
    // A damaged snapshot is an error, never a silent guess. WinINet is
    // notified (options 37/39, the same pair the shipped client uses).
    internal static class SystemProxy
    {
        private const string KeyPath = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        private const int InternetOptionRefresh = 37;
        private const int InternetOptionSettingsChanged = 39;

        [DllImport("wininet.dll", SetLastError = true)]
        private static extern bool InternetSetOption(IntPtr internet, int option, IntPtr buffer, int bufferLength);

        private static void Notify()
        {
            InternetSetOption(IntPtr.Zero, InternetOptionSettingsChanged, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, InternetOptionRefresh, IntPtr.Zero, 0);
        }

        public static void Enable(string snapshotPath, int socksPort)
        {
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(KeyPath, true))
            {
                if (key == null) throw new InvalidOperationException("Internet Settings registry key is unavailable.");
                if (!File.Exists(snapshotPath)) SaveSnapshot(snapshotPath, key);
                key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
                key.SetValue("ProxyServer", "socks=127.0.0.1:" + socksPort, RegistryValueKind.String);
                key.SetValue("ProxyOverride", "<local>", RegistryValueKind.String);
            }
            Notify();
        }

        public static void Restore(string snapshotPath)
        {
            if (!File.Exists(snapshotPath)) return;
            var map = JsonMini.Parse(File.ReadAllText(snapshotPath)) as Dictionary<string, object>;
            if (map == null) throw new InvalidOperationException("Proxy snapshot is damaged; system proxy was left unchanged.");
            using (RegistryKey key = Registry.CurrentUser.OpenSubKey(KeyPath, true))
            {
                if (key == null) throw new InvalidOperationException("Internet Settings registry key is unavailable.");
                RestoreValue(key, map, "ProxyEnable", true);
                RestoreValue(key, map, "ProxyServer", false);
                RestoreValue(key, map, "ProxyOverride", false);
                RestoreValue(key, map, "AutoConfigURL", false);
            }
            Notify();
            File.Delete(snapshotPath);
        }

        private static void SaveSnapshot(string snapshotPath, RegistryKey key)
        {
            string dir = Path.GetDirectoryName(snapshotPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var parts = new List<string>();
            parts.Add(SnapshotField(key, "ProxyEnable", true));
            parts.Add(SnapshotField(key, "ProxyServer", false));
            parts.Add(SnapshotField(key, "ProxyOverride", false));
            parts.Add(SnapshotField(key, "AutoConfigURL", false));
            File.WriteAllText(snapshotPath, "{" + string.Join(",", parts.ToArray()) + "}");
        }

        private static string SnapshotField(RegistryKey key, string name, bool numeric)
        {
            object v = key.GetValue(name, null);
            if (v == null) return JsonMini.Quote(name) + ":null";
            if (numeric) return JsonMini.Quote(name) + ":" + Convert.ToInt32(v).ToString();
            return JsonMini.Quote(name) + ":" + JsonMini.Quote(Convert.ToString(v));
        }

        private static void RestoreValue(RegistryKey key, Dictionary<string, object> map, string name, bool numeric)
        {
            object v;
            if (!map.TryGetValue(name, out v) || v == null)
            {
                key.DeleteValue(name, false);
                return;
            }
            if (numeric) key.SetValue(name, (int)(double)v, RegistryValueKind.DWord);
            else key.SetValue(name, (string)v, RegistryValueKind.String);
        }
    }
}
