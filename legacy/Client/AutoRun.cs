using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using Microsoft.Win32;

namespace Sora.Legacy.Client;

// The "launch at sign-in" registration shared by the installer, the
// uninstaller and both clients. The value name and command line are the
// ones v2rayN Tool/Utils.cs writes (SetAutoRun/IsAutoRun): the installer
// cannot name the value in a [Registry] entry because the name hashes the
// install directory, so Sora.iss scans the Run key at uninstall and
// removes values whose command line points at the shipped executable.
// This class must keep producing exactly that name and command line, or
// the value becomes an orphan the uninstaller no longer recognises and
// the in-app option stops reading back (the c955461 bug).
internal static class AutoRun
{
    private const string RunPath = @"Software\Microsoft\Windows\CurrentVersion\Run";

    // MD5 of the install directory, hex lowercase — Utils.GetMD5(StartupPath()).
    internal static string DirectoryHash
    {
        get
        {
            using var md5 = MD5.Create();
            var bytes = md5.ComputeHash(Encoding.UTF8.GetBytes(Application.StartupPath));
            var builder = new StringBuilder(bytes.Length * 2);
            foreach (var value in bytes) builder.Append(value.ToString("x2"));
            return builder.ToString();
        }
    }

    public static string ValueName => "SoraAutoRun_" + DirectoryHash;

    // The command line every writer registers: the exe, quoted, hidden start.
    public static string Command => "\"" + Application.ExecutablePath + "\" --silent";

    public static string? ReadCommand()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunPath, writable: false);
            return key?.GetValue(ValueName) as string;
        }
        catch (Exception exception)
        {
            Trace.WriteLine("Legacy client autostart read: " + exception.GetType().Name);
            return null;
        }
    }

    // Accepts exactly the forms SetEnabled and the earlier client write
    // (bare path, quoted path, quoted path with --silent) — the read-back
    // set fixed by c955461.
    public static bool IsEnabled()
    {
        var value = ReadCommand();
        var exe = Application.ExecutablePath;
        return value == exe || value == "\"" + exe + "\"" || value == Command;
    }

    public static void SetEnabled(bool enabled)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(RunPath);
            if (enabled) key.SetValue(ValueName, Command);
            // An empty write deletes the value in the shared semantics
            // (Utils.RegWriteValue), so disabling leaves no stub behind.
            else key.DeleteValue(ValueName, throwOnMissingValue: false);
        }
        catch (Exception exception)
        {
            // Group policy can lock the Run key. The option then simply
            // does not take effect; the next read-back shows the truth.
            Trace.WriteLine("Legacy client autostart write: " + exception.GetType().Name);
        }
    }

    // Startup reconciliation. The registry is written by whichever client
    // the install shipped, under this directory's hash; when the stage
    // switches to this client the value still names the old executable.
    // Adopt an existing value into the setting and repoint it at this
    // executable; when the setting is on but the value is gone (cleaned
    // by hand or by the uninstaller of a previous install), write it back.
    public static void Reconcile(ClientSettings settings)
    {
        var current = ReadCommand();
        if (current != null)
        {
            if (!settings.AutoRun)
            {
                settings.AutoRun = true;
                settings.Save();
            }
            if (current != Command) SetEnabled(true);
        }
        else if (settings.AutoRun)
        {
            SetEnabled(true);
        }
    }
}
