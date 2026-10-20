using System;
using System.Diagnostics;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;
using Sora.Core.V1;
using Sora.Legacy.Control;

namespace Sora.Legacy.Client;

// Entry point implementing the installer contract of Sora.iss, in the
// semantics the shipped v2rayN client defines today (its Program.cs):
//   --silent           start without a window (the autorun shortcut);
//   --restore-proxy    replay the recorded pre-Sora system proxy and
//                      exit; 0 = restored or nothing recorded, 1 = the
//                      record could not be applied. Without --silent
//                      the change needs the user's explicit confirmation
//                      (LEGACY-L11) — the uninstaller passes --silent;
//   --wait-for <pid>   wait (bounded) for a previous process to exit;
//   sora://…           import the subscription the link carries.
// One instance per executable path: a second launch hands any link to
// the running instance, activates its window and exits.
internal static class Program
{
    // Kept referenced for the process lifetime: the named mutex exists
    // while a handle to it is open.
    private static Mutex? singleInstance;

    [DllImport("user32.dll")]
    private static extern bool SetProcessDPIAware();

    [DllImport("user32.dll")]
    private static extern bool IsWindow(IntPtr hwnd);

    [DllImport("user32.dll")]
    private static extern int ShowWindow(IntPtr hwnd, int command);

    [DllImport("user32.dll")]
    private static extern void SwitchToThisWindow(IntPtr hwnd, bool altTab);

    [STAThread]
    private static int Main(string[] args)
    {
        var silent = HasArg(args, ClientContract.SilentArgument);
        var settings = new ClientSettings();
        using var text = LoadText(settings);
        if (HasArg(args, ClientContract.RestoreProxyArgument)) return RestoreProxy(silent, text);
        WaitForPreviousInstance(args);
        EnableDpiAwareness();
        InstallExceptionHandlers();
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        AutoRun.Reconcile(settings);
        var link = ImportLink.FindArgument(args);
        if (!TryEnterSingleInstance())
        {
            if (link != null) ImportLink.Forward(link);
            if (!TryActivateRunningInstance() && link == null && text != null)
                MessageBox.Show(text["alreadyRunning"], "Sora", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 0;
        }

        using var form = new MainForm();
        using var context = new ClientContext(form, text, startHidden: silent && link == null, initialLink: link);
        Application.Run(context);
        return 0;
    }

    private static bool HasArg(string[] args, string name)
    {
        foreach (var arg in args)
            if (string.Equals(arg, name, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static Strings? LoadText(ClientSettings settings)
    {
        // A damaged or unknown saved language must not take down the
        // headless contract paths; fall back to English, then to no
        // dialogs at all (the exit code still speaks).
        try { return new Strings(settings.Language); }
        catch { try { return new Strings("en"); } catch { return null; } }
    }

    private static int RestoreProxy(bool silent, Strings? text)
    {
        if (!silent)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            // Without a text resource there is no honest way to ask, and
            // an unconfirmed silent change is exactly what LEGACY-L11
            // forbids — refuse rather than guess.
            if (text == null) return 1;
            var answer = MessageBox.Show(text["restoreProxyConfirm"], "Sora",
                MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2);
            if (answer != DialogResult.Yes) return 0;
        }
        return SystemProxy.Restore() ? 0 : 1;
    }

    private static void WaitForPreviousInstance(string[] args)
    {
        var marker = Array.FindIndex(args, arg => string.Equals(arg, ClientContract.WaitForArgument, StringComparison.OrdinalIgnoreCase));
        if (marker < 0 || marker + 1 >= args.Length || !int.TryParse(args[marker + 1], out var processId)) return;
        try { Process.GetProcessById(processId).WaitForExit(15000); }
        catch { /* Already gone or not ours to wait for: start anyway. */ }
    }

    private static void InstallExceptionHandlers()
    {
        // As in the shipped client (v2rayN Program.cs): an unhandled
        // exception must never surface as the raw .NET dialog with its
        // stack trace. UI-thread exceptions are caught and recorded —
        // the exception type name only, the convention of every other
        // handler in this client — and the application keeps running;
        // anything that still escapes is recorded by the AppDomain
        // handler on its way out. Nothing is shown to the user here:
        // there is no honest localized text for "the program broke",
        // so the log is the record and the exit stays quiet.
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, e) =>
            Trace.WriteLine("Legacy client thread exception: " + e.Exception.GetType().Name);
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            Trace.WriteLine("Legacy client unhandled exception: " + (e.ExceptionObject?.GetType().Name ?? "unknown"));
    }

    private static void EnableDpiAwareness()
    {
        // Capability check, as in the shipped client: SetProcessDPIAware
        // exists from Vista (6.0) on; on anything older the process
        // simply stays DPI-unaware instead of failing to start.
        if (Environment.OSVersion.Version.Major < 6) return;
        try { SetProcessDPIAware(); }
        catch (DllNotFoundException) { }
        catch (EntryPointNotFoundException) { }
    }

    private static string MutexName => Application.ExecutablePath.Replace("\\", "/");

    private static string WindowHwndName => "WindowHwnd_" + AutoRun.DirectoryHash;

    private static bool TryEnterSingleInstance()
    {
        singleInstance = new Mutex(false, MutexName, out var createdNew);
        if (!createdNew && !IsOwnExecutableRunning())
        {
            // LEGACY-L11: the name is taken but no live process of this
            // executable exists — the mutex was squatted or left behind.
            // Drop the foreign handle and try to create it once more.
            try { singleInstance.Close(); } catch { }
            singleInstance = new Mutex(false, MutexName, out createdNew);
        }
        return createdNew;
    }

    private static bool IsOwnExecutableRunning()
    {
        var exePath = Application.ExecutablePath;
        var currentId = Process.GetCurrentProcess().Id;
        Process[] processes;
        try { processes = Process.GetProcessesByName(System.IO.Path.GetFileNameWithoutExtension(exePath)); }
        catch { return true; } // Cannot verify: assume an instance exists (fail-closed).
        foreach (var process in processes)
        {
            using (process)
            {
                try
                {
                    if (process.Id != currentId &&
                        string.Equals(process.MainModule?.FileName, exePath, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
                catch { /* No access to that process, or it just exited. */ }
            }
        }
        return false;
    }

    private static bool TryActivateRunningInstance()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(ClientContract.RegistryPath, writable: false);
            if (key?.GetValue(WindowHwndName) is not string raw) return false;
            if (!long.TryParse(raw, out var value) || value <= 0) return false;
            var hwnd = new IntPtr(value);
            if (!IsWindow(hwnd)) return false;
            ShowWindow(hwnd, 4); // SW_SHOWNOACTIVATE, as the shipped client passes.
            SwitchToThisWindow(hwnd, true);
            return true;
        }
        catch { return false; }
    }

    // Owns the main form for the process: hidden (tray) starts, showing
    // on demand, forwarding of links handed over by later launches, and
    // exit when the form is closed for real.
    private sealed class ClientContext : ApplicationContext
    {
        private readonly MainForm form;
        private readonly Strings? text;
        private readonly NotifyIcon? tray;
        private readonly System.Windows.Forms.Timer pendingLinks = new() { Interval = 1000 };

        public ClientContext(MainForm form, Strings? text, bool startHidden, string? initialLink)
        {
            this.form = form;
            this.text = text;
            form.FormClosed += (_, _) => ExitThread();
            form.Shown += (_, _) => PublishWindowHandle();
            PublishWindowHandle();
            if (startHidden)
            {
                tray = CreateTray();
            }
            else
            {
                form.Show();
            }
            if (initialLink != null)
            {
                // Queued to the message loop: runs once it is up, on the
                // UI thread, exactly once — whether Shown already fired
                // during the constructor's Show() or fires inside Run.
                form.BeginInvoke((Action)(() => _ = ImportAsync(initialLink)));
            }
            pendingLinks.Tick += async (_, _) =>
            {
                var pending = ImportLink.TakePending();
                if (pending != null) await ImportAsync(pending);
            };
            pendingLinks.Start();
        }

        private NotifyIcon CreateTray()
        {
            var menu = new ContextMenuStrip();
            if (text != null)
            {
                menu.Items.Add(text["trayOpen"], null, (_, _) => ShowMainWindow());
                menu.Items.Add(text["trayQuit"], null, (_, _) => form.Close());
            }
            else
            {
                menu.Items.Add("Sora", null, (_, _) => ShowMainWindow());
            }
            var icon = new NotifyIcon
            {
                Icon = LoadTrayIcon(),
                Text = "Sora Legacy",
                ContextMenuStrip = menu,
                Visible = true
            };
            icon.DoubleClick += (_, _) => ShowMainWindow();
            return icon;
        }

        private static Icon LoadTrayIcon()
        {
            // The exe carries the product icon (ApplicationIcon in the
            // project); extracting it avoids a second asset. Any failure
            // degrades to the system application icon, never to a crash.
            try { return Icon.ExtractAssociatedIcon(Application.ExecutablePath) ?? SystemIcons.Application; }
            catch { return SystemIcons.Application; }
        }

        private void ShowMainWindow()
        {
            form.Show();
            if (form.WindowState == FormWindowState.Minimized) form.WindowState = FormWindowState.Normal;
            form.Activate();
            PublishWindowHandle();
        }

        private void PublishWindowHandle()
        {
            // The activation address of this instance, in the same
            // registry location and format the shipped client uses
            // (Software\Sora, WindowHwnd_<MD5 of the install directory>).
            try
            {
                using var key = Registry.CurrentUser.CreateSubKey(ClientContract.RegistryPath);
                key.SetValue(WindowHwndName, form.Handle.ToInt64().ToString());
            }
            catch (Exception exception)
            {
                Trace.WriteLine("Legacy client window handle publish: " + exception.GetType().Name);
            }
        }

        // Saves the subscription a sora:// link carries, through the
        // same core request the add-subscription dialog sends. Runs on
        // the UI thread; feedback goes through the localized strings —
        // success is silent (the subscription appears in the list via
        // the form's own subscription watch).
        private async Task ImportAsync(string link)
        {
            var parsed = ImportLink.Parse(link);
            if (parsed == null)
            {
                if (text != null)
                    MessageBox.Show(form.Visible ? form : null, text["errSubFormat"], "Sora",
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            try
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
                using var connection = await CoreService.ConnectAsync(timeout.Token);
                var answer = await connection.CallAsync(new SaveSubscriptionRequest
                {
                    ApiVersion = connection.Version,
                    ControlAuthenticator = connection.Authenticator,
                    Settings = new SubscriptionSettings { Url = parsed.Url, Name = parsed.Name, AutoUpdate = true }
                }, SaveSubscriptionResponse.Parser, timeout.Token);
                if (answer.Error != null && text != null)
                    MessageBox.Show(form.Visible ? form : null, text.Error(answer.Error.UserMessageKey), "Sora",
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            catch (Exception exception)
            {
                if (text == null) return;
                MessageBox.Show(form.Visible ? form : null,
                    exception is InvalidOperationException ? text.Error(exception.Message) : text["errCore"],
                    "Sora", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                pendingLinks.Dispose();
                if (tray != null)
                {
                    tray.Visible = false;
                    tray.ContextMenuStrip?.Dispose();
                    tray.Dispose();
                }
            }
            base.Dispose(disposing);
        }
    }
}
