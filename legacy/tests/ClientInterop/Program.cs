using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Google.Protobuf.WellKnownTypes;
using Newtonsoft.Json.Linq;
using Sora.Core.V1;
using Sora.Legacy.Control;
using FormsControl = System.Windows.Forms.Control;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            if (args.Length != 1) throw new ArgumentException("Expected the screenshot directory.");
            if (new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
                throw new Exception("The GUI check must run without administrator rights.");
            Directory.CreateDirectory(args[0]);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.ThrowException);
            var assembly = Assembly.Load("Sora.Legacy");
            var formType = assembly.GetType("Sora.Legacy.Client.MainForm", true)!;
            for (var cycle = 0; cycle < 3; cycle++)
            {
                using var form = (Form)Activator.CreateInstance(formType, true)!;
                form.ClientSize = new Size(920, 650);
                var fields = formType.GetFields(BindingFlags.Instance | BindingFlags.NonPublic)
                    .ToDictionary(field => field.Name, field => field.GetValue(form));
                var orb = (AntdUI.Button)fields["orb"]!;
                var error = (Label)fields["error"]!;
                var state = (Label)fields["state"]!;
                Exception? failure = null;
                form.Shown += async (_, _) =>
                {
                    try
                    {
                        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                        while (!orb.Enabled) await Task.Delay(50, timeout.Token);
                        if (error.Text.Length != 0) throw new Exception("GUI startup: " + error.Text);
                        var controls = Descendants(form).ToArray();
                        if (controls.Count(control => control.Visible && (string?)control.Tag == "addSubscription") != 1)
                            throw new Exception("An empty subscription list must show exactly one add button.");
                        var language = controls.OfType<AntdUI.Select>().Single();
                        if (language.Items.Count != 31) throw new Exception("Missing language choices.");
                        foreach (var item in language.Items.Cast<AntdUI.SelectItem>())
                        {
                            var code = (string)item.Tag;
                            language.SelectedValue = code;
                            using var stream = assembly.GetManifestResourceStream("Sora.Legacy.Client.Assets.l10n.app_" + code + ".arb")
                                ?? throw new Exception("Missing language resource: " + code);
                            using var reader = new StreamReader(stream);
                            var expected = (string)JObject.Parse(reader.ReadToEnd())["stateOff"]!;
                            if (state.Text != expected) throw new Exception("Language was not applied: " + code);
                            if (language.Prefix == null) throw new Exception("The selected language has no flag: " + code);
                            if (cycle == 0 && code is "ru" or "zh_Hant")
                            {
                                form.Refresh();
                                using var screenshot = new Bitmap(form.Width, form.Height);
                                form.DrawToBitmap(screenshot, new Rectangle(Point.Empty, form.Size));
                                screenshot.Save(Path.Combine(args[0], "legacy-" + code + ".png"), ImageFormat.Png);
                            }
                        }
                        language.SelectedValue = "ru";
                        await CheckConnectionIntent(form, formType);
                        await CheckJournal(form, fields, args[0], cycle);
                        Console.WriteLine("PASS GUI cycle " + cycle + ": service, one add button, 31 real language resources");
                    }
                    catch (Exception exception) { failure = exception; }
                    finally { form.Close(); }
                };
                Application.Run(form);
                if (failure != null) throw failure;
                if (!form.IsDisposed || Application.OpenForms.Count != 0)
                    throw new Exception("The GUI retained a window after closing.");
            }
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            using var connected = CoreService.ConnectAsync(deadline.Token).GetAwaiter().GetResult();
            var status = connected.CallAsync(new GetStatusRequest { ApiVersion = connected.Version },
                GetStatusResponse.Parser, deadline.Token).GetAwaiter().GetResult();
            if (status.Error != null || status.Status.Connection.Value != ConnectionStateValue.Disconnected)
                throw new Exception("Opening and closing the GUI changed the disconnected session.");
            Console.WriteLine("PASS ordinary-user GUI: three native opens/closes, service remains reachable and disconnected");
            return 0;
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception);
            return 1;
        }
    }

    private static IEnumerable<FormsControl> Descendants(FormsControl parent)
    {
        foreach (FormsControl child in parent.Controls)
        {
            yield return child;
            foreach (var nested in Descendants(child)) yield return nested;
        }
    }

    private static async Task CheckConnectionIntent(Form form, System.Type type)
    {
        var flags = BindingFlags.Instance | BindingFlags.NonPublic;
        var desired = type.GetField("desiredConnected", flags)!;
        var pending = type.GetField("connectionPending", flags)!;
        var read = type.GetMethod("ReadStatus", flags)!;
        desired.SetValue(form, true);
        pending.SetValue(form, false);
        await (Task)read.Invoke(form, null)!;
        if ((bool)desired.GetValue(form)!) throw new Exception("The disconnected service left a stale disconnect intent in the connection button.");
        desired.SetValue(form, true);
        pending.SetValue(form, true);
        try
        {
            await (Task)read.Invoke(form, null)!;
            if (!(bool)desired.GetValue(form)!) throw new Exception("Status polling cancelled a pending connection intent.");
        }
        finally { pending.SetValue(form, false); }
        await (Task)read.Invoke(form, null)!;
        Console.WriteLine("PASS connection intent: the real service clears stale disconnected intent and preserves a pending connection");
    }

    private static async Task CheckJournal(Form form, Dictionary<string, object> fields, string screenshots, int cycle)
    {
        var page = (FormsControl)fields["logsPage"]!;
        var type = page.GetType();
        var flags = BindingFlags.Instance | BindingFlags.NonPublic;
        var home = (AntdUI.Button)fields["homeNavigation"]!;
        var logs = (AntdUI.Button)fields["logsNavigation"]!;
        var categories = (Dictionary<string, AntdUI.Button>)type.GetField("categories", flags)!.GetValue(page)!;
        for (var i = 0; i < 12; i++)
        {
            logs.PerformClick();
            categories[i % 2 == 0 ? "core" : "all"].PerformClick();
            home.PerformClick();
        }
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        while (type.GetField("reading", flags)!.GetValue(page) != null || type.GetField("watch", flags)!.GetValue(page) != null)
            await Task.Delay(25, deadline.Token);
        logs.PerformClick();
        categories["all"].PerformClick();
        while (type.GetField("watch", flags)!.GetValue(page) == null || (bool)type.GetField("loading", flags)!.GetValue(page)!)
            await Task.Delay(25, deadline.Token);
        if (!page.Visible || ((Label)type.GetField("message", flags)!.GetValue(page)!).Text == "Не удалось связаться с ядром")
            throw new Exception("The journal did not finish querying the real service after navigation races.");
        await (Task)type.GetMethod("StopAsync")!.Invoke(page, null)!;
        var entries = (SortedList<ulong, LogEntry>)type.GetField("entries", flags)!.GetValue(page)!;
        var list = (ListView)type.GetField("list", flags)!.GetValue(page)!;
        var arrive = type.GetMethod("Arrive", flags)!;
        for (var i = 0; i < 300; i++) arrive.Invoke(page, new object[] { new LogEntry
        { Sequence = (ulong)(1000000 + i), Time = Timestamp.FromDateTime(DateTime.UtcNow), Source = "core", Message = "Viewport test " + i } });
        list.TopItem = list.Items[30];
        var top = list.TopItem!.Index;
        var anchor = entries.Keys[entries.Count - top - 1];
        var position = list.GetItemRect(top).Y;
        for (var i = 300; i < 450; i++) arrive.Invoke(page, new object[] { new LogEntry
        { Sequence = (ulong)(1000000 + i), Time = Timestamp.FromDateTime(DateTime.UtcNow), Source = "core", Message = "Viewport test " + i } });
        top = list.TopItem!.Index;
        if (entries.Keys[entries.Count - top - 1] != anchor || list.GetItemRect(top).Y != position)
            throw new Exception("New journal entries moved the row being read.");
        list.TopItem = list.Items[0];
        arrive.Invoke(page, new object[] { new LogEntry
        { Sequence = 1000450, Time = Timestamp.FromDateTime(DateTime.UtcNow), Source = "core", Message = "Viewport test latest" } });
        if (list.TopItem!.Index != 0) throw new Exception("The journal stopped following at the top.");
        if (cycle == 0)
        {
            form.Refresh();
            using var screenshot = new Bitmap(form.Width, form.Height);
            form.DrawToBitmap(screenshot, new Rectangle(Point.Empty, form.Size));
            screenshot.Save(Path.Combine(screenshots, "legacy-logs-viewport-test.png"), ImageFormat.Png);
        }
        home.PerformClick();
        Console.WriteLine("PASS journal: real RPC query/watch after 12 navigation races; 150 incoming fixture rows preserve the viewport; top follows latest");
    }
}
