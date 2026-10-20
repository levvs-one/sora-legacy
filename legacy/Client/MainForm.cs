using System;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Google.Protobuf;
using Newtonsoft.Json.Linq;
using Sora.Core.V1;
using Sora.Legacy.Control;
using Button = AntdUI.Button;
using FormsControl = System.Windows.Forms.Control;

namespace Sora.Legacy.Client;

internal sealed class MainForm : Form
{
    private static readonly Color Field = Color.FromArgb(235, 235, 240);
    private static readonly Color Background = Color.FromArgb(246, 246, 248);
    private readonly ClientSettings settings = new();
    private readonly Strings text;
    // The design sizes are pixels at 96 DPI, expressed in points so the
    // Dpi scaling of the form (and the PerMonitorV2 manifest) grows the
    // glyphs themselves at 150-200% instead of stretching a bitmap.
    private readonly Font body = new("Segoe UI", 13f * 72f / 96f, FontStyle.Regular, GraphicsUnit.Point);
    private readonly Font heading = new("Segoe UI", 22f * 72f / 96f, FontStyle.Bold, GraphicsUnit.Point);
    private readonly Font strong = new("Segoe UI", 15f * 72f / 96f, FontStyle.Bold, GraphicsUnit.Point);
    private readonly CancellationTokenSource lifetime = new();
    private readonly Dictionary<string, SubscriptionState> subscriptions = new();
    private readonly HashSet<string> collapsed = new(), hiddenDescriptions = new();
    private readonly Dictionary<string, uint> pings = new();
    private readonly FlowLayoutPanel cards = new() { Dock = DockStyle.Fill, AutoScroll = true, FlowDirection = FlowDirection.TopDown, WrapContents = false };
    private readonly FlowLayoutPanel center = new() { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(24, 36, 24, 24) };
    private readonly Label state = new() { Height = 48, TextAlign = ContentAlignment.MiddleCenter };
    private readonly Label error = new() { AutoSize = true, MaximumSize = new Size(460, 0), Margin = new Padding(0, 20, 0, 0) };
    private readonly AntdUI.Input search = new() { Dock = DockStyle.Top, Height = 44, Radius = 8 };
    private readonly System.Windows.Forms.Timer poll = new() { Interval = 1000 };
    private readonly Button orb, add, addAbove, retry, modes, apply;
    private readonly Button homeNavigation, logsNavigation;
    private readonly Panel mainView = new() { Dock = DockStyle.Fill };
    private readonly LogsPage logsPage;
    private readonly ToolTip navigationHints = new();
    // Tray state is a projection of the same status the form renders
    // (SessionStatus + connectionPending + the core-loss paths below);
    // it is never a second source of truth.
    private enum TrayState { Disconnected, Connecting, Connected, Error }
    private readonly NotifyIcon tray = new();
    private readonly ContextMenuStrip trayMenu = new();
    private readonly ToolStripMenuItem trayOpenItem = new(), trayToggleItem = new(), trayQuitItem = new();
    private readonly Dictionary<TrayState, Icon> trayIcons = new();
    private readonly List<IntPtr> trayIconHandles = new();
    private TrayState? trayState;
    private bool coreLost;
    private CoreConnection? core;
    private SessionRequests? requests;
    private Task? subscriptionWatch;
    private CancellationTokenSource? probing;
    private SessionStatus? status;
    private bool desiredConnected, closing, polling, connectionPending;
    private long revision;

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr handle);

    public MainForm()
    {
        text = new Strings(settings.Language);
        Text = "Sora Legacy";
        Font = body;
        ForeColor = Color.FromArgb(31, 31, 33);
        BackColor = Background;
        MinimumSize = new Size(780, 560);
        ClientSize = new Size(1060, 720);
        AutoScaleMode = AutoScaleMode.Dpi;
        StartPosition = FormStartPosition.CenterScreen;
        var left = new Panel { Dock = DockStyle.Left, Width = 340, Padding = new Padding(16) };
        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = false };
        addAbove = MakeButton("addSubscription", 300);
        addAbove.Click += async (_, _) => await Run(AddSubscription);
        bar.Controls.Add(addAbove);
        left.Controls.Add(cards);
        left.Controls.Add(search);
        left.Controls.Add(bar);
        search.TextChanged += (_, _) => RenderSubscriptions();
        cards.SizeChanged += (_, _) => RenderSubscriptions();

        orb = MakeButton("", 176);
        orb.Height = 176;
        orb.Shape = AntdUI.TShape.Circle;
        orb.Icon = text.Image("logo.png");
        orb.IconSize = new Size(92, 92);
        orb.Enabled = false;
        orb.Click += async (_, _) => await Run(() => ChooseConnection(!desiredConnected));
        add = MakeButton("addSubscription", 280);
        add.Click += async (_, _) => await Run(AddSubscription);
        retry = MakeButton("refresh", 280);
        retry.Click += async (_, _) => await Run(OpenCore);
        modes = MakeButton("modes", 280);
        modes.Click += (_, _) => ChooseModes();
        apply = MakeButton("reconnectNow", 340);
        apply.Visible = false;
        apply.Click += async (_, _) => await Run(() => ChooseConnection(true));
        var language = MakeLanguageSelect();
        center.Controls.AddRange(new FormsControl[] { language, state, orb, modes, apply, add, error, retry });
        center.SizeChanged += (_, _) =>
        {
            var width = center.ClientSize.Width - center.Padding.Horizontal;
            foreach (FormsControl control in center.Controls)
            {
                if (control == state) control.Width = width;
                if (control == apply) control.Width = Math.Min(340, Math.Max(160, width));
                control.Margin = new Padding(Math.Max(0, (width - control.Width) / 2), 8, 0, 8);
            }
        };
        mainView.Controls.Add(center);
        mainView.Controls.Add(left);
        logsPage = new LogsPage(text, body, strong) { Dock = DockStyle.Fill, Visible = false };
        var content = new Panel { Dock = DockStyle.Fill };
        content.Controls.Add(mainView);
        content.Controls.Add(logsPage);
        var navigation = new FlowLayoutPanel { Dock = DockStyle.Left, Width = 64, BackColor = Color.White,
            FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(10, 16, 10, 8) };
        navigation.Controls.Add(new PictureBox { Width = 44, Height = 44, Image = text.Image("logo.png"), SizeMode = PictureBoxSizeMode.Zoom,
            Padding = new Padding(8), Margin = new Padding(0, 0, 0, 20) });
        homeNavigation = MakeButton("home", 44);
        homeNavigation.IconSvg = Strings.Read("Icons.house-bold.svg");
        logsNavigation = MakeButton("logs", 44);
        logsNavigation.IconSvg = Strings.Read("Icons.terminal-window-bold.svg");
        foreach (var button in new[] { homeNavigation, logsNavigation })
        {
            button.IconSize = new Size(22, 22);
            navigation.Controls.Add(button);
        }
        homeNavigation.Click += async (_, _) => await Run(async () =>
        {
            logsPage.Visible = false;
            mainView.Visible = true;
            await logsPage.StopAsync();
            ApplyText();
        });
        logsNavigation.Click += async (_, _) => await Run(async () =>
        {
            mainView.Visible = false;
            logsPage.Visible = true;
            logsPage.BringToFront();
            ApplyText();
            await logsPage.LoadAsync(core);
        });
        Controls.Add(content);
        Controls.Add(navigation);
        // Tab order is designed, not the incidental creation order:
        // navigation first, then the subscription column (add, search,
        // cards), then the connection column top to bottom. Labels and
        // panels are not tab stops; the indexes order their children.
        navigation.TabIndex = 0;
        content.TabIndex = 1;
        homeNavigation.TabIndex = 0;
        logsNavigation.TabIndex = 1;
        mainView.TabIndex = 0;
        logsPage.TabIndex = 1;
        left.TabIndex = 0;
        center.TabIndex = 1;
        bar.TabIndex = 0;
        addAbove.TabIndex = 0;
        search.TabIndex = 1;
        cards.TabIndex = 2;
        language.TabIndex = 0;
        orb.TabIndex = 1;
        modes.TabIndex = 2;
        apply.TabIndex = 3;
        add.TabIndex = 4;
        retry.TabIndex = 5;
        foreach (var kind in Enum.GetValues(typeof(TrayState)).Cast<TrayState>()) trayIcons[kind] = CreateTrayIcon(kind);
        trayOpenItem.Click += (_, _) => ShowFromTray();
        trayToggleItem.Click += async (_, _) => await Run(() => ChooseConnection(!desiredConnected));
        trayQuitItem.Click += (_, _) => Close();
        trayMenu.Items.AddRange(new ToolStripItem[] { trayOpenItem, trayToggleItem, new ToolStripSeparator(), trayQuitItem });
        tray.ContextMenuStrip = trayMenu;
        tray.DoubleClick += (_, _) => ShowFromTray();
        tray.Visible = true;
        Shown += async (_, _) => await Run(OpenCore);
        poll.Tick += async (_, _) =>
        {
            if (core == null || polling) return;
            polling = true;
            try { await ReadStatus(); }
            catch (OperationCanceledException) when (closing) { }
            catch { coreLost = true; error.Text = text["errCore"]; retry.Visible = true; RenderStatus(); }
            finally { polling = false; }
        };
        ApplyText();
    }

    private Button MakeButton(string key, int width) => new()
    {
        Text = key.Length == 0 ? "" : text[key], Tag = key, Width = width, Height = 44,
        Radius = 8, BorderWidth = 0, BackColor = Color.White, BackHover = Field,
        BackActive = Field, ForeColor = ForeColor, ForeHover = ForeColor,
        Font = body, Margin = new Padding(0, 4, 0, 4), WaveSize = 0
    };

    private AntdUI.Select MakeLanguageSelect()
    {
        var select = new AntdUI.Select { Width = 240, Height = 40, Radius = 8, Font = body, BackColor = Color.White,
            ForeColor = ForeColor, BorderColor = Field, BorderHover = ForeColor, BorderActive = ForeColor,
            PrefixWidth = 24, MaxCount = 8 };
        var items = text.Languages.Cast<JObject>().Select(language => new AntdUI.SelectItem(
            text.Image("flags." + language["country"] + ".png"), (string)language["native"]!, (string)language["code"]!)
        { SubText = (string?)language["english"] }).ToArray();
        foreach (var item in items) select.Items.Add(item);
        select.SelectedValue = settings.Language;
        select.Prefix = text.Image("flags." + text.Languages.Single(language => (string?)language["code"] == settings.Language)["country"] + ".png");
        select.FilterChanged += (_, query) => text.Languages.Cast<JObject>()
            .Where(language => string.Join(" ", language.Properties().Select(value => value.Value.ToString()))
                .IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0)
            .Select(language => (object)items.Single(item => (string)item.Tag == (string)language["code"]!)).ToList();
        select.SelectedValueChanged += (_, choice) =>
        {
            if (choice.Value is not string code || !text.Languages.Any(language => (string?)language["code"] == code)) return;
            settings.Language = code;
            settings.Save();
            select.Prefix = text.Image("flags." + text.Languages.Single(language => (string?)language["code"] == code)["country"] + ".png");
            text.SetLanguage(code);
            ApplyText();
        };
        return select;
    }

    private void ApplyText()
    {
        foreach (var button in new[] { add, addAbove, retry, modes, apply }) button.Text = text[(string)button.Tag];
        search.PlaceholderText = text["search"];
        state.Font = heading;
        foreach (var button in new[] { homeNavigation, logsNavigation })
        {
            button.Text = "";
            button.AccessibleName = text[(string)button.Tag];
            navigationHints.SetToolTip(button, button.AccessibleName);
        }
        homeNavigation.BackColor = mainView.Visible ? Field : Color.White;
        logsNavigation.BackColor = logsPage.Visible ? Field : Color.White;
        logsPage.ApplyText();
        RenderStatus();
        RenderSubscriptions();
    }

    private async Task OpenCore()
    {
        if (core != null) return;
        retry.Loading = true;
        var connected = await CoreService.ConnectAsync(lifetime.Token);
        if (closing) { connected.Dispose(); return; }
        ListSubscriptionsResponse listed;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
            timeout.CancelAfter(TimeSpan.FromSeconds(8));
            listed = await connected.CallAsync(new ListSubscriptionsRequest
            { ApiVersion = connected.Version, ControlAuthenticator = connected.Authenticator }, ListSubscriptionsResponse.Parser, timeout.Token);
            Check(listed.Error);
            var initial = await connected.CallAsync(new GetStatusRequest { ApiVersion = connected.Version }, GetStatusResponse.Parser, timeout.Token);
            Check(initial.Error);
            status = initial.Status;
        }
        catch { connected.Dispose(); throw; }
        if (closing) { connected.Dispose(); return; }
        core = connected;
        coreLost = false;
        requests = new SessionRequests(connected);
        subscriptions.Clear();
        foreach (var subscription in listed.Subscriptions) subscriptions[subscription.Settings.Id] = subscription;
        subscriptionWatch = connected.WatchAsync(new WatchSubscriptionsRequest
        { ApiVersion = connected.Version, ControlAuthenticator = connected.Authenticator }, SubscriptionState.Parser,
            new Progress<SubscriptionState>(subscription =>
            {
                if (closing) return;
                if (subscription.Deleted) subscriptions.Remove(subscription.Settings.Id);
                else subscriptions[subscription.Settings.Id] = subscription;
                RenderSubscriptions();
            }), lifetime.Token);
        _ = ObserveSubscriptionWatch(subscriptionWatch, connected);
        desiredConnected = status?.Connection.Value is ConnectionStateValue.Connected or ConnectionStateValue.Connecting or ConnectionStateValue.Reconnecting;
        orb.Enabled = true;
        retry.Loading = false;
        retry.Visible = false;
        error.Text = "";
        poll.Start();
        ApplyText();
        if (logsPage.Visible) await logsPage.LoadAsync(connected);
    }

    private async Task ObserveSubscriptionWatch(Task watch, CoreConnection connected)
    {
        try { await watch; }
        catch (Exception) when (closing) { return; }
        catch (Exception) { if (!ReferenceEquals(core, connected)) return; }
        if (closing || !ReferenceEquals(core, connected)) return;
        var worker = requests;
        core = null;
        requests = null;
        poll.Stop();
        orb.Enabled = false;
        coreLost = true;
        error.Text = text["errCore"];
        retry.Visible = true;
        RenderStatus();
        await logsPage.LoadAsync(null);
        if (worker != null) await worker.StopAsync();
        connected.Dispose();
    }

    private async Task ReadStatus()
    {
        var connected = core ?? throw new InvalidOperationException("core.error.unavailable");
        var current = revision;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        var answer = await connected.CallAsync(new GetStatusRequest { ApiVersion = connected.Version }, GetStatusResponse.Parser, timeout.Token);
        if (closing || current != revision || !ReferenceEquals(core, connected)) return;
        Check(answer.Error);
        coreLost = false;
        status = answer.Status;
        if (!connectionPending)
        {
            desiredConnected = status?.Connection.Value is ConnectionStateValue.Connected or ConnectionStateValue.Connecting or ConnectionStateValue.Reconnecting;
            if (!desiredConnected) apply.Visible = false;
        }
        RenderStatus();
    }

    private string StateKey() => connectionPending
        ? desiredConnected ? "stateConnecting" : "stateDisconnecting"
        : status?.Connection.Value switch
        {
            ConnectionStateValue.Connected => "stateConnected",
            ConnectionStateValue.Connecting => "stateConnecting",
            ConnectionStateValue.Reconnecting => "stateReconnecting",
            ConnectionStateValue.Failed => "stateFailed",
            _ => "stateOff"
        };

    private void RenderStatus()
    {
        state.Text = text[StateKey()];
        UpdateTray();
    }

    private TrayState CurrentTrayState() => coreLost ? TrayState.Error
        : connectionPending ? TrayState.Connecting
        : status?.Connection.Value switch
        {
            ConnectionStateValue.Connected => TrayState.Connected,
            ConnectionStateValue.Connecting or ConnectionStateValue.Reconnecting => TrayState.Connecting,
            ConnectionStateValue.Failed => TrayState.Error,
            _ => TrayState.Disconnected
        };

    private void UpdateTray()
    {
        if (trayIcons.Count == 0) return;
        var next = CurrentTrayState();
        var label = text[StateKey()];
        tray.Icon = trayIcons[next];
        var tip = text["trayTooltip"].Replace("{state}", label);
        // The pre-XP tooltip field holds 63 characters; longer texts
        // are cut by the shell itself on newer versions, so cut here
        // where the cut is at least deterministic.
        tray.Text = tip.Length > 63 ? tip.Substring(0, 63) : tip;
        var used = new HashSet<char>();
        trayOpenItem.Text = Mnemonic.Mark(text["trayOpen"], used, 'O', 'О');
        trayToggleItem.Text = Mnemonic.Mark(text[desiredConnected ? "trayDisconnect" : "trayConnect"], used, 'C', 'П', 'О');
        trayQuitItem.Text = Mnemonic.Mark(text["trayQuit"], used, 'Q', 'В');
        trayToggleItem.Enabled = core != null && !connectionPending;
        // Balloons only on the transitions a user in tray mode cannot
        // see on the form: connected, failed, or dropped after being
        // connected. NotifyIcon balloons exist since Windows 2000 and
        // are the honest ceiling on the old versions — where the user
        // or policy disabled them, the shell drops them silently.
        if (trayState is TrayState previous && previous != next &&
            (next == TrayState.Connected || next == TrayState.Error ||
             (next == TrayState.Disconnected && previous == TrayState.Connected)))
        {
            try
            {
                tray.ShowBalloonTip(3000, "Sora", label, next == TrayState.Error ? ToolTipIcon.Error
                    : next == TrayState.Connected ? ToolTipIcon.Info : ToolTipIcon.Warning);
            }
            catch { /* A hidden icon or a shell refusal must not break status rendering. */ }
        }
        trayState = next;
    }

    // The four states differ in shape as well as colour, so the icon
    // stays readable for colour-blind users and in grayscale themes:
    // a check, three dots, a hollow ring with a dash, an exclamation.
    private Icon CreateTrayIcon(TrayState kind)
    {
        var size = Math.Max(16, SystemInformation.SmallIconSize.Width);
        using var bitmap = new Bitmap(size, size);
        using (var graphics = Graphics.FromImage(bitmap))
        {
            graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            float Unit(float value) => value * size;
            if (kind == TrayState.Disconnected)
            {
                using var pen = new Pen(Color.FromArgb(140, 140, 148), Math.Max(1.5f, Unit(0.09f)));
                graphics.DrawEllipse(pen, Unit(0.10f), Unit(0.10f), Unit(0.80f), Unit(0.80f));
                graphics.DrawLine(pen, Unit(0.30f), Unit(0.50f), Unit(0.70f), Unit(0.50f));
            }
            else
            {
                var fill = kind == TrayState.Connected ? Color.FromArgb(38, 150, 70)
                    : kind == TrayState.Error ? Color.FromArgb(198, 48, 42)
                    : Color.FromArgb(222, 152, 0);
                using var brush = new SolidBrush(fill);
                graphics.FillEllipse(brush, Unit(0.04f), Unit(0.04f), Unit(0.92f), Unit(0.92f));
                using var glyph = new Pen(Color.White, Math.Max(1.5f, Unit(0.11f))) { StartCap = System.Drawing.Drawing2D.LineCap.Round, EndCap = System.Drawing.Drawing2D.LineCap.Round };
                if (kind == TrayState.Connected)
                    graphics.DrawLines(glyph, new[]
                    { new PointF(Unit(0.28f), Unit(0.52f)), new PointF(Unit(0.44f), Unit(0.68f)), new PointF(Unit(0.74f), Unit(0.34f)) });
                else if (kind == TrayState.Error)
                {
                    graphics.DrawLine(glyph, Unit(0.50f), Unit(0.24f), Unit(0.50f), Unit(0.58f));
                    using var dot = new SolidBrush(Color.White);
                    graphics.FillEllipse(dot, Unit(0.44f), Unit(0.66f), Unit(0.12f), Unit(0.12f));
                }
                else
                {
                    using var dot = new SolidBrush(Color.White);
                    foreach (var x in new[] { 0.30f, 0.50f, 0.70f })
                        graphics.FillEllipse(dot, Unit(x - 0.055f), Unit(0.445f), Unit(0.11f), Unit(0.11f));
                }
            }
        }
        var handle = bitmap.GetHicon();
        trayIconHandles.Add(handle);
        return Icon.FromHandle(handle);
    }

    private void ShowFromTray()
    {
        Show();
        if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
        Activate();
    }

    private async Task ChooseConnection(bool connect)
    {
        var worker = requests ?? throw new InvalidOperationException("core.error.unavailable");
        var current = ++revision;
        var node = subscriptions.Values.SelectMany(subscription => subscription.Outbounds).FirstOrDefault(candidate => candidate.Id == settings.Server)
            ?? subscriptions.Values.SelectMany(subscription => subscription.Outbounds).FirstOrDefault();
        if (connect && node == null) { await AddSubscription(); return; }
        desiredConnected = connect;
        probing?.Cancel();
        connectionPending = true;
        RenderStatus();
        RenderSubscriptions();
        var plan = connect ? new SessionPlan
        {
            TunnelMode = settings.Tun ? TunnelMode.System : TunnelMode.Application,
            NetworkControlAllowed = true,
            TunStack = settings.Tun ? settings.Engine switch { "xray" => settings.XrayStack, "mihomo" => settings.MihomoStack, _ => "" } : ""
        } : null;
        if (plan != null)
        {
            plan.Outbounds.Add(node!.Clone());
            if (settings.Engine.Length > 0) plan.Engines.Add(settings.Engine);
            settings.Server = node.Id;
            settings.Save();
        }
        try
        {
            var result = await worker.SetAsync(plan, settings.KillSwitch);
            if (closing || current != revision) return;
            status = result;
            apply.Visible = false;
            error.Text = "";
        }
        catch (OperationCanceledException) when (closing || current != revision) { return; }
        catch
        {
            if (current == revision) desiredConnected = status?.Connection.Value is ConnectionStateValue.Connected or ConnectionStateValue.Reconnecting;
            throw;
        }
        finally
        {
            if (current == revision) connectionPending = false;
            if (!closing) { RenderStatus(); RenderSubscriptions(); }
        }
    }

    private void ChooseModes()
    {
        using var dialog = new Form { Text = text["modes"], Font = body, BackColor = Color.White, AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink, FormBorderStyle = FormBorderStyle.FixedDialog,
            AutoScaleMode = AutoScaleMode.Dpi,
            MaximizeBox = false, MinimizeBox = false, StartPosition = FormStartPosition.CenterParent };
        var layout = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.TopDown, WrapContents = false, Padding = new Padding(20) };
        // One mnemonic set for the whole dialog: letters are unique by
        // construction (see Mnemonic). The radio/check controls are
        // standard WinForms and render the markers; the AntdUI selects
        // and buttons below are reached by the designed tab order.
        var used = new HashSet<char>();
        var tun = new RadioButton { Text = Mnemonic.Mark(text["tunMode"], used, 'T', 'Т'), Checked = settings.Tun, AutoSize = true, Margin = new Padding(0, 8, 0, 8), TabIndex = 0 };
        var proxy = new RadioButton { Text = Mnemonic.Mark(text["tunnelProxy"], used, 'P', 'П'), Checked = !settings.Tun, AutoSize = true, Margin = tun.Margin, TabIndex = 1 };
        var killSwitch = new CheckBox { Text = Mnemonic.Mark(text["killSwitch"], used, 'K', 'I', 'И'), Checked = settings.KillSwitch, AutoSize = true, Margin = tun.Margin, TabIndex = 2 };
        // The registry is the truth for autostart (AutoRun owns the Run
        // value the uninstaller scans), so the box opens with the
        // read-back, not with what settings last hoped was written.
        var autoRun = new CheckBox { Text = Mnemonic.Mark(text["launchAtLogin"], used, 'L', 'В', 'A'), Checked = AutoRun.IsEnabled(), AutoSize = true, Margin = tun.Margin, TabIndex = 3 };
        var engine = new AntdUI.Select { Width = 300, Height = 44, List = true, Font = strong, BackColor = Field, ForeColor = ForeColor, Radius = 8, TabIndex = 4 };
        engine.Items.Add(new AntdUI.SelectItem(text["engineAuto"], ""));
        foreach (var kind in new[] { "sing-box", "xray", "mihomo" }) engine.Items.Add(new AntdUI.SelectItem(kind, kind));
        engine.SelectedValue = settings.Engine;
        var stack = new AntdUI.Select { Width = 300, Height = 44, List = true, Font = body, Radius = 8, TabIndex = 5 };
        foreach (var name in new[] { "gvisor", "system", "mixed", "mips" }) stack.Items.Add(name);
        void RenderStack()
        {
            stack.Visible = tun.Checked && (string?)engine.SelectedValue is "xray" or "mihomo";
            stack.SelectedValue = (string?)engine.SelectedValue == "xray" ? settings.XrayStack : settings.MihomoStack;
        }
        engine.SelectedValueChanged += (_, _) => RenderStack();
        tun.CheckedChanged += (_, _) => RenderStack();
        var save = MakeButton("save", 300);
        save.TabIndex = 6;
        var cancel = MakeButton("cancel", 300);
        cancel.TabIndex = 7;
        cancel.Click += (_, _) => dialog.DialogResult = DialogResult.Cancel;
        save.Click += (_, _) =>
        {
            // Autostart is written first and read back: when the
            // registry refuses (policy locks the Run key), the box
            // stays open showing the state that is actually in effect
            // and nothing else is saved on a false premise.
            var wantAutoRun = autoRun.Checked;
            AutoRun.SetEnabled(wantAutoRun);
            var actualAutoRun = AutoRun.IsEnabled();
            settings.AutoRun = actualAutoRun;
            if (actualAutoRun != wantAutoRun)
            {
                autoRun.Checked = actualAutoRun;
                settings.Save();
                return;
            }
            settings.Tun = tun.Checked;
            settings.KillSwitch = killSwitch.Checked;
            settings.Engine = (string?)engine.SelectedValue ?? "";
            if (settings.Engine == "xray") settings.XrayStack = (string?)stack.SelectedValue ?? "gvisor";
            if (settings.Engine == "mihomo") settings.MihomoStack = (string?)stack.SelectedValue ?? "mixed";
            settings.Save();
            apply.Visible = desiredConnected;
            dialog.DialogResult = DialogResult.OK;
        };
        layout.Controls.AddRange(new FormsControl[] { tun, proxy, killSwitch, autoRun, engine, stack, save, cancel });
        dialog.Controls.Add(layout);
        dialog.AcceptButton = save;
        dialog.CancelButton = cancel;
        dialog.ActiveControl = tun;
        RenderStack();
        dialog.ShowDialog(this);
    }

    private async Task AddSubscription()
    {
        if (core == null) throw new InvalidOperationException("core.error.unavailable");
        using var dialog = new Form { Text = text["addSubscription"], Font = body, BackColor = Color.White, ClientSize = new Size(460, 156),
            AutoScaleMode = AutoScaleMode.Dpi,
            FormBorderStyle = FormBorderStyle.FixedDialog, StartPosition = FormStartPosition.CenterParent, MaximizeBox = false, MinimizeBox = false };
        // Anchored to the dialog edges instead of bare coordinates, so
        // the fixed layout follows the Dpi-scaled client area.
        var input = new AntdUI.Input { Bounds = new Rectangle(20, 20, 420, 48), Anchor = AnchorStyles.Left | AnchorStyles.Top | AnchorStyles.Right,
            PlaceholderText = text["subscriptionLink"], Font = body, Radius = 8, TabIndex = 0 };
        var confirm = MakeButton("add", 120);
        confirm.Location = new Point(320, 88);
        confirm.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        confirm.TabIndex = 1;
        confirm.Click += (_, _) => dialog.DialogResult = DialogResult.OK;
        var cancel = MakeButton("cancel", 120);
        cancel.Location = new Point(192, 88);
        cancel.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        cancel.TabIndex = 2;
        cancel.Click += (_, _) => dialog.DialogResult = DialogResult.Cancel;
        dialog.Controls.AddRange(new FormsControl[] { input, confirm, cancel });
        dialog.AcceptButton = confirm;
        dialog.CancelButton = cancel;
        dialog.ActiveControl = input;
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        var answer = await core.CallAsync(new SaveSubscriptionRequest
        {
            ApiVersion = core.Version, ControlAuthenticator = core.Authenticator,
            Settings = new SubscriptionSettings { Url = input.Text.Trim(), AutoUpdate = true }
        }, SaveSubscriptionResponse.Parser, lifetime.Token);
        input.Text = "";
        Check(answer.Error);
        subscriptions[answer.State.Settings.Id] = answer.State;
        RenderSubscriptions();
    }

    private void RenderSubscriptions()
    {
        if (closing) return;
        var scroll = cards.AutoScrollPosition;
        cards.SuspendLayout();
        foreach (var card in cards.Controls.Cast<FormsControl>().ToArray()) card.Dispose();
        cards.Controls.Clear();
        var width = Math.Max(220, cards.ClientSize.Width - 20);
        foreach (var subscription in subscriptions.Values)
            cards.Controls.Add(new SubscriptionCard(subscription, width, text, body, strong, settings.Server, pings,
                collapsed, hiddenDescriptions, search.Text, RenderSubscriptions,
                node => Run(async () => { settings.Server = node.Id; settings.Save(); if (desiredConnected) await ChooseConnection(true); else RenderSubscriptions(); }),
                () => Run(() => RefreshSubscription(subscription.Settings.Id)),
                () => Run(() => Probe(subscription)),
                () => Run(() => DeleteSubscription(subscription)),
                connectionPending || status?.Connection.Value is ConnectionStateValue.Connecting or ConnectionStateValue.Reconnecting));
        cards.ResumeLayout();
        cards.AutoScrollPosition = new Point(-scroll.X, -scroll.Y);
        add.Visible = subscriptions.Count == 0;
        add.Enabled = core != null;
        addAbove.Visible = subscriptions.Count > 0;
        search.Visible = subscriptions.Count > 0;
    }

    private async Task RefreshSubscription(string id)
    {
        if (core == null) return;
        var answer = await core.CallAsync(new RefreshSubscriptionRequest
        { ApiVersion = core.Version, ControlAuthenticator = core.Authenticator, Id = id }, RefreshSubscriptionResponse.Parser, lifetime.Token);
        Check(answer.Error);
        subscriptions[id] = answer.State;
        RenderSubscriptions();
    }

    private async Task Probe(SubscriptionState subscription)
    {
        if (core == null || connectionPending || status?.Connection.Value is ConnectionStateValue.Connecting or ConnectionStateValue.Reconnecting) return;
        probing?.Cancel();
        using var attempt = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
        probing = attempt;
        var request = new ProbeServersRequest { ApiVersion = core.Version, RequestId = Guid.NewGuid().ToString("N"), Options = new ProbeOptions { Concurrency = 2, TimeoutMs = 3000 } };
        request.Outbounds.Add(subscription.Outbounds);
        try
        {
            await core.WatchAsync(request, ProbeResult.Parser, new Progress<ProbeResult>(result =>
            {
                if (closing || attempt.IsCancellationRequested) return;
                if (result.Reachable) pings[result.ServerId] = result.LatencyMs;
                else pings.Remove(result.ServerId);
                RenderSubscriptions();
            }), attempt.Token);
        }
        catch (OperationCanceledException) when (attempt.IsCancellationRequested) { }
        finally { if (ReferenceEquals(probing, attempt)) probing = null; }
    }

    private async Task DeleteSubscription(SubscriptionState subscription)
    {
        // Destructive confirmation: the default button and the
        // initial focus are on Cancel, so Enter never deletes.
        if (core == null || MessageBox.Show(this, text["deleteSubscription"].Replace("{name}", subscription.DisplayName),
            text["delete"], MessageBoxButtons.OKCancel, MessageBoxIcon.None, MessageBoxDefaultButton.Button2) != DialogResult.OK) return;
        var answer = await core.CallAsync(new DeleteSubscriptionRequest
        { ApiVersion = core.Version, ControlAuthenticator = core.Authenticator, Id = subscription.Settings.Id }, DeleteSubscriptionResponse.Parser, lifetime.Token);
        Check(answer.Error);
        subscriptions.Remove(subscription.Settings.Id);
        RenderSubscriptions();
    }

    private static void Check(SoraError? error)
    {
        if (error != null) throw new InvalidOperationException(error.UserMessageKey);
    }

    private async Task Run(Func<Task> action)
    {
        try { await action(); }
        catch (OperationCanceledException) when (closing) { }
        catch (Exception exception)
        {
            if (closing) return;
            error.Text = exception is InvalidOperationException ? text.Error(exception.Message) : text["errGeneric"];
            retry.Visible = core == null;
            retry.Loading = false;
        }
    }

    protected override async void OnFormClosing(FormClosingEventArgs e)
    {
        if (closing) { base.OnFormClosing(e); return; }
        e.Cancel = true;
        closing = true;
        poll.Stop();
        lifetime.Cancel();
        try
        {
            await logsPage.StopAsync();
            if (requests != null) await requests.StopAsync();
            if (subscriptionWatch != null) await subscriptionWatch;
        }
        catch (OperationCanceledException) { System.Diagnostics.Trace.WriteLine("Legacy client watches cancelled during shutdown."); }
        catch (Exception exception) { System.Diagnostics.Trace.WriteLine("Legacy client shutdown: " + exception.GetType().Name); }
        finally
        {
            core?.Dispose();
            Close();
        }
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (!disposing) return;
        tray.Visible = false;
        tray.Dispose();
        trayMenu.Dispose();
        foreach (var icon in trayIcons.Values) icon.Dispose();
        foreach (var handle in trayIconHandles) DestroyIcon(handle);
        trayIcons.Clear();
        trayIconHandles.Clear();
        poll.Dispose();
        navigationHints.Dispose();
        lifetime.Dispose();
        text.Dispose();
        body.Dispose();
        strong.Dispose();
        heading.Dispose();
    }
}
