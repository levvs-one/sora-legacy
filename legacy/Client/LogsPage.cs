using System;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using Sora.Core.V1;
using Sora.Legacy.Control;
using Button = AntdUI.Button;
using FormsControl = System.Windows.Forms.Control;

namespace Sora.Legacy.Client;

internal sealed class LogsPage : UserControl
{
    private const int Keep = 200000;
    private readonly Strings text;
    private readonly Font metadata;
    private readonly SortedList<ulong, LogEntry> entries = new();
    private readonly ListView list = new() { Dock = DockStyle.Fill, View = View.Details, VirtualMode = true,
        OwnerDraw = true, HeaderStyle = ColumnHeaderStyle.None, BorderStyle = BorderStyle.None,
        FullRowSelect = true, HideSelection = false, MultiSelect = false };
    private readonly ImageList rowHeight = new() { ImageSize = new Size(1, 72) };
    private readonly Bitmap rowSpacer = new(1, 72);
    private readonly Label message = new() { Dock = DockStyle.Top, Height = 32, AutoEllipsis = true };
    private readonly AntdUI.Input search = new() { Dock = DockStyle.Top, Height = 44, Radius = 8 };
    private readonly System.Windows.Forms.Timer debounce = new() { Interval = 250 };
    private readonly Button export, clear, refresh;
    private readonly Dictionary<string, Button> categories = new();
    private readonly Dictionary<LogLevel, Button> levels = new();
    private CoreConnection? core;
    private CancellationTokenSource? reading;
    private Task? watch;
    private bool loading, disposed;
    private string category = "all";
    private LogLevel level = LogLevel.Debug;
    private long revision;

    public LogsPage(Strings text, Font body, Font strong)
    {
        this.text = text;
        Font = body;
        AutoScaleMode = AutoScaleMode.Dpi;
        metadata = new Font(body, FontStyle.Bold);
        Padding = new Padding(24);
        BackColor = Color.FromArgb(246, 246, 248);
        ForeColor = Color.FromArgb(31, 31, 33);
        list.BackColor = BackColor;
        list.ForeColor = ForeColor;
        rowHeight.Images.Add(rowSpacer);
        list.SmallImageList = rowHeight;
        list.Columns.Add("", 400);
        list.Resize += (_, _) => list.Columns[0].Width = Math.Max(80, list.ClientSize.Width - 24);
        list.RetrieveVirtualItem += (_, request) => request.Item = new ListViewItem(" ") { ImageIndex = 0 };
        list.DrawColumnHeader += (_, request) => request.DrawDefault = false;
        list.DrawItem += (_, request) => request.DrawDefault = false;
        list.DrawSubItem += DrawEntry;
        list.DoubleClick += (_, _) => OpenEntry();
        var header = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(0, 0, 0, 12) };
        var title = new Label { Text = text["logs"], Tag = "logs", Font = strong, Width = 160, Height = 44, TextAlign = ContentAlignment.MiddleLeft };
        export = MakeButton("export", 44);
        export.IconSvg = Strings.Read("Icons.export-bold.svg");
        clear = MakeButton("clear", 44);
        clear.IconSvg = Strings.Read("Icons.trash-bold.svg");
        refresh = MakeButton("refresh", 44);
        refresh.IconSvg = Strings.Read("Icons.arrows-clockwise-bold.svg");
        header.Controls.AddRange(new FormsControl[] { title, export, clear, refresh });
        var levelBar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(0, 0, 0, 8) };
        foreach (var choice in new[] { LogLevel.Debug, LogLevel.Warning, LogLevel.Error })
        {
            var button = MakeButton(choice switch { LogLevel.Warning => "logsImportant", LogLevel.Error => "logsErrors", _ => "logsAll" }, 130);
            button.Click += async (_, _) => { level = choice; ApplyText(); await ReloadAsync(); };
            levels[choice] = button;
            levelBar.Controls.Add(button);
        }
        var categoryBar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, WrapContents = true, Padding = new Padding(0, 0, 0, 8) };
        foreach (var name in new[] { "all", "engine", "tun", "dns", "subscriptions", "core" })
        {
            var button = MakeButton("", name == "subscriptions" ? 138 : 90);
            button.Click += async (_, _) => { category = name; ApplyText(); await ReloadAsync(); };
            categories[name] = button;
            categoryBar.Controls.Add(button);
        }
        Controls.Add(list);
        Controls.Add(message);
        Controls.Add(search);
        Controls.Add(categoryBar);
        Controls.Add(levelBar);
        Controls.Add(header);
        // Designed tab order: header actions, level filter, category
        // filter, search, then the list itself. The sibling panels
        // carry explicit indexes too, so the panels' mutual order is
        // pinned by value instead of resting on equal zero indexes
        // and z-order (a reordered Controls.Add would silently break
        // it); the buttons inside each panel keep their own indexes
        // within that panel.
        header.TabIndex = 0;
        levelBar.TabIndex = 1;
        categoryBar.TabIndex = 2;
        search.TabIndex = 3;
        list.TabIndex = 4;
        export.TabIndex = 0;
        clear.TabIndex = 1;
        refresh.TabIndex = 2;
        var tab = 3;
        foreach (var choice in new[] { LogLevel.Debug, LogLevel.Warning, LogLevel.Error }) levels[choice].TabIndex = tab++;
        foreach (var name in new[] { "all", "engine", "tun", "dns", "subscriptions", "core" }) categories[name].TabIndex = tab++;
        search.TextChanged += (_, _) => { debounce.Stop(); debounce.Start(); };
        debounce.Tick += async (_, _) => { debounce.Stop(); await ReloadAsync(); };
        refresh.Click += async (_, _) => await ReloadAsync();
        clear.Click += async (_, _) => await ClearAsync();
        export.Click += (_, _) => OpenExportMenu();
        ApplyText();
    }

    private Button MakeButton(string key, int width) => new()
    {
        Tag = key, Width = width, Height = 40, Radius = 8, BorderWidth = 0,
        BackColor = Color.White, BackHover = Color.FromArgb(235, 235, 240),
        ForeColor = ForeColor, ForeHover = ForeColor, Font = Font, WaveSize = 0,
        Margin = new Padding(0, 0, 6, 4), IconSize = new Size(20, 20)
    };

    public void ApplyText()
    {
        search.PlaceholderText = text["search"];
        foreach (var button in levels.Values) button.Text = text[(string)button.Tag];
        foreach (var button in new[] { export, clear, refresh }) button.AccessibleName = text[(string)button.Tag];
        foreach (var choice in categories)
            choice.Value.Text = choice.Key switch { "tun" => "TUN", "dns" => "DNS", "core" => "SoraCore",
                "engine" => text["engine"], "subscriptions" => text["subscriptions"], _ => text["logsAll"] };
        foreach (var choice in categories) choice.Value.BackColor = choice.Key == category ? Color.FromArgb(235, 235, 240) : Color.White;
        foreach (var choice in levels) choice.Value.BackColor = choice.Key == level ? Color.FromArgb(235, 235, 240) : Color.White;
        foreach (var title in Controls.OfType<FlowLayoutPanel>().SelectMany(panel => panel.Controls.OfType<Label>()))
            if (title.Tag is string key) title.Text = text[key];
        message.Text = core == null ? text["coreMissing"] : entries.Count == 0 && !loading ? text["logsEmpty"] : "";
    }

    private LogFilter Filter()
    {
        var filter = new LogFilter { MinLevel = level, Contains = search.Text.Trim() };
        if (category == "engine") filter.Sources.Add(new[] { "sing-box", "xray", "mihomo", "zapret" });
        if (category == "subscriptions") filter.Sources.Add("subscription");
        if (category == "core") filter.Sources.Add("core");
        filter.Pattern = category switch { "tun" => @"\b(tun|tunnel|adapter)\b|proxy/tun|inbound/tun",
            "dns" => @"\b(dns|doh|dot|resolver)\b", _ => "" };
        return filter;
    }

    public async Task LoadAsync(CoreConnection? connected)
    {
        core = connected;
        await ReloadAsync();
    }

    private async Task ReloadAsync()
    {
        var stopping = StopAsync();
        var current = revision;
        await stopping;
        if (disposed || current != revision) return;
        var connected = core;
        export.Enabled = clear.Enabled = connected != null;
        if (connected == null) { ApplyText(); return; }
        var attempt = reading = new CancellationTokenSource();
        var filter = Filter();
        loading = true;
        refresh.Loading = true;
        try
        {
            var record = new Dictionary<ulong, LogEntry>();
            ulong before = 0, after = 0;
            do
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(attempt.Token);
                timeout.CancelAfter(TimeSpan.FromSeconds(8));
                var page = await connected.CallAsync(new QueryLogsRequest { ApiVersion = connected.Version,
                    ControlAuthenticator = connected.Authenticator, Filter = filter, Limit = 500, BeforeSequence = before },
                    QueryLogsResponse.Parser, timeout.Token);
                if (page.Error != null) throw new InvalidOperationException(page.Error.UserMessageKey);
                if (!ReferenceEquals(reading, attempt) || disposed || attempt.IsCancellationRequested) return;
                foreach (var entry in page.Entries) { record[entry.Sequence] = entry; after = Math.Max(after, entry.Sequence); }
                before = page.BeforeSequence;
            } while (before != 0 && record.Count < Keep);
            entries.Clear();
            foreach (var entry in record.OrderBy(pair => pair.Key)) entries.Add(entry.Key, entry.Value);
            list.VirtualListSize = entries.Count;
            list.Invalidate();
            loading = false;
            ApplyText();
            watch = FollowAsync(connected, filter, after, attempt);
        }
        catch (OperationCanceledException) when (attempt.IsCancellationRequested) { }
        catch (Exception exception)
        {
            if (!disposed && ReferenceEquals(reading, attempt)) message.Text = exception is InvalidOperationException
                ? text.Error(exception.Message) : text["errCore"];
        }
        finally
        {
            if (!disposed && ReferenceEquals(reading, attempt)) { loading = false; refresh.Loading = false; }
        }
    }

    private async Task FollowAsync(CoreConnection connected, LogFilter filter, ulong after, CancellationTokenSource attempt)
    {
        try
        {
            await connected.WatchAsync(new WatchLogsRequest { ApiVersion = connected.Version,
                ControlAuthenticator = connected.Authenticator, Filter = filter, AfterSequence = after }, LogEntry.Parser,
                new Progress<LogEntry>(entry =>
                {
                    if (!disposed && ReferenceEquals(reading, attempt) && !attempt.IsCancellationRequested) Arrive(entry);
                }), attempt.Token);
            if (!disposed && ReferenceEquals(reading, attempt) && !attempt.IsCancellationRequested) message.Text = text["errCore"];
        }
        catch (OperationCanceledException) when (attempt.IsCancellationRequested) { }
        catch (Exception) { if (!disposed && ReferenceEquals(reading, attempt)) message.Text = text["errCore"]; }
    }

    private void Arrive(LogEntry entry)
    {
        var top = list.TopItem?.Index ?? 0;
        var anchor = top > 0 && top < entries.Count ? entries.Keys[entries.Count - top - 1] : 0;
        entries[entry.Sequence] = entry;
        while (entries.Count > Keep) entries.RemoveAt(0);
        list.BeginUpdate();
        list.VirtualListSize = entries.Count;
        if (anchor != 0)
        {
            var index = entries.IndexOfKey(anchor);
            if (index >= 0) list.TopItem = list.Items[entries.Count - index - 1];
        }
        else if (entries.Count > 0) list.TopItem = list.Items[0];
        list.EndUpdate();
        message.Text = "";
        list.Invalidate();
    }

    private void DrawEntry(object? sender, DrawListViewSubItemEventArgs request)
    {
        if (request.ItemIndex >= entries.Count) return;
        var entry = entries.Values[entries.Count - request.ItemIndex - 1];
        var background = request.Item.Selected ? Color.FromArgb(235, 235, 240) : BackColor;
        using var brush = new SolidBrush(background);
        request.Graphics.FillRectangle(brush, request.Bounds);
        var time = entry.Time?.ToDateTime().ToLocalTime().ToString("HH:mm:ss", CultureInfo.CurrentCulture) ?? "";
        var caption = time + "  " + entry.Source + (entry.Repeat > 1 ? "  ×" + entry.Repeat.ToString(CultureInfo.CurrentCulture) : "");
        var flags = TextFormatFlags.NoPrefix | TextFormatFlags.EndEllipsis;
        TextRenderer.DrawText(request.Graphics, caption, metadata,
            new Rectangle(request.Bounds.X + 8, request.Bounds.Y + 8, request.Bounds.Width - 16, 18), ForeColor, flags);
        TextRenderer.DrawText(request.Graphics, entry.Message, Font,
            new Rectangle(request.Bounds.X + 8, request.Bounds.Y + 28, request.Bounds.Width - 16, 40), ForeColor, flags | TextFormatFlags.WordBreak);
    }

    private void OpenEntry()
    {
        if (list.SelectedIndices.Count != 1) return;
        var entry = entries.Values[entries.Count - list.SelectedIndices[0] - 1];
        using var dialog = new Form { Text = entry.Source, Font = Font, ClientSize = new Size(640, 360),
            AutoScaleMode = AutoScaleMode.Dpi,
            StartPosition = FormStartPosition.CenterParent, MinimizeBox = false, BackColor = BackColor, Padding = new Padding(16) };
        dialog.Controls.Add(new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, Text = entry.Message, TabIndex = 0,
            Font = Font, BackColor = BackColor, ForeColor = ForeColor, BorderStyle = BorderStyle.None });
        dialog.ShowDialog(this);
    }

    private void OpenExportMenu()
    {
        var items = new[] { "log", "txt", "json", "jsonl", "csv", "xml", "zip", "gz" }
            .Select(extension => (AntdUI.IContextMenuStripItem)new AntdUI.ContextMenuStripItem(text["exportLogFile"].Replace("{name}",
                "sora-log_" + category + "_" + DateTime.Now.ToString("dd_MM_yyyy", CultureInfo.InvariantCulture) + "." + extension)) { ID = extension }).ToArray();
        AntdUI.ContextMenuStrip.open(new AntdUI.ContextMenuStrip.Config(export, async item =>
            {
                if (item is AntdUI.ContextMenuStripItem choice && choice.ID is string extension) await ExportAsync(extension);
            }, items) { Font = Font, Radius = 8 });
    }

    private async Task ExportAsync(string extension)
    {
        var connected = core;
        var current = reading;
        if (connected == null || current == null || export.Loading) return;
        export.Loading = true;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(current.Token);
            timeout.CancelAfter(TimeSpan.FromSeconds(30));
            var answer = await connected.CallAsync(new ExportLogsRequest { ApiVersion = connected.Version,
                ControlAuthenticator = connected.Authenticator, Category = category, Filter = Filter(), Format = extension switch
                { "log" => LogExportFormat.Log, "json" => LogExportFormat.Json, "jsonl" => LogExportFormat.JsonLines,
                    "csv" => LogExportFormat.Csv, "xml" => LogExportFormat.Xml, "zip" => LogExportFormat.Zip,
                    "gz" => LogExportFormat.Gzip, _ => LogExportFormat.Unspecified } }, ExportLogsResponse.Parser, timeout.Token);
            if (answer.Error != null) throw new InvalidOperationException(answer.Error.UserMessageKey);
            if (disposed || current.IsCancellationRequested || !ReferenceEquals(reading, current)) return;
            using var dialog = new SaveFileDialog { FileName = Path.GetFileName(answer.FileName), DefaultExt = extension,
                Filter = extension.ToUpperInvariant() + "|*." + extension, OverwritePrompt = true };
            if (dialog.ShowDialog(this) == DialogResult.OK) File.WriteAllBytes(dialog.FileName, answer.Data.ToByteArray());
        }
        catch (OperationCanceledException) when (current.IsCancellationRequested) { }
        catch (Exception exception) { if (!disposed) message.Text = exception is InvalidOperationException ? text.Error(exception.Message) : text["errGeneric"]; }
        finally { if (!disposed) export.Loading = false; }
    }

    private async Task ClearAsync()
    {
        var connected = core;
        var current = reading;
        if (connected == null || current == null || clear.Loading) return;
        clear.Loading = true;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(current.Token);
            timeout.CancelAfter(TimeSpan.FromSeconds(8));
            var answer = await connected.CallAsync(new ClearLogsRequest { ApiVersion = connected.Version,
                ControlAuthenticator = connected.Authenticator }, ClearLogsResponse.Parser, timeout.Token);
            if (answer.Error != null) throw new InvalidOperationException(answer.Error.UserMessageKey);
            if (!disposed && !current.IsCancellationRequested && ReferenceEquals(reading, current)) await ReloadAsync();
        }
        catch (OperationCanceledException) when (current.IsCancellationRequested) { }
        catch (Exception exception) { if (!disposed) message.Text = exception is InvalidOperationException ? text.Error(exception.Message) : text["errGeneric"]; }
        finally { if (!disposed) clear.Loading = false; }
    }

    public async Task StopAsync()
    {
        revision++;
        debounce.Stop();
        var previous = reading;
        reading = null;
        previous?.Cancel();
        var pending = watch;
        watch = null;
        if (pending != null) await pending;
        previous?.Dispose();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !disposed)
        {
            disposed = true;
            reading?.Cancel();
            reading?.Dispose();
            reading = null;
            debounce.Dispose();
            rowHeight.Dispose();
            rowSpacer.Dispose();
            metadata.Dispose();
        }
        base.Dispose(disposing);
    }
}
