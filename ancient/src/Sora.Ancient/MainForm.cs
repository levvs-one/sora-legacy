using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Windows.Forms;

namespace Sora.Ancient
{
    // The whole UI: a server list, import (single link / subscription
    // URL), connect/disconnect, and a status line. Honest states only:
    // "Connected" is shown after the engine process survived its startup
    // window AND the system proxy was set; every failure is one named
    // sentence, never a stack trace or raw engine output.
    internal sealed class MainForm : Form
    {
        private readonly ListBox _servers = new ListBox();
        private readonly Label _status = new Label();
        private readonly Button _connect = new Button();
        private readonly Button _disconnect = new Button();
        private readonly CheckBox _useSystemProxy = new CheckBox();
        private readonly EngineRunner _engine = new EngineRunner();
        private List<ServerEntry> _entries = new List<ServerEntry>();
        private bool _connected;

        public MainForm()
        {
            Text = "Sora Ancient — XP / Vista / Windows 8.0";
            Width = 640;
            Height = 460;
            MinimumSize = new System.Drawing.Size(520, 360);
            StartPosition = FormStartPosition.CenterScreen;

            _servers.Dock = DockStyle.Fill;
            _servers.DoubleClick += delegate { Connect(); };

            var top = new FlowLayoutPanel();
            top.Dock = DockStyle.Top;
            top.Height = 34;
            top.Controls.Add(MakeButton("Add link…", delegate { AddLink(); }));
            top.Controls.Add(MakeButton("Subscription…", delegate { AddSubscription(); }));
            top.Controls.Add(MakeButton("Remove", delegate { RemoveSelected(); }));

            var bottom = new FlowLayoutPanel();
            bottom.Dock = DockStyle.Bottom;
            bottom.Height = 34;
            _connect.Text = "Connect";
            _connect.Width = 110;
            _connect.Click += delegate { Connect(); };
            _disconnect.Text = "Disconnect";
            _disconnect.Width = 110;
            _disconnect.Enabled = false;
            _disconnect.Click += delegate { Disconnect(true); };
            _useSystemProxy.Text = "Set system proxy while connected";
            _useSystemProxy.Checked = true;
            _useSystemProxy.AutoSize = true;
            bottom.Controls.Add(_connect);
            bottom.Controls.Add(_disconnect);
            bottom.Controls.Add(_useSystemProxy);

            // The status line gets its own full-width row under the
            // buttons. Inside the wrapping button panel the longer
            // states (the connected line names both local ports) were
            // clipped at the form's minimum width; on its own row the
            // text has the whole width, and AutoEllipsis ends it
            // cleanly instead of cutting a glyph in half.
            _status.Dock = DockStyle.Bottom;
            _status.Height = 22;
            _status.AutoEllipsis = true;
            _status.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            _status.Padding = new Padding(4, 0, 0, 0);
            _status.Text = "Not connected.";

            // Docking fills in reverse add order: the status row is
            // added last, so it takes the bottom edge and the button
            // panel stacks directly above it.
            Controls.Add(_servers);
            Controls.Add(top);
            Controls.Add(bottom);
            Controls.Add(_status);

            FormClosing += delegate { Disconnect(false); };

            try { _entries = ServerStore.Load(); }
            catch (FormatException) { /* Damaged store: start with the empty list. */ }
            RefreshList();
            string engine = EngineRunner.FindEngine(AppDomain.CurrentDomain.BaseDirectory);
            _status.Text = engine == null
                ? "Not connected. The connection engine is missing."
                : "Not connected.";
        }

        private static Button MakeButton(string text, EventHandler onClick)
        {
            var b = new Button();
            b.Text = text;
            b.AutoSize = true;
            b.Click += onClick;
            return b;
        }

        private void RefreshList()
        {
            _servers.Items.Clear();
            foreach (ServerEntry e in _entries) _servers.Items.Add(e.DisplayName);
        }

        private void AddLink()
        {
            string link = Prompt("Paste a vmess://, ss:// or socks:// link:", "Add link");
            if (link == null) return;
            try
            {
                _entries.Add(LinkParser.ParseLink(link));
                ServerStore.Save(_entries);
                RefreshList();
                _status.Text = "Link added.";
            }
            catch (FormatException ex) { ShowError(ex.Message); }
        }

        private void AddSubscription()
        {
            string url = Prompt("Subscription URL:", "Add subscription");
            if (url == null) return;
            try
            {
                string body;
                using (var client = new WebClient())
                {
                    // Era TLS honesty: .NET 4.0/4.6 SChannel on XP/Vista
                    // cannot offer modern TLS to every host; a failure
                    // here is reported as such, not retried insecurely.
                    body = client.DownloadString(url.Trim());
                }
                List<ServerEntry> parsed = LinkParser.ParseSubscriptionBody(body);
                _entries.AddRange(parsed);
                ServerStore.Save(_entries);
                RefreshList();
                _status.Text = parsed.Count == 1
                    ? "Subscription imported: 1 server."
                    : "Subscription imported: " + parsed.Count + " servers.";
            }
            catch (WebException) { ShowError("Subscription download failed (network or TLS). Nothing was imported."); }
            catch (FormatException ex) { ShowError(ex.Message); }
        }

        private void RemoveSelected()
        {
            int i = _servers.SelectedIndex;
            if (i < 0 || i >= _entries.Count) return;
            _entries.RemoveAt(i);
            ServerStore.Save(_entries);
            RefreshList();
        }

        private void Connect()
        {
            int i = _servers.SelectedIndex;
            if (i < 0 || i >= _entries.Count) { ShowError("Select a server first."); return; }
            try
            {
                string config = ConfigBuilder.Build(_entries[i], ConfigBuilder.DefaultSocksPort, ConfigBuilder.DefaultHttpPort);
                File.WriteAllText(ServerStore.RuntimeConfigPath, config);
                string engine = EngineRunner.FindEngine(AppDomain.CurrentDomain.BaseDirectory);
                _engine.Start(engine, ServerStore.RuntimeConfigPath);
                if (_useSystemProxy.Checked)
                    SystemProxy.Enable(ServerStore.ProxySnapshotPath, ConfigBuilder.DefaultSocksPort);
                _connected = true;
                _connect.Enabled = false;
                _disconnect.Enabled = true;
                _status.Text = "Connected: SOCKS 127.0.0.1:" + ConfigBuilder.DefaultSocksPort +
                               ", HTTP 127.0.0.1:" + ConfigBuilder.DefaultHttpPort + ". Proxy mode — no TUN.";
            }
            catch (FormatException ex) { ShowError(ex.Message); }
            catch (InvalidOperationException ex) { ShowError(ex.Message); }
            catch (IOException) { ShowError("Could not save the file needed to connect."); }
        }

        private void Disconnect(bool updateUi)
        {
            _engine.Stop();
            try { SystemProxy.Restore(ServerStore.ProxySnapshotPath); }
            catch (InvalidOperationException ex) { if (updateUi) ShowError(ex.Message); }
            _connected = false;
            if (updateUi)
            {
                _connect.Enabled = true;
                _disconnect.Enabled = false;
                _status.Text = "Disconnected.";
            }
        }

        // Invariant: `message` here is only ever a sentence authored in
        // this assembly. Every throw site reachable from the handlers
        // above writes its own user-facing sentence (EraGate, LinkParser,
        // ServerStore, SystemProxy, EngineRunner), and the two sources
        // whose wording is NOT authored — the runtime base64 decoder and
        // the JsonMini tokenizer — are translated to authored sentences
        // at their boundaries in LinkParser/ServerStore/SystemProxy.
        // Raw runtime or parser text never reaches this status line or
        // dialog.
        private void ShowError(string message)
        {
            _status.Text = message;
            MessageBox.Show(this, message, "Sora Ancient", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }

        private static string Prompt(string label, string title)
        {
            using (var form = new Form())
            {
                form.Text = title;
                form.Width = 520;
                form.Height = 156;
                form.StartPosition = FormStartPosition.CenterParent;
                // A fixed input dialog: not resizable, no min/max boxes.
                form.FormBorderStyle = FormBorderStyle.FixedDialog;
                form.MaximizeBox = false;
                form.MinimizeBox = false;
                var text = new TextBox();
                text.Dock = DockStyle.Top;
                var caption = new Label();
                caption.Text = label;
                caption.Dock = DockStyle.Top;
                caption.AutoSize = true;
                caption.Padding = new Padding(4, 6, 0, 2);
                // Standard era dialog buttons: OK / Cancel at the usual
                // 75 px, bottom right (in the old full-width bottom bar
                // OK stretched across the whole dialog). Cancel also
                // gives the dialog its Esc key.
                var buttons = new FlowLayoutPanel();
                buttons.Dock = DockStyle.Bottom;
                buttons.Height = 37;
                buttons.FlowDirection = FlowDirection.RightToLeft;
                buttons.Padding = new Padding(6);
                var ok = new Button();
                ok.Text = "OK";
                ok.Width = 75;
                ok.DialogResult = DialogResult.OK;
                var cancel = new Button();
                cancel.Text = "Cancel";
                cancel.Width = 75;
                cancel.DialogResult = DialogResult.Cancel;
                // Right-to-left flow: the first control added sits at
                // the right edge, so Cancel goes in first and OK ends
                // up directly left of it.
                buttons.Controls.Add(cancel);
                buttons.Controls.Add(ok);
                // Docking fills in reverse add order: the button panel
                // is added last, so it takes the bottom edge, the
                // caption takes the top, and the text box sits under
                // the caption.
                form.Controls.Add(text);
                form.Controls.Add(caption);
                form.Controls.Add(buttons);
                form.AcceptButton = ok;
                form.CancelButton = cancel;
                return form.ShowDialog() == DialogResult.OK && text.Text.Trim().Length > 0 ? text.Text : null;
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing) _engine.Dispose();
            base.Dispose(disposing);
        }

        public bool Connected { get { return _connected; } }
    }
}
