using System;
using System.Collections.Generic;
using System.Text;

namespace Sora.Ancient
{
    // Share-link and subscription parsing for the formats the era engine
    // can actually run. Deliberately NOT the modern core parser: that one
    // targets a Go core whose own floor is NT 6.1+ and whose formats
    // (VLESS/REALITY/Hysteria2...) are exactly what EraGate must refuse.
    internal static class LinkParser
    {
        public static ServerEntry ParseLink(string link)
        {
            if (link == null) throw new FormatException("Link is empty.");
            link = link.Trim();
            int sep = link.IndexOf("://", StringComparison.Ordinal);
            if (sep < 0) throw new FormatException("Link has no scheme.");
            string scheme = link.Substring(0, sep);
            EraGate.CheckScheme(scheme);
            switch (scheme.ToLowerInvariant())
            {
                case "vmess": return ParseVmess(link.Substring(sep + 3));
                case "ss": return ParseShadowsocks(link);
                case "socks": return ParseSocks(link);
                default: throw new FormatException("Unsupported link scheme.");
            }
        }

        // vmess://<base64 of the v2 JSON document>
        // {"v":"2","ps":..,"add":..,"port":..,"id":..,"aid":..,"scy":..,
        //  "net":..,"type":..,"host":..,"path":..,"tls":..,"sni":..}
        private static ServerEntry ParseVmess(string payload)
        {
            string json = DecodeBase64(payload, "VMess link payload is not valid base64.");
            Dictionary<string, object> map;
            try { map = JsonMini.Parse(json) as Dictionary<string, object>; }
            catch (FormatException) { throw new FormatException("VMess link payload is not a JSON object."); }
            if (map == null) throw new FormatException("VMess link payload is not a JSON object.");
            var e = new ServerEntry();
            e.Protocol = "vmess";
            e.Name = JsonMini.GetString(map, "ps", "");
            e.Address = JsonMini.GetString(map, "add", "");
            e.Port = JsonMini.GetInt(map, "port", 0);
            e.Uuid = JsonMini.GetString(map, "id", "");
            e.AlterId = JsonMini.GetInt(map, "aid", 64);
            string scy = JsonMini.GetString(map, "scy", "auto");
            e.Security = string.IsNullOrEmpty(scy) ? "auto" : scy.ToLowerInvariant();
            string net = JsonMini.GetString(map, "net", "tcp").ToLowerInvariant();
            e.Network = net == "http" ? "h2" : net;
            e.HostHeader = JsonMini.GetString(map, "host", "");
            e.Path = JsonMini.GetString(map, "path", "");
            e.Tls = JsonMini.GetString(map, "tls", "").ToLowerInvariant() == "tls";
            e.Sni = JsonMini.GetString(map, "sni", "");
            string streamSecurity = JsonMini.GetString(map, "tls", "").ToLowerInvariant();
            if (streamSecurity == "reality" || streamSecurity == "xtls")
                EraGate.Refuse(streamSecurity.ToUpperInvariant(), "It postdates this engine; the pinned binary contains no such code (verified by binary scan, not just config test).");
            e.Validate();
            return e;
        }

        // ss:// in both era spellings:
        //   legacy:  ss://base64(method:password@host:port)#name
        //   SIP002:  ss://base64(method:password)@host:port#name
        // SIP002 plugin parameters (obfs etc.) are refused when they ask
        // for anything beyond era "simple-obfs"-free operation: the pinned
        // engine has no obfs plugin runtime, so accepting them silently
        // would misrepresent the connection.
        private static ServerEntry ParseShadowsocks(string link)
        {
            string body = link.Substring("ss://".Length);
            string name = "";
            int hash = body.IndexOf('#');
            if (hash >= 0) { name = Uri.UnescapeDataString(body.Substring(hash + 1)); body = body.Substring(0, hash); }
            string method, password, host;
            int port;
            int at = body.LastIndexOf('@');
            if (at >= 0 && body.IndexOf('@') == at && IsBase64ish(body.Substring(0, at)) && body.Substring(at + 1).IndexOf(':') > 0 && !body.Substring(0, at).Contains(":"))
            {
                // SIP002
                string creds = DecodeBase64(Uri.UnescapeDataString(body.Substring(0, at)), "Shadowsocks link is malformed.");
                SplitCreds(creds, out method, out password);
                // The query (?plugin=...) sits AFTER host:port in a SIP002
                // link, so it must be separated BEFORE SplitHostPort:
                // parsing the port first would choke on
                // "8388?plugin=..." and the named SIP003 refusal below
                // would never be reached.
                string hostPort = body.Substring(at + 1);
                string query = "";
                int q = hostPort.IndexOf('?');
                if (q >= 0) { query = hostPort.Substring(q + 1); hostPort = hostPort.Substring(0, q); }
                hostPort = hostPort.TrimEnd('/');
                if (query.IndexOf("plugin=", StringComparison.OrdinalIgnoreCase) >= 0)
                    EraGate.Refuse("Shadowsocks plugins", "The pinned engine has no SIP003 plugin runtime; a plugin link would not behave as its author intended.");
                SplitHostPort(hostPort, out host, out port);
            }
            else
            {
                string decoded = DecodeBase64(body, "Shadowsocks link is malformed.");
                int credEnd = decoded.LastIndexOf('@');
                if (credEnd < 0) throw new FormatException("Shadowsocks link is malformed.");
                SplitCreds(decoded.Substring(0, credEnd), out method, out password);
                SplitHostPort(decoded.Substring(credEnd + 1), out host, out port);
            }
            var e = new ServerEntry();
            e.Protocol = "shadowsocks";
            e.Name = name;
            e.Method = (method ?? "").ToLowerInvariant();
            e.Password = password ?? "";
            e.Address = host;
            e.Port = port;
            e.Validate();
            return e;
        }

        // socks://base64(user:pass@host:port) or socks://host:port (era
        // v2rayN also emitted a plain form); user info is optional.
        private static ServerEntry ParseSocks(string link)
        {
            string body = link.Substring("socks://".Length);
            string name = "";
            int hash = body.IndexOf('#');
            if (hash >= 0) { name = Uri.UnescapeDataString(body.Substring(hash + 1)); body = body.Substring(0, hash); }
            string decoded = body;
            if (body.IndexOf('@') < 0 && body.IndexOf(':') < 0 || IsBase64ish(body))
            {
                try { decoded = Encoding.UTF8.GetString(Convert.FromBase64String(PadBase64(StripWhitespace(body)))); }
                catch (FormatException) { decoded = body; }
            }
            string host; int port;
            int at = decoded.LastIndexOf('@');
            string hostPort = at >= 0 ? decoded.Substring(at + 1) : decoded;
            SplitHostPort(hostPort, out host, out port);
            var e = new ServerEntry();
            e.Protocol = "socks";
            e.Name = name;
            e.Address = host;
            e.Port = port;
            e.Validate();
            return e;
        }

        public static List<ServerEntry> ParseSubscriptionBody(string body)
        {
            if (body == null) throw new FormatException("Subscription body is empty.");
            string text = body.Trim();
            // Era subscriptions are a base64 document of newline-separated
            // links; a plain-text list is accepted too.
            if (!text.Contains("://"))
            {
                text = DecodeBase64(text, "Subscription body is not valid base64.");
            }
            var result = new List<ServerEntry>();
            var errors = new List<string>();
            foreach (string raw in text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string line = raw.Trim();
                if (line.Length == 0) continue;
                try { result.Add(ParseLink(line)); }
                catch (FormatException ex) { errors.Add(ex.Message); }
            }
            if (result.Count == 0)
                throw new FormatException(errors.Count > 0
                    ? "No usable era servers in subscription. First refusal: " + errors[0]
                    : "No servers in subscription.");
            return result;
        }

        // Base64 decoding whose failure is an authored sentence, never
        // the runtime's FormatException text: every FormatException that
        // reaches the UI (MainForm.ShowError) is a sentence written in
        // this assembly, and the decoder's own wording ("Invalid length
        // for a Base-64 char array…" and friends) must not leak through
        // it. The same applies to JsonMini's tokenizer wording, which
        // callers of JsonMini.Parse translate at their boundary.
        private static string DecodeBase64(string payload, string failure)
        {
            try
            {
                return Encoding.UTF8.GetString(Convert.FromBase64String(PadBase64(StripWhitespace(payload))));
            }
            catch (FormatException) { throw new FormatException(failure); }
        }

        private static void SplitCreds(string creds, out string method, out string password)
        {
            int colon = creds.IndexOf(':');
            if (colon < 0) throw new FormatException("Credentials are malformed (no ':' separator).");
            method = creds.Substring(0, colon);
            password = creds.Substring(colon + 1);
        }

        private static void SplitHostPort(string hostPort, out string host, out int port)
        {
            int colon = hostPort.LastIndexOf(':');
            if (colon < 0) throw new FormatException("Address has no port.");
            host = hostPort.Substring(0, colon).Trim('[', ']');
            if (!int.TryParse(hostPort.Substring(colon + 1), out port))
                throw new FormatException("Address port is not a number.");
        }

        private static bool IsBase64ish(string s)
        {
            if (string.IsNullOrEmpty(s)) return false;
            foreach (char c in s)
            {
                bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                          || c == '+' || c == '/' || c == '-' || c == '_' || c == '=' || c == '%';
                if (!ok) return false;
            }
            return true;
        }

        private static string StripWhitespace(string s)
        {
            var sb = new StringBuilder(s.Length);
            foreach (char c in s) if (!char.IsWhiteSpace(c)) sb.Append(c);
            return sb.ToString();
        }

        private static string PadBase64(string s)
        {
            s = s.Replace('-', '+').Replace('_', '/');
            int rem = s.Length % 4;
            if (rem == 1) throw new FormatException("Base64 payload has an invalid length.");
            if (rem > 0) s = s.PadRight(s.Length + (4 - rem), '=');
            return s;
        }
    }
}
