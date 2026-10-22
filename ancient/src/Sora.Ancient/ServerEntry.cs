using System;
using System.Collections.Generic;
using System.Text;

namespace Sora.Ancient
{
    // One server as the era engine (v2ray-core v3.36) can run it. Fields
    // that later protocols need simply do not exist here; EraGate refuses
    // links that would need them instead of silently degrading a config.
    internal sealed class ServerEntry
    {
        public string Name = "";
        public string Protocol = ""; // "vmess" | "shadowsocks" | "socks"
        public string Address = "";
        public int Port;
        // vmess
        public string Uuid = "";
        public int AlterId = 64; // era default; AEAD (alterId 0) exists in the binary's config parser but era servers overwhelmingly used legacy VMess — kept explicit, never invented
        public string Security = "auto"; // vmess user security: auto/none/aes-128-gcm/chacha20-poly1305
        // shadowsocks
        public string Method = "";
        public string Password = "";
        // transport (vmess)
        public string Network = "tcp"; // tcp | ws | kcp | h2 (rendered "http" for the engine)
        public string HostHeader = "";
        public string Path = "";
        public bool Tls;
        public string Sni = "";

        public string DisplayName
        {
            get
            {
                string n = string.IsNullOrEmpty(Name) ? Address : Name;
                return n + "  [" + Protocol + " " + Address + ":" + Port + "]";
            }
        }

        public string ToStoreJson()
        {
            var sb = new StringBuilder();
            sb.Append('{');
            Field(sb, "name", Name, true);
            Field(sb, "protocol", Protocol, false);
            Field(sb, "address", Address, false);
            sb.Append(",\"port\":").Append(Port);
            Field(sb, "uuid", Uuid, false);
            sb.Append(",\"alterId\":").Append(AlterId);
            Field(sb, "security", Security, false);
            Field(sb, "method", Method, false);
            Field(sb, "password", Password, false);
            Field(sb, "network", Network, false);
            Field(sb, "host", HostHeader, false);
            Field(sb, "path", Path, false);
            sb.Append(",\"tls\":").Append(Tls ? "true" : "false");
            Field(sb, "sni", Sni, false);
            sb.Append('}');
            return sb.ToString();
        }

        private static void Field(StringBuilder sb, string key, string value, bool first)
        {
            if (!first) sb.Append(',');
            sb.Append(JsonMini.Quote(key)).Append(':').Append(JsonMini.Quote(value ?? ""));
        }

        public static ServerEntry FromStoreJson(Dictionary<string, object> map)
        {
            var e = new ServerEntry();
            e.Name = JsonMini.GetString(map, "name", "");
            e.Protocol = JsonMini.GetString(map, "protocol", "");
            e.Address = JsonMini.GetString(map, "address", "");
            e.Port = JsonMini.GetInt(map, "port", 0);
            e.Uuid = JsonMini.GetString(map, "uuid", "");
            e.AlterId = JsonMini.GetInt(map, "alterId", 64);
            e.Security = JsonMini.GetString(map, "security", "auto");
            e.Method = JsonMini.GetString(map, "method", "");
            e.Password = JsonMini.GetString(map, "password", "");
            e.Network = JsonMini.GetString(map, "network", "tcp");
            e.HostHeader = JsonMini.GetString(map, "host", "");
            e.Path = JsonMini.GetString(map, "path", "");
            object tls;
            e.Tls = map != null && map.TryGetValue("tls", out tls) && (tls as bool?) == true;
            e.Sni = JsonMini.GetString(map, "sni", "");
            return e;
        }

        public void Validate()
        {
            if (string.IsNullOrEmpty(Address)) throw new FormatException("Server address is empty.");
            if (Port < 1 || Port > 65535) throw new FormatException("Server port is out of range.");
            EraGate.CheckServer(this);
        }
    }
}
