using System.Text;

namespace Sora.Ancient
{
    // Renders the config grammar of the pinned engine. v2ray-core v3.36
    // predates the plural "inbounds"/"outbounds" arrays of 4.x: its JSON
    // loader takes singular "inbound" / "outbound" objects (proven: the
    // plural form fails its own -test with "no inbound config specified").
    // Rendering the modern shape here would produce a client whose every
    // config the engine rejects.
    internal static class ConfigBuilder
    {
        public const int DefaultSocksPort = 10808;
        public const int DefaultHttpPort = 10809;

        public static string Build(ServerEntry server, int socksPort, int httpPort)
        {
            server.Validate();
            var sb = new StringBuilder();
            sb.Append("{\"log\":{\"loglevel\":\"warning\"},");
            // One inbound object in era grammar: SOCKS on the primary port;
            // the HTTP inbound rides inboundDetour, the era mechanism for
            // additional inbounds (both proven by -test on the pinned build).
            sb.Append("\"inbound\":{\"listen\":\"127.0.0.1\",\"port\":").Append(socksPort)
              .Append(",\"protocol\":\"socks\",\"settings\":{\"auth\":\"noauth\",\"udp\":true}},");
            sb.Append("\"inboundDetour\":[{\"listen\":\"127.0.0.1\",\"port\":").Append(httpPort)
              .Append(",\"protocol\":\"http\",\"settings\":{}}],");
            sb.Append("\"outbound\":").Append(Outbound(server));
            sb.Append('}');
            return sb.ToString();
        }

        private static string Outbound(ServerEntry e)
        {
            var sb = new StringBuilder();
            sb.Append("{\"protocol\":").Append(JsonMini.Quote(e.Protocol)).Append(",\"settings\":");
            if (e.Protocol == "vmess")
            {
                sb.Append("{\"vnext\":[{\"address\":").Append(JsonMini.Quote(e.Address))
                  .Append(",\"port\":").Append(e.Port)
                  .Append(",\"users\":[{\"id\":").Append(JsonMini.Quote(e.Uuid))
                  .Append(",\"alterId\":").Append(e.AlterId)
                  .Append(",\"security\":").Append(JsonMini.Quote(e.Security))
                  .Append("}]}]}");
                sb.Append(",\"streamSettings\":").Append(StreamSettings(e));
            }
            else if (e.Protocol == "shadowsocks")
            {
                sb.Append("{\"servers\":[{\"address\":").Append(JsonMini.Quote(e.Address))
                  .Append(",\"port\":").Append(e.Port)
                  .Append(",\"method\":").Append(JsonMini.Quote(e.Method))
                  .Append(",\"password\":").Append(JsonMini.Quote(e.Password))
                  .Append("}]}");
            }
            else // socks — era outbound is a bare server entry, no auth fields are emitted (the parser only accepts credential-free era socks links end-to-end here)
            {
                sb.Append("{\"servers\":[{\"address\":").Append(JsonMini.Quote(e.Address))
                  .Append(",\"port\":").Append(e.Port)
                  .Append("}]}");
            }
            sb.Append('}');
            return sb.ToString();
        }

        private static string StreamSettings(ServerEntry e)
        {
            string network = e.Network == "h2" ? "http" : e.Network;
            var sb = new StringBuilder();
            sb.Append("{\"network\":").Append(JsonMini.Quote(network));
            if (e.Tls)
            {
                sb.Append(",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":")
                  .Append(JsonMini.Quote(string.IsNullOrEmpty(e.Sni) ? e.Address : e.Sni))
                  .Append(",\"allowInsecure\":false}");
            }
            if (e.Network == "ws")
            {
                sb.Append(",\"wsSettings\":{\"path\":").Append(JsonMini.Quote(string.IsNullOrEmpty(e.Path) ? "/" : e.Path));
                if (!string.IsNullOrEmpty(e.HostHeader))
                    sb.Append(",\"headers\":{\"Host\":").Append(JsonMini.Quote(e.HostHeader)).Append('}');
                sb.Append('}');
            }
            else if (e.Network == "h2")
            {
                sb.Append(",\"httpSettings\":{\"path\":").Append(JsonMini.Quote(string.IsNullOrEmpty(e.Path) ? "/" : e.Path));
                if (!string.IsNullOrEmpty(e.HostHeader))
                    sb.Append(",\"host\":[").Append(JsonMini.Quote(e.HostHeader)).Append(']');
                sb.Append('}');
            }
            else if (e.Network == "kcp")
            {
                sb.Append(",\"kcpSettings\":{\"mtu\":1350,\"tti\":50,\"uplinkCapacity\":12,\"downlinkCapacity\":100,\"congestion\":false,\"readBufferSize\":2,\"writeBufferSize\":2,\"header\":{\"type\":\"none\"}}");
            }
            sb.Append('}');
            return sb.ToString();
        }
    }
}
