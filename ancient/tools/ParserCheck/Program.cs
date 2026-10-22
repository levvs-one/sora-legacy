using System;
using System.Text;
using Sora.Ancient;

namespace ParserCheck
{
    internal static class Program
    {
        private static int _failures;

        private static int Main()
        {
            // vmess v2 link (era shape)
            string vmessJson = "{\"v\":\"2\",\"ps\":\"era-node\",\"add\":\"example.com\",\"port\":\"443\",\"id\":\"b831381d-6324-4d53-ad4f-8cda48b30811\",\"aid\":\"64\",\"scy\":\"auto\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"cdn.example.com\",\"path\":\"/ray\",\"tls\":\"tls\",\"sni\":\"example.com\"}";
            ServerEntry vmess = LinkParser.ParseLink("vmess://" + B64(vmessJson));
            Eq("vmess name", vmess.Name, "era-node");
            Eq("vmess port", vmess.Port.ToString(), "443");
            Eq("vmess network", vmess.Network, "ws");
            Check("vmess tls", vmess.Tls);

            string cfg = ConfigBuilder.Build(vmess, 10808, 10809);
            Check("era config singular inbound", cfg.Contains("\"inbound\":{"));
            Check("era config no plural arrays", !cfg.Contains("\"inbounds\"") && !cfg.Contains("\"outbounds\""));
            Check("era config inboundDetour http", cfg.Contains("\"inboundDetour\"") && cfg.Contains("\"protocol\":\"http\""));
            Check("era config ws", cfg.Contains("\"network\":\"ws\""));

            // ss legacy + SIP002
            ServerEntry legacy = LinkParser.ParseLink("ss://" + B64("aes-256-gcm:secret@ss.example.com:8388") + "#legacy");
            Eq("ss legacy method", legacy.Method, "aes-256-gcm");
            Eq("ss legacy port", legacy.Port.ToString(), "8388");
            ServerEntry sip = LinkParser.ParseLink("ss://" + B64("chacha20-poly1305:secret") + "@ss.example.com:8389#sip");
            Eq("ss sip002 method", sip.Method, "chacha20-poly1305");
            Eq("ss sip002 port", sip.Port.ToString(), "8389");

            // subscription: base64 document with one good + one refused line
            string doc = "vmess://" + B64(vmessJson) + "\n" +
                         "trojan://pw@example.com:443#late-protocol";
            // One usable + one era-refused line: the usable entry imports,
            // the refused one is skipped (total refusal only when nothing
            // in the document is usable).
            System.Collections.Generic.List<ServerEntry> imported = LinkParser.ParseSubscriptionBody(B64(doc));
            Eq("subscription usable count", imported.Count.ToString(), "1");

            // Era refusals — each must throw FormatException naming the gate
            Refuses("vless", "vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443#x");
            Refuses("trojan", "trojan://pw@example.com:443#x");
            Refuses("ss-2022", "ss://" + B64("2022-blake3-aes-128-gcm:secret") + "@ss.example.com:8388#x");
            // SIP002 with a plugin query: the query sits after host:port
            // (host:port/?plugin=...), so this pins that query extraction
            // happens before port parsing and the refusal is the named
            // EraGate SIP003 refusal, not a generic port FormatException.
            // Control: the plain SIP002 link above (no plugin) still parses.
            Refuses("sip003-plugin", "ss://" + B64("chacha20-poly1305:secret") + "@ss.example.com:8389/?plugin=obfs-local#sip-plugin");
            string quicJson = vmessJson.Replace("\"net\":\"ws\"", "\"net\":\"quic\"");
            Refuses("quic", "vmess://" + B64(quicJson));
            string realityJson = vmessJson.Replace("\"tls\":\"tls\"", "\"tls\":\"reality\"");
            Refuses("reality", "vmess://" + B64(realityJson));

            // store round-trip
            var map = (System.Collections.Generic.Dictionary<string, object>)JsonMini.Parse(vmess.ToStoreJson());
            ServerEntry back = ServerEntry.FromStoreJson(map);
            Eq("store round-trip address", back.Address, vmess.Address);
            Eq("store round-trip uuid", back.Uuid, vmess.Uuid);

            Console.WriteLine(_failures == 0 ? "ParserCheck: ALL PASS" : "ParserCheck: " + _failures + " FAILURE(S)");
            return _failures == 0 ? 0 : 1;
        }

        private static string B64(string s)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(s));
        }

        private static void Eq(string name, string actual, string expected)
        {
            if (actual == expected) Console.WriteLine("PASS " + name);
            else Fail(name + " (got '" + actual + "', want '" + expected + "')");
        }

        private static void Check(string name, bool ok)
        {
            if (ok) Console.WriteLine("PASS " + name); else Fail(name);
        }

        private static void Refuses(string name, string link)
        {
            try
            {
                LinkParser.ParseLink(link);
                Fail("refusal " + name + " (link was accepted)");
            }
            catch (FormatException ex)
            {
                if (ex.Message.IndexOf("ancient", StringComparison.OrdinalIgnoreCase) >= 0)
                    Console.WriteLine("PASS refusal " + name);
                else
                    Fail("refusal " + name + " (message does not name the era gate: " + ex.Message + ")");
            }
        }

        private static void Fail(string name)
        {
            _failures++;
            Console.WriteLine("FAIL " + name);
        }
    }
}
