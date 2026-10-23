using System;

namespace Sora.Ancient
{
    // The era allowlist. Every entry here was proven against the pinned
    // engine binary (v2ray-core v3.36, Linux build of the same release —
    // config grammar is platform-independent): `v2ray -test` PASS, plus a
    // strings() cross-check because v2ctl's JSON converter is LENIENT
    // about unknown streamSettings.security values (it accepted
    // "reality"/"xtls" strings that the binary does not contain at all).
    // Anything not listed is refused by name — never passed to the engine
    // in the hope it might work.
    internal static class EraGate
    {
        // Proven by -test PASS on the pinned binary.
        public static readonly string[] Protocols = { "vmess", "shadowsocks", "socks" };
        // Proven by -test PASS. "h2" is the share-link spelling; the engine
        // config name is "http".
        public static readonly string[] Networks = { "tcp", "ws", "kcp", "h2" };
        // Proven by -test PASS: aes-256-gcm, aes-128-gcm, chacha20-poly1305,
        // chacha20-ietf-poly1305 and the legacy stream ciphers below.
        // Proven FAIL and therefore refused: 2022-blake3-* (SS-2022 did not
        // exist in 2018), aes-192-gcm, xchacha20-poly1305, "none".
        public static readonly string[] ShadowsocksMethods =
        {
            "aes-256-gcm", "aes-128-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305",
            "aes-256-cfb", "aes-128-cfb", "chacha20", "chacha20-ietf", "rc4-md5"
        };
        public static readonly string[] VmessSecurities = { "auto", "none", "aes-128-gcm", "chacha20-poly1305" };

        public static void Refuse(string feature, string reason)
        {
            throw new FormatException("Not supported in Sora Ancient: " + feature + ". " + reason);
        }

        public static void CheckScheme(string scheme)
        {
            switch ((scheme ?? "").ToLowerInvariant())
            {
                case "vmess":
                case "ss":
                case "socks":
                    return;
                case "vless":
                    Refuse("VLESS", "It appeared years after this engine.");
                    return;
                case "trojan":
                    Refuse("Trojan", "It appeared years after this engine.");
                    return;
                case "hysteria":
                case "hysteria2":
                case "hy2":
                    Refuse("Hysteria", "It appeared years after this engine.");
                    return;
                case "tuic":
                    Refuse("TUIC", "It appeared years after this engine.");
                    return;
                case "wireguard":
                case "wg":
                    Refuse("WireGuard outbound", "It appeared years after this engine.");
                    return;
                default:
                    Refuse("scheme '" + scheme + "'", "Only vmess://, ss:// and socks:// links are supported.");
                    return;
            }
        }

        public static void CheckServer(ServerEntry e)
        {
            if (Array.IndexOf(Protocols, e.Protocol) < 0)
                Refuse("protocol '" + e.Protocol + "'", "Only VMess, Shadowsocks and SOCKS are supported.");
            if (e.Protocol == "vmess")
            {
                Guid g;
                if (!Guid.TryParse(e.Uuid, out g))
                    throw new FormatException("VMess user ID is invalid.");
                if (Array.IndexOf(Networks, e.Network) < 0)
                    Refuse("transport '" + e.Network + "'", "Only TCP, WebSocket, KCP and HTTP/2 are supported here.");
                if (Array.IndexOf(VmessSecurities, e.Security) < 0)
                    Refuse("VMess security '" + e.Security + "'", "Supported values are auto, none, aes-128-gcm and chacha20-poly1305.");
                if (e.AlterId < 0 || e.AlterId > 65535)
                    throw new FormatException("VMess alterId is out of range.");
            }
            if (e.Protocol == "shadowsocks")
            {
                if (Array.IndexOf(ShadowsocksMethods, e.Method) < 0)
                    Refuse("Shadowsocks method '" + e.Method + "'", "It is not supported by this engine.");
                if (string.IsNullOrEmpty(e.Password))
                    throw new FormatException("Shadowsocks password is empty.");
            }
        }
    }
}
