using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Sora.Ancient
{
    // Server list persistence: %AppData%\Sora\Ancient\servers.json.
    // The file holds credentials (it IS the user's server list) — it is
    // written only under the per-user profile, never logged, and a damaged
    // file loads as an empty list with a named error instead of a crash.
    internal static class ServerStore
    {
        public static string DataDir
        {
            get
            {
                string dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Sora", "Ancient");
                Directory.CreateDirectory(dir);
                return dir;
            }
        }

        public static string StorePath { get { return Path.Combine(DataDir, "servers.json"); } }
        public static string ProxySnapshotPath { get { return Path.Combine(DataDir, "proxy-snapshot.json"); } }
        public static string RuntimeConfigPath { get { return Path.Combine(DataDir, "runtime-config.json"); } }

        public static List<ServerEntry> Load()
        {
            var list = new List<ServerEntry>();
            if (!File.Exists(StorePath)) return list;
            var arr = JsonMini.Parse(File.ReadAllText(StorePath)) as List<object>;
            if (arr == null) throw new FormatException("Saved server list is damaged.");
            foreach (object item in arr)
            {
                var map = item as Dictionary<string, object>;
                if (map != null) list.Add(ServerEntry.FromStoreJson(map));
            }
            return list;
        }

        public static void Save(List<ServerEntry> servers)
        {
            var sb = new StringBuilder();
            sb.Append('[');
            for (int i = 0; i < servers.Count; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append(servers[i].ToStoreJson());
            }
            sb.Append(']');
            File.WriteAllText(StorePath, sb.ToString());
        }
    }
}
