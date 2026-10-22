using System;
using System.Collections.Generic;
using System.IO;
using Sora.Ancient;

namespace WineCheck
{
    internal static class Program
    {
        // Usage: WineCheck.exe <link> [outConfigPath]
        // Exercises, on the era runtime itself: link import (LinkParser),
        // era config generation (ConfigBuilder) and the store round-trip
        // (ServerStore.Save/Load under the prefix's %AppData%).
        private static int Main(string[] args)
        {
            try
            {
                if (args.Length < 1) { Console.WriteLine("WINECHECK FAIL usage: WineCheck.exe <link> [outConfigPath]"); return 2; }
                ServerEntry e = LinkParser.ParseLink(args[0]);
                Console.WriteLine("WINECHECK PASS import protocol=" + e.Protocol + " name=" + e.Name +
                                  " address=" + e.Address + " port=" + e.Port + " network=" + e.Network + " tls=" + e.Tls);
                string cfg = ConfigBuilder.Build(e, ConfigBuilder.DefaultSocksPort, ConfigBuilder.DefaultHttpPort);
                if (cfg.IndexOf("\"inbound\":{", StringComparison.Ordinal) < 0) throw new FormatException("config lacks singular inbound");
                if (cfg.IndexOf("\"inbounds\"", StringComparison.Ordinal) >= 0) throw new FormatException("config uses plural inbounds (post-era grammar)");
                string outPath = args.Length > 1 ? args[1] : ServerStore.RuntimeConfigPath;
                File.WriteAllText(outPath, cfg);
                Console.WriteLine("WINECHECK PASS config written=" + outPath + " bytes=" + cfg.Length);
                Console.WriteLine("WINECHECK CONFIG " + cfg);
                var list = new List<ServerEntry>(); list.Add(e);
                ServerStore.Save(list);
                List<ServerEntry> back = ServerStore.Load();
                if (back.Count != 1 || back[0].Address != e.Address || back[0].Uuid != e.Uuid)
                    throw new FormatException("store round-trip mismatch");
                Console.WriteLine("WINECHECK PASS store round-trip path=" + ServerStore.StorePath);
                Console.WriteLine("WINECHECK ALL PASS framework=" + Environment.Version);
                return 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("WINECHECK FAIL " + ex.GetType().Name + ": " + ex.Message);
                return 1;
            }
        }
    }
}
