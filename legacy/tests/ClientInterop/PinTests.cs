using System;
using System.Collections.Generic;
using System.Reflection;

// Pin tests for the pure logic of the new client (REVIEW-CS1 §4):
// SystemProxy.ParseFlags and the WinINet flag values behind it (F1),
// ImportLink.Parse in both link forms (F4), and Mnemonic.Mark —
// including text that already carries '&' and the RU trayOpen word
// order (REVIEW-CS2 §2). The client's types are internal, so — like
// the GUI checks in Program.cs — these go through reflection on the
// loaded Sora.Legacy assembly. Run with the single argument --logic:
// no GUI, service or administrator rights are needed. Exit code 0
// means every vector holds.
internal static class PinTests
{
    private static int failures;

    public static int Run()
    {
        var assembly = Assembly.Load("Sora.Legacy");
        CheckFlags(assembly);
        CheckLinks(assembly);
        CheckMnemonics(assembly);
        if (failures == 0)
            Console.WriteLine("PASS pin tests: flag values, numeric vectors, PAC bit, both link forms and mnemonic marking hold");
        return failures == 0 ? 0 : 1;
    }

    private static void CheckMnemonics(Assembly assembly)
    {
        var type = assembly.GetType("Sora.Legacy.Client.Mnemonic", true)!;
        var mark = type.GetMethod("Mark", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public)!;
        string Mark(string text, HashSet<char> used, params char[] candidates) =>
            (string)mark.Invoke(null, new object?[] { text, used, candidates })!;

        // Text already carrying a marker is returned exactly as
        // written — no second '&' is inserted — and its mnemonic
        // joins the surface set, so a later control cannot take it.
        var used = new HashSet<char>();
        Expect(Mark("&Save", used, 'S') == "&Save", "pre-marked text is returned as-is");
        Expect(used.Contains('S'), "pre-marked mnemonic is registered in used");
        Expect(Mark("Start", used, 'S', 'T') == "S&tart", "a registered mnemonic is skipped for a later control");
        // A bare '&' (here before a space) is left untouched: not
        // doubled, no second marker planted, nothing registered.
        used = new HashSet<char>();
        Expect(Mark("Save & Exit", used, 'S') == "Save & Exit", "bare & is left untouched");
        Expect(used.Count == 0, "bare & before a space registers no mnemonic");
        // The escaped literal form '&&' stays escaped and unmarked.
        Expect(Mark("Fish && Chips", new HashSet<char>(), 'F') == "Fish && Chips", "escaped && is left untouched");
        // Tray Open, with the candidate order MainForm passes: the
        // localized word is preferred over the product-name tail, and
        // English is unaffected (no Cyrillic О in "Open Sora").
        Expect(Mark("Открыть Sora", new HashSet<char>(), 'О', 'O') == "&Открыть Sora", "RU trayOpen marks the localized word");
        Expect(Mark("Open Sora", new HashSet<char>(), 'О', 'O') == "&Open Sora", "EN trayOpen still marks the Latin O");
        // No candidate present: text and used both stay untouched.
        used = new HashSet<char>();
        Expect(Mark("Open", used, 'X') == "Open" && used.Count == 0, "no candidate leaves the text unchanged");
        // Uniqueness on a surface: a taken candidate falls through to
        // the next candidate letter.
        Expect(Mark("Options", new HashSet<char> { 'O' }, 'O', 'P') == "O&ptions", "taken candidate falls through to the next");
    }

    private static void CheckFlags(Assembly assembly)
    {
        var type = assembly.GetType("Sora.Legacy.Client.SystemProxy", true)!;
        var parse = type.GetMethod("ParseFlags", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public)!;
        int? Flags(string? raw) => (int?)parse.Invoke(null, new object?[] { raw });

        // The flag values themselves are the F1 pin: they must equal
        // the reference enum (v2rayN/Handler/ProxySetting.cs,
        // PerConnFlags) and the WinINet INTERNET_PER_CONN_FLAGS standard.
        Expect(Constant(type, "FlagDirect") == 1, "FlagDirect == 1");
        Expect(Constant(type, "FlagProxy") == 2, "FlagProxy == 2");
        Expect(Constant(type, "FlagAutoProxyUrl") == 4, "FlagAutoProxyUrl == 4 (PROXY_TYPE_AUTO_PROXY_URL)");
        Expect(Constant(type, "FlagAutoDetect") == 8, "FlagAutoDetect == 8 (PROXY_TYPE_AUTO_DETECT)");

        // The numeric form is what the recorder actually writes.
        Expect(Flags(null) == 1, "ParseFlags(null) == 1");
        Expect(Flags("") == 1, "ParseFlags(\"\") == 1");
        Expect(Flags("1") == 1, "ParseFlags(\"1\") == 1");
        Expect(Flags("5") == 5, "ParseFlags(\"5\") == 5");
        Expect(Flags("7") == 7, "ParseFlags(\"7\") == 7");
        Expect(Flags("13") == 13, "ParseFlags(\"13\") == 13");
        Expect(Flags("15") == 15, "ParseFlags(\"15\") == 15");
        Expect(Flags("PROXY_TYPE_DIRECT|PROXY_TYPE_AUTO_PROXY_URL") == 5, "token form == 5");
        Expect(Flags("PROXY_TYPE_AUTO_DETECT") == 8, "token AUTO_DETECT == 8");
        Expect(Flags("bogus") == null, "unknown token fails the record");

        // The PAC predicate of Restore(): AutoConfigURL is written
        // back exactly when the AUTO_PROXY_URL bit (4) is set — "9"
        // (DIRECT|AUTO_DETECT) must not resurrect a PAC URL.
        var pacBit = Constant(type, "FlagAutoProxyUrl");
        foreach (var (raw, pac) in new[] { ("1", false), ("5", true), ("7", true), ("13", true), ("15", true), ("9", false), ("3", false), ("2", false) })
        {
            var flags = Flags(raw);
            Expect(flags != null && ((flags.Value & pacBit) != 0) == pac, "PAC bit for \"" + raw + "\"");
        }
    }

    private static void CheckLinks(Assembly assembly)
    {
        var type = assembly.GetType("Sora.Legacy.Client.ImportLink", true)!;
        var parse = type.GetMethod("Parse", BindingFlags.Static | BindingFlags.Public)!;
        (string Url, string Name)? Link(string raw)
        {
            var link = parse.Invoke(null, new object?[] { raw });
            if (link == null) return null;
            var linkType = link.GetType();
            return ((string)linkType.GetProperty("Url")!.GetValue(link)!,
                    (string)linkType.GetProperty("Name")!.GetValue(link)!);
        }

        var inline = Link("sora://add/https://example.com/sub?token=abc");
        Expect(inline != null && inline.Value.Url == "https://example.com/sub?token=abc" && inline.Value.Name == "",
            "add/<url> verbatim form");
        var encoded = Link("sora://add/https%3A%2F%2Fexample.com%2Fsub");
        Expect(encoded != null && encoded.Value.Url == "https://example.com/sub",
            "add/<url> percent-encoded form decodes once");
        var query = Link("sora://add?url=https%3A%2F%2Fexample.com%2Fsub&name=My%2520Sub");
        Expect(query != null && query.Value.Url == "https://example.com/sub" && query.Value.Name == "My%20Sub",
            "query form: name decoded exactly once (F4)");
        var spaced = Link("sora://add?url=https%3A%2F%2Fexample.com%2Fsub&name=My%20Sub");
        Expect(spaced != null && spaced.Value.Name == "My Sub", "query form: %20 in the name is a space");
        var fragment = Link("sora://add?url=https%3A%2F%2Fexample.com%2Fsub#My%20Sub");
        Expect(fragment != null && fragment.Value.Name == "My Sub", "fragment name is decoded");
        Expect(Link("sora://routing/add/https://example.com/sub") == null, "routing form is refused");
        Expect(Link("sora://add/ftp://example.com/sub") == null, "non-http(s) target is refused");
    }

    private static int Constant(Type type, string name) =>
        (int)type.GetField(name, BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public)!.GetValue(null)!;

    private static void Expect(bool condition, string what)
    {
        if (condition) return;
        failures++;
        Console.Error.WriteLine("FAIL pin test: " + what);
    }
}
