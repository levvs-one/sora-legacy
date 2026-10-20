using System;
using System.Reflection;

// Pin tests for the pure logic of the new client (REVIEW-CS1 §4):
// SystemProxy.ParseFlags and the WinINet flag values behind it (F1),
// and ImportLink.Parse in both link forms (F4). The client's types
// are internal, so — like the GUI checks in Program.cs — these go
// through reflection on the loaded Sora.Legacy assembly. Run with
// the single argument --logic: no GUI, service or administrator
// rights are needed. Exit code 0 means every vector holds.
internal static class PinTests
{
    private static int failures;

    public static int Run()
    {
        var assembly = Assembly.Load("Sora.Legacy");
        CheckFlags(assembly);
        CheckLinks(assembly);
        if (failures == 0)
            Console.WriteLine("PASS pin tests: flag values, numeric vectors, PAC bit and both link forms hold");
        return failures == 0 ? 0 : 1;
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
