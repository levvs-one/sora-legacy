using System;
using System.Collections.Generic;
using System.Diagnostics;
using Microsoft.Win32;

namespace Sora.Legacy.Client;

// A sora:// import link, as registered in Sora.iss and as parsed by the
// sora client (app/lib/src/desktop/links.dart): sora://add/<url> with the
// subscription URL inline (percent-encoded when it has no scheme of its
// own) or sora://add?url=<url>&name=<name>. Only the subscription form
// is recognised: the legacy core has no routing-profile import, so
// sora://routing/add/… deliberately parses to null instead of being
// accepted and dropped. The target must be an HTTP(S) URL with a host;
// the core re-validates it (and requires https) when the subscription
// is saved, and its verdict is what the user sees.
internal sealed class ImportLink
{
    private ImportLink(string url, string name)
    {
        Url = url;
        Name = name;
    }

    public string Url { get; }
    public string Name { get; }

    // The link argument of a launch, if any: the shell passes the whole
    // sora://… URI as one quoted argument ("%1" in Sora.iss).
    public static string? FindArgument(string[] args)
    {
        foreach (var arg in args)
            if (arg.StartsWith(ClientContract.LinkSchemePrefix, StringComparison.OrdinalIgnoreCase)) return arg;
        return null;
    }

    public static ImportLink? Parse(string link)
    {
        try
        {
            link = link.Trim();
            var schemeEnd = link.IndexOf("://", StringComparison.Ordinal);
            if (schemeEnd <= 0) return null;
            if (!link.Substring(0, schemeEnd).Equals("sora", StringComparison.OrdinalIgnoreCase)) return null;
            var rest = link.Substring(schemeEnd + 3);
            if (rest.StartsWith("routing/add/", StringComparison.OrdinalIgnoreCase)) return null;
            if (rest.StartsWith("add/", StringComparison.OrdinalIgnoreCase))
            {
                var pasted = rest.Substring("add/".Length);
                return Subscription(pasted.Contains("://") ? pasted : Uri.UnescapeDataString(pasted), "");
            }
            if (!Uri.TryCreate(link, UriKind.Absolute, out var uri)) return null;
            if (!uri.Host.Equals("add", StringComparison.OrdinalIgnoreCase)) return null;
            var query = ParseQuery(uri.Query);
            if (!query.TryGetValue("url", out var target)) return null;
            // ParseQuery has already percent-decoded the query values
            // exactly once (as the reference parser in links.dart
            // does); decoding a query name again would corrupt names
            // that legitimately contain a %XX sequence. The fragment
            // fallback is the opposite: Uri.Fragment arrives still
            // escaped, so it is decoded here, once.
            if (query.TryGetValue("name", out var named)) return Subscription(target, named);
            return Subscription(target, Uri.UnescapeDataString(uri.Fragment.TrimStart('#')));
        }
        catch (UriFormatException) { return null; }
        catch (InvalidOperationException) { return null; }
    }

    private static ImportLink? Subscription(string target, string name)
    {
        target = target.Trim();
        if (target.IndexOfAny(new[] { '\r', '\n' }) >= 0) return null;
        if (!Uri.TryCreate(target, UriKind.Absolute, out var url)) return null;
        if (url.Scheme != Uri.UriSchemeHttp && url.Scheme != Uri.UriSchemeHttps) return null;
        if (url.Host.Length == 0) return null;
        return new ImportLink(target, name.Trim());
    }

    private static Dictionary<string, string> ParseQuery(string query)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in query.TrimStart('?').Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var equals = pair.IndexOf('=');
            if (equals < 0) continue;
            var key = Uri.UnescapeDataString(pair.Substring(0, equals).Replace('+', ' '));
            values[key] = Uri.UnescapeDataString(pair.Substring(equals + 1).Replace('+', ' '));
        }
        return values;
    }

    // Handing a link to the already-running instance: the second process
    // stores the link under the shared Software\Sora key (the same key
    // family that carries the window handle) and activates the first
    // window; the first instance polls for the value and imports it, so
    // the click in the browser is never lost with the exiting process.
    private static string PendingName => "PendingImport_" + AutoRun.DirectoryHash;

    public static void Forward(string link)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(ClientContract.RegistryPath);
            key.SetValue(PendingName, link);
        }
        catch (Exception exception)
        {
            Trace.WriteLine("Legacy client link forward: " + exception.GetType().Name);
        }
    }

    public static string? TakePending()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(ClientContract.RegistryPath, writable: true);
            if (key?.GetValue(PendingName) is not string link) return null;
            key.DeleteValue(PendingName, throwOnMissingValue: false);
            return link;
        }
        catch (Exception exception)
        {
            Trace.WriteLine("Legacy client link pending read: " + exception.GetType().Name);
            return null;
        }
    }
}
