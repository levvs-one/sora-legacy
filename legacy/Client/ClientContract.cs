namespace Sora.Legacy.Client;

// The installer-facing contract of this client, in one place: the
// command-line arguments Sora.iss passes, the link scheme it
// registers and the per-user registry key shared with the shipped
// client (v2rayN keeps the same values in one home, Global.MyRegPath
// and its Program.cs). Every consumer uses these constants instead of
// spelling the literals, so the contract cannot drift between files
// the way a duplicated constant can.
internal static class ClientContract
{
    public const string SilentArgument = "--silent";
    public const string RestoreProxyArgument = "--restore-proxy";
    public const string WaitForArgument = "--wait-for";
    public const string LinkSchemePrefix = "sora://";
    public const string RegistryPath = @"Software\Sora";
}
