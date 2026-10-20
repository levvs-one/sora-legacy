using System.Configuration;

namespace Sora.Legacy.Client;

internal sealed class ClientSettings : ApplicationSettingsBase
{
    [UserScopedSetting, DefaultSettingValue("ru")]
    public string Language { get => (string)this[nameof(Language)]; set => this[nameof(Language)] = value; }

    [UserScopedSetting, DefaultSettingValue("")]
    public string Server { get => (string)this[nameof(Server)]; set => this[nameof(Server)] = value; }

    [UserScopedSetting, DefaultSettingValue("")]
    public string Engine { get => (string)this[nameof(Engine)]; set => this[nameof(Engine)] = value; }

    [UserScopedSetting, DefaultSettingValue("True")]
    public bool Tun { get => (bool)this[nameof(Tun)]; set => this[nameof(Tun)] = value; }

    [UserScopedSetting, DefaultSettingValue("False")]
    public bool KillSwitch { get => (bool)this[nameof(KillSwitch)]; set => this[nameof(KillSwitch)] = value; }

    // The in-app "launch at sign-in" option (ARB key launchAtLogin).
    // Program reconciles it with the registry Run value AutoRun owns at
    // startup; the value itself is the contract the uninstaller scans.
    [UserScopedSetting, DefaultSettingValue("False")]
    public bool AutoRun { get => (bool)this[nameof(AutoRun)]; set => this[nameof(AutoRun)] = value; }

    [UserScopedSetting, DefaultSettingValue("gvisor")]
    public string XrayStack { get => (string)this[nameof(XrayStack)]; set => this[nameof(XrayStack)] = value; }

    [UserScopedSetting, DefaultSettingValue("mixed")]
    public string MihomoStack { get => (string)this[nameof(MihomoStack)]; set => this[nameof(MihomoStack)] = value; }
}
