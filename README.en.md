# Sora Legacy

[Русский](README.md)

A separate Sora client for older Windows (7 SP1, 8.1, 10, 11; x86, running on x64 via WoW64). The current Windows and Linux client is in [sora](https://github.com/levvs-one/sora).

There is no finished release yet, and the state is stated plainly:

- The executable that ships today is the v2rayN-based client (`sora_<target>.exe`). The new client (`legacy/Client`, .NET Framework 4.8) is built and covered by interop tests against the real core service, but it is **not in the delivery stage yet**.
- The installer already registers the `sora://` scheme, but the shipped client does not handle such links yet — a click is silently dropped today. The handler that imports a subscription from a link is the new client; the registration takes effect unchanged when the stage switches to it.
- Native .NET Framework 4.8 x86/x64 checks cover service access without administrator rights, the main screen, 31 interface languages and closing the app. These checks ran on modern Windows; Windows 7 SP1 and 8.1 runtime compatibility still needs verification on those systems.

Full documentation is in Russian: [installation, updates and uninstall](docs/install.md), [building from source](docs/development.md), [security notes](docs/security.md).

[Build checks](https://github.com/levvs-one/sora-legacy/actions/workflows/legacy.yml) · [Remaining work](legacy/PLANS.md) · [Build instructions](README.md)

[GPL-3.0](LICENSE). [Third-party notices](THIRD-PARTY-NOTICES.md).
