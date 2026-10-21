# Сборка из исходников

Все команды ниже проверены по фактическому составу репозитория. Пути — от корня репозитория, если не сказано иное.

## Что нужно

| Инструмент | Зачем |
| --- | --- |
| Go | служба ядра, модуль `core/`. Локально — системный Go или сборка из `~/workspace/go`; для Windows 7 службы CI собирает закреплённый Windows 7 SDK Go 1.26.9 (архив и его SHA-256 — в `.github/workflows/legacy.yml`) |
| .NET SDK 8 | клиенты и тесты C#. Проекты — .NET Framework 4.8; на Linux net48 собирается через ReferenceAssemblies, это проверенный путь тулчейна |
| Inno Setup 6 | установщик Windows из `legacy/installer/Sora.iss` (только на Windows) |
| nfpm | пакеты службы для Linux |
| C-компилятор, zlib, заголовки libnetfilter_queue/libnfnetlink/libmnl | сборка zapret (`tpws`/`nfqws`) для Linux-пакета |

## Каталоги

| Каталог | Что там |
| --- | --- |
| `core` | служба ядра на Go |
| `legacy/Client` | новый клиент (net48 WinForms) — в поставку пока не входит |
| `legacy/Control` | транспорт и управление сессиями нового клиента |
| `legacy/v2rayN` | поставляемый клиент |
| `legacy/tests` | интероп-тесты C# (`ClientInterop`, `ControlInterop`, `ServiceInterop`) и QA-скрипты PowerShell |
| `legacy/build`, `legacy/installer` | профили сборки, комплект (stage) и установщик Windows |
| `proto` | контракт `sora.core.v1` (в этом поколении — версия 1.7) |
| `packaging/engines` | `engines.lock`, `fetch.sh` |
| `packaging/zapret` | шаг сборки zapret для Linux-пакета |
| `packaging/linux` | nfpm-описание пакета службы |

## Ядро (Go)

```sh
cd core
go build ./...
go vet ./...
go test ./...
```

Сборка исполняемого файла службы:

```sh
# из core/
CGO_ENABLED=0 go build -trimpath -ldflags '-s -w -X main.buildVersion=<версия>' -o sora-core ./cmd/sora-core
```

На Windows служба регистрируется сама: `sora-core --install-service` (служба `SoraLegacyCore`), снимается — `sora-core --uninstall-service`. Каталог данных по умолчанию — `%APPDATA%\sora-legacy\core` на Windows и `~/.config/sora-legacy/core` на Linux; для привилегированного запуска переменная окружения `SORA_LEGACY_DATA_DIR` игнорируется сознательно (см. `core/cmd/sora-core/cli.go`).

## Клиенты и тесты (C#)

Пять проектов net48:

```sh
dotnet build legacy/Client/Sora.Legacy.Client.csproj -c Release -p:PlatformTarget=x86
dotnet build legacy/Control/Sora.Legacy.Control.csproj -c Release -p:PlatformTarget=x86
dotnet build legacy/tests/ControlInterop/ControlInterop.csproj -c Release -p:PlatformTarget=x86
dotnet build legacy/tests/ServiceInterop/ServiceInterop.csproj -c Release -p:PlatformTarget=x86
dotnet build legacy/tests/ClientInterop/ClientInterop.csproj -c Release -p:PlatformTarget=x86
```

`-p:PlatformTarget=x64` даёт 64-битные варианты там, где они применимы. Сборка проходит и на Linux; запуск net48 — только на Windows.

## Поставляемый клиент: профили Windows

```powershell
# из legacy/
.\build\Build-WindowsProfiles.ps1
```

Собирает четыре профиля x86 поставляемого клиента — `sora_win7.exe`, `sora_win8.exe`, `sora_win10.exe`, `sora_win11.exe` (win8 — это 8.1). В CI те же профили собирает job `windows-x86` workflow `legacy.yml`, плюс регрессия подписок на собранном exe.

## Движки

Версии и SHA-256 закреплены в `packaging/engines/engines.lock`:

| Движок | Версия в lock |
| --- | --- |
| sing-box (upstream SagerNet) | 1.14.3 |
| Xray | 26.3.27 (сознательно: XTLS помечает более новые теги как prerelease, lock держит только stable) |
| mihomo | 1.19.32 |

```sh
packaging/engines/fetch.sh amd64 dist/engines
```

`fetch.sh` скачивает архивы по HTTPS и останавливается, если сумма хоть одного не совпала; базы geoip/geosite берутся из архива Xray той же версии. После раскладки пишется `SHA256SUMS` с дайджестами извлечённых бинарей — по нему служба сверяет движки при запуске (fail-closed).

Для Windows-комплекта движки берутся не из lock, а из compat payload, и `Stage-Release.ps1` сверяет `xray.exe`, `sing-box.exe` и файлы `tun2proxy` с SHA-256, закреплёнными прямо в скрипте. Windows-вариант sing-box в payload — lx-форк (см. `legacy/PLANS.md`); Linux-lock держит upstream 1.14.3. Возможности, существующие только в lx (например, REALITY KeyShare), ядро заявляет только при обнаружении lx-сборки.

## Zapret (шаг сборки Linux-пакета)

`nfpm.yaml` требует в `dist/engines` бинари `tpws`, `nfqws` и каталог `zapret/fake`, которых `fetch.sh` не даёт. Их собирает отдельный шаг — без него рецепт пакета падает на шаге nfpm:

```sh
packaging/zapret/build.sh dist/engines
```

Скрипт собирает `tpws` и `nfqws` из vendored-копии в `third_party/zapret` во временном каталоге (vendored-дерево не изменяется), кладёт fake-рукопожатия в `dist/engines/zapret/fake` и **дописывает** дайджесты `tpws` и `nfqws` в `dist/engines/SHA256SUMS` — поэтому запускается строго после `fetch.sh`. Дайджест `tpws` служба проверяет строго; `nfqws` записан для полноты манифеста, это ядро использует tpws.

## Пакет службы для Linux

```sh
cd core && CGO_ENABLED=0 GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o ../dist/sora-core ./cmd/sora-core && cd ..
packaging/engines/fetch.sh amd64 dist/engines
packaging/zapret/build.sh dist/engines
SORA_ARCH=amd64 SORA_VERSION=0.3.0 nfpm package --config packaging/linux/nfpm.yaml --packager deb --target dist/
```

`--packager rpm` и `--packager archlinux` — остальные форматы. Детали состава пакета — [packaging/linux/README.md](../packaging/linux/README.md).

## Установщик Windows

```powershell
# 1. Профили поставляемого клиента (см. выше) — источник бинарей комплекта.
# 2. Комплект: сверяет SHA-256 движков и tun-файлов payload, требует
#    обязательный состав файлов.
.\legacy\build\Stage-Release.ps1 -SourceBin <каталог сборки клиента> -StagePath <каталог>\stage -CompatPayload <payload> -XrayArchive <архив Xray> -WindowsTarget win7
# 3. Установщик (Inno Setup), профиль по умолчанию — Windows 7 SP1.
iscc legacy\installer\Sora.iss
```

Профили 8.1/10/11 задаются определениями Inno Setup (`WindowsTarget`, `WindowsDisplayName`, `MinimumWindowsVersion`), значения по умолчанию в `Sora.iss` — win7 / `6.1sp1`. Встроенные установщики .NET Framework 4.8 и KB3033929 скрипт ожидает рядом и сверяет по SHA-256 внутри себя; их хеши закреплены в `Sora.iss`.
