# Сборка из исходников

Все команды ниже проверены по фактическому составу репозитория. Пути — от корня репозитория, если не сказано иное.

## Что нужно

| Инструмент | Зачем |
| --- | --- |
| Go | служба ядра, модуль `core/`. Локально — системный Go или сборка из `~/workspace/go`; сборка службы для Windows 7 — только пропатченным Windows 7 SDK Go 1.26.9: в CI его собирает job `control-windows` (архив и его SHA-256 — в `.github/workflows/legacy.yml`), локально — скрипт `legacy/build/Build-CoreWin7.ps1`. Обычный `go build` системным Go даёт службу с полом Windows 10, см. предупреждение в разделе «Ядро (Go)» |
| .NET SDK 8 | клиенты и тесты C#. Проекты — .NET Framework 4.8; на Linux net48 собирается через ReferenceAssemblies, это проверенный путь тулчейна |
| Inno Setup 6 | установщик Windows из `legacy/installer/Sora.iss` (только на Windows) |
| nfpm | пакеты службы для Linux |
| C-компилятор, zlib, заголовки libnetfilter_queue/libnfnetlink/libmnl | сборка zapret (`tpws`/`nfqws`) для Linux-пакета |
| JDK 17, Android SDK (platform 34, build-tools 34.0.0), NDK 27.2, gomobile/gobind | AAR для Android (`mobileapi.aar`, `libbox.aar`) и ручной APK-пайплайн; канонические версии и хэши — в разделе «Android» |
| Swift 6.0.3 (Linux) | typecheck и тесты Foundation-частей macOS/iOS (`swift test`); AppKit/UIKit этим не собираются |
| Mac с Xcode, XcodeGen, Apple Developer аккаунт | сборка и подпись приложений macOS/iOS и обоих xcframework — в этой среде недоступны, спеки: `macos/README.md`, `ios/BUILD-MAC.md` |

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
| `core/mobileapi` | gomobile-фасад ядра для мобильных клиентов (`ImportLinks`/`ParseSubscription`/`BuildPlan`/`RenderSingBoxConfig`/`EngineInfo`) |
| `core/ipc` | транспорт службы; darwin-часть — верификация пира `LOCAL_PEERCRED` и сокет `/var/run/sora/core.sock` |
| `android` | Android-клиент (`one.levvs.sora.legacy`, Kotlin, framework Views) + ручной APK-пайплайн `tools/build-manual.sh` |
| `macos` | macOS-клиент: AppKit-приложение, Go-хелпер `helper/` (`sora-ctl`), пины движков `engines-darwin.lock` |
| `service/darwin` | корневой LaunchDaemon службы для macOS (plist, install/uninstall) |
| `ios` | iOS-клиент: UIKit-приложение, расширение PacketTunnel, SPM-пакет `SoraLegacyCore`, спека сборки `BUILD-MAC.md` |

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

> **Пол Windows задаёт SDK, а не рецепт.** Приведённая выше сборка системным
> Go даёт исполняемый файл с полом Windows 10: стоковый Go начиная с 1.21 на
> Windows 7 и 8.1 не запускается. Исполняемый файл для Windows 7 SP1
> получается только из пропатченного SDK XTLS/go-win7 (базовая линия NT 6.1):
> в CI это job `control-windows` workflow `legacy.yml`, локально — та же
> последовательность одним скриптом:
>
> ```powershell
> # из legacy/, на Windows, стоковый Go версии из core/go.mod — в PATH
> .\build\Build-CoreWin7.ps1
> ```
>
> Скрипт скачивает тот же архив SDK, сверяет его SHA-256 и `VERSION` с
> версией из `core/go.mod`, собирает SDK стоковым Go и кладёт
> `sora-legacy-core-x86.exe` и `sora-legacy-core-x64.exe` в
> `legacy/artifacts` — те же имена, что у артефактов CI. Ядро, собранное
> обычным `go build`, на Windows 7 не стартует; не выдавайте его за сборку
> для Windows 7.

На Windows служба регистрируется сама: `sora-core --install-service` (служба `SoraLegacyCore`), снимается — `sora-core --uninstall-service`. Каталог данных по умолчанию — `%APPDATA%\sora-legacy\core` на Windows и `~/.config/sora-legacy/core` на Linux; для привилегированного запуска переменная окружения `SORA_LEGACY_DATA_DIR` игнорируется сознательно (см. `core/cmd/sora-core/cli.go`).

## Клиенты и тесты (C#)

В репозитории шесть проектов с целевым net48: пять ниже (новый клиент, Control и три интероп-теста; `Control` и `ControlInterop` при этом мультитаргетны — `net48;net8.0`) плюс поставляемый `legacy/v2rayN/v2rayN/v2rayN.csproj`, который собирается профилями из следующего раздела:

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

Для Windows-комплекта движки берутся не из lock, а из compat payload, и `Stage-Release.ps1` сверяет `xray.exe`, `sing-box.exe` и файлы `tun2proxy` с SHA-256, закреплёнными прямо в скрипте. Payload-Xray — тот же выпуск, что и пол каталога ядра: `Xray-win7-32` v26.3.27 (поднят с 25.9.11, который не несёт Hysteria-аутбаунд каталога; доказательства бинарями и Win7-PE — LEGACY-FULL-2-XRAY). Windows-вариант sing-box в payload — lx-форк (см. `legacy/PLANS.md`); Linux-lock держит upstream 1.14.3. Возможности, существующие только в lx (например, REALITY KeyShare), ядро заявляет только при обнаружении lx-сборки.

## Zapret (шаг сборки Linux-пакета)

`nfpm.yaml` требует в `dist/engines` бинари `tpws`, `nfqws` и каталог `zapret/fake`, которых `fetch.sh` не даёт. Их собирает отдельный шаг — без него рецепт пакета падает на шаге nfpm:

```sh
packaging/zapret/build.sh dist/engines
```

Скрипт собирает `tpws` и `nfqws` из vendored-копии в `third_party/zapret` во временном каталоге (vendored-дерево не изменяется), кладёт fake-рукопожатия в `dist/engines/zapret/fake` и **дописывает** дайджесты `tpws` и `nfqws` в `dist/engines/SHA256SUMS` — поэтому запускается строго после `fetch.sh`. Дайджест `tpws` служба проверяет строго; `nfqws` записан для полноты манифеста, это ядро использует tpws.

## Пакет службы для Linux

```sh
cd core && CGO_ENABLED=0 GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o ../dist/sora-core ./cmd/sora-core && cd ..
cd macos/helper && CGO_ENABLED=0 GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o ../../dist/sora-ctl . && cd ../..
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

## Мобильное ядро (mobileapi)

Общий фундамент Android и iOS. Пакет `core/mobileapi` собирается как обычный пакет ядра (кросс-сборки `GOOS=darwin` amd64/arm64 и `GOOS=android` arm64 — exit 0), тесты — в составе `go test ./...` из `core/`. Настоящий `gomobile bind` в сам репозиторий не делается: современный gomobile требует `golang.org/x/mobile` в графе модуля, поэтому bind выполняется из копии `core/` с добавленной tool-директивой (`go get -tool golang.org/x/mobile/cmd/gobind@…`) — исходники в копии не меняются. Версии, которыми строились AAR/xcframework в этой работе: официальный gomobile `golang.org/x/mobile v0.0.0-20261011034528-197770444867` (хост-Go 1.24.7, тулчейн модуля — 1.26.9 по `core/go.mod`); для libbox — sagernet gomobile v0.1.8 из `go.mod` пина sing-box 1.12.12. Детали Android-тулчейна (JDK, SDK, NDK, хэши пакетов и диагноз песочницы) — в `android/README.md` и отчётах отдела; спека iOS-bind — `ios/BUILD-MAC.md` §2.

## Android

Дерево `android/`: пакет `one.levvs.sora.legacy`, `minSdk 21` / `targetSdk 34`, зависимости — только Kotlin stdlib, framework API и `org.json` (без AndroidX/Compose).

Каноническая сборка (dev-машина): нужны JDK 17, Android SDK platform 34 / build-tools 34.0.0, NDK 27.2 и оба AAR в `android/app/libs/` (`mobileapi.aar` — gomobile bind `./mobileapi` с `-androidapi 21` из копии `core/`; `libbox.aar` — штатный bind пина sing-box 1.12.12; AAR в git не коммитятся):

```sh
cp /path/to/mobileapi.aar /path/to/libbox.aar android/app/libs/
cd android && ./gradlew assembleDebug
```

AGP 8.5.2 + Kotlin 2.0.21, Gradle 8.7 (wrapper properties в `gradle/wrapper/`; сам wrapper jar в песочнице сгенерировать нечем — на dev-машине это `gradle wrapper` одной командой).

Ручной пайплайн (песочница): Gradle в этой среде невозможен — демон общается по loopback-TCP, который песочница перехватывает у Java-процессов (`Could not receive a message from the daemon` до резолва плагинов). Замена на официальных инструментах:

```sh
bash android/tools/build-manual.sh
```

Скрипт: kotlinc 2.0.21 (zip скачивается curl'ом, SHA-256 `0352c0a45bd22f80f6b26e485cd04da8047baa5de54865281fb9f89a4a7bcf2a` закреплён в скрипте и перепроверяется на каждом запуске) компилирует Kotlin + сгенерированный `R.java` против `android.jar` (34) и classes.jar обоих AAR; дальше aapt2 compile+link, d8 (с дедупом `go/**`: остаётся копия libbox), zip из dex + ресурсов + `lib/<abi>/*.so`, zipalign, apksigner debug-ключом. Результат этой среды: APK 279 213 197 байт, SHA-256 `81f55b9fee04d778ff5daa305c19a8fb7f6f42f7b131f6ea430491c474dcaa7c`, `apksigner verify` — v1/v2/v3 true. Известный след пайплайна: d8 из build-tools 34 печатает `malformed kotlin.Metadata` по классам Kotlin 2.0 — dex при этом валиден, AGP-сборка этого предупреждения не имеет. На устройстве сборка не проверялась (verify-on-device — `android/README.md`).

## macOS

Три части: демон и хелпер (Go), Swift-клиент, служба (launchd).

```sh
export PATH=$HOME/workspace/go/bin:$PATH
# демон и хелпер — реальные darwin Mach-O, обе архитектуры
cd core && CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath ./cmd/sora-core
cd ../macos/helper && go test ./... && CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath .
# движки службы (пины и SHA-256 — macos/engines-darwin.lock)
sh macos/fetch-engines-darwin.sh amd64 build/darwin/engines
# Swift-ядро клиента (Foundation-only): typecheck и тесты возможны и на Linux
cd macos && swift test
```

Что этим доказано: тесты хелпера гоняют настоящий стек ipc + legacycontrol + control (стаб — только движок); `swift test` — 8/8 по `macos/App/Core`. Файлы `macos/App/UI` (AppKit) на Linux только `swiftc -parse` — не typecheck. Полы измерены по Mach-O: демон и `sora-ctl` — macOS 12.0 обе архитектуры; клиент проектируется под 10.13 (API ≤ 10.13 в общем пути); sing-box службы на amd64 пиннится legacy-ассетом 10.13, на arm64 regular-ассет требует macOS 26 (см. `macos/engines-darwin.lock`).

Сборка приложения — только на Mac: `brew install xcodegen`, `xcodegen generate --spec macos/project.yml`, сборка таргета (deployment 10.13) в Xcode; установка службы — `sudo sh service/darwin/install.sh <каталог с бинарями и движками>`. Verify-on-mac — 8 пунктов в `macos/README.md`; kill switch на darwin не форсится (`NoopFirewall` в `core/guard`) — в коде и UI это помечено, не маскируется.

## iOS

В этой среде iOS не собирается: нет Xcode и Apple SDK. Проверяемое здесь:

```sh
cd ios/SoraLegacyCore && swift test   # Linux Swift 6.0.3: 19/19
swiftc -parse <каждый Swift-файл дерева>   # 18/18; App/ и PacketTunnel/ — parse-only, не typecheck
```

Полная сборка — только на Mac, точная спека — `ios/BUILD-MAC.md`:

1. **Libbox.xcframework** — из исходников пина sing-box 1.12.12 (архив SHA-256 `f08add81eab7e4d6091195179bb39fa3f64dbb0326feaa022994566b702d1245`): сначала sagernet gomobile/gobind v0.1.8 в `GOPATH/bin` (без них `build_libbox` фаталит), затем `go run ./cmd/internal/build_libbox -target apple -platform ios`.
2. **Mobileapi.xcframework** — официальным gomobile (версии — раздел «Мобильное ядро» выше) из копии `core/` с tool-директивой: `gomobile bind -target ios -iosversion 13.0 -o ios/Frameworks/Mobileapi.xcframework ./mobileapi`.
3. **Проект** — `brew install xcodegen`, `xcodegen generate --spec ios/project.yml`; подписи, entitlements (packet-tunnel, App Group `group.one.levvs.sora.legacy`, keychain group) и `DEVELOPMENT_TEAM` через `$(SORA_DEVELOPMENT_TEAM)` — `ios/BUILD-MAC.md` §3–§4. Оба фреймворка в git не коммитятся (`ios/Frameworks/`).

Пол iOS 13.0 — не декларация, а вывод из пина (`build_libbox` без `-iosversion` + дефолт sagernet gomobile v0.1.8), цепочка — `ios/BUILD-MAC.md` §1. Verify-on-mac — 11 пунктов там же (§7), включая сверку всех спеллингов `TODO(verify-on-mac)` с заголовками собранных фреймворков, реальный туннель на устройстве, Keychain round-trip и проверку нижней границы на iOS 13.
