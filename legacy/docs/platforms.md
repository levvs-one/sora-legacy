# Платформы Sora

Раздела «Позже» в этом документе больше нет: Android, macOS и iOS — настоящие деревья в этом репозитории (`android/`, `macos/` + `service/darwin` + `core/ipc` для darwin, `ios/`), а не планы. Ниже для каждой платформы — что за код, чем доказана сборка в этой среде и что осталось проверить на устройстве или на Mac. Никакой статус здесь не означает «проверено на устройстве», если это прямо не сказано: в этой среде нет ни Android-устройства или эмулятора, ни Mac с Xcode.

Общий фундамент мобильных и Apple-платформ — пакет `core/mobileapi` (gomobile-фасад ядра): публичные функции только на `string`/`[]byte`/`error` — `ImportLinks`, `ParseSubscription`, `BuildPlan`, `RenderSingBoxConfig`, `EngineInfo` (плюс константа `DefaultLocalPort = 7890`). Пайплайн внутри — десктопный, а не переписанный: `parser` → `control.CredentialDocument` → `control.BuildEnginePlan` → статический каталог `engine.Catalog` → `singbox.Render`. Кросс-сборки полного модуля ядра проверены в этой среде: `GOOS=darwin GOARCH=amd64` и `GOARCH=arm64`, `GOOS=android GOARCH=arm64` (все — `CGO_ENABLED=0 go build ./...`, exit 0). Два фикса ядра, на которых стоят мобильные клиенты:

- **WireGuard transport**: парсер пишет `transport: "udp"` для wg://-ссылок и .conf-файлов, а словарь плана такого stream-транспорта не знает. Канонический фикс — в единственной точке конверсии `control.outboundFromProto`: для WireGuard написания `"", "tcp", "udp"` нормализуются в пустой транспорт, любое другое значение отклоняется именованной ошибкой. Временная нормализация внутри mobileapi этим фиксом поглощена.
- **ECH `query_server_name`**: поле есть только в sing-box ≥ 1.13; payload-пин 1.12.12 отвергает его при загрузке конфига (`json: unknown field "query_server_name"`). Гейт в каталоге движков выдаёт клейм `FeatureECHQueryServerName` только сборкам ≥ 1.13, поэтому план с этим полем отклоняется при выборе движка и в `mobileapi.RenderSingBoxConfig` — до рендера, а не падением в движке.

## Windows

Все Windows-сборки поставляемого клиента (на базе v2rayN) собираются из одной кодовой базы. Это сохраняет одинаковое поведение импорта, подписок, прокси, TUN, проверки задержки и журналов. Новый клиент (`legacy/Client`) в эти профили и в установочный комплект пока не входит.

Статус матрицы — честно: поддержка Windows 7 SP1 и 8.1 здесь — целевая конструкция (профили сборки, клиент на .NET Framework 4.8, Win7-движки, ядро на Windows 7 SDK Go), а не подтверждённый запуском факт. На самих Windows 7 SP1 и 8.1 клиент пока не запускался; оставшаяся проверка — «Проверка старых систем» в [PLANS.md](../PLANS.md).

| Файл | Целевая система | Архитектура | Состояние |
| --- | --- | --- | --- |
| `sora_win7.exe` | Windows 7 SP1 | x86 | основной профиль совместимости |
| `sora_win8.exe` | Windows 8.1 | x86 | профиль сборки и установщика |
| `sora_win10.exe` | Windows 10 | x86, работает на x64 через WoW64 | профиль сборки и установщика |
| `sora_win11.exe` | Windows 11 | x86, работает на x64 через WoW64 | профиль сборки и установщика |

Windows 8.0 не входит в матрицу: .NET Framework 4.8 официально поддерживает Windows 8.1, но не Windows 8.0. Короткое имя `sora_win8.exe` относится именно к Windows 8.1.

Каждый профиль проходит одинаковый набор регрессионных проверок в CI. Это подтверждает сборку и поведение кода, но не заменяет запуск на реальной машине соответствующей версии Windows.

Локальная сборка всех четырёх профилей:

```powershell
.\build\Build-WindowsProfiles.ps1
```

Профиль установщика задаётся определениями Inno Setup. В `installer/Sora.iss` по умолчанию задан профиль Windows 7 SP1 (`WindowsTarget=win7`, `MinimumWindowsVersion=6.1sp1`). Для Windows 8.1 при сборке установщика передаются `WindowsTarget=win8`, `WindowsDisplayName=Windows 8.1` и `MinimumWindowsVersion=6.3`; для Windows 10 и 11 — соответственно `10.0` и `10.0.22000` в `MinimumWindowsVersion`.

Windows XP не входит в матрицу и «позже» не обещается: текущий стек (.NET Framework 4.8, современные Go-движки, Wintun) опирается минимум на NT 6.1, отдельного старого рантайма для XP в репозитории нет.

## Linux (служба, без графического клиента)

Графического клиента для Linux в этом поколении нет. Для Linux собирается служба ядра тех же исходников (`core/`): пакеты `.deb`, `.rpm` и Arch из `packaging/linux` (nfpm), движки закреплены в `packaging/engines/engines.lock`, рядом ставятся собранные из исходников `tpws`/`nfqws` (zapret). Рецепт — в [packaging/linux/README.md](../../packaging/linux/README.md) и [docs/development.md](../../docs/development.md).

Установка пакетов на живой системе с запуском службы, TUN и kill switch не проверялась (нужен root); проверены состав пакетов, скрипты, systemd-unit и политика polkit. Kill switch на Linux форсится (nftables, `core/guard`), в отличие от darwin ниже.

## Android

Код: дерево `android/`, пакет `one.levvs.sora.legacy`, три экрана на framework Views (без AndroidX/Compose — сознательно, ради `minSdk 21` и офлайн-сборки). Ядро не переписано: импорт, план и рендер — через `mobileapi` (gomobile AAR), движок — libbox из upstream sing-box 1.12.12, который ведёт `SoraVpnService` (Android `VpnService`) через полную реализацию `PlatformInterface` пина — 18 методов. Клиент сам добавляет в отрендеренный конфиг ровно один `tun` inbound (`172.19.0.1/30` + `fdfe:dcba:9876::1/126`; /30 обязателен по контракту `GetDNSServerAddress` в libbox), потому что рендер mobileapi — application-mode и TUN принадлежит мобильному клиенту.

| Параметр | Значение |
| --- | --- |
| `minSdk` / `targetSdk` / `compileSdk` | 21 / 34 / 34 |
| AAR | `mobileapi.aar` (gomobile bind `-androidapi 21`) + `libbox.aar` (sing-box 1.12.12, sagernet gomobile v0.1.8); в git не коммитятся |
| Новое API — только за рантайм-гейтами | connection owner и HTTP-proxy Builder — 29+, `excludeRoute` и `POST_NOTIFICATIONS` — 33+, типизированный `startForeground` — 34 |

Чем доказана сборка: APK реально собран в этой песочнице ручным пайплайном `android/tools/build-manual.sh` (kotlinc 2.0.21 + aapt2 + d8 + zipalign + apksigner на официальных инструментах SDK 34; SHA-256 zip kotlinc закреплён в скрипте и перепроверяется на каждом запуске). Gradle в песочнице невозможен физически: демон общается с клиентом по loopback-TCP, а Java-TCP в песочнице перехватывается — все три попытки (daemon / `--offline` / `--no-daemon`) падают до резолва плагинов одной ошибкой `Could not receive a message from the daemon`. Каноническая Gradle-форма проекта в дереве есть — для dev-машины. Итоговый APK после фикса IPv6-зон (адреса с `%scope` срезаются до передачи в libbox, иначе его `netip.MustParsePrefix` паникует): размер 279 213 197 байт, SHA-256 `81f55b9fee04d778ff5daa305c19a8fb7f6f42f7b131f6ea430491c474dcaa7c`; `apksigner verify` — v1/v2/v3 true, подпись — debug-ключ (не релизная идентичность); `aapt2 dump badging` подтверждает пакет, `minSdk 21`, `targetSdk 34` и ровно 6 разрешений. Размер — оба Go-рантайма по 4 ABI без сжатия; per-ABI сплиты — шаг дистрибуции, не клиента.

Что **не проверено** (verify-on-device, полный список из 11 пунктов — в `android/README.md`): установка и VPN consent-флоу, реальный трафик через туннель и поведение DNS у инжектированного tun inbound (в отрендеренном route нет явного `hijack-dns` — утечку проверять трафиком), совместная жизнь двух gomobile `.so` с одним общим `go.Seq`, disconnect/reconnect и `onRevoke`, always-on/lockdown, foreground-service типа `specialUse` на реальном API 34, per-app фильтры и `excludeRoute` на 33+ против <33, загрузка подписки по URL с устройства, `findConnectionOwner` на 29+ и честный отказ ниже, старт на сети со scoped IPv6.

## macOS

Код — три части: `core/ipc` для darwin (верификация пира по `LOCAL_PEERCRED`/`LOCAL_PEERPID`, сокет `/var/run/sora/core.sock` вместо несуществующего на macOS `/run`), служба `service/darwin` (корневой LaunchDaemon: utun и маршруты требуют root, более узкой launchd-идентичности для этого нет; данные `/Library/SoraLegacy/core`, бинари и движки `/usr/local/lib/sora-legacy/`) и клиент `macos/` (AppKit-приложение + тонкий Go-хелпер `sora-ctl` в `macos/helper/`). Хелпер говорит с демоном на его штатном протоколе — `legacycontrol` JSON-RPC 2.0 поверх unix-сокета (режим демона по умолчанию, тот же, что у поставляемого .NET-клиента), а не на gRPC: gRPC потребовал бы нештатный режим демона и тяжёлый Swift-стек. Swift протокольного кода не содержит: запускает хелпер, читает один JSON на команду. Токен Handshake живёт только в памяти процесса хелпера; его state-файл хранит план со ссылками на секреты, не сам материал (тест хелпера это ассертит).

Измеренные полы (Mach-O load commands реальных бинарей, а не декларации):

| Компонент | Минимум macOS |
| --- | --- |
| Демон `sora-core` и хелпер `sora-ctl` | **12.0**, обе архитектуры (пол Go-тулчейна) |
| Клиент (AppKit) | дизайн-пол 10.13; в общем пути — только API ≤ 10.13 |
| Xray 26.3.27 | 12.0 / 12.0 |
| mihomo 1.19.32 | 10.13 (amd64) / 11.0 (arm64) |
| sing-box 1.14.3 regular | **26.0**, обе архитектуры |
| sing-box 1.14.3 `legacy-macos-10.13` (только amd64) | 10.13 |

Пины движков службы — `macos/engines-darwin.lock` (сервисные версии sing-box 1.14.3 / Xray 26.3.27 / mihomo 1.19.32, не Windows payload): на amd64 sing-box закреплён именно legacy-ассетом 10.13; на Apple Silicon ниже macOS 26 upstream-бинаря sing-box нет вообще — честный пробел: Xray и mihomo несут планы, которые могут, остальное выбор движка ядра честно отклоняет.

Чем доказана сборка: демон и хелпер реально собраны под darwin amd64 и arm64 в Mach-O (SHA-256: `sora-core` amd64 `97d4ef4b91528593605f5003c67a1967c9d0a508c5c3e521e300032e65151b09`, arm64 `94f456c1a99e150c4e67fb06d554d03e8df1d8479e7a7614d36aab7b368ff79a`; `sora-ctl` amd64 `af18aa0798df996509f4d6eaead494a7c6c8cf7b676065760bfa1b798601d3c8`, arm64 `1137b988f7edf6252376f334229fa68fec8bb61801753fe89f7c1bff194ad73d`); тесты хелпера на Linux зелёны против настоящего стека ipc + legacycontrol + control (стаб — только движок); Swift-ядро клиента (`macos/App/Core`, Foundation-only) — `swift test` на Linux Swift 6.0.3, 8/8, полный typecheck. Файлы AppKit (`macos/App/UI`) на Linux только `swiftc -parse`: AppKit там не typecheck-ится.

Что **не проверено** (verify-on-mac, чек-лист из 8 пунктов — в `macos/README.md`): Xcode-сборка приложения, установка и запуск службы, TUN и system-proxy на железе, `TestPeerOfDarwin`, отказ в авторизации `networksetup`, поведение на мульти-сервисной машине, Apple Silicon ниже macOS 26 без sing-box. Отдельно: два замечания ревью macOS исправлены коммитом `74caff7` и открытыми не являются — установщик службы валидирует `SHA256SUMS` движков до любых мутаций и честно отказывает при отсутствующем каталоге движков или манифесте, а все мутации AppKit в `MainWindowController` выполняются на главной очереди.

**Kill switch на darwin не форсится**: `core/guard` возвращает там `NoopFirewall`. Ядро записывает запрос, клиент показывает «requested, NOT enforced» и никогда — «protected». Это помечено в клиенте, в README службы и в plist; pf-реализация — будущая работа, не скрытый пробел. NetworkExtension на macOS не реализован: только спека-перспектива (entitlements, нотаризация), кода-обманки нет.

## iOS

Код: дерево `ios/` — UIKit-приложение (3 вкладки), расширение `PacketTunnel` (`NEPacketTunnelProvider`) и SPM-пакет `SoraLegacyCore` (Foundation-only: модели, `TunConfig` — дословное зеркало Android, шов mobileapi, App Group store). Движок — настоящий `BoxService` пина sing-box 1.12.12 (Setup / NewService / Start / Close / Pause / Wake), `PlatformInterface` реализован полностью — 18/18 методов; `TunOptions` дренируются все — 19/19 геттеров, route ranges реально используются при построении `NEPacketTunnelNetworkSettings`, exclude при использованных ranges повторно не применяются. Честные отказы вместо эмуляции: `FindConnectionOwner`/`PackageNameByUid`/`UIDByPackageName` бросают (публичного iOS API нет), `ReadWIFIState` — nil, `SystemCertificates` — пустой итератор, `ClearDNSCache` — no-op.

Пол — **iOS 13.0**, выведен из пина, а не назначен: `build_libbox` пина собирает Apple-bind без `-iosversion`, `IPHONEOS_DEPLOYMENT_TARGET` в дереве пина нет, а его sagernet gomobile v0.1.8 по умолчанию ставит `-iosversion 13.0`. Deployment target 13.0 зафиксирован в `project.yml` и `SoraLegacyCore/Package.swift`. UI — UIKit по решению: при поле 13 у SwiftUI нет scene lifecycle.

Чем доказана сборка: `SoraLegacyCore` — `swift test` на Linux Swift 6.0.3, **19/19**; все Swift-файлы дерева — `swiftc -parse` 18/18 (файлы `App/` и `PacketTunnel/` на Linux не typecheck-ились — честно: parse-only). Xcode-сборки здесь нет и быть не может: оба xcframework (Libbox штатным `build_libbox`, Mobileapi официальным gomobile с `-iosversion 13.0`) и сборка проекта — только на Mac по спеке `ios/BUILD-MAC.md`, чек-лист verify-on-mac там — 11 пунктов (включая Keychain round-trip на устройстве и проверку именно нижней границы на iOS 13). Креды серверов хранятся только в Keychain (access group резолвится в рантайме probe-записью из константы Models — литерал `$(AppIdentifierPrefix)…` в Swift-исходник класть нельзя); честная оговорка: tunnel exchange в App Group suite несёт полный отрендеренный конфиг с кредами аутбаундов внутри — расширению нужен полный конфиг, это by design, а не «креды в suite не попадают».

**Include/exclude package на iOS — документированный отказ**: списки дренируются в snapshot целиком, но не применяются — per-app VPN на iOS доступен только через MDM, публичного API у не-MDM провайдера нет. При непустых списках провайдер пишет явный отказ в лог; молчаливого игнорирования нет. On Demand осознанно выключен: подключение — только явным действием пользователя.

## Обфускация на legacy-пинах payload

Проверка — настоящими бинарями поставляемого payload (не каталогом): каждый конфиг получен путями ядра (`mobileapi` → `control.BuildEnginePlan` → рендеры sing-box/Xray) и прогнан через `sing-box check` (строг: неизвестные поля режет на decode) и `xray run -test` (мягок к `tlsSettings`, поэтому PASS по лениво валидируемым полям дополнен поиском символов в бинаре).

| Пин | Итог | Что не работает (доказано отказом бинаря) |
| --- | --- | --- |
| sing-box 1.12.12 (upstream) | **37 PASS / 11 FAIL из 48** | XHTTP (транспорта нет, в тегах нет `with_xhttp`), AmneziaWG (нет `with_awg`), REALITY `key_share` (написание lx-форка), VLESS encryption (поля нет в upstream), ECH `query_server_name` (поле появилось в 1.13), фингерпринты `chrome_133` и `hellochrome_auto` |
| Xray 25.9.11 | **24 PASS / 4 FAIL из 28** | Hysteria2 через Xray-рендер недоступен (`unknown transport protocol: hysteria`; hy2-obfs рендерер ядра для Xray именованно не рендерит, TUIC и AnyTLS Xray не поддерживаются), фингерпринт `chrome_133`. ECH на этом пине **бинарно не доказан**: поля `echConfigList`/`echForceQuery` в бинаре есть (strings), но загрузчик список не парсит и wire-эффект не измерялся — статус «поле есть, эффект не доказан» |

Работающая поверхность payload-sing-box (PASS бинарём): REALITY+Vision, ECH (закреплённый список и fetch по DNS), TLS-фрагментация, Hy2 с salamander-obfs и port hopping, TUIC, Shadowsocks-2022, AnyTLS, обычный WireGuard, фингерпринты chrome/firefox/safari/edge/ios/android/random/randomized. На Xray-пине реально есть XHTTP (включая полный xmux + padding + download split) и VLESS encryption (`mlkem768x25519plus`). Разница между пинами — свойство бинарей, а не настроек; клеймы каталога ядра этому не противоречат: XHTTP/AWG/key_share/VLESS-encryption для sing-box выдаются только lx-гейтом `BuildCapabilities`, статического клейма у upstream-записи нет.

## PARITY: функции по платформам

Статусы: **есть** — реализовано и доказано на уровне, указанном в разделе платформы; **частично** — код есть, но проверка или часть поверхности отсутствует (причина — одной фразой в ячейке); **нет** — отсутствует (причина — одной фразой). «Windows» здесь — поставляемый клиент; новый клиент (`legacy/Client`) идёт по тому же ядру и службе, но в комплект пока не входит.

| Функция | Windows | Android | macOS | iOS |
| --- | --- | --- | --- | --- |
| Импорт ссылок и подписок | есть | есть — через `mobileapi`, те же форматы ядра | есть — через демон (`sora-ctl import`/`import-url`, есть и офлайн-превью `--local`) | есть — через шов `mobileapi`, вставка и URL-фетч |
| Подключение TUN | есть | частично — код и APK собраны, трафик на устройстве не проверен | частично — служба и клиент написаны, запуск на Mac не проверен | частично — PacketTunnel написан, сборка и туннель только на Mac/устройстве |
| Локальный прокси (mixed inbound) | есть | есть — рендер mobileapi, порт настраивается | есть — режим proxy у службы, verify-on-mac | частично — порт есть в рендере, основной путь клиента — TUN |
| Системный прокси ОС | есть | нет — Android не даёт ставить системный прокси чужому приложению, вместо него TUN | есть — `networksetup`, snapshot/restore, verify-on-mac | нет — iOS не даёт такого API VPN-клиенту, вместо него TUN |
| Kill switch (enforced) | есть — WFP в ядре службы | нет — системный lockdown отдаётся настройкам Android, в клиенте не форсится | нет — `NoopFirewall` на darwin, запрос только записывается | нет — enforced-механизма в NE-клиенте нет, не обещается |
| Выбор и переключение сервера | есть | есть — один выбранный сервер в плане | есть — `sora-ctl select`, состояние в state-файле хелпера | есть — выбор в App Group store |
| Настройки MTU / strict route / локальный порт | частично — берутся из настроек клиента, не из аргументов запуска | есть — реальные поля плана и tun inbound | частично — режим и kill-switch флаг у хелпера, MTU в клиенте не выставлен | есть — порт/MTU/strict route в настройках, зеркало Android |
| Per-app фильтрация (include/exclude) | нет — в поставляемом профиле такой настройки нет | частично — Builder allow/disallow есть, на устройстве не проверено; exclude-маршруты только на 33+ | нет — per-app маршрутизации в клиенте нет | нет — документированный отказ: per-app VPN только через MDM |
| Движки sing-box / Xray / mihomo | есть — payload: sing-box 1.12.12 + Xray 25.9.11 (см. оговорку про пол Xray ниже) | частично — только sing-box (libbox 1.12.12), Xray/mihomo в клиент не входят | есть — сервисные пины 1.14.3 / 26.3.27 / 1.19.32, с пробелом sing-box на arm64 < macOS 26 | частично — только sing-box (libbox 1.12.12), Xray/mihomo в клиент не входят |
| REALITY + Vision, ECH, TLS-фрагментация, Hy2 obfs/hopping | есть — на payload-sing-box, доказано бинарём | есть — тот же пин libbox 1.12.12, та же поверхность | есть — на сервисном бандле, по каталогу ядра | есть — тот же пин libbox 1.12.12, та же поверхность |
| XHTTP | частично — есть на Xray-пине, нет на payload-sing-box | нет — пин libbox 1.12.12 транспорта XHTTP не содержит | есть — через Xray 26.3.27 и lx-гейты каталога | нет — пин libbox 1.12.12 транспорта XHTTP не содержит |
| AmneziaWG | нет — payload-sing-box без `with_awg`, обычный WireGuard при этом есть | нет — тот же пин без `with_awg`, обычный WireGuard есть | частично — только на lx-сборке sing-box по тегу `with_awg`, на darwin-пинах выше не заявлен | нет — тот же пин без `with_awg`, обычный WireGuard есть |
| VLESS encryption | частично — есть на Xray-пине, нет на payload-sing-box | нет — поля нет в upstream sing-box 1.12.12 | есть — через Xray 26.3.27 / lx-гейт sing-box | нет — поля нет в upstream sing-box 1.12.12 |
| ECH `query_server_name` | нет — на payload 1.12.12 гейт каталога отклоняет план до рендера | нет — тот же гейт в `mobileapi` на пине 1.12.12 | есть — сервисный sing-box 1.14.3 ≥ 1.13 проходит гейт | нет — тот же гейт на пине 1.12.12 |
| olcRTC | частично — только импорт: рантайм честно отказывает, транспорта в legacy нет | частично — только импорт через `mobileapi`, `BuildPlan` отказывает с именем протокола | частично — только импорт тем же ядром, рантайм отказывает | частично — только импорт тем же швом `mobileapi`, рантайм отказывает |
| Zapret (`tpws`/`nfqws`) | нет — zapret в Windows-комплект не входит | нет — zapret в клиент не входит | нет — zapret в darwin-службу не входит | нет — zapret на iOS не существует в этом дереве |
| Служба/демон в фоне | есть — служба ядра (путь нового клиента), поставляемый клиент запускает движки сам | нет — отдельного демона нет, движок живёт в процессе `VpnService` | есть — корневой LaunchDaemon, verify-on-mac | нет — отдельного демона нет, движок живёт в расширении |
| Автозапуск | есть — ярлык автозагрузки / запись Run (см. install.md) | нет — always-on отдаётся системным настройкам Android, в клиенте не обещается | нет — автоподключения в клиенте нет, служба стартует по LaunchDaemon сама | нет — On Demand осознанно выключен, always-on — MDM-территория |

## Известные ограничения, зафиксированные как ограничения

- **Развязка пина и пола Xray.** Payload-Xray — 25.9.11, а каталог ядра требует для Xray минимум 26.3.27 (`MinVersion`). `SelectEngine` такой план отклонит по версии до рендера — для любого плана. То есть внутри проводки этого ядра payload-Xray недостижим целиком: таблица обфускации выше описывает запас совместимости самого бинаря, а не достижимый путь клиента. Поднимать пин минимум до пола и перепрогнать на бинаре пола Hysteria2-рендер — решение владельца; в этих документах это фиксируется как известное ограничение, а не как «работает».
- **olcRTC в legacy — только импорт.** Ссылки и документы разбираются, креденшалы переживают vault; рантайм транспорта в legacy нет, построение плана честно отказывает с именем протокола на всех платформах.
- **Креды в mobileapi путешествуют в JSON документов** (`Server.Credentials`): у мобильных клиентов нет vault, документ надо хранить как секрет (Android — app-private `filesDir`, iOS — Keychain + оговорка про tunnel exchange выше) и не писать в логи.
- **Clash API в мобильном рендере — без секрета** (`Runtime.Secret` пуст, контроллер на `127.0.0.1:9090`): мобильный хост должен игнорировать контроллер либо закрывать его на уровне приложения; отдельного параметра секрета в минимальном API сознательно нет.
