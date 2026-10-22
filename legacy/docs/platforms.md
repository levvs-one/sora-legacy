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

Windows XP не входит в матрицу **основного** стека: текущий стек (.NET Framework 4.8, современные Go-движки, Wintun) опирается минимум на NT 6.1. Для XP, Vista и Windows 8.0 существует отдельный аддитивный трек — см. «Древний трек» ниже; основной стек он не меняет.

### Древний трек: Windows XP SP3 / Vista SP2 / Windows 8.0

Отдельное дерево `ancient/` в корне репозитория (не путать с основным клиентом выше): свой минимальный WinForms-клиент и движок эпохи, выбранные по первоисточникам и замерам бинарей, а не по аналогии с основным стеком. Детали, источники и протоколы проб — в [`ancient/README.md`](../../ancient/README.md).

| Параметр | Значение |
| --- | --- |
| Клиент | `ancient/src/Sora.Ancient`, одни исходники → две сборки: `net40` (потолок XP SP3 — .NET Framework 4.0.3) и `net46` (потолок Vista — 4.6; Windows 8.0 доходит до 4.6.1, поэтому Vista и 8.0 делят сборку net46; net462 невозможен на обеих: 4.6.1 убрал Vista, 4.6.2 убрал Windows 8.0). Источник полов — Microsoft Learn, «Install .NET Framework on Windows» |
| Движок | v2ray-core **v3.36** (пины и SHA-256 — `ancient/engines.lock`, сверка с SHA-1 из upstream `metadata.txt` сходится). Это последний релиз, чьи официальные бинари собраны Go 1.10.2 (замерено по самому бинарю); Go 1.10 — последний Go для XP/Vista, у v3.37 уже go1.11 с полом Windows 7 |
| Режимы | только прокси: локальные SOCKS 10808 + HTTP 10809, системный прокси (HKCU, snapshot/restore). **TUN нет и не обещается**: у движка эпохи TUN-режима нет, Wintun начинается с Windows 7, а связка tap-windows 9.9.2 (NDIS 5) + tun2socks для этого трека не собрана и не проверена |
| Протоколы | по пробам `v2ray -test` на пине + скан бинаря: VMess (tcp/ws/kcp/h2, TLS), Shadowsocks (AEAD эпохи и legacy-шифры), SOCKS. Честные отказы на импорте по имени: VLESS, Trojan, Hysteria, TUIC, WireGuard, SS-2022, REALITY/XTLS, QUIC, SIP003-плагины — в бинаре 2018 года их нет |

Статус — честно по уровням доказательства: клиент **собран** на Linux по обоим TFM (0 ошибок / 0 предупреждений), парсер и рендер конфигов эпохи доказаны harness-прогоном, движок доказан конфиг-пробами и loopback-запуском Linux-сборки того же релиза. **Runtime на самих XP/Vista/8.0 не проверен**: Wine-фаза (префиксы winxp/winvista, .NET эпохи, smoke + loopback) подготовлена скриптами в `ancient/wine/` и выполняется отдельным заданием; финальный гейт — запуск на устройстве.

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

Пины движков службы — `macos/engines-darwin.lock` (сервисные версии sing-box 1.14.3 / Xray 26.3.27 / mihomo 1.19.32, не Windows payload): на amd64 sing-box закреплён именно legacy-ассетом 10.13; на Apple Silicon ниже macOS 26 upstream-бинаря sing-box нет вообще — честный пробел поставляемой службы: Xray и mihomo несут планы, которые могут, остальное выбор движка ядра честно отклоняет.

Тиры ниже пола службы (LEGACY-FULL WS3, полные протоколы и рецепты — `macos/TIERS.md`, рецепт — `macos/build-singbox-darwin.sh`):

| Тир | Статус по факту попыток |
| --- | --- |
| macOS 11 | Демон и хелпер **не собираются** тулчейном пола 11 (Go 1.24.13, последняя линия Go для macOS 11): граф зависимостей ядра требует Go ≥ 1.25/1.26 (`x/sys v0.48.0 requires go >= 1.26.0`; `jrpc2 v1.3.5 requires go >= 1.25.0` — граф не резолвится даже для даунгрейда). Тир 11 для демона — форк зависимостей, а не рецепт сборки; службы на 11 нет. Движки: собственный sing-box **1.13.21** darwin arm64+amd64 собран Go 1.24.13 (теги релиза минус `with_tailscale` — её форк требует API Go 1.25 `reflect.TypeAssert`), Mach-O пол **11.0/11.0**, корпус на linux-сборке той же версии 11/12 (отказ — только AmneziaWG, фича lx-форка); дайджесты бинарей — аддитивно в `macos/engines-darwin.lock` (`sing-box-selfbuilt-1.13.21`), сборка байт-воспроизводима |
| macOS 10.15-limited | Демон тулчейном Go 1.20.14 **не собирается**: не хватает stdlib-пакетов `log/slog`, `maps`, `slices` в собственном коде ядра (`core/logs/slog.go:5`, `core/engine/catalog.go:6-7`) и `crypto/mlkem`/`crypto/hkdf`/`crypto/sha3` в зависимостях; вывод не зависит от тулчейна внутри тира (граф требует Go ≥ 1.25). Ограниченный режим основной sora (libbox в процессе приложения) legacy-клиенту недоступен по построению: единственный драйвер legacy — демон. Тир честно сужен до движков и корпуса: собственный sing-box **1.11.15** amd64 собран Go **1.22.12** (последняя линия с полом 10.15; Go 1.20 сборку пина ломает гард форка quic-go `!go1.21` в ECH): честный пол **10.15** (load command говорит 10.13, рантайм Go 1.22 требует 10.15 — штамп тир не расширяет). Корпус: без DNS-трансляции 0/12 (бинарь не знает новый DNS-формат, `dns.servers[0].path: unknown field`), после трансляции 11/12 (отказ — AmneziaWG). На arm64 тира 10.15 не существует в природе: первый Apple Silicon — Big Sur, arm64-сборка 1.11.15 честно декларирует пол 11.0 |
| Клиент по тирам | AppKit-клиент (дизайн-пол 10.13) на 11 и 10.15 запускается и объясняет; `Capabilities.serviceAvailable` не менялся и по-прежнему говорит 12.0 — это правда про демон. Расхождение зафиксировано, а не замазано: движки для 11/10.15 теперь существуют, драйвера (демона) для них в legacy нет |

Отдельная оговорка по рендеру на самосборных движках: ядро эмитит поля только-1.14 (`hop_interval_max`, `bbr_profile`, obfs `gecko`) без версионного гейта в каталоге/рендере — планы с ними движок 1.13.21/1.11.15 отклонит при загрузке конфига; гейт-список тиров — в `macos/TIERS.md` §3.5.

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
| Xray 26.3.27 (payload поднят с 25.9.11, LEGACY-FULL WS2) | **27 PASS / 2 FAIL из 29** | На бинаре пола работает весь корпус каталога: REALITY+Vision, XHTTP полный набор, VLESS encryption, фрагментация и **Hysteria2** (plain, hopping-рендер и brutal `up_mbps`/`down_mbps`) — именно Hy2 отсутствовал в 25.9.11 (24 PASS / 5 FAIL из 29 тем же корпусом: все три Hy2-конфига — `unknown transport protocol: hysteria`; аутбаунд добавлен upstream PR 5508, впервые в теге v26.1.13). Остальные 2 FAIL — на обоих бинарях одинаково: фингерпринт `chrome_133` (написания нет ни в одном пине; `hellochrome_auto` при этом PASS) и контрольный `bogus-fp`. hy2-obfs рендерер ядра для Xray именованно не рендерит, TUIC и AnyTLS Xray не поддерживаются. ECH **бинарно не доказан** и на новом пине: поля `echConfigList`/`echForceQuery` в бинаре есть (strings ×3/×4, как в 25.9.11), но загрузчик список не парсит и wire-эффект не измерялся — статус «поле есть, эффект не доказан» |

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
| Движки sing-box / Xray / mihomo | есть — payload: sing-box 1.12.12 + Xray 26.3.27 (пин равен полу каталога, см. «Известные ограничения») | частично — только sing-box (libbox 1.12.12), Xray/mihomo в клиент не входят | есть — сервисные пины 1.14.3 / 26.3.27 / 1.19.32, с пробелом sing-box на arm64 < macOS 26 | частично — только sing-box (libbox 1.12.12), Xray/mihomo в клиент не входят |
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

- **Пин и пол Xray развязаны (LEGACY-FULL WS2, 2026-10-22).** Payload-Xray поднят с 25.9.11 до **26.3.27** — ровно пол каталога (`MinVersion`), тем же официальным ассетом `Xray-win7-32.zip` (SHA-256 архива и `xray.exe` — в `legacy/build/Stage-Release.ps1` и `THIRD-PARTY-NOTICES.md`, сверены с upstream `.dgst`). Снижать пол до 25.9.11 было нельзя: тем же корпусом из 29 конфигов старый бинарь даёт 24 PASS / 5 FAIL — все три Hysteria2-рендера отклонены (`unknown transport protocol: hysteria`; Hy2-аутбаунда в 25.9.11 нет — добавлен upstream PR 5508, впервые в теге v26.1.13; пол 26.3.27 — верифицированная поставляемая сборка, а не «первая версия с Hy2»), а новый — 27 PASS / 2 FAIL (только `chrome_133` и контрольный bogus, одинаково на обоих). Win7-безопасность нового пина доказана заголовками самого бинаря: PE i386, MajorOperatingSystemVersion и MajorSubsystemVersion **6.1** (как у 25.9.11), статические импорты — только kernel32, все функции доступны на Windows 7. `SelectEngine` теперь пропускает payload-Xray: обычный VLESS- и Hy2-планы на 26.3.27 выбираются, на 25.9.11 — отклоняются по версии (запинено тестами `catalog_xray_floor_test.go` и бинарным корпусом `engine/xray/binary_floor_test.go`). Xray-путь клиента достижим; поверхность — строка Xray в таблице обфускации выше. Запуск именно на живой Windows 7 по-прежнему не проверялся (как и весь Windows-трек выше).
- **olcRTC в legacy — только импорт.** Ссылки и документы разбираются, креденшалы переживают vault; рантайм транспорта в legacy нет, построение плана честно отказывает с именем протокола на всех платформах.
- **Креды в mobileapi путешествуют в JSON документов** (`Server.Credentials`): у мобильных клиентов нет vault, документ надо хранить как секрет (Android — app-private `filesDir`, iOS — Keychain + оговорка про tunnel exchange выше) и не писать в логи.
- **Clash API в мобильном рендере — без секрета** (`Runtime.Secret` пуст, контроллер на `127.0.0.1:9090`): мобильный хост должен игнорировать контроллер либо закрывать его на уровне приложения; отдельного параметра секрета в минимальном API сознательно нет.
