# BUILD-MAC — sora-legacy iOS: сборка на Mac

Это дерево написано на Linux без Xcode: gomobile bind для iOS и
сборка xcframework здесь невозможны физически (нужен Apple SDK).
Всё ниже — точная спека для Mac; чек-лист верификации — §7.

## 1. Пол iOS: 13.0 — из исходников пина, не из предположений

Движок — upstream sing-box **1.12.12** (архив
`sing-box-1.12.12.tar.gz`, sha256
`f08add81eab7e4d6091195179bb39fa3f64dbb0326feaa022994566b702d1245` —
сверено с локальным архивом в `~/workspace/.legplat/downloads/`).

- `cmd/internal/build_libbox/main.go`, `buildApple()`: команда bind
  собирается как `bind -v -target <ios|ios,tvos,macos> -libname=box
  -tags-not-macos=with_low_memory … ./experimental/libbox` —
  **флага `-iosversion` нет** (и никакого deployment target в файле
  нет вообще).
- В дереве пина нет ни одного `IPHONEOS_DEPLOYMENT_TARGET`
  (grep по всему архиву: 0 совпадений) и нет дерева
  sing-box-for-apple (SFI) — пол задаёт только gomobile.
- gomobile пина: `go.mod` sing-box 1.12.12 —
  `github.com/sagernet/gomobile v0.1.8`. В его
  `cmd/gomobile/build.go` (строка с `addBuildFlags`):
  `cmd.flag.StringVar(&buildIOSVersion, "iosversion", "13.0", "")`,
  и `cmd/gomobile/doc.go`: «Flag -iosversion sets the minimal
  version of the iOS SDK to compile against. The default version is
  13.0.»

Итог: **минимальный iOS = 13.0**. Пол НЕ 15+ — занижать/завышать
нечего: legacy iOS на legacy-пине покрывает и 13–14 (у основного
дерева sora пол 15 задан его lx-форком — это другой пин и другой
факт, см. PARITY-запись в README). Deployment target в
`project.yml` и `Package.swift` — 13.0.

## 2. Фреймворки (оба — на Mac, в `ios/Frameworks/`, не в git)

### 2.1 Libbox.xcframework (sagernet/gomobile v0.1.8)

```sh
# исходники пина из архива с sha256 выше
tar -xzf sing-box-1.12.12.tar.gz && cd sing-box-1.12.12
# СНАЧАЛА sagernet gomobile/gobind v0.1.8 в GOPATH/bin — без них
# build_libbox фаталит: cmd/internal/build_shared.FindMobile
# проверяет $GOPATH/bin/gobind и делает log.Fatal("missing
# gomobile installation"). Версия — та же, что в go.mod пина
# (github.com/sagernet/gomobile v0.1.8), по образцу установки
# официального gomobile в §2.2:
go install github.com/sagernet/gomobile/cmd/gomobile@v0.1.8
go install github.com/sagernet/gomobile/cmd/gobind@v0.1.8
go run ./cmd/internal/build_libbox -target apple -platform ios
# результат: Libbox.xcframework в текущей папке
cp -R Libbox.xcframework ~/…/sora-legacy/ios/Frameworks/
```

`-platform ios` сужает bind до iOS (иначе соберутся ios+tvos+macos).

### 2.2 Mobileapi.xcframework (официальный gomobile)

Тот же пакет, что дал Android-AAR (`mobileapi.Mobileapi`), официальным
gomobile — версии из `LEGACY-PLAT-ANDROID-TOOLCHAIN.md`:
`golang.org/x/mobile v0.0.0-20261011034528-197770444867`,
хост-Go go1.24.7, тулчейн модуля core — go 1.26.9 (GOTOOLCHAIN=auto).

```sh
GOFLAGS=-mod=mod go install golang.org/x/mobile/cmd/gomobile@v0.0.0-20261011034528-197770444867
GOFLAGS=-mod=mod go install golang.org/x/mobile/cmd/gobind@v0.0.0-20261011034528-197770444867
gomobile init
# bind нельзя делать в самом репо без правки go.mod (та же причина,
# что на Android: x/mobile должен быть в графе модуля) — биндить из
# копии core/ с добавленной tool-директивой:
cp -R ~/…/sora-legacy/core /tmp/sora-legacy-core-ios
cd /tmp/sora-legacy-core-ios
go get -tool golang.org/x/mobile/cmd/gobind@v0.0.0-20261011034528-197770444867
gomobile bind -target ios -iosversion 13.0 \
  -o ~/…/sora-legacy/ios/Frameworks/Mobileapi.xcframework ./mobileapi
```

`-iosversion 13.0` здесь — явная фиксация того же пола §1.

## 3. Проект

```sh
brew install xcodegen
cd sora-legacy/ios
xcodegen generate --spec project.yml
open SoraLegacy.xcodeproj
```

Таргеты: `SoraLegacy` (приложение, `one.levvs.sora.legacy`) и
`PacketTunnel` (app-extension,
`one.levvs.sora.legacy.PacketTunnel`, встраивается в приложение).

## 4. Подписи и entitlements

- Нужен Apple Developer аккаунт; NetworkExtension — capability,
  включаемая на App ID обоих бандлов.
- `DEVELOPMENT_TEAM` — через `$(SORA_DEVELOPMENT_TEAM)`
  (xcconfig/CI/секрет), в репо team id нет.
- Entitlements уже в дереве: приложение и расширение —
  `packet-tunnel-provider`, App Group
  `group.one.levvs.sora.legacy`, keychain access group
  `$(AppIdentifierPrefix)one.levvs.sora.legacy`. App Group должен
  быть зарегистрирован на оба App ID, иначе контейнер не шарится и
  расширение не найдёт конфиг (fallback в provider честно упадёт с
  «startTunnel without config»).
- Расширение НЕ должно встраивать Mobileapi; приложение НЕ должно
  встраивать Libbox в свой бинарь — Libbox линкуют в расширение
  (статические слайсы xcframework); проверить в Build Phases, что
  нет duplicate symbols при линке приложения (приложение Libbox не
  импортирует вообще).

## 5. Нотаризация / стор

- iOS: нотаризации нет. TestFlight/App Store: нужен
  `ITSAppUsesNonExemptEncryption`-разбор (туннельный клиент —
  экспортный контроль шифрования, вопрос владельца), Privacy
  Nutrition Labels (трафик не собирается — по факту кода), скриншоты.
- Провижининг NetworkExtension для distribution — отдельный профиль
  расширения.

## 6. Поведение VPN

- On Demand: `isOnDemandEnabled = false` в TunnelManager —
  осознанно: подключение только явным действием пользователя.
  Always-on на iOS для обычных NE-провайдеров не существует (это
  MDM/per-app VPN территория) — не обещаем.
- Sleep/wake: provider вызывает BoxService.Pause()/Wake()
  (service_pause.go пина).
- Per-app фильтрация (tun inbound include_package/exclude_package):
  значения дренируются из TunOptions в snapshot целиком, но на iOS
  НЕ применяются — per-app VPN это MDM-возможность (per-app VPN
  payload), у не-MDM packet-tunnel провайдера публичного API для
  неё нет. Поведение честное, а не молчаливое: при непустых списках
  provider пишет явный отказ в лог (PacketTunnelProvider
  .applyTunOptions), туннель при этом работает для всех приложений.
- Системный рестарт расширения: конфиг берётся из зеркала App
  Group (ServerStore.exchangeKey), не только из providerConfiguration.

## 7. Verify-on-mac чек-лист

1. [ ] Оба xcframework собраны командами §2 без правок исходников.
2. [ ] Сверить спаллинги `TODO(verify-on-mac)` в
       `PacketTunnel/LibboxBridgeImpl.swift` и
       `SoraLegacyCore/…/MobileAPIGenerated.swift` с заголовками
       `Libbox.h` / `Mobileapi.h` фактически собранных фреймворков
       (имена протоколов `LibboxPlatformInterfaceProtocol` и т.п.,
       свойства SetupOptions, `LibboxGetTunnelFileDescriptor`,
       `getDNSServerAddress`, сигнатуры итераторов
       NetworkInterface.Addresses/DNSServer, unit статуса) — каждый
       снятый TODO фиксировать коммитом, который его проверил.
3. [ ] `xcodegen generate` + сборка Debug на симуляторе и устройстве.
4. [ ] Реальный туннель на устройстве: импорт ссылки → connect →
       трафик идёт, DNS hijack работает (DNS-сервер из TunOptions),
       disconnect чистый, kill приложения ≠ смерть туннеля.
5. [ ] Wi-Fi↔LTE переход: monitor listener получает события,
       туннель переживает (BoxService.UpdateWIFIState при
       необходимости — сейчас не вызывается, оценить по факту).
6. [ ] ReadWIFIState: сейчас честный nil (публичного API в
       расширении нет). Если правила маршрутизации по SSID станут
       нужны — app-side NEHotspotNetwork + передача через App
       Group; не эмулировать в расширении.
7. [ ] SystemCertificates: сейчас пустой итератор (публичного API
       перечисления trust store в расширении нет). Проверить на
       устройстве, что libbox без них валидирует цепочки (Go на
       iOS и системные корни — открытый вопрос пина).
8. [ ] GetInterfaces: DNS-серверы по интерфейсам пусты
       (getifaddrs их не даёт). Если движку это мешает — источник:
       `res_ninit`/`res_getservers` из libresolv, добавить тогда.
       Заодно: MTU сейчас 0 (unknown) — Darwin несёт ifi_mtu в
       ifa_data AF_LINK-записей ifaddrs, но перечисление их не
       декодирует; если движку понадобится MTU интерфейсов —
       декодировать там, а не выдумывать значение.
9. [ ] Энергопотребление/память расширения (лимит NE ~50 MB):
       профиль Instruments на слабом сервере с QUIC.
10. [ ] TestFlight сборка и установка на iOS 13-устройстве/симуляторе
       (пол — проверять именно нижнюю границу).
11. [ ] Keychain round-trip на устройстве: импортировать сервер с
       кредами → убедиться, что сервер работает → полностью
       перезапустить приложение → сервер на месте И креды на месте
       (подключение проходит без повторного импорта). Отдельно:
       тот же сценарий после переустановки/обновления приложения.
       Это единственный пункт, закрывающий access group: группа
       резолвится в рантайме из константы Models (префикс
       `$(AppIdentifierPrefix)` Xcode раскрывает только в
       entitlements), и на Linux эта цепочка не проверяется в
       принципе — тесты ходят через InMemorySecrets.
