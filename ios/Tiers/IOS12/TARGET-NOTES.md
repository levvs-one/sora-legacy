# TARGET-NOTES — тир iOS 12 (аддитивный)

Статус: **достижимость доказана первоисточниками и выполнимыми
пробами; сборка и запуск — verify-on-mac** (в этой среде нет Xcode,
как и у тира 13.0).

Существующий тир iOS 13.0 этим тиром не изменяется и не понижается:
все файлы тира 12 — новые, общие файлы не тронуты.

## 1. Пин

| | Тир 13.0 (существующий) | Тир 12.0 (этот) |
| --- | --- | --- |
| sing-box (upstream SagerNet) | 1.12.12 | **1.11.15** (последний патч линии 1.11.x) |
| sha256 исходников | `f08add81…1245` | `97d58dd8…09fd` |
| sha256 linux-amd64 релиза | `7c103cb2…889f` | `950af37e…d9c5` |
| gomobile пина (go.mod) | sagernet/gomobile v0.1.8 | sagernet/gomobile **v0.1.4** (sha исходников `6101c7f8…47a4`) |
| `go` в go.mod пина | 1.23.1 | **1.20** |
| Deployment target | 13.0 (= дефолт gomobile) | **12.0** (явный `-iosversion 12.0`) |
| Данные в коде | — | `EngineTier.ios12` в SoraLegacyCore |

Почему именно 1.11.15: новейшая линия, чья поверхность ещё
отличается от 1.12 только измеренным списком гейтов (§3–§4), а
gomobile/Go-цепочка не ставит пола выше 12.0 (§2). Линии 1.9/1.10
дают тот же gomobile v0.1.4 и тот же пол, но строго меньше
поверхности (ENGINES.md основной sora, §2.2/§5.1: бинарь 1.10.7
падает на корпусе идентично 1.11.15) — причин предпочесть их нет.

## 2. Пол 12.0: цепочка доказательств (кратко, детали — отчёт §2–§3)

1. `build_libbox` пина 1.11.15 (`cmd/internal/build_libbox/main.go`,
   `buildApple()`): bind собирается **без `-iosversion`** — как и у
   1.12.12, пол задаёт gomobile, а не пин.
2. gomobile v0.1.4 (`cmd/gomobile/build.go:262`): `-iosversion` —
   строковый флаг с дефолтом `"13.0"`. Дефолт ≠ минимум: единственная
   числовая валидация во всём дереве gomobile — Mac Catalyst
   (`build.go` runBuildImpl и `bind_iosapp.go` goAppleBind:
   `platform == "maccatalyst" && v < 13.0` → ошибка). Для платформы
   `ios` значение уходит дословно в clang:
   `-miphoneos-version-min=<value>` (`cmd/gomobile/env.go:219`).
3. Выполнимая проба (Linux): собранный из архивных исходников
   `gomobile v0.1.4 bind -target ios -iosversion 12.0` принимает
   флаг и падает только на `-target="ios" requires Xcode` —
   байт-в-байт та же ошибка, что с 13.0 (и с любым значением:
   валидации формата на ios-пути нет).
4. Официальный gomobile (Mobileapi-пи́н BUILD-MAC §2.2) — та же
   конструкция: `cmd/gomobile/ios_version.go`
   `validateCatalystVersion` возвращает nil сразу для любой
   платформы, кроме maccatalyst; собственный тест модуля утверждает
   `{platform: "ios", iOSVersion: "invalid"}` → без ошибки.
5. Go-рантайм: go.dev/wiki/MinimumRequirements, раздел iOS —
   **«iOS 12 or later»**. Это ровно пол: 12.0 достижим, 11.x — ниже
   пола рантайма и здесь не заявляется.
6. Предсобранных iOS-артефактов линия 1.11 не публикует
   (xcframework в релизах нет ни у одного пина) — Mach-O-проверка
   пола возможна только на собранном на Mac фреймворке (§6, п. 2).

## 3. Поверхность libbox 1.11.15 против 1.12.12 (по исходникам обоих пинов)

| Поверхность | 1.12.12 (тир 13) | 1.11.15 (тир 12) |
| --- | --- | --- |
| BoxService (Setup/NewService/Start/Close/Pause/Wake) | есть | есть; SetupOptions — тот же файл (diff пуст); iOS-путь Pause/Wake идентичен (автопробуждение через минуту), различаются только не-iOS ветки service_pause.go |
| TunOptions | 19 геттеров | 19 геттеров, файл идентичен (diff пуст) |
| PlatformInterface | **18** методов | **16** методов: нет `LocalDNSTransport()` и `SystemCertificates()` |
| Local DNS transport | метод интерфейса; config.go сам забирает его у платформы | пакетная `RegisterLocalDNSTransport(transport)` в dns.go; **пин её сам нигде не вызывает** — мост обязан зарегистрировать до NewService, иначе у `local`-серверов адаптированного конфига нет транспорта |
| SystemCertificates | метод интерфейса (пустой итератор — честный ответ) | шва нет вообще: корни — дело Go-рантайма; открытый вопрос §5 |
| Теги libbox (build_libbox, apple-бинды) | shared: with_gvisor, with_quic, with_wireguard, with_utls, with_clash_api, with_conntrack; darwin: +with_dhcp; memc-вариант: +with_tailscale, `-tags-not-macos=with_low_memory` | shared: **with_gvisor, with_quic, with_wireguard, with_ech, with_utls, with_clash_api**; apple: **+with_dhcp, with_low_memory, with_conntrack** (9 тегов; список дословно в рецепте BUILD-MAC §8). Композиция у пинов разная (у 1.11 `with_ech` — тег, у 1.12 ECH безусловен) — для тира значим только список его пина |

Мост тира — файл-замена `Replacements/LibboxBridgeImpl.swift`
(композиция — §4): дельта к оригиналу — регистрация локального DNS
в `setup()`, докстроки и перенумерация методов; тел методов дельта
не меняет. Спеллинги сгенерированных имён (включая новое
`LibboxRegisterLocalDNSTransport`) — TODO(verify-on-mac), как у
тира 13.

## 4. Конфиги: гейты тира (SoraLegacyCore, данные + адаптер)

Рендер `core/mobileapi` целится в статическую запись каталога
(пол 1.12.0) — тир 12 адаптирует отрендеренный конфиг в
`TierConfigAdapter` (для тира 13 адаптер — тождество):

- **DNS — трансляция** в до-1.12 формат: typed-серверы → `address`-
  строки (схемы https/tls/quic/tcp/h3, без схемы = UDP),
  `domain_resolver` → `address_resolver`, `detour` переносится
  (поле есть в 1.11), fakeip-сервер → блок `dns.fakeip` + сервер
  `{"address": "fakeip"}` (правило query_type продолжает на него
  указывать), `route.default_domain_resolver` снимается (поля в
  1.11 нет; имена аутбаундов разрешаются цепочкой address_resolver).
  Ключ без до-1.12 написания → отказ `dnsUntranslatable`, не тихое
  снятие.
- **Обязательные отказы** (другая связь, а не деградация): AnyTLS
  (протокола в 1.11 нет), XHTTP-транспорт, параметры AmneziaWG,
  REALITY `key_share`. Ядро эти планы для статической записи в
  основном отклоняет ещё до рендера (кроме AnyTLS — её статическая
  запись заявляет); адаптер — последний рубеж для конфигов,
  пришедших иным путём.
- **Деградации с пометкой** (`TierAdaptedConfig.degraded`): TLS
  `fragment` снимается (поля в 1.11 нет; связь та же, обфускация
  слабее), ECH `query_server_name` снимается, uTLS-фингерпринт вне
  сета 1.11 (ровно один лишний у 1.12 — `chrome_pq_psk`): при
  REALITY заменяется на `chrome`, без REALITY блок utls снимается;
  `route.default_domain_resolver` снимается с записью
  `routeDefaultDomainResolver` (деталь — тег сервера резолвера).
- Корпус: адаптированные фикстуры прогнаны через настоящий
  linux-бинарь 1.11.15 `check` — результат в отчёте §5; тот же
  бинарь на неадаптированном рендере падает на DNS-формате
  (негативный контроль).

## 5. Композиция тира (что собирается, что заменяется)

- `project-ios12.yml` (XcodeGen) вместо `project.yml`; генерирует
  отдельный `SoraLegacyIOS12.xcodeproj`.
- Фреймворки — `Frameworks/IOS12/` (Libbox пина 1.11.15 +
  Mobileapi с `-iosversion 12.0`), не `Frameworks/` тира 13.
- Файлы-замены: `Replacements/StatusViewController.swift` (два
  iOS 13+ семантических цвета: `.systemBackground`,
  `.secondaryLabel` — обе в одном файле App/; гейт `#available`,
  фолбэки `.white`/`.gray` — тёмной темы в iOS 12 нет) и
  `Replacements/LibboxBridgeImpl.swift` (§3).
- `SoraLegacyCore/Package.swift`: в тир-чек-ауте одна строка —
  `.iOS(.v13)` → `.iOS(.v12)` (BUILD-MAC §8, шаг 0); коммитнутый
  файл держит .v13 для тира 13. Код пакета при этом один и тот же:
  тесты гоняют оба тира как данные.
- Остальное дерево App/ и PacketTunnel/ — общее без изменений.
  Аудит API по дереву: единственный другой «молодой» API —
  `NWPathMonitor` (Network) — существует ровно с iOS 12.0, запас
  нулевой, но валиден; UIScene/SwiftUI/Combine в дереве нет
  (UIKit, AppDelegate-цикл — решение тира 13 заодно является
  условием тира 12).

## 6. Остаточные риски / verify-on-mac (дополнение к BUILD-MAC §7)

1. Всё из §7 тира 13 применимо; ниже — только дельты тира 12.
2. **Пол собранного фреймворка**: после сборки §8 проверить
   `LC_BUILD_VERSION`/`LC_VERSION_MIN_IPHONEOS` обоих слайсов
   Libbox.xcframework и Mobileapi.xcframework (otool -l) — должно
   быть 12.0; и `IPHONEOS_DEPLOYMENT_TARGET` проекта = 12.0.
3. **Xcode-приёмка цели 12.0**: актуальный Xcode может предупреждать
   или отказывать на deployment target 12.0 (политика SDK/стора —
   не свойство пина). Если актуальный Xcode цель не принимает,
   тир собирается последним принимающим Xcode; это ограничение
   тулчейна владельца, фиксировать по факту сборки, а не здесь.
   Дистрибуция мимо App Store (ad-hoc/enterprise) политикой стора
   не связана; сторовая судьба тира — решение владельца.
4. **Local DNS на устройстве**: конфиг с `local`-сервером обязан
   стартовать (регистрация §3 работает), резолв имён аутбаундов —
   через зарегистрированный транспорт.
5. **Сертификаты**: TLS-цепочки к серверам с публичными CA на
   устройстве (шва SystemCertificates в пине нет — §3).
6. **Нижняя граница**: установка и туннель на iOS 12 устройстве/
   симуляторе (аналог §7 п. 10 тира 13) + Keychain round-trip
   (§7 п. 11) на 12.
7. Хост-Go для сборки пина: **не 1.20**. Измерено сборкой
   (`macos/TIERS.md` §3.3):
   дерево 1.11.15 тулчейном Go 1.20.14 не собирается — форк
   sagernet/quic-go v0.49.0-beta.1 держит намеренный гард
   `//go:build !go1.21` в `internal/qtls_ech/go_oldversion.go`
   («ECH can't be built using outdated Go versions»), а тег
   `with_ech` входит в собственный список тегов пина, то есть
   bind libbox упрётся в тот же гард. Пин собран (CLI,
   darwin) тулчейном **Go 1.22.12**; рецепт §8 требует хост
   ≥ 1.21. Что на Mac остаётся проверить — именно bind
   (gomobile v0.1.4 + хост ≥ 1.21), а не сам факт собираемости
   графа пина: он измерен.
