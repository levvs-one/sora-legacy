# Установщик Windows

Скрипт Inno Setup поставляемого комплекта Sora Legacy: `Sora.iss`.

## Рецепт

1. Соберите профили клиента скриптом `../build/Build-WindowsProfiles.ps1`.
2. Соберите комплект скриптом `../build/Stage-Release.ps1`: он сверяет SHA-256 движков и файлов tun2proxy с закреплёнными значениями и кладёт в комплект канонические файлы из корня репозитория (LICENSE, README, NOTICE, CHANGELOG, THIRD-PARTY-NOTICES).
3. Скомпилируйте `Sora.iss` в Inno Setup 6.

## Профили и версия

- Целевая система задаётся профилем сборки: `WindowsTarget` — `win7` (по умолчанию, отображение «Windows 7 SP1»), `win8`, `win10`, `win11`; вместе с ней меняются `WindowsDisplayName` и `MinimumWindowsVersion`.
- Версия продукта задаётся одним местом: `#define MyAppVersion` в начале `Sora.iss`. Текущая версия — 0.2.4; то же значение стоит во всех build-источниках репозитория: корневой CHANGELOG, `v2rayN.csproj` (`Version`/`AssemblyVersion`/`FileVersion`), примеры команд упаковки Linux и CI Linux-пакетов (`.github/workflows/legacy.yml`, `SORA_VERSION`). Android следует версии продукта: `versionName` равен ей (0.2.4), а `versionCode` производен от неё как major*10000+minor*100+patch (204) и задаётся в `android/app/build.gradle.kts` и `android/tools/build-manual.sh`. Apple `MARKETING_VERSION` — счётчик со своей конвенцией, версией продукта не является.
- Иконка установщика — `sora.ico` из комплекта (семейный знак, 7 образов 16–256).

## Оформление мастера

- Фон мастера — плоские grounds из `art/`: подключены `back-light.png` (596×432) и `back-light@2x.png` (1192×864); тёмная пара `back-dark{,@2x}.png` лежит рядом для dynamic-режима, если владелец его когда-нибудь включит. Набор тот же, что у установщика sora. Боковых баннеров нет (`WizardImageFile` пуст).
- Ключи `dynamic windows11` эталона здесь сознательно не применены: целевой пол мастера — Windows 7, и поведение dynamic-стиля Inno на ней из этой среды не проверяется. Компиляция и визуальная проверка обеих тем и языков мастера — на машине владельца или в CI с Inno Setup.
- Все видимые строки задач и запуска после установки заданы через `[CustomMessages]` на русском и английском (`{cm:…}`), а не литералами.
- Страница лицензии (`LicenseFile`) в мастере сохранена; вопрос её отключения по образцу одностраничного мастера sora — решение владельца, в этой стадии не принято.
