# Sora Legacy

Новый интерфейс Sora для старых Windows. Отдельный репозиторий, ветка `legacy`, служба `SoraLegacyCore` и данные; обычный клиент находится в [sora](https://github.com/levvs-one/sora).

Готового нового релиза пока нет. Проверены сборка .NET Framework 4.8 для x86/x64, связь со службой без прав администратора, переключение 31 языка и закрытие окна. Эти проверки выполнялись на современной Windows; совместимость с Windows 7 SP1 и 8.1 ещё не подтверждена запуском.

- [Текущие проверки и сборки](https://github.com/levvs-one/sora-legacy/actions/workflows/legacy.yml)
- [Что проверено и что осталось](legacy/PLANS.md)
- [Telegram](https://t.me/sora_client)

## Сборка интерфейса

На Windows с .NET SDK 8:

```powershell
dotnet build legacy/Client/Sora.Legacy.Client.csproj -c Release -p:PlatformTarget=x86
dotnet build legacy/Client/Sora.Legacy.Client.csproj -t:Rebuild -c Release -p:PlatformTarget=x64
```

Для службы используется закреплённый Windows 7 SDK Go 1.26.9; его контрольная сумма и команды сборки находятся в [.github/workflows/legacy.yml](.github/workflows/legacy.yml).

`legacy/Client` — новый клиент, `legacy/Control` — транспорт и управление сессиями, `core` — служба и движки. Прежний интерфейс в `legacy/v2rayN` сохранён вместе с историей исходного кода и проверками.

## Лицензия

[GPL-3.0](LICENSE). [Сторонние компоненты](THIRD-PARTY-NOTICES.md).
