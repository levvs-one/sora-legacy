# Sora Legacy — клиенты Windows

Каталог клиентов Windows этого репозитория. Корневой обзор проекта — в [README.md](../README.md), полный указатель документации — в [docs/README.md](../docs/README.md).

Что здесь находится:

- `v2rayN` — поставляемый сегодня клиент на базе v2rayN; именно он собирается в CI и кладётся в установочный комплект скриптом `build/Stage-Release.ps1`.
- `Client` — новый клиент (.NET Framework 4.8, WinForms), пользуется службой ядра `SoraLegacyCore`; **в установочный комплект пока не включён** и пользователю не поставляется.
- `Control` — транспорт и управление сессиями для нового клиента.
- `installer` — скрипт Inno Setup поставляемого комплекта, `build` — скрипты сборки, комплекта и профилей Windows.

Установка — [docs/install.md](../docs/install.md). Платформы и честное состояние проверок — [docs/platforms.md](docs/platforms.md) и [PLANS.md](PLANS.md).
