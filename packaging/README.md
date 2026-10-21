# packaging

Что на самом деле собирается из этого каталога и рядом с ним. Никаких MSI, AppImage и Android-пакетов в этом репозитории нет.

| Каталог | Результат |
| --- | --- |
| `engines` | `engines.lock` — закреплённые версии и SHA-256 движков для Linux; `fetch.sh` скачивает их по HTTPS и останавливается при несовпадении суммы |
| `zapret` | `build.sh` собирает `tpws` и `nfqws` из vendored-копии zapret в `third_party/zapret` и дописывает их дайджесты в `SHA256SUMS` движков |
| `linux` | Пакеты службы ядра `.deb`, `.rpm` и Arch, собранные [nfpm](https://github.com/goreleaser/nfpm) из одного `nfpm.yaml`; рецепт и состав — в [linux/README.md](linux/README.md) |

Windows-установщик живёт не здесь, а в `legacy/`: скрипт комплекта `legacy/build/Stage-Release.ps1` и Inno Setup `legacy/installer/Sora.iss`. Рецепт полной сборки — в [docs/development.md](../docs/development.md).

Подписи релизов (offline minisign-ключ) — за владельцем проекта; до церемонии ключа подпись не выпускается и документация её не обещает.
