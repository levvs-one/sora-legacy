# Документация Sora Legacy

Указатель всей документации репозитория. Документы на английском помечены `(in English)`.

## Пользователям

- [Установка, обновление и удаление](install.md)
- [Использование](usage.md)
- [Частые вопросы](faq.md)
- [Если что-то не работает](troubleshooting.md)
- [Платформы: что где работает и чем проверено](../legacy/docs/platforms.md)

## Разработчикам

- [Сборка из исходников](development.md)
- [Архитектура ядра](architecture/core.md)
- [Движки](architecture/engines.md) — датированный снимок проверки кода (06.10.2026), не актуальное состояние пинов
- [Центр логов и центр соединений](architecture/logs.md) — датированный снимок проверки кода (06.10.2026)
- [Состояние работ и проверок](../legacy/PLANS.md)
- README поддеревьев: [древний трек Windows](../ancient/README.md) (in English), [Android](../android/README.md) (in English), [macOS](../macos/README.md) (in English), [iOS](../ios/README.md) (in English), [клиенты Windows](../legacy/README.md), [ядро](../core/README.md) (in English), [скелет Flutter-приложения](../app/README.md)
- [Пакеты Linux](../packaging/linux/README.md), [служба Linux](../service/linux/README.md), [служба macOS](../service/darwin/README.md), [служба Windows](../service/windows/README.md)

## Безопасность

- [Безопасность: хранение данных и проверки](security.md)
- [Политика сообщения об уязвимостях](../SECURITY.md)
- [Требования безопасности Android-приложения](android-security-requirements.md) — требования к разработке; реализация — дерево `android/`, состояние проверки — в его README

## Исследования и архив

Датированные снимки и исследования. Это не руководства и не актуальное состояние проекта.

- [Аудит поверхности управления, 02.10.2026](audits/2026-10-02-control-surface.md)
- [Аудит качества кода ядра, 02.10.2026](audits/2026-10-02-core-quality.md)
- [Аудит безопасности ядра, 02.10.2026](audits/2026-10-02-core-security.md)
- [Исследование: конкурент Happ](research/competitor-happ.md)
- [Исследование: движок mihomo](research/mihomo-engine.md)
- [Заметки прежних выпусков 0.1.0–0.2.2](../legacy/docs/releases/0.1.0.md) — архив прежнего репозитория sora-client
