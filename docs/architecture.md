# Границы крейтов

Клиент разделён по ролям. Ниже — что каждому крейту разрешено хранить и куда ему разрешено ходить.

**rvpn-model.** Доменные типы и их JSON. Сети нет. SQLite нет. Черновик маршрута живёт полями `draft_profile_id` и `draft_routing_enabled`.

**rvpn-links.** Разбор share-ссылки. Сети нет.

**rvpn-subscription.** Загрузка подписки и мета Happ. Сеть только для URL подписки и четырёх хостов DoH.

**rvpn-routing.** Профили маршрута Happ, allowlist загрузки geo, документы routing и dns для Xray.

**rvpn-xray.** Сборка конфига и запуск бинарника. Inbound остаются на loopback. JSON-подписка проходит `prepare_passthrough`.

**rvpn-tun.** TUN через tun2proxy. sing-box здесь нет.

**rvpn-probe.** Локальные проверки задержки и `tunnel_ready`.

**rvpn-platform.** Системный прокси, автозапуск, HWID.

**rvpn-store.** SQLite. Протокол сервера остаётся в теле записи. Черновик маршрута становится applied только через `commit_routing`.

**rvpn-app.** Сессия. `connect` вызывает `commit_routing` до запуска Xray. Настройки окна — непрозрачный blob, не `CoreSettings`.

**rvpn-ffi.** Фасад UniFFI. Биндинги собираются при мобильной сборке и в репозиторий не входят.

**apps/desktop.** Окно на Slint. Оно вызывает `Client` и не говорит на JSON Xray.

Черновик маршрута (`draft_profile_id`, `draft_routing_enabled`) применяется к процессу только когда `connect` вызывает `commit_routing`.

## Мобильный туннель

**Android.** `stageSession`, затем дескриптор TUN, затем `connect`. `shutdown` вызывается, когда сервис останавливается или `connect` завершается ошибкой.

**iOS.** `stageSession`, затем сетевые настройки, затем `prepareBridge`, затем насос пакетов. `shutdown` вызывается в `stopTunnel`.

`shutdown` включает `disconnect`.

## Записанные ограничения

База `state.db` и рабочий файл `xray.json` хранят секреты открытым текстом. На Unix права файла `0600`, каталога `0700`. Это граница одного пользователя машины.

При включённом системном прокси локальный SOCKS inbound без пароля, потому что у GNOME нет поля пароля. Он слушает только `127.0.0.1`.

Релизная сборка desktop обязана положить бинарник Xray рядом с `rustvpn`: так его ищет `locate_binary`. Пауза 250 мс в `Supervisor::start` остаётся.
