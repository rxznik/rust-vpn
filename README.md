# <img src="logo.svg" alt="rustvpn" width="40"> RUST VPN

Настольный VPN-клиент, совместимый с подписками Happ. Датаплан — бинарник Xray-core. Туннель TUN поднимает tun2proxy, не sing-box. Приложения для iOS и Android в этот релиз не входят.

Границы крейтов — в [docs/architecture.md](docs/architecture.md). По каждому крейту есть короткий текст в [docs/modules](docs/modules).

## Установка

Репозиторий: [https://github.com/rxznik/rust-vpn](https://github.com/rxznik/rust-vpn).

Скрипты ставят клиент без прав администратора и качают архив последнего релиза. По умолчанию это `rxznik/rust-vpn`. Другой репозиторий задаётся `RUSTVPN_REPO` как `owner/name` или полным адресом GitHub. Скрипты работают после публикации тега `v*`.

Из клона:

```sh
git clone https://github.com/rxznik/rust-vpn.git
bash scripts/install-linux.sh
bash scripts/install-macos.sh
```

```powershell
.\scripts\install-windows.ps1
```

Без клона, с ветки `main`:

```sh
curl -fsSL https://raw.githubusercontent.com/rxznik/rust-vpn/main/scripts/install-linux.sh | bash
curl -fsSL https://raw.githubusercontent.com/rxznik/rust-vpn/main/scripts/install-macos.sh | bash
```

```powershell
irm https://raw.githubusercontent.com/rxznik/rust-vpn/main/scripts/install-windows.ps1 | iex
```

Куда попадают файлы:

- Linux и macOS: `~/.local/bin`
- Windows: `%LOCALAPPDATA%\rustvpn`

Чтобы запускать `rustvpn` из терминала, `~/.local/bin` должен быть в `PATH`. Пункт меню на Linux указывает на полный путь. Окну на Linux нужен пакет `libfontconfig1`.

Повторный запуск заменяет установленные файлы. Базу `state.db` скрипт не трогает.

В этом релизе публикуются `rustvpn-linux-x86_64.tar.gz`, `rustvpn-macos-x86_64.tar.gz` или `rustvpn-macos-aarch64.tar.gz`, и `rustvpn-windows-x86_64.zip`. На другой архитектуре скрипт называет отсутствующий архив и останавливается.

## Как пользоваться

Вставьте ссылку подписки или одного сервера, обновите список и подключитесь. Системный прокси на Linux включается только в GNOME. По умолчанию локальный SOCKS слушает порт 10808, HTTP — порт 10809. Оба адреса — `127.0.0.1`.

Каталог данных окна: `$XDG_DATA_HOME/rustvpn` или `~/.local/share/rustvpn`.

## Стек

Rust, интерфейс на Slint, состояние в SQLite, датаплан — Xray-core v26.3.27. Версия ядра зафиксирована в `resources/xray/VERSION`.

## Как устроено

Окно вызывает сессию `rvpn-app` и не собирает JSON Xray. Сессия хранит серверы и подписки в SQLite, разбирает ссылки и подписку Happ, коммитит черновик маршрута и только потом запускает Xray. Входящие сокеты остаются на `127.0.0.1`. Карта границ — [docs/architecture.md](docs/architecture.md), устройство крейтов — каталог [docs/modules](docs/modules).

## Ограничения

База `state.db` и рабочий файл `xray.json` хранят секреты открытым текстом. На Unix права файла `0600`, каталога `0700`. Это граница одного пользователя машины.

При включённом системном прокси локальный SOCKS без пароля: у GNOME нет поля пароля. Сокет слушает только `127.0.0.1`.

Релиз должен поставлять бинарник Xray рядом с `rustvpn`. Без этого файла клиент датаплан не запускает.

Сборки macOS и Windows не подписаны. Система может попросить подтвердить первый запуск.

## Дорожная карта

Секреты планируется перенести в связку ключей ОС. Статистику трафика — читать без отдельного процесса. Системный прокси — добавить для KDE. Оболочки для iOS и Android остаются следующим шагом и в этот релиз не входят.
