# basehub-relay

Ретранслятор **Basehub Remote** и общий протокол `remote-proto`: связь приложения Basehub для Android
с Basehub на компьютере, когда они в разных сетях. Компьютер сам держит исходящее соединение —
открывать порты не нужно.

*Relay server and protocol for Basehub Remote: the Android app talks to Basehub on a PC through it.
End-to-end encrypted (Noise), the relay sees only device ids and sizes. MIT licensed.*

**Ретранслятор не видит содержимое.** Телефон и компьютер шифруют всё между собой (Noise:
сопряжение `XXpsk3` по коду с экрана компьютера, дальше `KK` по сохранённым ключам). Ретранслятор
пересылает конверты «от кого — кому — шифротекст», держит в памяти список устройств в сети и ничего
не пишет на диск. Вход на ретранслятор — подпись ed25519: занять чужой id нельзя.

По умолчанию Basehub работает через `wss://api.basehub-tools.ru/v1/ws`. Свой ретранслятор — для тех,
кому данные нельзя пропускать через чужой сервер. Инструкция по установке:
**https://basehub-tools.ru/relay.html**

## Состав

| Каталог | |
|---|---|
| [`relay/`](relay) | сервер `basehub-relay` (Rust, axum): сборка, Dockerfile, systemd, сквозной тест |
| [`remote-proto/`](remote-proto) | протокол: ключи устройства, сопряжение по коду, шифрование Noise, конверты, клиент WebSocket; `examples/phone.rs` — консольный «телефон» для проверки |

## Запуск

Docker (amd64, arm64):

```sh
docker run -d --name basehub-relay --restart unless-stopped -p 127.0.0.1:8790:8790 \
  -e RELAY_TRUST_PROXY=1 ghcr.io/rus1am89/basehub-relay:latest
```

Бинарники для Linux и Windows — в [Releases](../../releases) и на https://basehub-tools.ru/relay.html.
Перед ретранслятором нужен HTTPS с поддержкой WebSocket (Caddy, nginx, прокси Synology DSM).
Подробности и настройки — в [relay/README.md](relay/README.md).

## Сборка из исходников

```sh
cd remote-proto && cargo test --features client
cd ../relay && cargo test && cargo build --release
docker build -f relay/Dockerfile -t basehub-relay .   # из корня репозитория
```

## Лицензия

MIT — см. [LICENSE](LICENSE). Basehub — независимая разработка, не аффилирована с фирмой «1С».

Репозиторий — зеркало каталогов `relay/` и `remote-proto/` из основного (закрытого) репозитория
Basehub; вопросы и предложения — в Issues, https://t.me/basehubapp или devteamra@gmail.com.
