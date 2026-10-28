//! basehub-relay — ретранслятор Basehub Remote.
//!
//! Переменные окружения:
//! - `RELAY_LISTEN` — адрес и порт (по умолчанию `0.0.0.0:8790`);
//! - `RELAY_TRUST_PROXY=1` — за обратным прокси: IP клиента из X-Forwarded-For;
//! - `RELAY_MAX_CONN_PER_IP` — соединений с одного IP (по умолчанию 20).

use basehub_relay::{serve, Config};

#[tokio::main]
async fn main() {
    let listen = std::env::var("RELAY_LISTEN").unwrap_or_else(|_| "0.0.0.0:8790".into());
    let mut cfg = Config::default();
    cfg.trust_proxy = matches!(std::env::var("RELAY_TRUST_PROXY").as_deref(), Ok("1") | Ok("true"));
    if let Some(n) = std::env::var("RELAY_MAX_CONN_PER_IP").ok().and_then(|v| v.parse().ok()) {
        cfg.max_conn_per_ip = n;
    }
    let listener = match tokio::net::TcpListener::bind(&listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("не удалось занять {listen}: {e}");
            std::process::exit(1);
        }
    };
    println!("basehub-relay {} слушает {listen} (протокол {})", env!("CARGO_PKG_VERSION"), remote_proto::PROTOCOL);
    let stop = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let stop = async move {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM");
        tokio::select! { _ = stop => {}, _ = term.recv() => {} }
    };
    if let Err(e) = serve(listener, cfg, stop).await {
        eprintln!("ошибка: {e}");
        std::process::exit(1);
    }
}
