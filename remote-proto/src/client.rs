//! Подключение к ретранслятору по WebSocket (tokio) — общее для ПК и телефона.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::identity::Identity;
use crate::relay::{Relay, Role};

/// Как часто слать ping: ретранслятор рвёт соединение после 90 с тишины.
const KEEPALIVE: Duration = Duration::from_secs(30);
const AUTH_TIMEOUT: Duration = Duration::from_secs(15);

/// Отправка конвертов; клонируется.
#[derive(Clone)]
pub struct RelaySender(mpsc::UnboundedSender<Relay>);

impl RelaySender {
    pub fn send(&self, m: Relay) -> Result<(), String> {
        self.0.send(m).map_err(|_| "соединение с ретранслятором закрыто".to_string())
    }

    pub fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
}

/// Входящие конверты; `None` — соединение закрыто.
pub struct RelayReceiver(mpsc::UnboundedReceiver<Relay>);

impl RelayReceiver {
    pub async fn recv(&mut self) -> Option<Relay> {
        self.0.recv().await
    }
}

/// Следующий конверт во время входа (с таймаутом).
async fn next_relay<S>(stream: &mut S) -> Result<Relay, String>
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    let fut = async {
        loop {
            match stream.next().await {
                Some(Ok(Message::Text(t))) => return Relay::from_text(&t),
                Some(Ok(Message::Close(_))) | None => return Err("ретранслятор закрыл соединение".to_string()),
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(e.to_string()),
            }
        }
    };
    tokio::time::timeout(AUTH_TIMEOUT, fut).await.map_err(|_| "ретранслятор не ответил".to_string())?
}

/// Подключиться, пройти вход и вернуть каналы отправки/приёма. Фоновые задачи — на текущем runtime tokio.
pub async fn connect(url: &str, me: &Identity, role: Role) -> Result<(RelaySender, RelayReceiver), String> {
    // rustls 0.23 без провайдера по умолчанию паникует на первом wss://; повторная установка — не ошибка
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (ws, _) = tokio::time::timeout(AUTH_TIMEOUT, tokio_tungstenite::connect_async(url))
        .await
        .map_err(|_| "ретранслятор не ответил".to_string())?
        .map_err(|e| format!("не удалось подключиться к ретранслятору: {e}"))?;
    let (mut sink, mut stream) = ws.split();

    let hello = Relay::Hello { id: me.id(), pk: me.sign_public(), role, proto: crate::PROTOCOL };
    sink.send(Message::Text(hello.to_text())).await.map_err(|e| e.to_string())?;

    let nonce = match next_relay(&mut stream).await? {
        Relay::Challenge { n } => crate::relay::decode_data(&n)?,
        Relay::Error { msg, .. } => return Err(msg),
        _ => return Err("ретранслятор ответил не по протоколу".into()),
    };
    sink.send(Message::Text(Relay::Auth { sig: me.sign_challenge(&nonce) }.to_text())).await.map_err(|e| e.to_string())?;
    match next_relay(&mut stream).await? {
        Relay::Ready => {}
        Relay::Error { msg, .. } => return Err(msg),
        _ => return Err("ретранслятор ответил не по протоколу".into()),
    }

    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Relay>();
    let (in_tx, in_rx) = mpsc::unbounded_channel::<Relay>();

    tokio::spawn(async move {
        let mut tick = tokio::time::interval(KEEPALIVE);
        tick.tick().await;
        loop {
            tokio::select! {
                m = out_rx.recv() => match m {
                    Some(m) => if sink.send(Message::Text(m.to_text())).await.is_err() { break },
                    None => break,
                },
                _ = tick.tick() => if sink.send(Message::Text(Relay::Ping.to_text())).await.is_err() { break },
            }
        }
        let _ = sink.close().await;
    });
    tokio::spawn(async move {
        while let Some(m) = stream.next().await {
            match m {
                Ok(Message::Text(t)) => match Relay::from_text(&t) {
                    Ok(Relay::Pong) => {}
                    Ok(r) => {
                        if in_tx.send(r).is_err() {
                            break;
                        }
                    }
                    Err(_) => {}
                },
                Ok(Message::Close(_)) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });
    Ok((RelaySender(out_tx), RelayReceiver(in_rx)))
}
