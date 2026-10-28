//! Конверты ретранслятора — текстовые кадры WebSocket с JSON.
//!
//! Вход: клиент → `hello`, ретранслятор → `challenge`, клиент → `auth` (подпись), ретранслятор → `ready`.
//! Дальше `send`/`recv` с данными канала (base64url), `watch`/`presence` — кто в сети,
//! `invite_put`/`invite_get` — приглашение для ввода кода вручную, `ping`/`pong`.

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::b64;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Relay {
    Hello { id: String, pk: String, role: Role, proto: u32 },
    Challenge { n: String },
    Auth { sig: String },
    Ready,
    Error { code: String, msg: String },

    Send { to: String, data: String },
    Recv { from: String, data: String },
    /// Получателя нет в сети.
    Offline { id: String },

    /// Следить, в сети ли устройства (не больше 50 id).
    Watch { ids: Vec<String> },
    Presence { id: String, online: bool },

    /// ПК кладёт приглашение по номеру (первые 4 символа кода); живёт 5 минут.
    InvitePut { key: String, invite: crate::pair::Invite },
    InviteGet { key: String },
    Invite { key: String, invite: crate::pair::Invite },

    Ping,
    Pong,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Basehub на ПК.
    Agent,
    /// Телефон.
    Client,
}

impl Relay {
    pub fn to_text(&self) -> String {
        serde_json::to_string(self).expect("relay json")
    }

    pub fn from_text(s: &str) -> Result<Relay, String> {
        serde_json::from_str(s).map_err(|e| format!("непонятный кадр ретранслятора: {e}"))
    }

    pub fn send(to: &str, frame: &[u8]) -> Relay {
        Relay::Send { to: to.to_string(), data: b64().encode(frame) }
    }

    pub fn error(code: &str, msg: &str) -> Relay {
        Relay::Error { code: code.to_string(), msg: msg.to_string() }
    }
}

/// Данные кадра из `recv`.
pub fn decode_data(data: &str) -> Result<Vec<u8>, String> {
    b64().decode(data).map_err(|_| "повреждённые данные".to_string())
}

pub fn encode_bytes(b: &[u8]) -> String {
    b64().encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_shape() {
        let m = Relay::send("abc", &[1, 2, 3]);
        assert_eq!(m.to_text(), r#"{"t":"send","to":"abc","data":"AQID"}"#);
        assert_eq!(Relay::from_text(r#"{"t":"ready"}"#).unwrap(), Relay::Ready);
        let h = Relay::Hello { id: "i".into(), pk: "p".into(), role: Role::Agent, proto: 1 };
        assert_eq!(Relay::from_text(&h.to_text()).unwrap(), h);
        assert!(Relay::from_text(r#"{"t":"nope"}"#).is_err());
    }
}
