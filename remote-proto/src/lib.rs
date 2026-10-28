//! Basehub Remote — протокол удалённого доступа: телефон (пульт) ⇄ ретранслятор ⇄ Basehub на ПК (агент).
//!
//! Ретранслятор видит только конверты [`relay::Relay`] с id отправителя и получателя; содержимое
//! зашифровано между устройствами протоколом Noise ([`channel::Channel`]):
//! - сопряжение — `Noise_XXpsk3`, PSK выводится из кода приглашения `XXXX-XXXX` ([`pair`]);
//! - каждое следующее подключение — `Noise_KK` по сохранённым публичным ключам.
//!
//! Внутри шифра — прикладные сообщения [`app::App`] (JSON).

pub mod app;
pub mod channel;
pub mod identity;
pub mod pair;
pub mod relay;

#[cfg(feature = "client")]
pub mod client;

pub use channel::{Channel, Out};
pub use identity::{peer_id, Identity};

/// Версия протокола: ретранслятор и стороны сверяют её в `hello`.
pub const PROTOCOL: u32 = 1;

/// Адрес ретранслятора Basehub по умолчанию.
pub const DEFAULT_RELAY: &str = "wss://api.basehub-tools.ru/v1/ws";

pub(crate) fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}
