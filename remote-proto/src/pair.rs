//! Приглашение к сопряжению: код `XXXX-XXXX` и QR `basehub://pair?...`.
//!
//! Первые 4 символа кода — номер приглашения на ретрансляторе (по нему телефон без камеры узнаёт id
//! и ключ ПК). PSK для `Noise_XXpsk3` выводится из всех 8 символов — ретранслятор его не знает.

use hkdf::Hkdf;
use rand_core::RngCore;
use sha2::Sha256;

/// Без I, O, 0, 1 — их путают при вводе с экрана.
const ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Сколько живёт приглашение на ПК и на ретрансляторе.
pub const INVITE_TTL_SECS: u64 = 300;

/// Новый код из 8 символов (40 бит), без дефиса.
pub fn new_code() -> String {
    let mut b = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| ALPHABET[(*x & 31) as usize] as char).collect()
}

/// Ввод пользователя → 8 символов кода: регистр, пробелы и дефис не важны.
pub fn normalize_code(input: &str) -> Option<String> {
    let s: String = input.chars().filter(|c| !c.is_whitespace() && *c != '-').map(|c| c.to_ascii_uppercase()).collect();
    (s.len() == 8 && s.bytes().all(|b| ALPHABET.contains(&b))).then_some(s)
}

/// Код для показа: `ABCD-EFGH`.
pub fn display_code(code: &str) -> String {
    format!("{}-{}", &code[..4], &code[4..])
}

/// Номер приглашения на ретрансляторе.
pub fn invite_key(code: &str) -> &str {
    &code[..4]
}

/// PSK рукопожатия сопряжения.
pub fn psk(code: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(b"basehub-pair-v1"), code.as_bytes()).expand(b"psk", &mut out).expect("hkdf 32");
    out
}

/// Что лежит в QR и (без кода) в приглашении на ретрансляторе.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Invite {
    /// Адрес ретранслятора (wss://…).
    pub relay: String,
    /// id ПК.
    pub agent: String,
    /// X25519 ПК, base64url.
    pub key: String,
    /// Имя компьютера — показать на телефоне до подтверждения.
    pub name: String,
}

impl Invite {
    pub fn to_uri(&self, code: &str) -> String {
        format!(
            "basehub://pair?r={}&a={}&k={}&n={}&c={}",
            enc(&self.relay),
            enc(&self.agent),
            enc(&self.key),
            enc(&self.name),
            code
        )
    }

    /// Разбор QR: приглашение и код.
    pub fn from_uri(uri: &str) -> Result<(Invite, String), String> {
        let q = uri.trim().strip_prefix("basehub://pair?").ok_or("это не QR-код Basehub")?;
        let mut inv = Invite { relay: String::new(), agent: String::new(), key: String::new(), name: String::new() };
        let mut code = None;
        for pair in q.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = dec(v);
            match k {
                "r" => inv.relay = v,
                "a" => inv.agent = v,
                "k" => inv.key = v,
                "n" => inv.name = v,
                "c" => code = normalize_code(&v),
                _ => {}
            }
        }
        if !(inv.relay.starts_with("wss://") || inv.relay.starts_with("ws://")) || inv.agent.is_empty() || inv.key.is_empty() {
            return Err("QR-код Basehub неполный".into());
        }
        crate::identity::decode_key(&inv.key)?;
        Ok((inv, code.ok_or("в QR-коде нет кода сопряжения")?))
    }
}

fn enc(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

fn dec(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_input_is_forgiving() {
        let c = new_code();
        assert_eq!(c.len(), 8);
        assert_eq!(normalize_code(&display_code(&c).to_lowercase()), Some(c.clone()));
        assert_eq!(normalize_code(&format!(" {} ", display_code(&c))), Some(c));
        assert_eq!(normalize_code("ABCD-EFG"), None);
        assert_eq!(normalize_code("ABCD-EFGO"), None);
        assert_ne!(psk("ABCDEFGH"), psk("ABCDEFGJ"));
    }

    #[test]
    fn qr_roundtrip() {
        let inv = Invite {
            relay: "wss://api.basehub-tools.ru/v1/ws".into(),
            agent: "agentid".into(),
            key: crate::identity::encode_key(&[7u8; 32]),
            name: "Бухгалтерия & склад".into(),
        };
        let (back, code) = Invite::from_uri(&inv.to_uri("ABCDEFGH")).unwrap();
        assert_eq!((back, code.as_str()), (inv, "ABCDEFGH"));
        assert!(Invite::from_uri("https://example.com").is_err());
    }
}
