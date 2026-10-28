//! Зашифрованный канал между телефоном и ПК поверх ретранслятора (Noise, snow).
//!
//! Кадр — `[вид][сообщение Noise]`: 1 — рукопожатие сопряжения (XXpsk3), 2 — рукопожатие по известным
//! ключам (KK), 3 — данные. Данные режутся на куски до 65000 байт (предел сообщения Noise — 65535):
//! первый байт расшифрованного куска — 1, если дальше будет продолжение.

use snow::{Builder, HandshakeState, TransportState};

use crate::identity::Identity;

pub const PARAMS_PAIR: &str = "Noise_XXpsk3_25519_ChaChaPoly_BLAKE2s";
pub const PARAMS_KK: &str = "Noise_KK_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE: &[u8] = b"basehub-remote-v1";

pub const KIND_PAIR: u8 = 1;
pub const KIND_KK: u8 = 2;
pub const KIND_DATA: u8 = 3;

const CHUNK: usize = 65000;
/// Предел собранного сообщения (результат запроса и т.п.).
pub const MAX_MESSAGE: usize = 32 * 1024 * 1024;

/// Что получилось из входящего кадра.
#[derive(Debug, PartialEq)]
pub enum Out {
    /// Отправить собеседнику (через ретранслятор).
    Frame(Vec<u8>),
    /// Рукопожатие завершено; публичный X25519 собеседника.
    Established([u8; 32]),
    /// Собранное прикладное сообщение.
    Message(Vec<u8>),
}

pub struct Channel {
    kind: u8,
    hs: Option<HandshakeState>,
    ts: Option<TransportState>,
    remote: Option<[u8; 32]>,
    partial: Vec<u8>,
}

fn err(e: snow::Error) -> String {
    format!("шифрование: {e}")
}

impl Channel {
    /// Телефон начинает сопряжение; первый кадр — в ответе.
    pub fn pair_initiator(me: &Identity, code: &str) -> Result<(Channel, Vec<u8>), String> {
        let hs = Builder::new(PARAMS_PAIR.parse().unwrap())
            .local_private_key(me.dh_secret())
            .psk(3, &crate::pair::psk(code))
            .prologue(PROLOGUE)
            .build_initiator()
            .map_err(err)?;
        Channel::start(KIND_PAIR, hs)
    }

    /// ПК отвечает на сопряжение по своему коду.
    pub fn pair_responder(me: &Identity, code: &str) -> Result<Channel, String> {
        let hs = Builder::new(PARAMS_PAIR.parse().unwrap())
            .local_private_key(me.dh_secret())
            .psk(3, &crate::pair::psk(code))
            .prologue(PROLOGUE)
            .build_responder()
            .map_err(err)?;
        Ok(Channel::new(KIND_PAIR, hs))
    }

    /// Подключение к уже сопряжённому устройству.
    pub fn kk_initiator(me: &Identity, remote: &[u8; 32]) -> Result<(Channel, Vec<u8>), String> {
        let hs = Builder::new(PARAMS_KK.parse().unwrap())
            .local_private_key(me.dh_secret())
            .remote_public_key(remote)
            .prologue(PROLOGUE)
            .build_initiator()
            .map_err(err)?;
        Channel::start(KIND_KK, hs)
    }

    pub fn kk_responder(me: &Identity, remote: &[u8; 32]) -> Result<Channel, String> {
        let hs = Builder::new(PARAMS_KK.parse().unwrap())
            .local_private_key(me.dh_secret())
            .remote_public_key(remote)
            .prologue(PROLOGUE)
            .build_responder()
            .map_err(err)?;
        Ok(Channel::new(KIND_KK, hs))
    }

    fn new(kind: u8, hs: HandshakeState) -> Channel {
        Channel { kind, hs: Some(hs), ts: None, remote: None, partial: Vec::new() }
    }

    fn start(kind: u8, mut hs: HandshakeState) -> Result<(Channel, Vec<u8>), String> {
        let mut buf = vec![0u8; 65535];
        let n = hs.write_message(&[], &mut buf).map_err(err)?;
        Ok((Channel::new(kind, hs), frame(kind, &buf[..n])))
    }

    /// Вид кадра (первый байт); `None` — пустой кадр.
    pub fn frame_kind(frame: &[u8]) -> Option<u8> {
        frame.first().copied()
    }

    pub fn is_established(&self) -> bool {
        self.ts.is_some()
    }

    /// Рукопожатие ещё идёт.
    pub fn in_handshake(&self) -> bool {
        self.hs.is_some()
    }

    pub fn kind(&self) -> u8 {
        self.kind
    }

    /// Публичный X25519 собеседника (после рукопожатия).
    pub fn remote_key(&self) -> Option<[u8; 32]> {
        self.remote
    }

    /// Разобрать входящий кадр.
    pub fn handle(&mut self, data: &[u8]) -> Result<Vec<Out>, String> {
        let (&kind, body) = data.split_first().ok_or("пустой кадр")?;
        let mut out = Vec::new();
        if let Some(hs) = self.hs.as_mut() {
            if kind != self.kind {
                return Err("кадр не того вида во время рукопожатия".into());
            }
            let mut buf = vec![0u8; 65535];
            hs.read_message(body, &mut buf).map_err(err)?;
            if !hs.is_handshake_finished() && hs.is_my_turn() {
                let n = hs.write_message(&[], &mut buf).map_err(err)?;
                out.push(Out::Frame(frame(self.kind, &buf[..n])));
            }
            if hs.is_handshake_finished() {
                let hs = self.hs.take().unwrap();
                let remote: [u8; 32] = hs.get_remote_static().and_then(|k| k.try_into().ok()).ok_or("нет ключа собеседника")?;
                self.ts = Some(hs.into_transport_mode().map_err(err)?);
                self.remote = Some(remote);
                out.push(Out::Established(remote));
            }
            return Ok(out);
        }
        let ts = self.ts.as_mut().ok_or("канал не открыт")?;
        if kind != KIND_DATA {
            return Err("ожидались данные".into());
        }
        let mut buf = vec![0u8; 65535];
        let n = ts.read_message(body, &mut buf).map_err(err)?;
        let (&more, chunk) = buf[..n].split_first().ok_or("пустой кусок")?;
        if self.partial.len() + chunk.len() > MAX_MESSAGE {
            self.partial.clear();
            return Err("сообщение слишком большое".into());
        }
        self.partial.extend_from_slice(chunk);
        if more == 0 {
            out.push(Out::Message(std::mem::take(&mut self.partial)));
        }
        Ok(out)
    }

    /// Зашифровать сообщение — один или несколько кадров.
    pub fn seal(&mut self, msg: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let ts = self.ts.as_mut().ok_or("канал не открыт")?;
        if msg.len() > MAX_MESSAGE {
            return Err("сообщение слишком большое".into());
        }
        let mut frames = Vec::new();
        let mut buf = vec![0u8; 65535];
        let mut chunks = msg.chunks(CHUNK).peekable();
        if chunks.peek().is_none() {
            let n = ts.write_message(&[0], &mut buf).map_err(err)?;
            return Ok(vec![frame(KIND_DATA, &buf[..n])]);
        }
        while let Some(c) = chunks.next() {
            let mut plain = Vec::with_capacity(c.len() + 1);
            plain.push(u8::from(chunks.peek().is_some()));
            plain.extend_from_slice(c);
            let n = ts.write_message(&plain, &mut buf).map_err(err)?;
            frames.push(frame(KIND_DATA, &buf[..n]));
        }
        Ok(frames)
    }
}

fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(body.len() + 1);
    f.push(kind);
    f.extend_from_slice(body);
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Прогнать кадры между сторонами, пока есть что отправлять; вернуть события обеих.
    fn pump(a: &mut Channel, b: &mut Channel, first: Vec<u8>) -> (Vec<Out>, Vec<Out>) {
        let (mut ea, mut eb) = (Vec::new(), Vec::new());
        let mut to_b = vec![first];
        let mut to_a: Vec<Vec<u8>> = Vec::new();
        while !to_b.is_empty() || !to_a.is_empty() {
            for f in std::mem::take(&mut to_b) {
                for o in b.handle(&f).unwrap() {
                    match o {
                        Out::Frame(f) => to_a.push(f),
                        o => eb.push(o),
                    }
                }
            }
            for f in std::mem::take(&mut to_a) {
                for o in a.handle(&f).unwrap() {
                    match o {
                        Out::Frame(f) => to_b.push(f),
                        o => ea.push(o),
                    }
                }
            }
        }
        (ea, eb)
    }

    #[test]
    fn pairing_then_kk_then_big_message() {
        let (phone, pc) = (Identity::generate(), Identity::generate());
        let code = crate::pair::new_code();
        let (mut p, first) = Channel::pair_initiator(&phone, &code).unwrap();
        let mut c = Channel::pair_responder(&pc, &code).unwrap();
        let (ep, ec) = pump(&mut p, &mut c, first);
        assert_eq!(ep, vec![Out::Established(pc.dh_public())]);
        assert_eq!(ec, vec![Out::Established(phone.dh_public())]);

        // следующее подключение — по сохранённым ключам
        let (mut p, first) = Channel::kk_initiator(&phone, &pc.dh_public()).unwrap();
        let mut c = Channel::kk_responder(&pc, &phone.dh_public()).unwrap();
        pump(&mut p, &mut c, first);
        assert!(p.is_established() && c.is_established());

        let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let mut got = Vec::new();
        for f in p.seal(&big).unwrap() {
            got.extend(c.handle(&f).unwrap());
        }
        assert_eq!(got, vec![Out::Message(big)]);
        let back = c.seal(b"").unwrap();
        assert_eq!(p.handle(&back[0]).unwrap(), vec![Out::Message(vec![])]);
    }

    #[test]
    fn wrong_code_fails() {
        let (phone, pc) = (Identity::generate(), Identity::generate());
        let (mut p, first) = Channel::pair_initiator(&phone, "ABCDEFGH").unwrap();
        let mut c = Channel::pair_responder(&pc, "ABCDEFGJ").unwrap();
        let reply = c.handle(&first).unwrap();
        let Out::Frame(f) = &reply[0] else { panic!() };
        let third = p.handle(f).unwrap();
        let Out::Frame(f) = &third[0] else { panic!() };
        // PSK вступает в третьем сообщении — ПК его не принимает
        assert!(c.handle(f).is_err());
    }

    #[test]
    fn kk_with_foreign_key_fails_and_tamper_detected() {
        let (phone, pc, other) = (Identity::generate(), Identity::generate(), Identity::generate());
        let (_, first) = Channel::kk_initiator(&phone, &pc.dh_public()).unwrap();
        // ПК ждёт другого телефона
        let mut c = Channel::kk_responder(&pc, &other.dh_public()).unwrap();
        assert!(c.handle(&first).is_err());

        let (mut p, first) = Channel::kk_initiator(&phone, &pc.dh_public()).unwrap();
        let mut c = Channel::kk_responder(&pc, &phone.dh_public()).unwrap();
        pump(&mut p, &mut c, first);
        let mut f = p.seal(b"hello").unwrap().remove(0);
        let last = f.len() - 1;
        f[last] ^= 1;
        assert!(c.handle(&f).is_err());
    }
}
