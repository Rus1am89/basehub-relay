//! Ключи устройства: ed25519 — вход на ретранслятор (подпись challenge), X25519 — шифрование Noise.
//! id устройства — первые 16 байт SHA-256 ключа ed25519 в base64url: его не подделать без секрета.

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::b64;

/// Что подписывает устройство при входе на ретранслятор (вместе со случайным `n` от ретранслятора).
const AUTH_CONTEXT: &[u8] = b"basehub-relay-auth-v1";

pub struct Identity {
    sign: SigningKey,
    dh_secret: [u8; 32],
    dh_public: [u8; 32],
}

impl Identity {
    pub fn generate() -> Identity {
        let sign = SigningKey::generate(&mut rand_core::OsRng);
        let kp = snow::Builder::new(crate::channel::PARAMS_KK.parse().expect("noise params"))
            .generate_keypair()
            .expect("x25519 keypair");
        let mut dh_secret = [0u8; 32];
        let mut dh_public = [0u8; 32];
        dh_secret.copy_from_slice(&kp.private);
        dh_public.copy_from_slice(&kp.public);
        Identity { sign, dh_secret, dh_public }
    }

    /// Секрет для хранения: 64 байта (ed25519 ‖ X25519) в base64url.
    pub fn to_secret(&self) -> String {
        let mut b = Vec::with_capacity(64);
        b.extend_from_slice(&self.sign.to_bytes());
        b.extend_from_slice(&self.dh_secret);
        b64().encode(b)
    }

    pub fn from_secret(s: &str) -> Result<Identity, String> {
        let b = b64().decode(s.trim()).map_err(|_| "ключ устройства повреждён".to_string())?;
        if b.len() != 64 {
            return Err("ключ устройства повреждён".into());
        }
        let sign = SigningKey::from_bytes(b[..32].try_into().unwrap());
        let mut dh_secret = [0u8; 32];
        dh_secret.copy_from_slice(&b[32..]);
        Ok(Identity { sign, dh_secret, dh_public: x25519_public(&dh_secret) })
    }

    pub fn id(&self) -> String {
        peer_id(&self.sign.verifying_key().to_bytes())
    }

    /// Публичный ключ ed25519 (base64url) — его ретранслятор проверяет в `hello`.
    pub fn sign_public(&self) -> String {
        b64().encode(self.sign.verifying_key().to_bytes())
    }

    pub fn dh_public(&self) -> [u8; 32] {
        self.dh_public
    }

    pub(crate) fn dh_secret(&self) -> &[u8; 32] {
        &self.dh_secret
    }

    /// Подпись challenge ретранслятора (base64url).
    pub fn sign_challenge(&self, nonce: &[u8]) -> String {
        b64().encode(self.sign.sign(&auth_message(nonce)).to_bytes())
    }
}

fn auth_message(nonce: &[u8]) -> Vec<u8> {
    [AUTH_CONTEXT, nonce].concat()
}

/// id по публичному ключу ed25519.
pub fn peer_id(sign_public: &[u8; 32]) -> String {
    b64().encode(&Sha256::digest(sign_public)[..16])
}

/// Проверка входа на стороне ретранслятора: ключ соответствует id и подписал `nonce`.
pub fn verify_auth(id: &str, sign_public_b64: &str, nonce: &[u8], sig_b64: &str) -> bool {
    let Ok(pk) = b64().decode(sign_public_b64) else { return false };
    let Ok(pk): Result<[u8; 32], _> = pk.try_into() else { return false };
    if peer_id(&pk) != id {
        return false;
    }
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else { return false };
    let Ok(sig) = b64().decode(sig_b64) else { return false };
    let Ok(sig): Result<[u8; 64], _> = sig.try_into() else { return false };
    vk.verify(&auth_message(nonce), &Signature::from_bytes(&sig)).is_ok()
}

/// Публичный X25519 по секретному (snow при загрузке ключа его не отдаёт).
fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*secret)).to_bytes()
}

/// Ключ X25519 в QR/хранилище — base64url.
pub fn encode_key(k: &[u8; 32]) -> String {
    b64().encode(k)
}

pub fn decode_key(s: &str) -> Result<[u8; 32], String> {
    b64().decode(s.trim()).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| "ключ повреждён".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_roundtrip_keeps_keys() {
        let a = Identity::generate();
        let b = Identity::from_secret(&a.to_secret()).unwrap();
        assert_eq!(a.id(), b.id());
        assert_eq!(a.dh_public(), b.dh_public());
        assert_eq!(a.id().len(), 22);
    }

    #[test]
    fn auth_signature() {
        let a = Identity::generate();
        let sig = a.sign_challenge(b"nonce");
        assert!(verify_auth(&a.id(), &a.sign_public(), b"nonce", &sig));
        assert!(!verify_auth(&a.id(), &a.sign_public(), b"other", &sig));
        let b = Identity::generate();
        // чужой ключ под своим id не проходит
        assert!(!verify_auth(&a.id(), &b.sign_public(), b"nonce", &b.sign_challenge(b"nonce")));
    }
}
