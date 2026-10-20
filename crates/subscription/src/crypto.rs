use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use super::SubError;

/// Happ publishes this 12-byte nonce for every AES-128-GCM subscription body.
/// It is not a secret and it does not change between updates. Two captured
/// bodies under the same key can be xored. The client keeps it so panels decrypt.
const GCM_IV: &[u8] = b"kkkkkkkkkkkk";

pub fn decrypt_body(key: &[u8], body_b64: &str, tag_b64: &str) -> Result<Vec<u8>, SubError> {
    if key.len() != 16 {
        return Err(SubError::Decrypt("AES-128 key must be 16 bytes".into()));
    }
    let cipher = body_bytes(body_b64)?;
    let tag = body_bytes(tag_b64)?;
    let mut combined = cipher;
    combined.extend_from_slice(&tag);
    let aes = Aes128Gcm::new_from_slice(key).map_err(|e| SubError::Decrypt(e.to_string()))?;
    aes.decrypt(Nonce::from_slice(GCM_IV), combined.as_ref()).map_err(|_| SubError::Decrypt("subscription decryption failed".into()))
}

pub fn encrypt_body(key: &[u8], plain: &[u8]) -> Result<(String, String), SubError> {
    if key.len() != 16 {
        return Err(SubError::Decrypt("AES-128 key must be 16 bytes".into()));
    }
    let aes = Aes128Gcm::new_from_slice(key).map_err(|e| SubError::Decrypt(e.to_string()))?;
    let mut combined = aes.encrypt(Nonce::from_slice(GCM_IV), plain).map_err(|_| SubError::Decrypt("encrypt".into()))?;
    let tag = combined.split_off(combined.len() - 16);
    Ok((STANDARD.encode(combined), STANDARD.encode(tag)))
}

pub(crate) fn decode_b64(value: &str) -> Option<Vec<u8>> {
    let standard = value.trim().replace('-', "+").replace('_', "/");
    if standard.is_empty() {
        return None;
    }
    let pad = (4 - standard.len() % 4) % 4;
    STANDARD.decode(format!("{standard}{}", "=".repeat(pad))).ok()
}

fn body_bytes(value: &str) -> Result<Vec<u8>, SubError> {
    decode_b64(value).ok_or_else(|| SubError::Message("base64".into()))
}
