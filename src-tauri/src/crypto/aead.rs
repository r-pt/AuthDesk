// [ENC-B64::cnB0|Z2Ft|cm9k]
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::RngCore;
use crate::error::AuthDeskError;
use crate::crypto::kdf::DerivedKek;

pub struct MasterKey {
    pub(crate) key: [u8; 32],
}

impl MasterKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn generate_master_key() -> Self {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self { key }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

impl Clone for MasterKey {
    fn clone(&self) -> Self {
        Self { key: self.key }
    }
}

impl Zeroize for MasterKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for MasterKey {}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MasterKey([REDACTED])")
    }
}

pub fn generate_master_key() -> MasterKey {
    MasterKey::generate_master_key()
}

pub fn compute_wrapped_key_aad(
    version: u32,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(15 + 16 + salt.len());
    aad.extend_from_slice(b"AUTHDESK_MK_V1:");
    aad.extend_from_slice(&version.to_be_bytes());
    aad.extend_from_slice(&m_cost.to_be_bytes());
    aad.extend_from_slice(&t_cost.to_be_bytes());
    aad.extend_from_slice(&p_cost.to_be_bytes());
    aad.extend_from_slice(salt);
    aad
}

pub fn compute_payload_aad(version: u32, updated_at: i64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(20 + 4 + 8);
    aad.extend_from_slice(b"AUTHDESK_PAYLOAD_V1:");
    aad.extend_from_slice(&version.to_be_bytes());
    aad.extend_from_slice(&updated_at.to_be_bytes());
    aad
}

#[inline(always)]
fn chacha_qr(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

fn chacha_rounds(state: &mut [u32; 16]) {
    for _ in 0..10 {
        chacha_qr(state, 0, 4, 8, 12);
        chacha_qr(state, 1, 5, 9, 13);
        chacha_qr(state, 2, 6, 10, 14);
        chacha_qr(state, 3, 7, 11, 15);

        chacha_qr(state, 0, 5, 10, 15);
        chacha_qr(state, 1, 6, 11, 12);
        chacha_qr(state, 2, 7, 8, 13);
        chacha_qr(state, 3, 4, 9, 14);
    }
}

fn hchacha20(key: &[u8; 32], nonce16: &[u8; 16]) -> [u8; 32] {
    let mut state = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        u32::from_le_bytes(key[0..4].try_into().unwrap()),
        u32::from_le_bytes(key[4..8].try_into().unwrap()),
        u32::from_le_bytes(key[8..12].try_into().unwrap()),
        u32::from_le_bytes(key[12..16].try_into().unwrap()),
        u32::from_le_bytes(key[16..20].try_into().unwrap()),
        u32::from_le_bytes(key[20..24].try_into().unwrap()),
        u32::from_le_bytes(key[24..28].try_into().unwrap()),
        u32::from_le_bytes(key[28..32].try_into().unwrap()),
        u32::from_le_bytes(nonce16[0..4].try_into().unwrap()),
        u32::from_le_bytes(nonce16[4..8].try_into().unwrap()),
        u32::from_le_bytes(nonce16[8..12].try_into().unwrap()),
        u32::from_le_bytes(nonce16[12..16].try_into().unwrap()),
    ];
    chacha_rounds(&mut state);
    let mut out = [0u8; 32];
    out[0..4].copy_from_slice(&state[0].to_le_bytes());
    out[4..8].copy_from_slice(&state[1].to_le_bytes());
    out[8..12].copy_from_slice(&state[2].to_le_bytes());
    out[12..16].copy_from_slice(&state[3].to_le_bytes());
    out[16..20].copy_from_slice(&state[12].to_le_bytes());
    out[20..24].copy_from_slice(&state[13].to_le_bytes());
    out[24..28].copy_from_slice(&state[14].to_le_bytes());
    out[28..32].copy_from_slice(&state[15].to_le_bytes());
    out
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce12: &[u8; 12]) -> [u8; 64] {
    let initial = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        u32::from_le_bytes(key[0..4].try_into().unwrap()),
        u32::from_le_bytes(key[4..8].try_into().unwrap()),
        u32::from_le_bytes(key[8..12].try_into().unwrap()),
        u32::from_le_bytes(key[12..16].try_into().unwrap()),
        u32::from_le_bytes(key[16..20].try_into().unwrap()),
        u32::from_le_bytes(key[20..24].try_into().unwrap()),
        u32::from_le_bytes(key[24..28].try_into().unwrap()),
        u32::from_le_bytes(key[28..32].try_into().unwrap()),
        counter,
        u32::from_le_bytes(nonce12[0..4].try_into().unwrap()),
        u32::from_le_bytes(nonce12[4..8].try_into().unwrap()),
        u32::from_le_bytes(nonce12[8..12].try_into().unwrap()),
    ];
    let mut state = initial;
    chacha_rounds(&mut state);
    let mut out = [0u8; 64];
    for i in 0..16 {
        let sum = state[i].wrapping_add(initial[i]);
        out[i * 4..(i + 1) * 4].copy_from_slice(&sum.to_le_bytes());
    }
    out
}

fn chacha20_crypt(key: &[u8; 32], counter: u32, nonce12: &[u8; 12], input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut c = counter;
    for chunk in input.chunks(64) {
        let block = chacha20_block(key, c, nonce12);
        for (b_in, b_k) in chunk.iter().zip(block.iter()) {
            out.push(b_in ^ b_k);
        }
        c = c.wrapping_add(1);
    }
    out
}

fn poly1305_process_block(
    h0: &mut u64,
    h1: &mut u64,
    h2: &mut u64,
    r0: u64,
    r1: u64,
    s1: u64,
    c0: u64,
    c1: u64,
    c2: u64,
) {
    let sum0 = (*h0 as u128) + (c0 as u128);
    let carry0 = (sum0 >> 64) as u64;
    *h0 = sum0 as u64;

    let sum1 = (*h1 as u128) + (c1 as u128) + (carry0 as u128);
    let carry1 = (sum1 >> 64) as u64;
    *h1 = sum1 as u64;

    *h2 = (*h2).wrapping_add(c2).wrapping_add(carry1);

    let d0 = (*h0 as u128) * (r0 as u128) + (*h1 as u128) * (s1 as u128);
    let d1 = (*h0 as u128) * (r1 as u128) + (*h1 as u128) * (r0 as u128) + (*h2 as u128) * (s1 as u128);
    let d2 = (*h2 as u128) * (r0 as u128);

    let c0 = d0 >> 64;
    *h0 = d0 as u64;

    let d1 = d1 + c0;
    let c1 = d1 >> 64;
    *h1 = d1 as u64;

    let d2 = d2 + c1;
    let c2 = d2 >> 2;
    *h2 = (d2 as u64) & 3;

    let carry_back = (c2 as u128) * 5;
    let d0 = (*h0 as u128) + carry_back;
    let c0 = d0 >> 64;
    *h0 = d0 as u64;

    let sum1 = (*h1 as u128) + (c0 as u128);
    *h1 = sum1 as u64;
    *h2 = (*h2).wrapping_add((sum1 >> 64) as u64);
}

fn compute_poly1305_tag(key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut r0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
    let mut r1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
    r0 &= 0x0ffffffc0fffffff;
    r1 &= 0x0ffffffc0ffffffc;
    let s1 = (r1 >> 2) * 5;

    let mut h0 = 0u64;
    let mut h1 = 0u64;
    let mut h2 = 0u64;

    let mut process_block = |chunk: &[u8]| {
        if chunk.len() < 16 {
            let mut buf = [0u8; 16];
            buf[..chunk.len()].copy_from_slice(chunk);
            buf[chunk.len()] = 0x01; // RFC 8439 1-byte padding delimiter
            let c0 = u64::from_le_bytes(buf[0..8].try_into().unwrap());
            let c1 = u64::from_le_bytes(buf[8..16].try_into().unwrap());
            let c2 = 0u64; // delimiter is at buf[chunk.len()], so 17th byte is 0
            poly1305_process_block(&mut h0, &mut h1, &mut h2, r0, r1, s1, c0, c1, c2);
        } else {
            let c0 = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
            let c1 = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
            let c2 = 1u64; // 17th byte is 1
            poly1305_process_block(&mut h0, &mut h1, &mut h2, r0, r1, s1, c0, c1, c2);
        }
    };

    for chunk in aad.chunks(16) {
        process_block(chunk);
    }
    for chunk in ciphertext.chunks(16) {
        process_block(chunk);
    }

    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    len_block[8..16].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    process_block(&len_block);

    let g0 = (h0 as u128) + 5;
    let c = (g0 >> 64) as u64;
    let g0 = g0 as u64;
    let g1 = (h1 as u128) + (c as u128);
    let c = (g1 >> 64) as u64;
    let g1 = g1 as u64;
    let g2 = h2 + c;

    let mask = (g2 >> 2).wrapping_neg();
    let h0 = (h0 & !mask) | (g0 & mask);
    let h1 = (h1 & !mask) | (g1 & mask);

    let s0 = u64::from_le_bytes(key[16..24].try_into().unwrap());
    let s1_key = u64::from_le_bytes(key[24..32].try_into().unwrap());
    let tag0 = (h0 as u128) + (s0 as u128);
    let tag1 = (h1 as u128) + (s1_key as u128) + (tag0 >> 64);

    let mut tag = [0u8; 16];
    tag[0..8].copy_from_slice(&(tag0 as u64).to_le_bytes());
    tag[8..16].copy_from_slice(&(tag1 as u64).to_le_bytes());
    tag
}

pub fn encrypt_master_key(
    master_key: &MasterKey,
    kek: &DerivedKek,
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; 24]), AuthDeskError> {
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let subkey = hchacha20(kek.as_bytes(), &nonce[0..16].try_into().unwrap());
    let mut sub_nonce = [0u8; 12];
    sub_nonce[4..12].copy_from_slice(&nonce[16..24]);

    let block0 = chacha20_block(&subkey, 0, &sub_nonce);
    let poly_key: [u8; 32] = block0[0..32].try_into().unwrap();

    let ct = chacha20_crypt(&subkey, 1, &sub_nonce, master_key.as_bytes());
    let tag = compute_poly1305_tag(&poly_key, aad, &ct);

    let mut out = ct;
    out.extend_from_slice(&tag);
    Ok((out, nonce))
}

pub fn decrypt_master_key(
    ciphertext: &[u8],
    nonce: &[u8; 24],
    kek: &DerivedKek,
    aad: &[u8],
) -> Result<MasterKey, AuthDeskError> {
    if ciphertext.len() != 48 {
        return Err(AuthDeskError::Vault(format!(
            "Invalid wrapped master key ciphertext length: expected 48, got {}",
            ciphertext.len()
        )));
    }

    let (ct, tag) = ciphertext.split_at(32);
    let subkey = hchacha20(kek.as_bytes(), &nonce[0..16].try_into().unwrap());
    let mut sub_nonce = [0u8; 12];
    sub_nonce[4..12].copy_from_slice(&nonce[16..24]);

    let block0 = chacha20_block(&subkey, 0, &sub_nonce);
    let poly_key: [u8; 32] = block0[0..32].try_into().unwrap();

    let expected_tag = compute_poly1305_tag(&poly_key, aad, ct);
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= tag[i] ^ expected_tag[i];
    }
    if diff != 0 {
        return Err(AuthDeskError::Vault("Authentication failed for wrapped master key".to_string()));
    }

    let mut pt = chacha20_crypt(&subkey, 1, &sub_nonce, ct);
    let mut key = [0u8; 32];
    key.copy_from_slice(&pt[..32]);
    pt.zeroize();
    Ok(MasterKey::new(key))
}

pub fn encrypt_payload(
    plaintext: &[u8],
    master_key: &MasterKey,
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; 24]), AuthDeskError> {
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let subkey = hchacha20(master_key.as_bytes(), &nonce[0..16].try_into().unwrap());
    let mut sub_nonce = [0u8; 12];
    sub_nonce[4..12].copy_from_slice(&nonce[16..24]);

    let block0 = chacha20_block(&subkey, 0, &sub_nonce);
    let poly_key: [u8; 32] = block0[0..32].try_into().unwrap();

    let ct = chacha20_crypt(&subkey, 1, &sub_nonce, plaintext);
    let tag = compute_poly1305_tag(&poly_key, aad, &ct);

    let mut out = ct;
    out.extend_from_slice(&tag);
    Ok((out, nonce))
}

pub fn decrypt_payload(
    ciphertext: &[u8],
    nonce: &[u8; 24],
    master_key: &MasterKey,
    aad: &[u8],
) -> Result<Vec<u8>, AuthDeskError> {
    if ciphertext.len() < 16 {
        return Err(AuthDeskError::Vault(format!(
            "Payload ciphertext too short: expected at least 16 bytes, got {}",
            ciphertext.len()
        )));
    }

    let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);
    let subkey = hchacha20(master_key.as_bytes(), &nonce[0..16].try_into().unwrap());
    let mut sub_nonce = [0u8; 12];
    sub_nonce[4..12].copy_from_slice(&nonce[16..24]);

    let block0 = chacha20_block(&subkey, 0, &sub_nonce);
    let poly_key: [u8; 32] = block0[0..32].try_into().unwrap();

    let expected_tag = compute_poly1305_tag(&poly_key, aad, ct);
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= tag[i] ^ expected_tag[i];
    }
    if diff != 0 {
        return Err(AuthDeskError::Vault("Authentication failed for payload ciphertext".to_string()));
    }

    let pt = chacha20_crypt(&subkey, 1, &sub_nonce, ct);
    Ok(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_key_debug_redacted() {
        let mk = MasterKey::new([99u8; 32]);
        let debug = format!("{:?}", mk);
        assert_eq!(debug, "MasterKey([REDACTED])");
        assert!(!debug.contains("99"));
    }

    #[test]
    fn test_master_key_encrypt_decrypt_roundtrip() {
        let mk = MasterKey::generate_master_key();
        let kek = DerivedKek::new([7u8; 32]);
        let aad = compute_wrapped_key_aad(1, 65536, 3, 1, &[0u8; 32]);

        let (ct, nonce) = encrypt_master_key(&mk, &kek, &aad).unwrap();
        assert_eq!(ct.len(), 48);

        let decrypted_mk = decrypt_master_key(&ct, &nonce, &kek, &aad).unwrap();
        assert_eq!(decrypted_mk.as_bytes(), mk.as_bytes());

        let bad_aad = compute_wrapped_key_aad(1, 65536, 3, 1, &[1u8; 32]);
        assert!(decrypt_master_key(&ct, &nonce, &kek, &bad_aad).is_err());

        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 0xff;
        assert!(decrypt_master_key(&bad_ct, &nonce, &kek, &aad).is_err());
    }

    #[test]
    fn test_payload_encrypt_decrypt_roundtrip() {
        let mk = MasterKey::generate_master_key();
        let payload = b"Test secret TOTP accounts json string content 1234567890";
        let aad = compute_payload_aad(1, 1710000000);

        let (ct, nonce) = encrypt_payload(payload, &mk, &aad).unwrap();
        assert_eq!(ct.len(), payload.len() + 16);

        let decrypted = decrypt_payload(&ct, &nonce, &mk, &aad).unwrap();
        assert_eq!(decrypted.as_slice(), payload);

        let bad_aad = compute_payload_aad(1, 1710000001);
        assert!(decrypt_payload(&ct, &nonce, &mk, &bad_aad).is_err());
    }

    #[test]
    fn test_aad_construction_byte_exactness() {
        let salt = [0x53u8; 32];
        let aad_mk = compute_wrapped_key_aad(1, 65536, 3, 1, &salt);
        assert!(aad_mk.starts_with(b"AUTHDESK_MK_V1:"));
        assert_eq!(aad_mk.len(), 15 + 16 + 32);

        let aad_payload = compute_payload_aad(1, 1710000000);
        assert!(aad_payload.starts_with(b"AUTHDESK_PAYLOAD_V1:"));
        assert_eq!(aad_payload.len(), 20 + 4 + 8);
    }

    #[test]
    fn test_fractional_block_padding_roundtrip() {
        let mk = MasterKey::generate_master_key();
        let kek = DerivedKek::new([42u8; 32]);

        // Test lengths that span multiple 16-byte boundaries and fractional remainders
        for len in [0, 1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127] {
            let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let aad = compute_payload_aad(1, 1710000000 + len as i64);

            let (ct, nonce) = encrypt_payload(&payload, &mk, &aad).unwrap();
            assert_eq!(ct.len(), len + 16);

            let pt = decrypt_payload(&ct, &nonce, &mk, &aad).unwrap();
            assert_eq!(pt, payload, "Failed roundtrip for payload length {}", len);
        }

        // Test wrapped MK with varying salt sizes (fractional AAD)
        for salt_len in [16, 20, 24, 32, 48, 64] {
            let salt = vec![0xabu8; salt_len];
            let aad = compute_wrapped_key_aad(1, 65536, 3, 1, &salt);
            let (ct, nonce) = encrypt_master_key(&mk, &kek, &aad).unwrap();
            let decrypted_mk = decrypt_master_key(&ct, &nonce, &kek, &aad).unwrap();
            assert_eq!(decrypted_mk.as_bytes(), mk.as_bytes());
        }
    }
}
