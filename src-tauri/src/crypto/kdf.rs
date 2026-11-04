// [ENC-B64::cnB0|Z2Ft|cm9k]
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::RngCore;
use crate::error::AuthDeskError;

pub const DEFAULT_M_COST_KIB: u32 = 65536;
pub const DEFAULT_T_COST: u32 = 3;
pub const DEFAULT_P_COST: u32 = 1;
pub const MIN_SALT_LEN: usize = 16;
pub const RECOMMENDED_SALT_LEN: usize = 32;
pub const KEK_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Argon2Params {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            m_cost_kib: DEFAULT_M_COST_KIB,
            t_cost: DEFAULT_T_COST,
            p_cost: DEFAULT_P_COST,
        }
    }
}

pub struct DerivedKek {
    pub(crate) key: [u8; 32],
}

impl DerivedKek {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

impl Clone for DerivedKek {
    fn clone(&self) -> Self {
        Self { key: self.key }
    }
}

impl Zeroize for DerivedKek {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for DerivedKek {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for DerivedKek {}

impl std::fmt::Debug for DerivedKek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DerivedKek([REDACTED])")
    }
}

pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

pub fn validate_kdf_params(params: &Argon2Params, salt_len: usize) -> Result<(), AuthDeskError> {
    if params.m_cost_kib < 65536 {
        return Err(AuthDeskError::Vault(format!(
            "Invalid KDF m_cost: expected at least 65536 KiB, got {}",
            params.m_cost_kib
        )));
    }
    if params.t_cost < 3 {
        return Err(AuthDeskError::Vault(format!(
            "Invalid KDF t_cost: expected at least 3, got {}",
            params.t_cost
        )));
    }
    if params.p_cost != 1 {
        return Err(AuthDeskError::Vault(format!(
            "Invalid KDF p_cost: expected 1, got {}",
            params.p_cost
        )));
    }
    if salt_len < MIN_SALT_LEN {
        return Err(AuthDeskError::Vault(format!(
            "Salt too short: expected at least {} bytes, got {}",
            MIN_SALT_LEN, salt_len
        )));
    }
    Ok(())
}

const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

const BLAKE2B_SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

#[inline(always)]
fn blake2b_g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn blake2b_compress(h: &mut [u64; 8], block: &[u8; 128], count: u64, is_last: bool) {
    let mut v = [0u64; 16];
    v[0..8].copy_from_slice(h);
    v[8..16].copy_from_slice(&BLAKE2B_IV);
    v[12] ^= count;
    if is_last {
        v[14] = !v[14];
    }

    let mut m = [0u64; 16];
    for (i, chunk) in block.chunks_exact(8).enumerate() {
        m[i] = u64::from_le_bytes(chunk.try_into().unwrap());
    }

    for r in 0..12 {
        let s = &BLAKE2B_SIGMA[r];
        blake2b_g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        blake2b_g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        blake2b_g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        blake2b_g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        blake2b_g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        blake2b_g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        blake2b_g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        blake2b_g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

pub fn blake2b(data: &[u8], out_len: usize) -> Vec<u8> {
    assert!(out_len > 0 && out_len <= 64);
    let mut h = BLAKE2B_IV;
    h[0] ^= 0x01010000 ^ (out_len as u64);

    let mut buf = [0u8; 128];
    let mut buf_len = 0;
    let mut total_bytes = 0u64;

    for &byte in data {
        if buf_len == 128 {
            total_bytes += 128;
            blake2b_compress(&mut h, &buf, total_bytes, false);
            buf_len = 0;
        }
        buf[buf_len] = byte;
        buf_len += 1;
    }

    total_bytes += buf_len as u64;
    for i in buf_len..128 {
        buf[i] = 0;
    }
    blake2b_compress(&mut h, &buf, total_bytes, true);

    let mut out = Vec::with_capacity(out_len);
    for word in &h {
        let bytes = word.to_le_bytes();
        let take = (out_len - out.len()).min(8);
        out.extend_from_slice(&bytes[..take]);
        if out.len() == out_len {
            break;
        }
    }
    out
}

fn blake2b_long(data: &[u8], out_len: usize) -> Vec<u8> {
    if out_len <= 64 {
        let mut prefix = Vec::with_capacity(4 + data.len());
        prefix.extend_from_slice(&(out_len as u32).to_le_bytes());
        prefix.extend_from_slice(data);
        return blake2b(&prefix, out_len);
    }

    let mut out = Vec::with_capacity(out_len);
    let mut prefix = Vec::with_capacity(4 + data.len());
    prefix.extend_from_slice(&(out_len as u32).to_le_bytes());
    prefix.extend_from_slice(data);

    let mut v = blake2b(&prefix, 64);
    let r = (out_len + 31) / 32 - 2;

    for _ in 1..=r {
        out.extend_from_slice(&v[..32]);
        v = blake2b(&v, 64);
    }
    let remaining = out_len - out.len();
    out.extend_from_slice(&v[..remaining]);
    out
}

#[derive(Clone, Copy)]
pub struct Block {
    pub v: [u64; 128],
}

impl Block {
    pub fn zero() -> Self {
        Self { v: [0u64; 128] }
    }

    pub fn xor(&mut self, other: &Block) {
        for i in 0..128 {
            self.v[i] ^= other.v[i];
        }
    }

    pub fn from_bytes(bytes: &[u8; 1024]) -> Self {
        let mut b = Self::zero();
        for (i, chunk) in bytes.chunks_exact(8).enumerate() {
            b.v[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        b
    }

    pub fn to_bytes(&self, out: &mut [u8; 1024]) {
        for (i, word) in self.v.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
        }
    }
}

impl Zeroize for Block {
    fn zeroize(&mut self) {
        self.v.zeroize();
    }
}

#[inline(always)]
fn f_g(v: &mut [u64; 128], a: usize, b: usize, c: usize, d: usize) {
    let m1 = ((v[a] as u32 as u64) * (v[b] as u32 as u64)).wrapping_mul(2);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(m1);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    let m2 = ((v[c] as u32 as u64) * (v[d] as u32 as u64)).wrapping_mul(2);
    v[c] = v[c].wrapping_add(v[d]).wrapping_add(m2);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    let m3 = ((v[a] as u32 as u64) * (v[b] as u32 as u64)).wrapping_mul(2);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(m3);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    let m4 = ((v[c] as u32 as u64) * (v[d] as u32 as u64)).wrapping_mul(2);
    v[c] = v[c].wrapping_add(v[d]).wrapping_add(m4);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

#[inline(always)]
fn f_round(v: &mut [u64; 128], r0: usize, r1: usize, r2: usize, r3: usize,
           r4: usize, r5: usize, r6: usize, r7: usize) {
    f_g(v, r0, r2, r4, r6);
    f_g(v, r1, r3, r5, r7);
}

fn permute_block(block: &mut Block) {
    let v = &mut block.v;
    for row in 0..8 {
        let base = row * 16;
        f_round(
            v,
            base, base + 1,
            base + 2, base + 3,
            base + 4, base + 5,
            base + 6, base + 7,
        );
        f_round(
            v,
            base + 8, base + 9,
            base + 10, base + 11,
            base + 12, base + 13,
            base + 14, base + 15,
        );
    }
    for col in 0..8 {
        let c0 = col * 2;
        let c1 = col * 2 + 1;
        f_round(
            v,
            c0, c1,
            c0 + 32, c1 + 32,
            c0 + 64, c1 + 64,
            c0 + 96, c1 + 96,
        );
        f_round(
            v,
            c0 + 16, c1 + 16,
            c0 + 48, c1 + 48,
            c0 + 80, c1 + 80,
            c0 + 112, c1 + 112,
        );
    }
}

pub fn derive_kek(password: &str, salt: &[u8], params: &Argon2Params) -> Result<DerivedKek, AuthDeskError> {
    validate_kdf_params(params, salt.len())?;

    let p = params.p_cost;
    let tau = 32u32;
    let m = params.m_cost_kib;
    let t = params.t_cost;
    let v = 0x13u32;
    let y = 2u32;

    let mut h0_input = Vec::new();
    h0_input.extend_from_slice(&p.to_le_bytes());
    h0_input.extend_from_slice(&tau.to_le_bytes());
    h0_input.extend_from_slice(&m.to_le_bytes());
    h0_input.extend_from_slice(&t.to_le_bytes());
    h0_input.extend_from_slice(&v.to_le_bytes());
    h0_input.extend_from_slice(&y.to_le_bytes());

    h0_input.extend_from_slice(&(password.len() as u32).to_le_bytes());
    h0_input.extend_from_slice(password.as_bytes());

    h0_input.extend_from_slice(&(salt.len() as u32).to_le_bytes());
    h0_input.extend_from_slice(salt);

    h0_input.extend_from_slice(&0u32.to_le_bytes());
    h0_input.extend_from_slice(&0u32.to_le_bytes());

    let mut h0 = blake2b(&h0_input, 64);
    h0_input.zeroize();

    let m_prime = (m / 4) * 4;
    let total_blocks = m_prime as usize;
    let mut memory = vec![Block::zero(); total_blocks];

    for i in 0..2 {
        let mut b_input = Vec::with_capacity(72);
        b_input.extend_from_slice(&h0);
        b_input.extend_from_slice(&(i as u32).to_le_bytes());
        b_input.extend_from_slice(&0u32.to_le_bytes());
        let block_bytes = blake2b_long(&b_input, 1024);
        b_input.zeroize();
        memory[i] = Block::from_bytes(block_bytes[..1024].try_into().unwrap());
    }
    h0.zeroize();

    let segment_len = total_blocks / 4;

    for pass in 0..t {
        for slice in 0..4 {
            let start = slice * segment_len;
            let end = start + segment_len;
            let initial_idx = if pass == 0 && slice == 0 { 2 } else { 0 };

            for index in (start + initial_idx)..end {
                let prev_idx = if index == 0 { total_blocks - 1 } else { index - 1 };
                let prev_block = memory[prev_idx];

                let is_data_independent = pass == 0 && slice < 2;
                let j_1 = if is_data_independent {
                    let mut input = [0u8; 12];
                    input[..4].copy_from_slice(&(pass as u32).to_le_bytes());
                    input[4..8].copy_from_slice(&0u32.to_le_bytes());
                    input[8..12].copy_from_slice(&(slice as u32).to_le_bytes());
                    let mut h = BLAKE2B_IV;
                    h[0] ^= 0x01010000 ^ 64;
                    let mut buf = [0u8; 128];
                    buf[..12].copy_from_slice(&input);
                    buf[12..16].copy_from_slice(&(index as u32).to_le_bytes());
                    blake2b_compress(&mut h, &buf, 16, true);
                    h[0] as u32
                } else {
                    prev_block.v[0] as u32
                };

                let area_size = if pass == 0 {
                    if slice == 0 {
                        index - 1
                    } else {
                        slice * segment_len + (index % segment_len) - 1
                    }
                } else {
                    total_blocks - segment_len + (index % segment_len) - 1
                };

                let ref_index = if area_size == 0 {
                    0
                } else {
                    let rel_idx = ((j_1 as u64 * j_1 as u64) >> 32) as usize % area_size;
                    let start_pos = if pass == 0 { 0 } else { ((slice + 1) % 4) * segment_len };
                    (start_pos + rel_idx) % total_blocks
                };

                let ref_block = memory[ref_index];
                let mut cur = prev_block;
                cur.xor(&ref_block);
                let y_block = cur;
                permute_block(&mut cur);
                cur.xor(&y_block);

                if pass > 0 {
                    memory[index].xor(&cur);
                } else {
                    memory[index] = cur;
                }
            }
        }
    }

    let mut last_bytes = [0u8; 1024];
    memory[total_blocks - 1].to_bytes(&mut last_bytes);
    let mut kek_bytes = blake2b_long(&last_bytes, 32);
    last_bytes.zeroize();

    for b in memory.iter_mut() {
        b.zeroize();
    }
    drop(memory);

    let mut key = [0u8; 32];
    key.copy_from_slice(&kek_bytes[..32]);
    kek_bytes.zeroize();
    Ok(DerivedKek::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake2b_vectors() {
        let digest = blake2b(b"abc", 64);
        let hex = digest.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        assert_eq!(hex, "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    }

    #[test]
    fn test_kdf_params_validation_rejects_downgrade() {
        let mut p = Argon2Params::default();
        p.m_cost_kib = 1024;
        assert!(validate_kdf_params(&p, 32).is_err());

        let mut p = Argon2Params::default();
        p.t_cost = 2;
        assert!(validate_kdf_params(&p, 32).is_err());

        let mut p = Argon2Params::default();
        p.p_cost = 2;
        assert!(validate_kdf_params(&p, 32).is_err());

        let p = Argon2Params::default();
        assert!(validate_kdf_params(&p, 8).is_err());
    }

    #[test]
    fn test_derived_kek_debug_redacted() {
        let kek = DerivedKek::new([42u8; 32]);
        let debug = format!("{:?}", kek);
        assert_eq!(debug, "DerivedKek([REDACTED])");
        assert!(!debug.contains("42"));
    }
}
