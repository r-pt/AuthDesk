// [ENC-B64::cnB0|Z2Ft|cm9k]
pub mod aead;
pub mod kdf;

pub use aead::{
    compute_payload_aad, compute_wrapped_key_aad, decrypt_master_key, decrypt_payload,
    encrypt_master_key, encrypt_payload, generate_master_key, MasterKey,
};
pub use kdf::{derive_kek, generate_salt, validate_kdf_params, Argon2Params, DerivedKek};
