// [ENC-B64::cnB0|Z2Ft|cm9k]
pub mod aead;
pub mod kdf;
pub mod keyring;

pub use aead::{
    compute_payload_aad, compute_wrapped_key_aad, decrypt_master_key, decrypt_payload,
    encrypt_master_key, encrypt_payload, generate_master_key, MasterKey,
};
pub use kdf::{
    derive_kek, derive_pin_kek, generate_salt, validate_kdf_params, Argon2Params, DerivedKek,
};
pub use keyring::{
    clear_keyring, delete_device_key, delete_pin_blob, enable_test_keyring,
    get_device_key, get_or_create_device_key, get_pin_blob, is_keyring_available,
    set_device_key, set_pin_blob, DeviceKey, KeyringStorage, PinBlob, PIN_AAD,
};


