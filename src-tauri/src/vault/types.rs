//! Tipos de datos para el almacenamiento seguro y cifrado del vault.
//! Cumple la regla de cero fugas en depuración (implementación manual de Debug con [REDACTED]).

/// Clave Maestra de 32 bytes (256 bits) generada mediante CSPRNG
pub struct MasterKey {
    pub key: [u8; 32],
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MasterKey([REDACTED])")
    }
}

/// Clave de derivación KEK obtenida mediante Argon2id a partir de la contraseña maestra
pub struct DerivedKek {
    pub key: [u8; 32],
}

impl std::fmt::Debug for DerivedKek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DerivedKek([REDACTED])")
    }
}
