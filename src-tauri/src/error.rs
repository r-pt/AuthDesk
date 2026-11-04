//! AuthDesk - Jerarquía de errores personalizada.
//! Invariante de seguridad: Ningún mensaje de error debe exponer secretos ni datos sensibles.

use serde::Serialize;

/// Errores unificados de AuthDesk.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthDeskError {
    #[error("Error al decodificar Base32: {0}")]
    Base32Decode(String),

    #[error("Error en motor TOTP: {0}")]
    TotpGeneration(String),

    #[error("Cuenta no encontrada: {0}")]
    AccountNotFound(String),

    #[error("Parámetro inválido: {0}")]
    InvalidParameter(String),

    #[error("Bloqueo de estado interno envenenado")]
    LockPoisoned,

    #[error("Error en reloj del sistema: {0}")]
    SystemTime(String),

    #[error("Error de bóveda segura: {0}")]
    Vault(String),
}

impl Serialize for AuthDeskError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl From<std::time::SystemTimeError> for AuthDeskError {
    fn from(err: std::time::SystemTimeError) -> Self {
        AuthDeskError::SystemTime(err.to_string())
    }
}

impl<T> From<std::sync::PoisonError<T>> for AuthDeskError {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        AuthDeskError::LockPoisoned
    }
}

impl From<AuthDeskError> for String {
    fn from(err: AuthDeskError) -> Self {
        err.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_serialization_as_string() {
        let err = AuthDeskError::InvalidParameter("Valor incorrecto".to_string());
        let json = serde_json::to_string(&err).expect("Debe serializar");
        assert_eq!(json, "\"Parámetro inválido: Valor incorrecto\"");
    }

    #[test]
    fn test_error_conversion_to_string() {
        let err = AuthDeskError::LockPoisoned;
        let s: String = err.into();
        assert_eq!(s, "Bloqueo de estado interno envenenado");
    }
}
