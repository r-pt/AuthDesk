//! AuthDesk - Normalización y decodificación de claves secretas Base32 según RFC 4648.
//! Invariante de seguridad: Ningún mensaje de error debe exponer el contenido de la clave secreta.

use crate::error::AuthDeskError;
use data_encoding::BASE32;

/// Normaliza una cadena Base32 eliminando espacios, guiones, tabulaciones y saltos de línea,
/// convirtiendo a mayúsculas y asegurando el padding '=' de RFC 4648.
pub fn normalize_base32(input: &str) -> Result<String, AuthDeskError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(AuthDeskError::Base32Decode(
            "El secreto Base32 no puede estar vacío".to_string(),
        ));
    }

    // Filtrar caracteres no significativos y convertir a mayúsculas
    let filtered: String = trimmed
        .chars()
        .filter(|&c| c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '-')
        .flat_map(|c| c.to_uppercase())
        .collect();

    // Eliminar padding previo para recalcularlo de forma determinista
    let unpadded = filtered.trim_end_matches('=');
    if unpadded.is_empty() {
        return Err(AuthDeskError::Base32Decode(
            "El secreto Base32 no contiene caracteres de datos válidos".to_string(),
        ));
    }

    // Validar alfabeto RFC 4648 (A-Z, 2-7) sin filtrar el secreto completo en el error
    for ch in unpadded.chars() {
        if !matches!(ch, 'A'..='Z' | '2'..='7') {
            return Err(AuthDeskError::Base32Decode(format!(
                "Carácter Base32 no válido detectado: '{}'",
                ch
            )));
        }
    }

    // Re-pad a múltiplo de 8 según RFC 4648
    let remainder = unpadded.len() % 8;
    let padding_len = if remainder == 0 {
        0
    } else {
        8 - remainder
    };

    let mut result = String::with_capacity(unpadded.len() + padding_len);
    result.push_str(unpadded);
    for _ in 0..padding_len {
        result.push('=');
    }

    Ok(result)
}

/// Decodifica una clave Base32 en bytes crudos luego de normalizarla.
pub fn decode_base32(input: &str) -> Result<Vec<u8>, AuthDeskError> {
    let normalized = normalize_base32(input)?;
    BASE32
        .decode(normalized.as_bytes())
        .map_err(|e| AuthDeskError::Base32Decode(format!("Fallo al decodificar Base32: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_base32_canonical() {
        let input = "JBSWY3DPEHPK3PXP";
        let normalized = normalize_base32(input).expect("Debe normalizar");
        assert_eq!(normalized, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn test_normalize_base32_lowercase_and_separators() {
        let canonical = "JBSWY3DPEHPK3PXP";
        let variations = [
            "jbswy3dpehpk3pxp",
            "JBSW Y3DP EHPK 3PXP",
            "JBSW-Y3DP-EHPK-3PXP",
            "JBSWY3DPEHPK3PXP====",
            "  jbsw-y3dp\tehpk\n3pxp==  ",
        ];

        for var in variations {
            let normalized = normalize_base32(var).expect("Debe normalizar");
            assert_eq!(normalized, canonical, "Falló variación: {}", var);
        }
    }

    #[test]
    fn test_normalize_base32_padding_calculation() {
        // Longitud 2 -> debe rellenar 6 '='
        let n2 = normalize_base32("MY").unwrap();
        assert_eq!(n2, "MY======");

        // Longitud 4 -> debe rellenar 4 '='
        let n4 = normalize_base32("MZXW").unwrap();
        assert_eq!(n4, "MZXW====");

        // Longitud 5 -> debe rellenar 3 '='
        let n5 = normalize_base32("MZXW6").unwrap();
        assert_eq!(n5, "MZXW6===");

        // Longitud 7 -> debe rellenar 1 '='
        let n7 = normalize_base32("MZXW6YQ").unwrap();
        assert_eq!(n7, "MZXW6YQ=");

        // Longitud 8 -> sin relleno
        let n8 = normalize_base32("MZXW6YTB").unwrap();
        assert_eq!(n8, "MZXW6YTB");
    }

    #[test]
    fn test_normalize_base32_empty_fails() {
        assert!(normalize_base32("").is_err());
        assert!(normalize_base32("    ").is_err());
        assert!(normalize_base32("---").is_err());
        assert!(normalize_base32("====").is_err());
        assert!(normalize_base32("  - - == ").is_err());
    }

    #[test]
    fn test_normalize_base32_invalid_characters_fails() {
        // '8' y '9' no existen en Base32 RFC 4648
        assert!(normalize_base32("JBSWY3DP8").is_err());
        assert!(normalize_base32("JBSWY3DP9").is_err());
        // '0' y '1' no existen en Base32 estándar
        assert!(normalize_base32("JBSWY3DP0").is_err());
        assert!(normalize_base32("JBSWY3DP1").is_err());
        // Caracteres especiales
        assert!(normalize_base32("JBSWY@P!").is_err());
    }

    #[test]
    fn test_decode_base32_rfc_test_vectors() {
        // "12345678901234567890" en Base32
        let rfc_secret_b32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let bytes = decode_base32(rfc_secret_b32).expect("Debe decodificar vector RFC");
        assert_eq!(bytes, b"12345678901234567890");

        // "Hello!\xde\xad\xbe\xef" en Base32
        let hello_b32 = "JBSWY3DPEHPK3PXP";
        let hello_bytes = decode_base32(hello_b32).expect("Debe decodificar");
        assert_eq!(hello_bytes, b"Hello!\xde\xad\xbe\xef");
    }

    #[test]
    fn test_decode_base32_error_has_no_secret() {
        let malformed = "INVALID_SECRET_KEY_WITH_9999";
        let err = decode_base32(malformed).unwrap_err();
        let err_msg = err.to_string();
        // Verificar que no se filtre el secreto completo en el mensaje de error
        assert!(!err_msg.contains(malformed));
    }
}
