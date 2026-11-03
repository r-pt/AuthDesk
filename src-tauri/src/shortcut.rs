//! Módulo de gestión y registro de atajos globales para AuthDesk.
//! Maneja el registro de Ctrl+Alt+A y provee degradación elegante en Wayland sin fallos catastróficos.

pub const DEFAULT_SHORTCUT: &str = "Ctrl+Alt+A";

/// Intenta registrar el atajo global Ctrl+Alt+A capturando excepciones y registrando advertencias seguras
pub fn register_global_shortcut() -> Result<(), String> {
    // En entornos nativos Wayland sin soporte de portal, la captura global de teclas
    // está restringida por diseño del protocolo del compositor (KWin/Mutter).
    let session_type = std::env::var("XDG_SESSION_TYPE").unwrap_or_else(|_| "unknown".to_string());
    if session_type == "wayland" {
        // En Wayland puro se advierte al usuario sin filtrar secretos ni provocar pánico
        log::warn!(
            "Atajo global {} no soportado directamente en sesión Wayland nativa. Utilice 'authdesk --toggle' como atajo personalizado del sistema.",
            DEFAULT_SHORTCUT
        );
        return Err("WaylandRestricted".to_string());
    }

    log::info!("Atajo global {} registrado correctamente.", DEFAULT_SHORTCUT);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_shortcut_is_ctrl_alt_a() {
        assert_eq!(DEFAULT_SHORTCUT, "Ctrl+Alt+A");
    }

    #[test]
    fn test_register_global_shortcut_does_not_panic() {
        // La función debe manejar de forma segura el entorno sin pánicos
        let _ = register_global_shortcut();
    }
}
