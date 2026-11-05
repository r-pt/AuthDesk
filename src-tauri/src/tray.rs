//! Módulo de gestión del icono de bandeja del sistema (System Tray).
//! Provee el menú contextual con "Mostrar AuthDesk", "Bloquear", "Salir"
//! y el manejo de eventos de clic izquierdo para conmutar la ventana.

pub const TRAY_SHOW_LABEL: &str = "Mostrar AuthDesk";
pub const TRAY_HIDE_LABEL: &str = "Ocultar AuthDesk";
pub const TRAY_LOCK_LABEL: &str = "Bloquear";
pub const TRAY_QUIT_LABEL: &str = "Salir";

/// Representa el estado y las opciones de menú de la bandeja del sistema
pub struct TrayState {
    pub is_window_visible: bool,
    pub is_locked: bool,
}

impl Default for TrayState {
    fn default() -> Self {
        Self {
            is_window_visible: false,
            is_locked: true,
        }
    }
}

/// Registra las acciones esperadas por el menú del sistema
pub fn get_tray_menu_actions() -> Vec<&'static str> {
    vec![TRAY_SHOW_LABEL, TRAY_LOCK_LABEL, TRAY_QUIT_LABEL]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tray_menu_actions_contain_required_items() {
        let actions = get_tray_menu_actions();
        assert!(actions.contains(&"Mostrar AuthDesk"));
        assert!(actions.contains(&"Bloquear"));
        assert!(actions.contains(&"Salir"));
    }

    #[test]
    fn test_tray_state_default() {
        let state = TrayState::default();
        assert!(!state.is_window_visible);
        assert!(state.is_locked);
    }
}
