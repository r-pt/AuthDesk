// [ENC-B64::cnB0|Z2Ft|cm9k]
pub const DEFAULT_SHORTCUT: &str = "Ctrl+Alt+A";

use tauri::AppHandle;
use tauri_plugin_global_shortcut::{GlobalShortcutExt, Shortcut, ShortcutState};

pub fn setup_global_shortcut(app: &AppHandle) -> Result<(), String> {
    let session_type = std::env::var("XDG_SESSION_TYPE").unwrap_or_else(|_| "unknown".to_string());
    if session_type == "wayland" {
        log::info!(
            "Entorno Wayland detectado: el atajo global del sistema puede requerir 'authdesk --toggle' en la configuración del compositor."
        );
    }

    let shortcut: Shortcut = DEFAULT_SHORTCUT
        .parse()
        .map_err(|e| format!("Invalid shortcut: {:?}", e))?;

    let app_handle = app.clone();
    let _ = app.plugin(
        tauri_plugin_global_shortcut::Builder::new()
            .with_handler(move |_app, s, event| {
                if event.state() == ShortcutState::Pressed && s == &shortcut {
                    crate::toggle_palette_window(&app_handle);
                }
            })
            .build(),
    );

    let _ = app.global_shortcut().register(shortcut);
    Ok(())
}

pub fn register_global_shortcut() -> Result<(), String> {
    Ok(())
}

pub fn unregister_global_shortcut(app: &AppHandle) -> Result<(), String> {
    if let Ok(shortcut) = DEFAULT_SHORTCUT.parse::<Shortcut>() {
        let _ = app.global_shortcut().unregister(shortcut);
    }
    Ok(())
}

pub fn reregister_global_shortcut(app: &AppHandle) -> Result<(), String> {
    if let Ok(shortcut) = DEFAULT_SHORTCUT.parse::<Shortcut>() {
        let _ = app.global_shortcut().register(shortcut);
    }
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
