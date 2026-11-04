// [ENC-B64::cnB0|Z2Ft|cm9k]
pub mod crypto;
pub mod error;
pub mod models;
pub mod otp;
pub mod shortcut;
pub mod state;
pub mod storage;
pub mod tray;
pub mod vault;

extern crate data_encoding;
extern crate hmac;
extern crate log;
extern crate serde;
extern crate serde_json;
extern crate sha1;
extern crate sha2;
extern crate tauri;
extern crate thiserror;
extern crate zeroize;

pub use error::AuthDeskError;
pub use models::{
    Account, AccountCodeDto, AccountSummaryDto, AccountType, AddAccountDto, Algorithm,
    VaultStatusDto,
};
pub use state::AppState;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub const APP_IDENTIFIER: &str = "com.rod.authdesk";
pub const SOCKET_NAME: &str = "authdesk_com_rod_authdesk.sock";

#[tauri::command]
pub fn current_codes(state: tauri::State<'_, AppState>) -> Result<Vec<AccountCodeDto>, String> {
    state.get_current_codes().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_vault_status(state: tauri::State<'_, AppState>) -> VaultStatusDto {
    state.get_vault_status()
}

use zeroize::Zeroize;

#[tauri::command]
pub fn init_vault(mut password: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    let res = state.init_vault(&password).map_err(|e| e.to_string());
    password.zeroize();
    res
}

#[tauri::command]
pub fn unlock_vault(mut password: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    let res = state.unlock_vault(&password).map_err(|e| e.to_string());
    password.zeroize();
    res
}

#[tauri::command]
pub fn lock_vault(state: tauri::State<'_, AppState>) -> Result<(), String> {
    state.lock_vault().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn hide_window() -> Result<(), String> {
    log::info!("Comando hide_window invocado.");
    Ok(())
}

#[tauri::command]
pub fn list_accounts(state: tauri::State<'_, AppState>) -> Result<Vec<AccountSummaryDto>, String> {
    state.list_account_summaries().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn add_account(
    req: AddAccountDto,
    state: tauri::State<'_, AppState>,
) -> Result<AccountSummaryDto, String> {
    state.add_account_dto(req).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn delete_account(
    account_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    state.delete_account(&account_id).map_err(|e| e.to_string())
}

pub fn get_current_codes_from_state(state: &AppState) -> Result<Vec<AccountCodeDto>, AuthDeskError> {
    state.get_current_codes()
}

pub fn get_socket_path() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        let dir = Path::new(&runtime_dir);
        if dir.exists() {
            return dir.join(SOCKET_NAME);
        }
    }
    PathBuf::from("/tmp").join(SOCKET_NAME)
}

#[derive(Debug, Clone)]
pub struct AppWindowState {
    pub visible: bool,
    pub always_on_top: bool,
    pub width: u32,
    pub height: u32,
    pub transparent: bool,
    pub decorations: bool,
    pub skip_taskbar: bool,
}

impl Default for AppWindowState {
    fn default() -> Self {
        Self {
            visible: false,
            always_on_top: true,
            width: 420,
            height: 560,
            transparent: true,
            decorations: false,
            skip_taskbar: true,
        }
    }
}

pub fn hide_window_state(state: &Arc<std::sync::Mutex<AppWindowState>>) {
    let mut s = state.lock().unwrap();
    s.visible = false;
    log::info!("Ventana paleta oculta.");
}

pub fn show_window(state: &Arc<std::sync::Mutex<AppWindowState>>) {
    let mut s = state.lock().unwrap();
    s.visible = true;
    log::info!("Ventana paleta visible y enfocada.");
}

pub fn toggle_window(state: &Arc<std::sync::Mutex<AppWindowState>>) -> bool {
    let mut s = state.lock().unwrap();
    s.visible = !s.visible;
    let new_state = s.visible;
    log::info!("Ventana paleta conmutada. Nuevo estado visible: {}", new_state);
    new_state
}

pub fn send_toggle_to_primary() -> Result<(), String> {
    let socket_path = get_socket_path();
    let mut stream = UnixStream::connect(&socket_path)
        .map_err(|e| format!("No se pudo conectar a la instancia primaria en {:?}: {}", socket_path, e))?;

    stream
        .write_all(b"--toggle\n")
        .map_err(|e| format!("Error al enviar comando --toggle: {}", e))?;
    stream.flush().map_err(|e| format!("Error al vaciar stream: {}", e))?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|e| format!("Error al leer respuesta de instancia primaria: {}", e))?;

    log::info!("Respuesta de instancia primaria recibida: {}", response.trim());
    Ok(())
}

pub fn start_single_instance_listener(
    state: Arc<std::sync::Mutex<AppWindowState>>,
    running: Arc<AtomicBool>,
) -> Result<PathBuf, String> {
    let socket_path = get_socket_path();

    if socket_path.exists() {
        if UnixStream::connect(&socket_path).is_ok() {
            return Err("Ya existe una instancia primaria en ejecución.".to_string());
        } else {
            let _ = std::fs::remove_file(&socket_path);
        }
    }

    let listener = UnixListener::bind(&socket_path)
        .map_err(|e| format!("No se pudo enlazar el socket single-instance en {:?}: {}", socket_path, e))?;

    listener
        .set_nonblocking(true)
        .map_err(|e| format!("Error al establecer modo non-blocking: {}", e))?;

    let socket_path_clone = socket_path.clone();
    thread::spawn(move || {
        while running.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let mut reader = BufReader::new(&stream);
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_ok() {
                        let cmd = line.trim();
                        if cmd == "--toggle" || cmd == "toggle" {
                            let is_vis = toggle_window(&state);
                            let mut writer = stream;
                            let _ = write!(writer, "ACK toggle:{}\n", is_vis);
                        } else if cmd == "--hide" || cmd == "hide" {
                            hide_window_state(&state);
                            let mut writer = stream;
                            let _ = write!(writer, "ACK hidden\n");
                        } else {
                            let mut writer = stream;
                            let _ = write!(writer, "ACK ok\n");
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(e) => {
                    log::warn!("Error al aceptar conexión single-instance: {}", e);
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
        let _ = std::fs::remove_file(&socket_path_clone);
    });

    Ok(socket_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_window_state_default() {
        let state = AppWindowState::default();
        assert_eq!(state.width, 420);
        assert_eq!(state.height, 560);
        assert!(!state.visible);
        assert!(state.always_on_top);
        assert!(state.skip_taskbar);
        assert!(state.transparent);
        assert!(!state.decorations);
    }

    #[test]
    fn test_window_toggle_logic() {
        let state = Arc::new(std::sync::Mutex::new(AppWindowState::default()));
        assert!(!state.lock().unwrap().visible);

        let v1 = toggle_window(&state);
        assert!(v1);
        assert!(state.lock().unwrap().visible);

        let v2 = toggle_window(&state);
        assert!(!v2);
        assert!(!state.lock().unwrap().visible);
    }

    #[test]
    fn test_window_show_and_hide() {
        let state = Arc::new(std::sync::Mutex::new(AppWindowState::default()));
        show_window(&state);
        assert!(state.lock().unwrap().visible);

        hide_window_state(&state);
        assert!(!state.lock().unwrap().visible);
    }

    #[test]
    fn test_hide_window_command() {
        assert!(hide_window().is_ok());
    }

    #[test]
    fn test_current_codes_command() {
        let app_state = AppState::with_accounts(AppState::default_test_accounts());
        let state_wrapper = tauri::State(&app_state);

        let result = current_codes(state_wrapper).unwrap();
        assert!(result.len() >= 4, "Debe retornar al menos 4 códigos");

        for code_dto in result {
            assert!(!code_dto.code.is_empty(), "El código no debe estar vacío");
            assert!(code_dto.digits == 6 || code_dto.digits == 8);
            assert!(code_dto.seconds_remaining <= code_dto.period);
            assert!(code_dto.seconds_remaining >= 1);
        }
    }

    #[test]
    fn test_current_codes_command_locked_errors() {
        let app_state = AppState::new();
        let state_wrapper = tauri::State(&app_state);
        assert!(current_codes(state_wrapper).is_err());
    }

    #[test]
    fn test_current_codes_from_state() {
        let app_state = AppState::with_accounts(AppState::default_test_accounts());
        let codes = get_current_codes_from_state(&app_state).unwrap();
        assert_eq!(codes.len(), app_state.accounts.read().unwrap().len());
    }
}
