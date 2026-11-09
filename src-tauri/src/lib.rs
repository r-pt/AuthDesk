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
    UpdateAccountDto, VaultStatusDto, WindowSettingsDto,
};
pub use state::AppState;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Emitter, Manager};
use zeroize::Zeroize;

pub const APP_IDENTIFIER: &str = "com.rod.authdesk";
pub const SOCKET_NAME: &str = "authdesk_com_rod_authdesk.sock";

#[tauri::command]
fn current_codes(state: tauri::State<'_, AppState>) -> Result<Vec<AccountCodeDto>, String> {
    state.get_current_codes().map_err(|e| e.to_string())
}

#[tauri::command]
fn get_vault_status(state: tauri::State<'_, AppState>) -> VaultStatusDto {
    state.get_vault_status()
}

#[tauri::command]
fn init_vault(mut password: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    let res = state.init_vault(&password).map_err(|e| e.to_string());
    password.zeroize();
    res
}

#[tauri::command]
fn unlock_vault(mut password: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    let res = state.unlock_vault(&password).map_err(|e| e.to_string());
    password.zeroize();
    res
}

#[tauri::command]
fn set_pin(mut pin: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    let res = state.set_pin(pin.clone()).map_err(|e| e.to_string());
    pin.zeroize();
    res
}

#[tauri::command]
fn unlock_with_pin(mut pin: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    let res = state.unlock_with_pin(pin.clone()).map_err(|e| e.to_string());
    pin.zeroize();
    res
}

#[tauri::command]
fn disable_pin(state: tauri::State<'_, AppState>) -> Result<(), String> {
    state.disable_pin().map_err(|e| e.to_string())
}

#[tauri::command]
fn lock_vault(state: tauri::State<'_, AppState>) -> Result<(), String> {
    state.lock_vault().map_err(|e| e.to_string())
}


#[tauri::command]
fn hide_window(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(win) = app.get_webview_window("palette") {
        let _ = win.hide();
    }
    Ok(())
}

#[tauri::command]
fn list_accounts(state: tauri::State<'_, AppState>) -> Result<Vec<AccountSummaryDto>, String> {
    state.list_account_summaries().map_err(|e| e.to_string())
}

#[tauri::command]
fn add_account(
    req: AddAccountDto,
    state: tauri::State<'_, AppState>,
) -> Result<AccountSummaryDto, String> {
    state.add_account_dto(req).map_err(|e| e.to_string())
}

#[tauri::command]
fn delete_account(
    account_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<bool, String> {
    state.delete_account(&account_id).map_err(|e| e.to_string())
}

#[tauri::command]
fn update_account(
    req: UpdateAccountDto,
    state: tauri::State<'_, AppState>,
) -> Result<AccountSummaryDto, String> {
    state.update_account_dto(req).map_err(|e| e.to_string())
}

#[tauri::command]
fn reorder_accounts(
    account_ids: Vec<String>,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state.reorder_accounts(account_ids).map_err(|e| e.to_string())
}

#[tauri::command]
fn toggle_global_shortcut(enabled: bool, app: tauri::AppHandle) -> Result<bool, String> {
    if enabled {
        let _ = shortcut::reregister_global_shortcut(&app);
        Ok(true)
    } else {
        let _ = shortcut::unregister_global_shortcut(&app);
        Ok(false)
    }
}

#[tauri::command]
fn start_window_drag(win: tauri::WebviewWindow) -> Result<(), String> {
    win.start_dragging().map_err(|e| e.to_string())
}

#[tauri::command]
fn get_window_settings(state: tauri::State<'_, AppState>) -> WindowSettingsDto {
    state.get_window_settings()
}

#[tauri::command]
fn set_window_mode(
    mode: String,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    state.mark_window_op();
    state.set_window_mode(&mode).map_err(|e| e.to_string())?;
    let cfg = state.get_window_settings();
    if let Some(win) = app.get_webview_window("palette") {
        let is_vis = win.is_visible().unwrap_or(false);
        let _ = win.set_skip_taskbar(mode != "taskbar");
        if mode == "tray-popup" {
            let _ = position_popup_window(&win, None, &cfg.popup_position);
        } else {
            let _ = win.center();
        }
        if is_vis {
            let _ = win.show();
            let _ = win.set_focus();
        }
    }
    Ok(())
}

#[tauri::command]
fn set_popup_position(
    pos: String,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    state.mark_window_op();
    state.set_popup_position(&pos).map_err(|e| e.to_string())?;
    let cfg = state.get_window_settings();
    if let Some(win) = app.get_webview_window("palette") {
        let is_vis = win.is_visible().unwrap_or(false);
        if is_vis && cfg.mode == "tray-popup" {
            let _ = position_popup_window(&win, None, &pos);
            let _ = win.show();
            let _ = win.set_focus();
        }
    }
    Ok(())
}

#[tauri::command]
fn set_always_on_top(
    enabled: bool,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    state.mark_window_op();
    state.set_always_on_top(enabled).map_err(|e| e.to_string())?;
    if let Some(win) = app.get_webview_window("palette") {
        let _ = win.set_always_on_top(enabled);
    }
    Ok(())
}

#[tauri::command]
fn set_auto_hide_on_blur(enabled: bool, state: tauri::State<'_, AppState>) -> Result<(), String> {
    state.set_auto_hide_on_blur(enabled).map_err(|e| e.to_string())
}

#[tauri::command]
fn create_vault_passwordless(state: tauri::State<'_, AppState>) -> Result<(), String> {
    state.init_vault_passwordless().map_err(|e| e.to_string())
}

#[tauri::command]
fn auto_unlock_if_passwordless(state: tauri::State<'_, AppState>) -> Result<bool, String> {
    state.auto_unlock_if_passwordless().map_err(|e| e.to_string())
}

#[tauri::command]
fn set_master_password(
    current_password: Option<String>,
    mut new_password: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let res = state
        .set_master_password(current_password.as_deref(), &new_password)
        .map_err(|e| e.to_string());
    new_password.zeroize();
    res
}

#[tauri::command]
fn remove_master_password(
    mut current_password: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let res = state
        .remove_master_password(&current_password)
        .map_err(|e| e.to_string());
    current_password.zeroize();
    res
}

#[tauri::command]
fn change_master_password(
    mut current_password: String,
    mut new_password: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let res = state
        .change_master_password(&current_password, &new_password)
        .map_err(|e| e.to_string());
    current_password.zeroize();
    new_password.zeroize();
    res
}

#[tauri::command]
fn load_demo_accounts(state: tauri::State<'_, AppState>) -> Result<usize, String> {
    state.load_demo_accounts().map_err(|e| e.to_string())
}

#[tauri::command]
fn remove_demo_accounts(state: tauri::State<'_, AppState>) -> Result<usize, String> {
    state.remove_demo_accounts().map_err(|e| e.to_string())
}

pub fn calculate_popup_coordinates(
    preferred_corner: &str,
    click_pos: Option<tauri::PhysicalPosition<f64>>,
    mon_pos: tauri::PhysicalPosition<i32>,
    mon_size: tauri::PhysicalSize<u32>,
    win_size: tauri::PhysicalSize<u32>,
) -> (i32, i32) {
    let margin = 16;
    let top_offset = 36;
    let bottom_offset = 48;

    let (mut x, mut y) = match preferred_corner {
        "bottom-right" => (
            mon_pos.x + (mon_size.width as i32) - (win_size.width as i32) - margin,
            mon_pos.y + (mon_size.height as i32) - (win_size.height as i32) - bottom_offset,
        ),
        "center" => (
            mon_pos.x + ((mon_size.width as i32) - (win_size.width as i32)) / 2,
            mon_pos.y + ((mon_size.height as i32) - (win_size.height as i32)) / 2,
        ),
        _ => (
            mon_pos.x + (mon_size.width as i32) - (win_size.width as i32) - margin,
            mon_pos.y + top_offset,
        ),
    };

    if let Some(pos) = click_pos {
        if pos.x != 0.0 || pos.y != 0.0 {
            let px = pos.x as i32;
            let py = pos.y as i32;
            if py < mon_pos.y + (mon_size.height as i32) / 2 {
                x = px - (win_size.width as i32) / 2;
                y = py + 12;
            } else {
                x = px - (win_size.width as i32) / 2;
                y = py - (win_size.height as i32) - 12;
            }
        }
    }

    let min_x = mon_pos.x + 8;
    let max_x = mon_pos.x + (mon_size.width as i32) - (win_size.width as i32) - 8;
    let min_y = mon_pos.y + 8;
    let max_y = mon_pos.y + (mon_size.height as i32) - (win_size.height as i32) - 8;

    let x = if min_x > max_x { min_x } else { x.clamp(min_x, max_x) };
    let y = if min_y > max_y { min_y } else { y.clamp(min_y, max_y) };

    (x, y)
}

pub fn position_popup_window(
    win: &tauri::WebviewWindow,
    click_pos: Option<tauri::PhysicalPosition<f64>>,
    preferred_corner: &str,
) -> Result<(), String> {
    let monitor = win
        .current_monitor()
        .map_err(|e| e.to_string())?
        .or_else(|| win.primary_monitor().ok().flatten())
        .ok_or_else(|| "No monitor detected".to_string())?;

    let mon_size = monitor.size();
    let mon_pos = monitor.position();
    let win_size = win
        .outer_size()
        .unwrap_or(tauri::PhysicalSize { width: 420, height: 560 });

    let (x, y) = calculate_popup_coordinates(
        preferred_corner,
        click_pos,
        *mon_pos,
        *mon_size,
        win_size,
    );

    win.set_position(tauri::Position::Physical(tauri::PhysicalPosition::new(x, y)))
        .map_err(|e| e.to_string())
}

pub fn toggle_palette_window(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window("palette") {
        if win.is_visible().unwrap_or(false) {
            let _ = win.hide();
        } else {
            let state = app.state::<AppState>();
            let cfg = state.get_window_settings();
            if cfg.mode == "tray-popup" {
                let _ = position_popup_window(&win, None, &cfg.popup_position);
            }
            let _ = win.show();
            let _ = win.set_focus();
        }
    }
}

pub fn run() {
    let start_hidden = std::env::args().any(|a| a == "--hidden");
    tauri::Builder::default()
        .manage(AppState::new())
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::Focused(false) = event {
                let app = window.app_handle();
                let state = app.state::<AppState>();
                if state.is_recent_window_op(600) {
                    return;
                }
                let cfg = state.get_window_settings();
                if cfg.auto_hide_on_blur {
                    let _ = window.hide();
                }
            }
        })
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            if argv.iter().any(|a| a == "--toggle") {
                toggle_palette_window(app);
            } else if let Some(win) = app.get_webview_window("palette") {
                let state = app.state::<AppState>();
                let cfg = state.get_window_settings();
                if cfg.mode == "tray-popup" {
                    let _ = position_popup_window(&win, None, &cfg.popup_position);
                }
                let _ = win.show();
                let _ = win.set_focus();
            }
        }))
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--hidden"]),
        ))
        .setup(move |app| {
            let state = app.state::<AppState>();
            let _ = state.auto_unlock_if_passwordless();

            let _ = shortcut::setup_global_shortcut(app.handle());
            let show_i = MenuItem::with_id(app, "show", tray::TRAY_SHOW_LABEL, true, None::<&str>)?;
            let lock_i = MenuItem::with_id(app, "lock", tray::TRAY_LOCK_LABEL, true, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", tray::TRAY_QUIT_LABEL, true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &lock_i, &quit_i])?;

            let mut tray_builder = TrayIconBuilder::new().menu(&menu);
            if let Some(icon) = app.default_window_icon().cloned() {
                tray_builder = tray_builder.icon(icon);
            }

            let _tray = tray_builder
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("palette") {
                            let state = app.state::<AppState>();
                            let cfg = state.get_window_settings();
                            if cfg.mode == "tray-popup" {
                                let _ = position_popup_window(&w, None, &cfg.popup_position);
                            }
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "lock" => {
                        let state = app.state::<AppState>();
                        let _ = state.lock_vault();
                        let _ = app.emit("vault-status-changed", ());
                    }
                    "quit" => {
                        let state = app.state::<AppState>();
                        let _ = state.lock_vault();
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        position,
                        ..
                    } = event
                    {
                        let app = tray.app_handle();
                        if let Some(win) = app.get_webview_window("palette") {
                            if win.is_visible().unwrap_or(false) {
                                let _ = win.hide();
                            } else {
                                let state = app.state::<AppState>();
                                let cfg = state.get_window_settings();
                                if cfg.mode == "tray-popup" {
                                    let _ = position_popup_window(&win, Some(position), &cfg.popup_position);
                                }
                                let _ = win.show();
                                let _ = win.set_focus();
                            }
                        }
                    }
                })
                .build(app)?;

            if !start_hidden {
                if let Some(w) = app.get_webview_window("palette") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            current_codes,
            get_vault_status,
            init_vault,
            unlock_vault,
            set_pin,
            unlock_with_pin,
            disable_pin,
            lock_vault,
            hide_window,
            list_accounts,
            add_account,
            delete_account,
            update_account,
            reorder_accounts,
            toggle_global_shortcut,
            start_window_drag,
            get_window_settings,
            set_window_mode,
            set_popup_position,
            set_always_on_top,
            set_auto_hide_on_blur,
            create_vault_passwordless,
            auto_unlock_if_passwordless,
            set_master_password,
            remove_master_password,
            change_master_password,
            load_demo_accounts,
            remove_demo_accounts
        ])

        .run(tauri::generate_context!())
        .expect("error while running tauri application");
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
    fn test_current_codes_command() {
        let app_state = AppState::with_accounts(AppState::default_test_accounts());

        let result = app_state.get_current_codes().unwrap();
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
        assert!(app_state.get_current_codes().is_err());
    }

    #[test]
    fn test_current_codes_from_state() {
        let app_state = AppState::with_accounts(AppState::default_test_accounts());
        let codes = get_current_codes_from_state(&app_state).unwrap();
        assert_eq!(codes.len(), app_state.accounts.read().unwrap().len());
    }

    // [ENC-B64::cnB0|Z2Ft|cm9k]
    #[test]
    fn test_calculate_popup_coordinates_small_display_no_panic() {
        let mon_pos = tauri::PhysicalPosition::new(0, 0);
        let mon_size = tauri::PhysicalSize::new(800, 480);
        let win_size = tauri::PhysicalSize::new(420, 560);

        let (x, y) = calculate_popup_coordinates("bottom-right", None, mon_pos, mon_size, win_size);
        assert_eq!(y, 8);
        assert!(x >= 8);

        let mon_size_narrow = tauri::PhysicalSize::new(400, 800);
        let (x2, y2) = calculate_popup_coordinates("top-right", None, mon_pos, mon_size_narrow, win_size);
        assert_eq!(x2, 8);
        assert!(y2 >= 8);
    }

    // [ENC-B64::cnB0|Z2Ft|cm9k]
    #[test]
    fn test_calculate_popup_coordinates_negative_multimonitor() {
        let mon_pos = tauri::PhysicalPosition::new(-1920, 0);
        let mon_size = tauri::PhysicalSize::new(1920, 1080);
        let win_size = tauri::PhysicalSize::new(420, 560);

        let click = Some(tauri::PhysicalPosition::new(-500.0, 20.0));
        let (x, y) = calculate_popup_coordinates("tray-popup", click, mon_pos, mon_size, win_size);
        assert_eq!(x, -500 - 210);
        assert_eq!(y, 32);
    }
}
