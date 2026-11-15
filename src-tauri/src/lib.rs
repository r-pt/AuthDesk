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
    ExportQrBatchDto, ExportQrResultDto, ImportConfirmResultDto, ImportPreviewItemDto,
    ImportPreviewResultDto, ImportSkippedItemDto, QrImageInputDto, UpdateAccountDto,
    VaultStatusDto, WindowSettingsDto,
};
pub use state::AppState;

use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Emitter, Manager};
use zeroize::Zeroize;

pub const APP_IDENTIFIER: &str = "com.rod.authdesk";
const POPUP_WIDTH: f64 = 420.0;
const POPUP_HEIGHT: f64 = 560.0;

struct TrayLockMenuItem(MenuItem<tauri::Wry>);

fn sync_tray_lock_menu_item(app: &tauri::AppHandle, state: &AppState) {
    if let Some(lock_item) = app.try_state::<TrayLockMenuItem>() {
        let _ = lock_item.0.set_enabled(state.can_lock_vault());
    }
}

pub fn is_wayland_env(wayland_display: Option<&str>, xdg_session_type: Option<&str>) -> bool {
    let has_wayland_display = wayland_display
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    let is_wayland_session = xdg_session_type
        .map(|v| v.trim().eq_ignore_ascii_case("wayland"))
        .unwrap_or(false);
    has_wayland_display || is_wayland_session
}

pub fn detect_wayland() -> bool {
    let wayland_display = std::env::var("WAYLAND_DISPLAY").ok();
    let xdg_session_type = std::env::var("XDG_SESSION_TYPE").ok();
    is_wayland_env(wayland_display.as_deref(), xdg_session_type.as_deref())
}

#[tauri::command]
fn is_wayland() -> bool {
    detect_wayland()
}

#[tauri::command]
fn current_codes(state: tauri::State<'_, AppState>) -> Result<Vec<AccountCodeDto>, String> {
    state.get_current_codes().map_err(|e| e.to_string())
}

#[tauri::command]
fn get_vault_status(state: tauri::State<'_, AppState>) -> VaultStatusDto {
    state.get_vault_status()
}

#[tauri::command]
fn init_vault(
    mut password: String,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let res = state.init_vault(&password).map_err(|e| e.to_string());
    password.zeroize();
    if res.is_ok() {
        sync_tray_lock_menu_item(&app, &state);
    }
    res
}

#[tauri::command]
fn unlock_vault(
    mut password: String,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let res = state.unlock_vault(&password).map_err(|e| e.to_string());
    password.zeroize();
    if res.is_ok() {
        sync_tray_lock_menu_item(&app, &state);
    }
    res
}

#[tauri::command]
fn set_pin(
    mut pin: String,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let res = state.set_pin(pin.clone()).map_err(|e| e.to_string());
    pin.zeroize();
    if res.is_ok() {
        sync_tray_lock_menu_item(&app, &state);
    }
    res
}

#[tauri::command]
fn unlock_with_pin(
    mut pin: String,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let res = state.unlock_with_pin(pin.clone()).map_err(|e| e.to_string());
    pin.zeroize();
    sync_tray_lock_menu_item(&app, &state);
    res
}

#[tauri::command]
fn disable_pin(
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let res = state.disable_pin().map_err(|e| e.to_string());
    if res.is_ok() {
        sync_tray_lock_menu_item(&app, &state);
    }
    res
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
fn toggle_global_shortcut(enabled: bool, app: tauri::AppHandle) -> Result<(), String> {
    if enabled {
        shortcut::reregister_global_shortcut(&app)
    } else {
        shortcut::unregister_global_shortcut(&app)
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

fn compute_preserved_normal_logical_size(
    inner_size: Option<tauri::PhysicalSize<u32>>,
    scale_factor: f64,
) -> tauri::LogicalSize<f64> {
    let sf = if scale_factor.is_finite() && scale_factor > 0.0 {
        scale_factor
    } else {
        1.0
    };
    match inner_size.filter(|s| s.width > 0 && s.height > 0) {
        Some(phys) => {
            let logical = phys.to_logical::<f64>(sf);
            tauri::LogicalSize::new(
                logical.width.round().max(POPUP_WIDTH),
                logical.height.round().max(POPUP_HEIGHT),
            )
        }
        None => tauri::LogicalSize::new(POPUP_WIDTH, POPUP_HEIGHT),
    }
}

fn apply_window_mode_flags(
    win: &tauri::WebviewWindow,
    mode: &str,
    always_on_top: bool,
    resizable: bool,
) {
    let fixed_size = tauri::Size::Logical(tauri::LogicalSize::new(POPUP_WIDTH, POPUP_HEIGHT));
    let _ = win.set_decorations(false);
    if mode == "normal" {
        let _ = win.set_skip_taskbar(false);
        if resizable {
            let scale_factor = win.scale_factor().unwrap_or(1.0);
            let target_size =
                compute_preserved_normal_logical_size(win.inner_size().ok(), scale_factor);
            let _ = win.set_max_size(None::<tauri::Size>);
            let _ = win.set_min_size(Some(fixed_size));
            let _ = win.set_resizable(true);
            let _ = win.set_size(tauri::Size::Logical(target_size));
        } else {
            let _ = win.set_min_size(Some(fixed_size));
            let _ = win.set_max_size(Some(fixed_size));
            let _ = win.set_size(fixed_size);
            let _ = win.set_resizable(false);
        }
        let _ = win.set_always_on_top(always_on_top);
    } else {
        let _ = win.set_skip_taskbar(true);
        let _ = win.set_min_size(Some(fixed_size));
        let _ = win.set_max_size(Some(fixed_size));
        let _ = win.set_size(fixed_size);
        let _ = win.set_resizable(false);
        let _ = win.set_always_on_top(always_on_top);
    }
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
        apply_window_mode_flags(&win, &cfg.mode, cfg.always_on_top, cfg.resizable);
        if is_vis {
            let _ = win.show();
            let _ = win.set_focus();
        }
    }
    Ok(())
}

#[tauri::command]
fn set_window_resizable(
    resizable: bool,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    state.mark_window_op();
    state.set_window_resizable(resizable).map_err(|e| e.to_string())?;
    let cfg = state.get_window_settings();
    if let Some(win) = app.get_webview_window("palette") {
        apply_window_mode_flags(&win, &cfg.mode, cfg.always_on_top, cfg.resizable);
    }
    Ok(())
}

#[tauri::command]
fn set_popup_position(
    pos: String,
    state: tauri::State<'_, AppState>,
    _app: tauri::AppHandle,
) -> Result<(), String> {
    state.set_popup_position(&pos).map_err(|e| e.to_string())
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
fn create_vault_passwordless(
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let res = state.init_vault_passwordless().map_err(|e| e.to_string());
    if res.is_ok() {
        sync_tray_lock_menu_item(&app, &state);
    }
    res
}

#[tauri::command]
fn auto_unlock_if_passwordless(
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<bool, String> {
    let res = state.auto_unlock_if_passwordless().map_err(|e| e.to_string());
    if res.is_ok() {
        sync_tray_lock_menu_item(&app, &state);
    }
    res
}

#[tauri::command]
fn set_master_password(
    mut current_password: Option<String>,
    mut new_password: String,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let res = state
        .set_master_password(current_password.as_deref(), &new_password)
        .map_err(|e| e.to_string());
    if let Some(ref mut cp) = current_password {
        cp.zeroize();
    }
    new_password.zeroize();
    if res.is_ok() {
        sync_tray_lock_menu_item(&app, &state);
    }
    res
}

#[tauri::command]
fn remove_master_password(
    mut current_password: String,
    state: tauri::State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    let res = state
        .remove_master_password(&current_password)
        .map_err(|e| e.to_string());
    current_password.zeroize();
    if res.is_ok() {
        sync_tray_lock_menu_item(&app, &state);
    }
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

#[tauri::command]
fn stage_import_uris(
    mut uris_text: String,
    state: tauri::State<'_, AppState>,
) -> Result<ImportPreviewResultDto, String> {
    let res = state.stage_import_uris(&uris_text).map_err(|e| e.to_string());
    uris_text.zeroize();
    res
}

#[tauri::command]
fn stage_import_qr_images(
    images: Vec<QrImageInputDto>,
    state: tauri::State<'_, AppState>,
) -> Result<ImportPreviewResultDto, String> {
    state.stage_import_qr_images(images).map_err(|e| e.to_string())
}

#[tauri::command]
fn confirm_staged_import(
    selected_indices: Vec<usize>,
    state: tauri::State<'_, AppState>,
) -> Result<ImportConfirmResultDto, String> {
    state
        .confirm_staged_import(selected_indices)
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn cancel_staged_import(state: tauri::State<'_, AppState>) -> Result<(), String> {
    state.cancel_staged_import().map_err(|e| e.to_string())
}

#[tauri::command]
fn export_vault_qr_batches(
    mut credential: Option<String>,
    confirmed_warning: bool,
    state: tauri::State<'_, AppState>,
) -> Result<ExportQrResultDto, String> {
    let res = state
        .export_vault_qr_batches(credential.take(), confirmed_warning)
        .map_err(|e| e.to_string());
    if let Some(ref mut c) = credential {
        c.zeroize();
    }
    res
}

pub fn point_in_bounds(
    point: tauri::PhysicalPosition<f64>,
    pos: tauri::PhysicalPosition<i32>,
    size: tauri::PhysicalSize<u32>,
) -> bool {
    let px = point.x;
    let py = point.y;
    let x0 = pos.x as f64;
    let y0 = pos.y as f64;
    let x1 = x0 + size.width as f64;
    let y1 = y0 + size.height as f64;
    px >= x0 && px < x1 && py >= y0 && py < y1
}

pub fn select_monitor_index(
    monitors: &[(tauri::PhysicalPosition<i32>, tauri::PhysicalSize<u32>)],
    point: Option<tauri::PhysicalPosition<f64>>,
) -> Option<usize> {
    let pt = point?;
    monitors
        .iter()
        .position(|(pos, size)| point_in_bounds(pt, *pos, *size))
}

pub fn effective_work_area(
    mon_pos: tauri::PhysicalPosition<i32>,
    mon_size: tauri::PhysicalSize<u32>,
    work_pos: tauri::PhysicalPosition<i32>,
    work_size: tauri::PhysicalSize<u32>,
) -> (tauri::PhysicalPosition<i32>, tauri::PhysicalSize<u32>) {
    if work_size.width > 0 && work_size.height > 0 {
        (work_pos, work_size)
    } else {
        (mon_pos, mon_size)
    }
}

pub fn calculate_popup_coordinates(
    preferred_corner: &str,
    click_pos: Option<tauri::PhysicalPosition<f64>>,
    mon_pos: tauri::PhysicalPosition<i32>,
    mon_size: tauri::PhysicalSize<u32>,
    win_size: tauri::PhysicalSize<u32>,
) -> (i32, i32) {
    let margin = 16;

    let (mut x, mut y) = match preferred_corner {
        "bottom-right" => (
            mon_pos.x + (mon_size.width as i32) - (win_size.width as i32) - margin,
            mon_pos.y + (mon_size.height as i32) - (win_size.height as i32) - margin,
        ),
        "center" => (
            mon_pos.x + ((mon_size.width as i32) - (win_size.width as i32)) / 2,
            mon_pos.y + ((mon_size.height as i32) - (win_size.height as i32)) / 2,
        ),
        _ => (
            mon_pos.x + (mon_size.width as i32) - (win_size.width as i32) - margin,
            mon_pos.y + margin,
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
    if detect_wayland() {
        return win.center().map_err(|e| e.to_string());
    }

    let monitors = win.available_monitors().unwrap_or_default();
    let lookup_pos = click_pos
        .filter(|p| p.x != 0.0 || p.y != 0.0)
        .or_else(|| win.cursor_position().ok());
    let monitor_rects: Vec<(tauri::PhysicalPosition<i32>, tauri::PhysicalSize<u32>)> =
        monitors.iter().map(|m| (*m.position(), *m.size())).collect();
    let selected_idx = select_monitor_index(&monitor_rects, lookup_pos);
    let monitor = selected_idx
        .and_then(|idx| monitors.into_iter().nth(idx))
        .or_else(|| win.current_monitor().ok().flatten())
        .or_else(|| win.primary_monitor().ok().flatten())
        .ok_or_else(|| "No monitor detected".to_string())?;

    let work_area = monitor.work_area();
    let (bounds_pos, bounds_size) = effective_work_area(
        *monitor.position(),
        *monitor.size(),
        work_area.position,
        work_area.size,
    );
    let win_size = win
        .outer_size()
        .ok()
        .filter(|s| s.width > 0 && s.height > 0)
        .unwrap_or_else(|| {
            tauri::LogicalSize::new(POPUP_WIDTH, POPUP_HEIGHT).to_physical(monitor.scale_factor())
        });

    let (x, y) = calculate_popup_coordinates(
        preferred_corner,
        click_pos,
        bounds_pos,
        bounds_size,
        win_size,
    );

    win.set_position(tauri::Position::Physical(tauri::PhysicalPosition::new(x, y)))
        .map_err(|e| e.to_string())
}

pub fn show_palette_window(
    app: &tauri::AppHandle,
    click_pos: Option<tauri::PhysicalPosition<f64>>,
) {
    if let Some(win) = app.get_webview_window("palette") {
        let state = app.state::<AppState>();
        state.mark_window_op();
        let cfg = state.get_window_settings();
        if cfg.mode == "popup" {
            apply_window_mode_flags(&win, "popup", cfg.always_on_top, cfg.resizable);
            let _ = position_popup_window(&win, click_pos, &cfg.popup_position);
        }
        let _ = win.show();
        let _ = win.set_focus();
    }
}

pub fn toggle_palette_window(app: &tauri::AppHandle) {
    if let Some(win) = app.get_webview_window("palette") {
        if win.is_visible().unwrap_or(false) {
            let _ = win.hide();
        } else {
            show_palette_window(app, None);
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
            } else {
                show_palette_window(app, None);
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
            let lock_i = MenuItem::with_id(
                app,
                "lock",
                tray::TRAY_LOCK_LABEL,
                state.can_lock_vault(),
                None::<&str>,
            )?;
            let quit_i = MenuItem::with_id(app, "quit", tray::TRAY_QUIT_LABEL, true, None::<&str>)?;
            app.manage(TrayLockMenuItem(lock_i.clone()));
            let menu = Menu::with_items(app, &[&show_i, &lock_i, &quit_i])?;

            let mut tray_builder = TrayIconBuilder::new().menu(&menu);
            if let Some(icon) = app.default_window_icon().cloned() {
                tray_builder = tray_builder.icon(icon);
            }

            let _tray = tray_builder
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        show_palette_window(app, None);
                    }
                    "lock" => {
                        let state = app.state::<AppState>();
                        if state.can_lock_vault() {
                            let _ = state.lock_vault();
                            let _ = app.emit("vault-status-changed", ());
                        }
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
                                show_palette_window(app, Some(position));
                            }
                        }
                    }
                })
                .build(app)?;

            let cfg = state.get_window_settings();
            if let Some(w) = app.get_webview_window("palette") {
                apply_window_mode_flags(&w, &cfg.mode, cfg.always_on_top, cfg.resizable);
                if !start_hidden {
                    show_palette_window(app.handle(), None);
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
            set_window_resizable,
            set_popup_position,
            set_always_on_top,
            set_auto_hide_on_blur,
            is_wayland,
            create_vault_passwordless,
            auto_unlock_if_passwordless,
            set_master_password,
            remove_master_password,
            change_master_password,
            load_demo_accounts,
            remove_demo_accounts,
            stage_import_uris,
            stage_import_qr_images,
            confirm_staged_import,
            cancel_staged_import,
            export_vault_qr_batches
        ])

        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

pub fn get_current_codes_from_state(state: &AppState) -> Result<Vec<AccountCodeDto>, AuthDeskError> {
    state.get_current_codes()
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_is_wayland_env_detection() {
        assert!(is_wayland_env(Some("wayland-0"), None));
        assert!(is_wayland_env(Some(" wayland-1 "), Some("x11")));
        assert!(is_wayland_env(None, Some("wayland")));
        assert!(is_wayland_env(Some(""), Some("Wayland")));
        assert!(is_wayland_env(Some("   "), Some("  WAYLAND  ")));
        assert!(!is_wayland_env(None, None));
        assert!(!is_wayland_env(Some(""), Some("x11")));
        assert!(!is_wayland_env(Some("   "), Some("tty")));
        let _ = detect_wayland();
        let _ = is_wayland();
    }

    #[test]
    fn test_monitor_selection_and_work_area_popup_coordinates() {
        let monitors = vec![
            (
                tauri::PhysicalPosition::new(-1920, 0),
                tauri::PhysicalSize::new(1920, 1080),
            ),
            (
                tauri::PhysicalPosition::new(0, 0),
                tauri::PhysicalSize::new(2560, 1440),
            ),
        ];

        assert_eq!(
            select_monitor_index(&monitors, Some(tauri::PhysicalPosition::new(-100.0, 500.0))),
            Some(0)
        );
        assert_eq!(
            select_monitor_index(&monitors, Some(tauri::PhysicalPosition::new(0.0, 0.0))),
            Some(1)
        );
        assert_eq!(
            select_monitor_index(&monitors, Some(tauri::PhysicalPosition::new(3000.0, 100.0))),
            None
        );
        assert_eq!(select_monitor_index(&monitors, None), None);

        let (wa_pos, wa_size) = effective_work_area(
            tauri::PhysicalPosition::new(0, 0),
            tauri::PhysicalSize::new(1920, 1080),
            tauri::PhysicalPosition::new(0, 32),
            tauri::PhysicalSize::new(1920, 1000),
        );
        assert_eq!(wa_pos, tauri::PhysicalPosition::new(0, 32));
        assert_eq!(wa_size, tauri::PhysicalSize::new(1920, 1000));

        let (fb_pos, fb_size) = effective_work_area(
            tauri::PhysicalPosition::new(0, 0),
            tauri::PhysicalSize::new(1920, 1080),
            tauri::PhysicalPosition::new(0, 0),
            tauri::PhysicalSize::new(0, 0),
        );
        assert_eq!(fb_pos, tauri::PhysicalPosition::new(0, 0));
        assert_eq!(fb_size, tauri::PhysicalSize::new(1920, 1080));

        let win_size = tauri::PhysicalSize::new(420, 560);
        assert_eq!(
            calculate_popup_coordinates("top-right", None, wa_pos, wa_size, win_size),
            (1920 - 420 - 16, 32 + 16)
        );
        assert_eq!(
            calculate_popup_coordinates("bottom-right", None, wa_pos, wa_size, win_size),
            (1920 - 420 - 16, 32 + 1000 - 560 - 16)
        );
        assert_eq!(
            calculate_popup_coordinates("center", None, wa_pos, wa_size, win_size),
            ((1920 - 420) / 2, 32 + (1000 - 560) / 2)
        );
    }

    #[test]
    fn test_compute_preserved_normal_logical_size() {
        assert_eq!(
            compute_preserved_normal_logical_size(Some(tauri::PhysicalSize::new(420, 560)), 1.0),
            tauri::LogicalSize::new(420.0, 560.0)
        );
        assert_eq!(
            compute_preserved_normal_logical_size(Some(tauri::PhysicalSize::new(840, 1120)), 2.0),
            tauri::LogicalSize::new(420.0, 560.0)
        );
        assert_eq!(
            compute_preserved_normal_logical_size(Some(tauri::PhysicalSize::new(720, 680)), 1.0),
            tauri::LogicalSize::new(720.0, 680.0)
        );
        assert_eq!(
            compute_preserved_normal_logical_size(Some(tauri::PhysicalSize::new(200, 300)), 1.0),
            tauri::LogicalSize::new(420.0, 560.0)
        );
        assert_eq!(
            compute_preserved_normal_logical_size(Some(tauri::PhysicalSize::new(0, 0)), 1.0),
            tauri::LogicalSize::new(420.0, 560.0)
        );
        assert_eq!(
            compute_preserved_normal_logical_size(None, 0.0),
            tauri::LogicalSize::new(420.0, 560.0)
        );
    }
}
