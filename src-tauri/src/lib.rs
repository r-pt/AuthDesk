//! AuthDesk - Gestor de códigos TOTP de escritorio para Linux
//! Arquitectura de seguridad, ciclo de vida de ventana, tray icon y atajos globales.

pub mod shortcut;
pub mod tray;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Identificador único de aplicación para sockets IPC y single-instance
pub const APP_IDENTIFIER: &str = "com.rod.authdesk";
pub const SOCKET_NAME: &str = "authdesk_com_rod_authdesk.sock";

/// Obtiene la ruta del socket Unix para IPC single-instance
pub fn get_socket_path() -> PathBuf {
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        let dir = Path::new(&runtime_dir);
        if dir.exists() {
            return dir.join(SOCKET_NAME);
        }
    }
    PathBuf::from("/tmp").join(SOCKET_NAME)
}

/// Estado de la ventana y de la aplicación en memoria
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

/// Oculta la ventana de la paleta
pub fn hide_window(state: &Arc<std::sync::Mutex<AppWindowState>>) {
    let mut s = state.lock().unwrap();
    s.visible = false;
    log::info!("Ventana paleta oculta.");
}

/// Muestra y enfoca la ventana de la paleta
pub fn show_window(state: &Arc<std::sync::Mutex<AppWindowState>>) {
    let mut s = state.lock().unwrap();
    s.visible = true;
    log::info!("Ventana paleta visible y enfocada.");
}

/// Conmuta la visibilidad de la ventana de la paleta
pub fn toggle_window(state: &Arc<std::sync::Mutex<AppWindowState>>) -> bool {
    let mut s = state.lock().unwrap();
    s.visible = !s.visible;
    let new_state = s.visible;
    log::info!("Ventana paleta conmutada. Nuevo estado visible: {}", new_state);
    new_state
}

/// Envía señal de conmutación a la instancia primaria en ejecución mediante socket Unix
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

/// Inicia el listener IPC de instancia única en un hilo en segundo plano
pub fn start_single_instance_listener(
    state: Arc<std::sync::Mutex<AppWindowState>>,
    running: Arc<AtomicBool>,
) -> Result<PathBuf, String> {
    let socket_path = get_socket_path();

    // Limpiar socket huérfano si la instancia anterior terminó inesperadamente
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
                            hide_window(&state);
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

        hide_window(&state);
        assert!(!state.lock().unwrap().visible);
    }
}
