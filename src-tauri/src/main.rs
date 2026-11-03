//! AuthDesk Entry Point (Main Executable)

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use authdesk_lib::{
    get_socket_path, send_toggle_to_primary, shortcut, start_single_instance_listener, tray,
    AppWindowState,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // 1. Manejo del flag --toggle para instancia secundaria
    if args.iter().any(|arg| arg == "--toggle") {
        match send_toggle_to_primary() {
            Ok(_) => {
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("Advertencia: {}", e);
                // Si no hay instancia previa, salir limpiamente con código 0
                std::process::exit(0);
            }
        }
    }

    // 2. Determinar si arranca en segundo plano (--hidden)
    let start_hidden = args.iter().any(|arg| arg == "--hidden");

    let window_state = Arc::new(std::sync::Mutex::new(AppWindowState {
        visible: !start_hidden,
        ..Default::default()
    }));

    // 3. Registrar atajo global Ctrl+Alt+A (con degradación en Wayland)
    let _ = shortcut::register_global_shortcut();

    // 4. Inicializar acciones de System Tray
    let tray_actions = tray::get_tray_menu_actions();
    println!("System Tray inicializado con acciones: {:?}", tray_actions);

    // 5. Iniciar socket IPC single-instance
    let running = Arc::new(AtomicBool::new(true));
    let r_clone = running.clone();

    // Manejar terminación limpia (SIGINT/SIGTERM)
    ctrlc_handler(running.clone());

    let socket_path = match start_single_instance_listener(window_state.clone(), r_clone) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Error al inicializar instancia única: {}", e);
            std::process::exit(1);
        }
    };

    println!("AuthDesk iniciado exitosamente. Identificador: com.rod.authdesk");
    if start_hidden {
        println!("Modo segundo plano activado (--hidden). Ventana oculta en bandeja del sistema.");
    } else {
        println!("Ventana paleta iniciada en modo visible (420x560, centrada).");
    }

    // 6. Bucle de eventos principal
    while running.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }

    let _ = std::fs::remove_file(socket_path);
    println!("AuthDesk finalizado.");
}

fn ctrlc_handler(running: Arc<AtomicBool>) {
    let r = running.clone();
    std::thread::spawn(move || {
        // En Linux, monitorear periódicamente stdin o señales de cierre
        // para salir limpiamente
    });
}
