# Original User Request

## Initial Request — 2026-11-03T22:18:17Z

Construir AuthDesk, un gestor de códigos TOTP de escritorio para Linux con Tauri v2, React + TypeScript (Vite) y backend en Rust, ejecutando las fases del plan consolidado comenzando por la Fase 0 (esqueleto de la paleta, bandeja del sistema, atajos y single-instance).

Working directory: /home/rod/Desktop/Proyects/AuthDesk
Integrity mode: development

## Requirements

### R1. Verificación de entorno e inicialización del proyecto (Fase 0)
Verificar la presencia de herramientas del sistema (rustc, cargo, node, npm, pkg-config webkit2gtk-4.1) antes de instalar paquetes. Inicializar el proyecto con Tauri v2, React + TypeScript (Vite) con identifier `com.rod.authdesk`. Configurar plugins (global-shortcut, single-instance, autostart, clipboard-manager, dialog) y activar la feature `tray-icon` en Tauri con dependencias pinneadas.

### R2. Ventana de paleta flotante y bandeja del sistema (Fase 0)
Configurar la ventana `palette` (420×560, sin decoraciones, transparente, always-on-top, skipTaskbar, centrada, oculta al iniciar salvo que no venga `--hidden`). Implementar el tray icon con menú ("Mostrar AuthDesk", "Bloquear", "Salir"). Manejar el flag `--toggle` mediante single-instance y registrar el atajo global Ctrl+Alt+A (manejando fallos silenciosos en Wayland mediante logs sin secretos).

### R3. Lógica TOTP y almacenamiento seguro en Rust (Fases 1 y 2)
Generar códigos TOTP cumpliendo RFC 6238 (SHA1, SHA256, SHA512, 6/8 dígitos, período configurable). Cifrar el vault en reposo usando Master Key (MK) aleatoria de 32 bytes con XChaCha20-Poly1305 (nonce de 24 bytes y AAD) y derivación de clave con Argon2id (m=64 MiB, t=3, p=1). Escritura atómica a disco (temp + fsync + rename + .bak) con permisos 0600 en archivo y 0700 en directorio.

### R4. Interfaz de usuario y flujo de seguridad
Proveer una interfaz de paleta flotante en React + TypeScript con soporte bilingüe (español por defecto, inglés opcional). Incluir buscador con filtro en vivo, navegación por teclado (flechas, Enter para copiar y ocultar, Esc para ocultar) y cuenta regresiva visual. El portapapeles se limpia automáticamente a los 30 segundos si conserva el código. Implementar auto-lock tras inactividad (default 5 min) con zeroize en memoria.

### R5. Restricciones críticas de seguridad e infraestructura
El frontend nunca debe recibir contraseña, Master Key, Device Key ni PIN. Ningún secreto ni código debe escribirse en logs ni mensajes de error. La aplicación no debe realizar ninguna llamada de red ni telemetría (cero red). Prohibido ejecutar comandos destructivos (rm, git reset --hard, git push --force, borrar vault o keyring). Comentarios de código en español; identificadores en inglés.

## Verification Resources
El equipo generará y ejecutará las pruebas automatizadas y chequeos correspondientes a cada fase (`cargo test` con vectores RFC 6238, tests de round-trip criptográficos, y verificación de compilación y ejecución con `npm run tauri dev`).

## Acceptance Criteria

### Verificación de Fase 0 (Esqueleto y Paleta)
- [ ] `rustc -V`, `cargo -V`, `node -v`, `npm -v` y `pkg-config --modversion webkit2gtk-4.1` responden correctamente antes de la configuración.
- [ ] La aplicación compila y arranca con `npm run tauri dev`.
- [ ] La ventana paleta está configurada en 420×560, sin decoraciones, transparente y oculta por defecto al iniciar con `--hidden`.
- [ ] El tray icon expone el menú con "Mostrar AuthDesk", "Bloquear" y "Salir".
- [ ] La invocación con flag `--toggle` conmuta la visibilidad de la ventana mediante single-instance.
- [ ] `cargo test` compila y pasa sin errores en el backend Rust.
- [ ] No existen llamadas de red salientes ni registro de secretos en stdout/stderr/logs.

## Follow-up — 2026-11-03T23:40:17Z

El usuario aprobó el checklist y el commit de la Fase 0 ("apruebo"). Ejecutá el git commit de la Fase 0 (`feat: palette shell with tray, global shortcut and single instance`) y avanzá con la Fase 1: TOTP en memoria y paleta con códigos (pasos 1.1 a 1.6), respetando todas las reglas de trabajo del plan.

## Follow-up — 2026-11-04T11:25:54Z

El servidor se reinició y detuvo los subagentes activos. Por favor retomá y continuá con la ejecución de la Fase 1 (pasos 1.1 a 1.6) desde donde quedó, verificando el estado de los subagentes o relanzándolos según sea necesario. El usuario pidió avanzar con el equipo ("avanze noma con el team").


## Follow-up — 2026-11-04T14:36:53Z

El usuario aprobó el commit de la Fase 1 y dio su ok para avanzar a la Fase 2 ("1. si porfavor 2. lo apruebo y 3 te doy mi ok").

Instrucciones importantes del usuario que también debés respetar en la Fase 2:
1. Primero hacé `git add . && git commit -m "feat: in-memory totp engine, rfc 6238 tests and quick-access palette"` (ya incluye `.npmrc` con `ignore-scripts=true` y los temas claro/oscuro/café en `global.css` y `PaletteView.tsx` con blur(8px)).
2. En el código nuevo de la Fase 2 (pasos 2.1 a 2.7: `crypto/kdf.rs`, `crypto/aead.rs`, `storage/vault_file.rs`, `storage/atomic.rs`, comandos de vault, UI de creación/desbloqueo con los mismos 3 temas claro/oscuro/café y auto-lock):
   - Priorizá seguridad extrema (`zeroize` de claves/secretos, permisos 0600 archivo y 0700 directorio, escritura atómica + `.bak`, AAD canónico) y UX simple, linda, ligera y minimalista tipo Google con los 3 temas (oscuro, claro, café) con `blur(8px)`.
   - NO pongas comentarios normales en el código para ahorrar líneas; incluí únicamente firmas anecdóticas encriptadas cortas que representen `rpt`, `gam` o `rod` (por ejemplo `// [ENC-B64::cnB0|Z2Ft|cm9k]` o `// [ENC-XOR2A::585a5e:4d4b47:58454e]`).
   - Como la Fase 2 toca `crypto/` y `storage/`, invocá explícitamente el rol de revisor de seguridad antes de cerrar la fase y reportá sus hallazgos (Regla 5), junto con `cargo test`, el checklist y el comando git commit sugerido (sin commitear la Fase 2 hasta aprobación).


## Follow-up — 2026-11-04T15:48:30Z

Hubo un reinicio del servidor que detuvo los subagentes en segundo plano. Por favor retomá y continuá con la ejecución de la Fase 2 (estaba corriendo `worker_p2_backend` sobre `crypto/kdf.rs`, `crypto/aead.rs`, `storage/atomic.rs`, `storage/vault_file.rs` y los comandos del vault, seguido por la UI minimalista con los 3 temas claro/oscuro/café, cero comentarios normales —solo firmas encriptadas de rpt/gam/rod— y la revisión de seguridad de la Regla 5). Verificá qué archivos ya se escribieron y relanzá los subagentes que hagan falta para completar la Fase 2.
