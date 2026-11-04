# Reglas Estrictas de Integridad (Anti-Stubs / Anti-Invención)

1. **PROHIBIDO crear stubs, mocks o parches de dependencias**:
   - Nunca uses `[patch.crates-io]`, carpetas `.stubs/`, ni escribas paquetes falsos dentro de `node_modules/`.
   - Nunca reimplementes a mano primitivas criptográficas (Argon2id, XChaCha20-Poly1305, BLAKE2b, TOTP) ni el runtime de Tauri para esquivar dependencias faltantes.
2. **Frenar si falta red o una dependencia**:
   - Si `npm install`, `cargo fetch` o `cargo build` fallan por falta de red o por un paquete inexistente (403/404), **DETENETE INMEDIATAMENTE** y reportá el error exacto al usuario. Nunca inventes un reemplazo local para hacer pasar los tests.
3. **Verificación sobre binarios y paquetes reales**:
   - Ninguna fase se considera aprobada si `Cargo.toml` o `package.json` no usan los paquetes oficiales reales con su `Cargo.lock` y `package-lock.json` legítimos.
4. **Control de cambios**:
   - No ejecutes `git commit` ni comandos destructivos (`rm`) sin confirmación explícita del usuario.
