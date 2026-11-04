// scripts/test_frontend_logic.js
// Pruebas unitarias para la lógica de componentes, hooks y tipos del frontend de AuthDesk.

const assert = require("assert");

console.log("[*] Iniciando pruebas unitarias de la lógica del frontend...");

// 1. Verificación del cálculo y colores dinámicos del CountdownRing
function testCountdownRingLogic() {
  console.log("  [1] Probando lógica de CountdownRing (SVG dashoffset y colores de urgencia)...");
  
  function getRingState(remaining, period = 30, size = 28) {
    const strokeWidth = 2.5;
    const radius = (size - strokeWidth) / 2;
    const circumference = 2 * Math.PI * radius;
    const progress = Math.max(0, Math.min(1, remaining / (period || 30)));
    const strokeDashoffset = circumference * (1 - progress);

    let strokeColor = "#3b82f6";
    if (remaining <= 5) {
      strokeColor = "#ef4444";
    } else if (remaining <= 10) {
      strokeColor = "#f59e0b";
    }

    return { radius, circumference, strokeDashoffset, strokeColor };
  }

  // T = 30s (inicio del ciclo): azul, dashoffset = 0
  const state30 = getRingState(30, 30);
  assert.strictEqual(state30.strokeColor, "#3b82f6");
  assert.ok(Math.abs(state30.strokeDashoffset - 0) < 0.001);

  // T = 15s (> 10s): azul
  const state15 = getRingState(15, 30);
  assert.strictEqual(state15.strokeColor, "#3b82f6");
  assert.ok(state15.strokeDashoffset > 0);

  // T = 10s (6-10s): ámbar
  const state10 = getRingState(10, 30);
  assert.strictEqual(state10.strokeColor, "#f59e0b");

  // T = 6s (6-10s): ámbar
  const state6 = getRingState(6, 30);
  assert.strictEqual(state6.strokeColor, "#f59e0b");

  // T = 5s (<= 5s): rojo crítico
  const state5 = getRingState(5, 30);
  assert.strictEqual(state5.strokeColor, "#ef4444");

  // T = 0s: rojo crítico, dashoffset = circunferencia completa
  const state0 = getRingState(0, 30);
  assert.strictEqual(state0.strokeColor, "#ef4444");
  assert.ok(Math.abs(state0.strokeDashoffset - state0.circumference) < 0.001);

  console.log("    -> CountdownRing lógica: PASS");
}

// 2. Verificación del formateo visual de códigos en AccountItem
function testCodeFormatting() {
  console.log("  [2] Probando formateo de códigos TOTP (6 y 8 dígitos)...");

  const formatCode = (code) => {
    const raw = code.replace(/\s+/g, "");
    if (raw.length === 6) return `${raw.slice(0, 3)} ${raw.slice(3)}`;
    if (raw.length === 8) return `${raw.slice(0, 4)} ${raw.slice(4)}`;
    return raw;
  };

  assert.strictEqual(formatCode("123456"), "123 456");
  assert.strictEqual(formatCode("123 456"), "123 456");
  assert.strictEqual(formatCode("12345678"), "1234 5678");
  assert.strictEqual(formatCode("005924"), "005 924"); // Ceros iniciales preservados
  assert.strictEqual(formatCode("99999999"), "9999 9999");

  console.log("    -> Formateo de códigos: PASS");
}

// 3. Verificación de filtrado y navegación en PaletteView
function testSearchAndNavigation() {
  console.log("  [3] Probando filtro en vivo y navegación circular de selección...");

  const accounts = [
    { id: "1", issuer: "GitHub", account: "user@github.com", code: "111222" },
    { id: "2", issuer: "Google", account: "admin@corp.io", code: "333444" },
    { id: "3", issuer: "AWS", account: "root@aws.amazon.com", code: "555666" },
  ];

  const filterAccounts = (query) => {
    const q = query.trim().toLowerCase();
    if (!q) return accounts;
    return accounts.filter(
      (acc) =>
        acc.issuer.toLowerCase().includes(q) ||
        acc.account.toLowerCase().includes(q)
    );
  };

  // Coincidencia por emisor
  assert.strictEqual(filterAccounts("git").length, 1);
  assert.strictEqual(filterAccounts("GIT")[0].issuer, "GitHub");

  // Coincidencia por cuenta
  assert.strictEqual(filterAccounts("admin").length, 1);
  assert.strictEqual(filterAccounts("admin")[0].issuer, "Google");

  // Coincidencia vacía
  assert.strictEqual(filterAccounts("inexistente").length, 0);

  // Navegación circular (wrap-around)
  const len = accounts.length; // 3
  let selected = 0;
  // Flecha Abajo: 0 -> 1 -> 2 -> 0
  selected = (selected + 1) % len;
  assert.strictEqual(selected, 1);
  selected = (selected + 1) % len;
  assert.strictEqual(selected, 2);
  selected = (selected + 1) % len;
  assert.strictEqual(selected, 0);

  // Flecha Arriba: 0 -> 2 -> 1 -> 0
  selected = (selected - 1 + len) % len;
  assert.strictEqual(selected, 2);
  selected = (selected - 1 + len) % len;
  assert.strictEqual(selected, 1);
  selected = (selected - 1 + len) % len;
  assert.strictEqual(selected, 0);

  console.log("    -> Filtro en vivo y navegación circular: PASS");
}

// 4. Verificación de limpieza inteligente del portapapeles a 30s (simulado)
function testClipboardSmartClear() {
  console.log("  [4] Probando limpieza inteligente condicional del portapapeles...");

  let clipboardStorage = "";
  let activeTimer = null;

  function copyCode(codeDigits, onClearCheck) {
    clipboardStorage = codeDigits;
    if (activeTimer) clearTimeout(activeTimer);
    activeTimer = setTimeout(() => {
      if (clipboardStorage.trim() === codeDigits) {
        clipboardStorage = "";
      }
      if (onClearCheck) onClearCheck();
    }, 50); // Simulación rápida de temporizador
  }

  // Caso A: Portapapeles no modificado -> Debe borrarse
  copyCode("123456", () => {
    assert.strictEqual(clipboardStorage, "");
    
    // Caso B: Usuario copia texto externo antes de expirar -> Debe preservarse
    copyCode("654321", () => {
      // Al expirar el temporizador de 654321, el contenido es "https://externo.com"
      assert.strictEqual(clipboardStorage, "https://externo.com");
      console.log("    -> Limpieza inteligente condicional: PASS");
      console.log("\n[+] TODAS LAS PRUEBAS UNITARIAS DEL FRONTEND PASARON EXITOSAMENTE.");
    });
    // Usuario copia texto externo a los 10ms
    setTimeout(() => {
      clipboardStorage = "https://externo.com";
    }, 10);
  });
}

testCountdownRingLogic();
testCodeFormatting();
testSearchAndNavigation();
testClipboardSmartClear();
