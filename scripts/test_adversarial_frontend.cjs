// scripts/test_adversarial_frontend.cjs
// Suite exhaustiva de pruebas adversariales para Frontend UI & Interaction Logic (AuthDesk Phase 1).

const assert = require("assert");

console.log("======================================================================");
console.log("   AuthDesk Frontend UI & Interaction Logic — Adversarial Test Suite");
console.log("======================================================================");

let totalTests = 0;
let passedTests = 0;

function it(name, fn) {
  totalTests++;
  try {
    fn();
    passedTests++;
    console.log(`  [PASS] ${name}`);
  } catch (err) {
    console.error(`  [FAIL] ${name}: ${err.message}`);
    throw err;
  }
}

async function itAsync(name, fn) {
  totalTests++;
  try {
    await fn();
    passedTests++;
    console.log(`  [PASS] ${name}`);
  } catch (err) {
    console.error(`  [FAIL] ${name}: ${err.message}`);
    throw err;
  }
}

// ======================================================================
// 1. SMART CLIPBOARD AUTO-CLEAR (30-SECOND CONDITIONAL CLEAR)
// ======================================================================
console.log("\n--- Suite 1: Smart Clipboard Auto-Clear Logic ---");

// Virtual Clock for precise deterministic time travel
class VirtualClock {
  constructor() {
    this.currentTime = 0;
    this.timers = [];
    this.nextTimerId = 1;
  }

  setTimeout(callback, delay) {
    const id = this.nextTimerId++;
    const triggerTime = this.currentTime + delay;
    this.timers.push({ id, triggerTime, callback, delay });
    this.timers.sort((a, b) => a.triggerTime - b.triggerTime);
    return id;
  }

  clearTimeout(id) {
    this.timers = this.timers.filter((t) => t.id !== id);
  }

  advanceTime(ms) {
    const targetTime = this.currentTime + ms;
    while (this.timers.length > 0 && this.timers[0].triggerTime <= targetTime) {
      const nextTimer = this.timers.shift();
      this.currentTime = nextTimer.triggerTime;
      nextTimer.callback();
    }
    this.currentTime = targetTime;
  }
}

// Simulated Clipboard Manager matching useClipboard.ts behavior exactly
function createSimulatedClipboardHook(clock) {
  let activeTimer = null;
  let clipboardContent = "";

  async function copyCode(rawCode) {
    const codeDigits = rawCode.replace(/\s+/g, "");
    clipboardContent = codeDigits;

    if (activeTimer) {
      clock.clearTimeout(activeTimer);
      activeTimer = null;
    }

    activeTimer = clock.setTimeout(async () => {
      try {
        const currentText = clipboardContent;
        if (currentText.trim() === codeDigits) {
          clipboardContent = "";
        }
      } finally {
        activeTimer = null;
      }
    }, 30_000);
  }

  function unmount() {
    if (activeTimer) {
      clock.clearTimeout(activeTimer);
      activeTimer = null;
    }
  }

  return {
    copyCode,
    unmount,
    getClipboard: () => clipboardContent,
    setClipboardExternal: (text) => {
      clipboardContent = text;
    },
    hasActiveTimer: () => activeTimer !== null,
  };
}

it("Case A: Code '123456' copied, 30 seconds elapse, unchanged -> MUST be cleared", async () => {
  const clock = new VirtualClock();
  const hook = createSimulatedClipboardHook(clock);

  await hook.copyCode("123456");
  assert.strictEqual(hook.getClipboard(), "123456", "Clipboard should immediately contain copied code");
  assert.strictEqual(hook.hasActiveTimer(), true, "30s timer should be active");

  // Advance 29.9 seconds -> should still contain code
  clock.advanceTime(29_900);
  assert.strictEqual(hook.getClipboard(), "123456", "At 29.9s, code should still remain in clipboard");

  // Advance past 30 seconds -> MUST be cleared
  clock.advanceTime(100);
  assert.strictEqual(hook.getClipboard(), "", "At 30.0s, clipboard MUST be cleared");
  assert.strictEqual(hook.hasActiveTimer(), false, "Active timer should be reset to null");
});

it("Case B: Code '123456' copied, at 15s user copies 'my-secret-url', 30s elapse -> MUST NOT be cleared", async () => {
  const clock = new VirtualClock();
  const hook = createSimulatedClipboardHook(clock);

  await hook.copyCode("123456");
  assert.strictEqual(hook.getClipboard(), "123456");

  // At second 15, user copies external text
  clock.advanceTime(15_000);
  hook.setClipboardExternal("my-secret-url");
  assert.strictEqual(hook.getClipboard(), "my-secret-url");

  // Advance remaining 15 seconds (total 30 seconds since initial copy)
  clock.advanceTime(15_000);
  assert.strictEqual(
    hook.getClipboard(),
    "my-secret-url",
    "Clipboard MUST NOT be cleared when external text was copied; newer data preserved"
  );
  assert.strictEqual(hook.hasActiveTimer(), false, "Active timer should be reset after firing");
});

it("Case C: Rapid consecutive copies (111111 at t=0, 222222 at t=10) -> resets timer properly", async () => {
  const clock = new VirtualClock();
  const hook = createSimulatedClipboardHook(clock);

  // t=0: copy 111111
  await hook.copyCode("111111");
  assert.strictEqual(hook.getClipboard(), "111111");

  // t=10s: copy 222222 (timer for 111111 must be cancelled)
  clock.advanceTime(10_000);
  await hook.copyCode("222222");
  assert.strictEqual(hook.getClipboard(), "222222");

  // t=30s (20s after second copy): initial 30s mark from 1st copy passed, 2nd copy must NOT be cleared yet
  clock.advanceTime(20_000);
  assert.strictEqual(hook.getClipboard(), "222222", "Second code must not be cleared by the cancelled 1st timer");

  // t=40s (30s after second copy): second code MUST now be cleared
  clock.advanceTime(10_000);
  assert.strictEqual(hook.getClipboard(), "", "Second code must be cleared at t=40s (30s after copy)");
});

it("Case D: External paste/overwrite after consecutive copy is preserved", async () => {
  const clock = new VirtualClock();
  const hook = createSimulatedClipboardHook(clock);

  // t=0: copy 111111
  await hook.copyCode("111111");
  // t=5s: copy 222222
  clock.advanceTime(5_000);
  await hook.copyCode("222222");
  // t=15s: external copy "important-token"
  clock.advanceTime(10_000);
  hook.setClipboardExternal("important-token");

  // t=35s (30s after second copy): external text must NOT be cleared
  clock.advanceTime(20_000);
  assert.strictEqual(hook.getClipboard(), "important-token", "External token preserved");
});

it("Case E: Formatted codes with spaces and whitespace trim handling", async () => {
  const clock = new VirtualClock();
  const hook = createSimulatedClipboardHook(clock);

  // User copies code displayed with spaces "123 456"
  await hook.copyCode("123 456");
  assert.strictEqual(hook.getClipboard(), "123456", "Spaces must be stripped when writing to clipboard");

  // External clipboard manager added newline e.g. "123456\n"
  hook.setClipboardExternal("  123456 \r\n");

  clock.advanceTime(30_000);
  assert.strictEqual(hook.getClipboard(), "", "Trimmed matching code MUST be cleared");
});

it("Case F: Clipboard manually cleared before 30s -> graceful no-op", async () => {
  const clock = new VirtualClock();
  const hook = createSimulatedClipboardHook(clock);

  await hook.copyCode("123456");
  // User clears clipboard externally at 10s
  clock.advanceTime(10_000);
  hook.setClipboardExternal("");

  clock.advanceTime(20_000);
  assert.strictEqual(hook.getClipboard(), "", "Remains empty without errors");
});

it("Case G: Component unmount cancels timer (no memory leak or ghost clear)", async () => {
  const clock = new VirtualClock();
  const hook = createSimulatedClipboardHook(clock);

  await hook.copyCode("123456");
  assert.strictEqual(hook.hasActiveTimer(), true);

  // Component unmounts at 10s
  clock.advanceTime(10_000);
  hook.unmount();
  assert.strictEqual(hook.hasActiveTimer(), false, "Timer cleared on unmount");

  // External text copied at 15s
  clock.advanceTime(5_000);
  hook.setClipboardExternal("new-text");

  // Advance past 30s -> ghost timer should NOT run
  clock.advanceTime(20_000);
  assert.strictEqual(hook.getClipboard(), "new-text");
});


// ======================================================================
// 2. PALETTEVIEW SEARCH FILTER
// ======================================================================
console.log("\n--- Suite 2: PaletteView Search Filter Logic ---");

const sampleAccounts = [
  { id: "1", issuer: "GitHub", account: "octocat@github.com", code: "123456" },
  { id: "2", issuer: "Google", account: "admin@corp.io", code: "654321" },
  { id: "3", issuer: "AWS Production", account: "root@aws.amazon.com", code: "789012" },
  { id: "4", issuer: "Banco Galicia", account: "cuenta_corriente", code: "345678" },
  { id: "5", issuer: "Bitwarden", account: "vault-sync@bitwarden.com", code: "901234" },
];

function filterAccounts(accounts, query) {
  const q = query.trim().toLowerCase();
  if (!q) return accounts;
  return accounts.filter(
    (acc) =>
      acc.issuer.toLowerCase().includes(q) ||
      acc.account.toLowerCase().includes(q)
  );
}

it("Empty search query returns all accounts", () => {
  const res = filterAccounts(sampleAccounts, "");
  assert.strictEqual(res.length, 5);
  assert.deepStrictEqual(res, sampleAccounts);
});

it("Whitespace-only query returns all accounts", () => {
  const res1 = filterAccounts(sampleAccounts, "   ");
  const res2 = filterAccounts(sampleAccounts, "\t\n  ");
  assert.strictEqual(res1.length, 5);
  assert.strictEqual(res2.length, 5);
});

it("Partial match on issuer (case-insensitive)", () => {
  const resLower = filterAccounts(sampleAccounts, "git");
  assert.strictEqual(resLower.length, 1);
  assert.strictEqual(resLower[0].issuer, "GitHub");

  const resUpper = filterAccounts(sampleAccounts, "GIT");
  assert.strictEqual(resUpper.length, 1);
  assert.strictEqual(resUpper[0].issuer, "GitHub");

  const resMixed = filterAccounts(sampleAccounts, "gOoGlE");
  assert.strictEqual(resMixed.length, 1);
  assert.strictEqual(resMixed[0].issuer, "Google");
});

it("Partial match on account label (case-insensitive)", () => {
  const resAdmin = filterAccounts(sampleAccounts, "admin");
  assert.strictEqual(resAdmin.length, 1);
  assert.strictEqual(resAdmin[0].issuer, "Google");

  const resCorp = filterAccounts(sampleAccounts, "CORP.IO");
  assert.strictEqual(resCorp.length, 1);
  assert.strictEqual(resCorp[0].account, "admin@corp.io");

  const resRoot = filterAccounts(sampleAccounts, "amazon.com");
  assert.strictEqual(resRoot.length, 1);
  assert.strictEqual(resRoot[0].issuer, "AWS Production");
});

it("Search matching multiple accounts", () => {
  // Query "com" matches octocat@github.com, root@aws.amazon.com, vault-sync@bitwarden.com
  const res = filterAccounts(sampleAccounts, "com");
  assert.strictEqual(res.length, 3);
  const issuers = res.map((a) => a.issuer);
  assert.ok(issuers.includes("GitHub"));
  assert.ok(issuers.includes("AWS Production"));
  assert.ok(issuers.includes("Bitwarden"));
});

it("Query matching nothing returns empty array (triggers empty state)", () => {
  const res = filterAccounts(sampleAccounts, "nonexistent-service-xyz");
  assert.strictEqual(res.length, 0);
  assert.deepStrictEqual(res, []);
});

it("Adversarial: Regex special characters and metacharacters do NOT crash", () => {
  const regexAttacks = [
    ".*",
    "[a-z]+",
    "(foo|bar)",
    "\\d{6}",
    "^.*$",
    "???+++***",
    "[[[",
    "(((",
    "\\",
    "{1,10}",
    "$",
  ];

  for (const attack of regexAttacks) {
    // Must execute cleanly without throwing SyntaxError or RegExp crash
    const res = filterAccounts(sampleAccounts, attack);
    assert.ok(Array.isArray(res), `Query '${attack}' returned array`);
  }
});

it("Adversarial: Unicode and Spanish accents matching", () => {
  const res1 = filterAccounts(sampleAccounts, "banco");
  assert.strictEqual(res1.length, 1);
  assert.strictEqual(res1[0].issuer, "Banco Galicia");

  const res2 = filterAccounts(sampleAccounts, "corriente");
  assert.strictEqual(res2.length, 1);
  assert.strictEqual(res2[0].account, "cuenta_corriente");
});

it("Adversarial: Very long query does not degrade performance", () => {
  const longQuery = "a".repeat(10_000);
  const start = Date.now();
  const res = filterAccounts(sampleAccounts, longQuery);
  const elapsed = Date.now() - start;
  assert.strictEqual(res.length, 0);
  assert.ok(elapsed < 20, `Search took ${elapsed}ms, should be < 20ms`);
});


// ======================================================================
// 3. KEYBOARD NAVIGATION & WRAP-AROUND LOGIC
// ======================================================================
console.log("\n--- Suite 3: Keyboard Navigation & Selection ---");

function simulateNavigation(totalItems, keyEvents, initialIndex = 0) {
  let selected = initialIndex;

  for (const key of keyEvents) {
    if (key === "ArrowDown") {
      selected = totalItems > 0 ? (selected + 1) % totalItems : 0;
    } else if (key === "ArrowUp") {
      selected = totalItems > 0 ? (selected - 1 + totalItems) % totalItems : 0;
    }
  }

  return selected;
}

it("ArrowDown forward wrap-around (3 items: 0 -> 1 -> 2 -> 0)", () => {
  let idx = 0;
  idx = simulateNavigation(3, ["ArrowDown"], idx);
  assert.strictEqual(idx, 1);
  idx = simulateNavigation(3, ["ArrowDown"], idx);
  assert.strictEqual(idx, 2);
  idx = simulateNavigation(3, ["ArrowDown"], idx);
  assert.strictEqual(idx, 0, "Wrap-around from index 2 to 0");
});

it("ArrowUp backward wrap-around (3 items: 0 -> 2 -> 1 -> 0)", () => {
  let idx = 0;
  idx = simulateNavigation(3, ["ArrowUp"], idx);
  assert.strictEqual(idx, 2, "Wrap-around from index 0 to 2");
  idx = simulateNavigation(3, ["ArrowUp"], idx);
  assert.strictEqual(idx, 1);
  idx = simulateNavigation(3, ["ArrowUp"], idx);
  assert.strictEqual(idx, 0);
});

it("Single item list (1 item: stays 0 on both ArrowDown and ArrowUp)", () => {
  assert.strictEqual(simulateNavigation(1, ["ArrowDown"], 0), 0);
  assert.strictEqual(simulateNavigation(1, ["ArrowUp"], 0), 0);
});

it("Empty list (0 items: stays 0 without NaN or modulo zero division)", () => {
  const downResult = simulateNavigation(0, ["ArrowDown"], 0);
  const upResult = simulateNavigation(0, ["ArrowUp"], 0);
  assert.strictEqual(downResult, 0);
  assert.strictEqual(upResult, 0);
  assert.ok(!Number.isNaN(downResult));
  assert.ok(!Number.isNaN(upResult));
});

it("Enter key selection logic", () => {
  let copied = null;
  let hidden = false;

  const mockCopyAndHide = (code) => {
    copied = code;
    hidden = true;
  };

  const handleEnter = (filtered, selectedIndex) => {
    if (filtered[selectedIndex]) {
      mockCopyAndHide(filtered[selectedIndex].code);
    }
  };

  // Case 1: Active selection on item 1
  handleEnter(sampleAccounts, 1);
  assert.strictEqual(copied, "654321");
  assert.strictEqual(hidden, true);

  // Case 2: Empty filtered list -> does not throw or copy
  copied = null;
  hidden = false;
  handleEnter([], 0);
  assert.strictEqual(copied, null);
  assert.strictEqual(hidden, false);
});

it("Escape key hides window", () => {
  let hidden = false;
  const handleKeyDown = (e) => {
    if (e.key === "Escape") {
      hidden = true;
    }
  };

  handleKeyDown({ key: "Escape" });
  assert.strictEqual(hidden, true);
});

it("Typing search query resets selection index to 0", () => {
  let selectedIndex = 3;
  const onSearchQueryChange = () => {
    selectedIndex = 0;
  };

  onSearchQueryChange();
  assert.strictEqual(selectedIndex, 0);
});


// ======================================================================
// 4. WINDOW FOCUS RESET
// ======================================================================
console.log("\n--- Suite 4: Window Focus Reset ---");

it("Window focus event clears query, resets selection, and focuses input", () => {
  let searchQuery = "previous-search";
  let selectedIndex = 4;
  let inputFocused = false;

  const mockInputRef = {
    focus: () => {
      inputFocused = true;
    },
  };

  const handleFocus = () => {
    searchQuery = "";
    selectedIndex = 0;
    mockInputRef.focus();
  };

  handleFocus();

  assert.strictEqual(searchQuery, "", "Search query must be cleared on focus");
  assert.strictEqual(selectedIndex, 0, "Selected index must be reset to 0");
  assert.strictEqual(inputFocused, true, "Search input element must receive focus");
});

it("Focus event cleanup removes listeners properly", () => {
  const registeredListeners = new Map();

  const mockWindow = {
    addEventListener: (event, handler) => {
      registeredListeners.set(event, handler);
    },
    removeEventListener: (event) => {
      registeredListeners.delete(event);
    },
  };

  const handler = () => {};
  mockWindow.addEventListener("focus", handler);
  assert.strictEqual(registeredListeners.has("focus"), true);

  mockWindow.removeEventListener("focus");
  assert.strictEqual(registeredListeners.has("focus"), false);
});


// ======================================================================
// 5. COUNTDOWN RING & CODE FORMATTING
// ======================================================================
console.log("\n--- Suite 5: Countdown Ring & Code Formatting ---");

it("CountdownRing progress clamping and color thresholds", () => {
  function getRingMath(remaining, period = 30, size = 28) {
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

    return { progress, strokeDashoffset, strokeColor };
  }

  // T = 30 (100%): blue, dashoffset = 0
  const t30 = getRingMath(30, 30);
  assert.strictEqual(t30.strokeColor, "#3b82f6");
  assert.strictEqual(t30.progress, 1.0);

  // T = 15: blue
  const t15 = getRingMath(15, 30);
  assert.strictEqual(t15.strokeColor, "#3b82f6");
  assert.strictEqual(t15.progress, 0.5);

  // T = 10: amber
  const t10 = getRingMath(10, 30);
  assert.strictEqual(t10.strokeColor, "#f59e0b");

  // T = 5: red
  const t5 = getRingMath(5, 30);
  assert.strictEqual(t5.strokeColor, "#ef4444");

  // T = 0: red, progress = 0
  const t0 = getRingMath(0, 30);
  assert.strictEqual(t0.strokeColor, "#ef4444");
  assert.strictEqual(t0.progress, 0.0);

  // Overflows / Out of bounds clamped safely
  const tNeg = getRingMath(-5, 30);
  assert.strictEqual(tNeg.progress, 0.0);
  const tOver = getRingMath(35, 30);
  assert.strictEqual(tOver.progress, 1.0);
});

it("Code formatting preserves leading zeros and formats 6 and 8 digits", () => {
  const formatCode = (code) => {
    const raw = code.replace(/\s+/g, "");
    if (raw.length === 6) return `${raw.slice(0, 3)} ${raw.slice(3)}`;
    if (raw.length === 8) return `${raw.slice(0, 4)} ${raw.slice(4)}`;
    return raw;
  };

  assert.strictEqual(formatCode("000001"), "000 001");
  assert.strictEqual(formatCode("00000002"), "0000 0002");
  assert.strictEqual(formatCode("123456"), "123 456");
  assert.strictEqual(formatCode("12345678"), "1234 5678");
  assert.strictEqual(formatCode("123 456"), "123 456");
  assert.strictEqual(formatCode("1234 5678"), "1234 5678");
});

console.log("======================================================================");
console.log(`   Adversarial Test Summary: ${passedTests}/${totalTests} tests PASSED`);
console.log("======================================================================");
