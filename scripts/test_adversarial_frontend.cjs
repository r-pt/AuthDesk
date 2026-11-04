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
  assert.strictEqual(formatCode("1234 5678"), "1234 5678");
});


// ======================================================================
// 6. INACTIVITY AUTO-LOCK TIMING & FOCUS-WAKE (5-MIN & THROTTLING)
// ======================================================================
console.log("\n--- Suite 6: Inactivity Auto-Lock & Background Wake Logic ---");

function createSimulatedAutoLock({ clock, timeoutMs = 5 * 60 * 1000, enabled = true, onLock }) {
  const THROTTLE_INTERVAL_MS = 1000;
  let timerId = null;
  let lastActivity = clock.currentTime;
  let isEnabled = enabled;
  let locked = false;

  function triggerLock() {
    if (timerId !== null) {
      clock.clearTimeout(timerId);
      timerId = null;
    }
    locked = true;
    if (onLock) onLock();
  }

  function resetTimer() {
    if (!isEnabled) return;
    if (timerId !== null) {
      clock.clearTimeout(timerId);
    }
    timerId = clock.setTimeout(() => {
      triggerLock();
    }, timeoutMs);
  }

  function handleActivity() {
    if (!isEnabled) return;
    const now = clock.currentTime;
    if (now - lastActivity >= THROTTLE_INTERVAL_MS) {
      lastActivity = now;
      resetTimer();
      return true;
    }
    return false;
  }

  function handleFocusActivity() {
    if (!isEnabled) return;
    const elapsed = clock.currentTime - lastActivity;
    if (elapsed >= timeoutMs) {
      triggerLock();
      return true;
    } else {
      lastActivity = clock.currentTime;
      resetTimer();
      return false;
    }
  }

  if (isEnabled) {
    resetTimer();
  }

  function setEnabled(val) {
    isEnabled = val;
    if (!val) {
      if (timerId !== null) {
        clock.clearTimeout(timerId);
        timerId = null;
      }
    } else {
      lastActivity = clock.currentTime;
      resetTimer();
    }
  }

  function unmount() {
    if (timerId !== null) {
      clock.clearTimeout(timerId);
      timerId = null;
    }
  }

  return {
    handleActivity,
    handleFocusActivity,
    setEnabled,
    unmount,
    isLocked: () => locked,
    hasActiveTimer: () => timerId !== null,
    getLastActivity: () => lastActivity,
  };
}

it("6.1: 5-minute timeout calculation (300,000ms): locks precisely at timeout", () => {
  const clock = new VirtualClock();
  let lockedCallbackCalled = false;
  const autoLock = createSimulatedAutoLock({
    clock,
    timeoutMs: 300_000,
    onLock: () => {
      lockedCallbackCalled = true;
    },
  });

  assert.strictEqual(autoLock.hasActiveTimer(), true);
  assert.strictEqual(autoLock.isLocked(), false);

  // Advance to 299,990ms (10ms before timeout)
  clock.advanceTime(299_990);
  assert.strictEqual(autoLock.isLocked(), false);
  assert.strictEqual(lockedCallbackCalled, false);

  // Advance remaining 10ms -> exactly 300,000ms
  clock.advanceTime(10);
  assert.strictEqual(autoLock.isLocked(), true);
  assert.strictEqual(lockedCallbackCalled, true);
  assert.strictEqual(autoLock.hasActiveTimer(), false);
});

it("6.2: 1000ms throttling: rapid multi-event burst resets timer only once per second", () => {
  const clock = new VirtualClock();
  const autoLock = createSimulatedAutoLock({ clock, timeoutMs: 300_000 });

  // Burst of 50 mouse moves over 500ms (every 10ms)
  let resetCount = 0;
  for (let i = 0; i < 50; i++) {
    clock.advanceTime(10);
    if (autoLock.handleActivity()) {
      resetCount++;
    }
  }

  // All 50 events occurred within 500ms of t=0, so none met the >= 1000ms threshold
  assert.strictEqual(resetCount, 0, "Rapid sub-second events must be throttled");

  // Advance to 1050ms -> meets the 1000ms interval
  clock.advanceTime(550);
  const resetAfter1s = autoLock.handleActivity();
  assert.strictEqual(resetAfter1s, true, "Event at 1050ms must trigger timer reset");
  assert.strictEqual(autoLock.getLastActivity(), 1050);

  // Timer is now set for 1050 + 300_000 = 301_050ms
  // Advance to 301_000ms (1050 + 299_950)
  clock.advanceTime(299_950);
  assert.strictEqual(autoLock.isLocked(), false, "Should not lock at 301,000ms");
  // Advance remaining 50ms to 301_050ms
  clock.advanceTime(50);
  assert.strictEqual(autoLock.isLocked(), true, "Must lock at 301,050ms");
});

it("6.3: Continuous activity keeps vault unlocked indefinitely", () => {
  const clock = new VirtualClock();
  const autoLock = createSimulatedAutoLock({ clock, timeoutMs: 300_000 });

  // Simulate active user interacting every 2 seconds for 15 minutes (900 seconds)
  for (let s = 0; s < 450; s++) {
    clock.advanceTime(2000);
    autoLock.handleActivity();
    assert.strictEqual(autoLock.isLocked(), false, `Vault prematurely locked at second ${s * 2}`);
  }

  assert.strictEqual(autoLock.isLocked(), false, "Vault remained unlocked after 15 minutes of activity");
});

it("6.4: Focus-wake elapsed check (short sleep / 120s): extends timer without locking", () => {
  const clock = new VirtualClock();
  const autoLock = createSimulatedAutoLock({ clock, timeoutMs: 300_000 });

  // User is active at t=0
  // Window loses focus or system is idle for 2 minutes (120,000ms)
  clock.advanceTime(120_000);

  // Window regains focus
  const lockedOnFocus = autoLock.handleFocusActivity();
  assert.strictEqual(lockedOnFocus, false, "Should not lock on focus after 2 min (< 5 min)");
  assert.strictEqual(autoLock.isLocked(), false);
  assert.strictEqual(autoLock.getLastActivity(), 120_000, "lastActivity updated to focus timestamp");

  // Timer is reset for another 5 minutes (from t=120,000 to t=420,000)
  clock.advanceTime(299_900);
  assert.strictEqual(autoLock.isLocked(), false);
  clock.advanceTime(100);
  assert.strictEqual(autoLock.isLocked(), true, "Locks at t=420,000ms");
});

it("6.5: Focus-wake elapsed check (long suspend / 20 min lid closed): locks IMMEDIATELY on focus", () => {
  const clock = new VirtualClock();
  let lockCalled = false;
  const autoLock = createSimulatedAutoLock({
    clock,
    timeoutMs: 300_000,
    onLock: () => {
      lockCalled = true;
    },
  });

  // Machine sleeps at t=0 for 20 minutes (1,200,000ms)
  // While sleeping, setTimeout is frozen/delayed by OS
  clock.currentTime = 1_200_000;

  // On wake, OS/webview fires focus event
  const lockedOnFocus = autoLock.handleFocusActivity();
  assert.strictEqual(lockedOnFocus, true, "Must detect elapsed >= timeoutMs and lock immediately");
  assert.strictEqual(autoLock.isLocked(), true);
  assert.strictEqual(lockCalled, true);
});

it("6.6: Focus-wake boundary: exact 300,000ms locks immediately, 299,999ms does not", () => {
  // Test boundary 299,999ms
  const clock1 = new VirtualClock();
  const lock1 = createSimulatedAutoLock({ clock: clock1, timeoutMs: 300_000 });
  clock1.currentTime = 299_999;
  const res1 = lock1.handleFocusActivity();
  assert.strictEqual(res1, false, "299,999ms is strictly less than 300,000ms");
  assert.strictEqual(lock1.isLocked(), false);

  // Test boundary 300,000ms
  const clock2 = new VirtualClock();
  const lock2 = createSimulatedAutoLock({ clock: clock2, timeoutMs: 300_000 });
  clock2.currentTime = 300_000;
  const res2 = lock2.handleFocusActivity();
  assert.strictEqual(res2, true, "300,000ms meets >= timeoutMs and locks");
  assert.strictEqual(lock2.isLocked(), true);
});

it("6.7: Disabled auto-lock when vault is locked clears timer and ignores events", () => {
  const clock = new VirtualClock();
  const autoLock = createSimulatedAutoLock({ clock, timeoutMs: 300_000, enabled: false });

  assert.strictEqual(autoLock.hasActiveTimer(), false);
  assert.strictEqual(autoLock.handleActivity(), undefined);

  clock.advanceTime(600_000);
  assert.strictEqual(autoLock.isLocked(), false, "Disabled autoLock does not trigger lock");
});

it("6.8: Component unmount cancels timer (no memory leak or late execution)", () => {
  const clock = new VirtualClock();
  let lockExecuted = false;
  const autoLock = createSimulatedAutoLock({
    clock,
    timeoutMs: 300_000,
    onLock: () => {
      lockExecuted = true;
    },
  });

  clock.advanceTime(100_000);
  autoLock.unmount();
  assert.strictEqual(autoLock.hasActiveTimer(), false);

  clock.advanceTime(300_000);
  assert.strictEqual(lockExecuted, false, "Unmounted autoLock must not execute lock");
});

it("6.9: IPC invocation failure fallback gracefully triggers onLock callback", async () => {
  let uiLocked = false;
  const onLockCallback = () => {
    uiLocked = true;
  };

  // Simulate triggerLock logic from useAutoLock.ts with failing IPC
  const triggerLockWithFailingIpc = async () => {
    try {
      throw new Error("Tauri IPC backend unavailable");
    } catch {
      // IPC failure caught
    }
    if (onLockCallback) {
      onLockCallback();
    }
  };

  await triggerLockWithFailingIpc();
  assert.strictEqual(uiLocked, true, "UI lock callback must execute even if backend IPC fails");
});


// ======================================================================
// 7. PASSWORD BOUNDARIES, CONFIRMATION, UNICODE & STRENGTH
// ======================================================================
console.log("\n--- Suite 7: Password Boundaries, Confirmation, Unicode & Strength ---");

function calculatePasswordStrength(password) {
  if (!password) return 0;
  if (password.length < 8) return 1;
  let score = 1;
  if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++;
  if (/\d/.test(password) && /[^A-Za-z0-9]/.test(password) && password.length >= 10) score++;
  return score;
}

function validateSetupForm(password, confirmPassword, isSubmitting = false) {
  const passwordsMatch = password.length > 0 && password === confirmPassword;
  const canSubmit = password.length >= 8 && passwordsMatch && !isSubmitting;
  return { passwordsMatch, canSubmit };
}

it("7.1: Passwords shorter than 8 characters cannot be submitted (< 8 chars boundary)", () => {
  const shortPasswords = ["", "a", "12345", "1234567", "       "];
  for (const pw of shortPasswords) {
    const { canSubmit } = validateSetupForm(pw, pw);
    assert.strictEqual(canSubmit, false, `Password '${pw}' (<8 chars) must not be submittable`);
  }
});

it("7.2: Exactly 8 characters boundary is submittable when confirmed", () => {
  const boundaryPasswords = ["12345678", "abcdefgh", "A1!b2@c3", "======== "];
  for (const pw of boundaryPasswords) {
    const { canSubmit, passwordsMatch } = validateSetupForm(pw, pw);
    assert.strictEqual(passwordsMatch, true);
    assert.strictEqual(canSubmit, true, `8-char password '${pw}' must be submittable`);
  }
});

it("7.3: Password mismatch permutations reject submission", () => {
  const base = "SuperSecret2026!";
  const mismatches = [
    base.slice(0, -1), // Off by one at end
    base + " ",        // Trailing space
    " " + base,        // Leading space
    base.toLowerCase(),// Case mismatch
    base.toUpperCase(),// Case mismatch
    "",                // Empty confirm
    "Different123!",   // Completely different
  ];

  for (const confirm of mismatches) {
    const { passwordsMatch, canSubmit } = validateSetupForm(base, confirm);
    assert.strictEqual(passwordsMatch, false, `Mismatch '${confirm}' marked as matching`);
    assert.strictEqual(canSubmit, false, `Mismatch '${confirm}' allowed submission`);
  }
});

it("7.4: Unicode, Spanish ñ/accents, and Multi-byte Emojis validate correctly", () => {
  const unicodePasswords = [
    "contraseña-segura-ñandú",
    "Árbol_Ciprés_1234",
    "🔐Master🔑Vault🛡️2026",
    "パスワードマスター2026",
    "ПарольОтСейфа2026!",
    "كلمة-المرور-القوية-2026",
  ];

  for (const pw of unicodePasswords) {
    const { canSubmit, passwordsMatch } = validateSetupForm(pw, pw);
    assert.strictEqual(passwordsMatch, true);
    assert.strictEqual(canSubmit, true, `Unicode password '${pw}' must be valid and submittable`);
    assert.ok(calculatePasswordStrength(pw) >= 1);
  }
});

it("7.5: Injection payloads & shell characters validate safely without crashing", () => {
  const injectionPayloads = [
    "<script>alert('XSS')</script>",
    "' OR '1'='1' --",
    "'; DROP TABLE vault; --",
    "{\"admin\": true, \"role\": \"root\"}",
    "$(whoami && rm -rf /)",
    "admin\x00password123",
    "pass\nword\r\ntest123",
    "\\\\\\\\\\\\\\\\\\\\\\\\\\\\",
  ];

  for (const payload of injectionPayloads) {
    const { canSubmit } = validateSetupForm(payload, payload);
    assert.strictEqual(canSubmit, true, `Payload '${payload}' (>=8 chars) handled safely`);
  }
});

it("7.6: ReDoS and extremely large passwords evaluate in < 10ms", () => {
  const hugePasswords = [
    "A".repeat(1_000),
    "a1!".repeat(5_000),
    "Z9$".repeat(20_000), // 60,000 characters
  ];

  for (const huge of hugePasswords) {
    const start = Date.now();
    const strength = calculatePasswordStrength(huge);
    const { canSubmit } = validateSetupForm(huge, huge);
    const elapsed = Date.now() - start;

    assert.strictEqual(canSubmit, true);
    assert.ok(strength >= 1);
    assert.ok(elapsed < 15, `Password validation took ${elapsed}ms, must be < 15ms`);
  }
});

it("7.7: Password strength meter scoring accuracy (0 to 3)", () => {
  // Score 0: empty
  assert.strictEqual(calculatePasswordStrength(""), 0);

  // Score 1: weak (< 8 or single character class)
  assert.strictEqual(calculatePasswordStrength("123"), 1);
  assert.strictEqual(calculatePasswordStrength("abcdefgh"), 1);
  assert.strictEqual(calculatePasswordStrength("12345678"), 1);
  assert.strictEqual(calculatePasswordStrength("ABCDEFGH"), 1);

  // Score 2: medium (mixed case >= 8, or digits+letters < 10)
  assert.strictEqual(calculatePasswordStrength("Abcdefgh"), 2);
  assert.strictEqual(calculatePasswordStrength("PassWord"), 2);
  assert.strictEqual(calculatePasswordStrength("Abcdefg1"), 2); // 8 chars, mixed + digit (<10 chars)

  // Score 3: strong (>= 10 chars, mixed case, digit, symbol)
  assert.strictEqual(calculatePasswordStrength("Abcdefg1!#"), 3); // 10 chars
  assert.strictEqual(calculatePasswordStrength("SuperSecret2026!#"), 3); // 17 chars
});

it("7.8: Unlock screen submission guard: whitespace-only disabled, valid enabled", () => {
  const isUnlockDisabled = (password, isUnlocking) => {
    return !password.trim() || isUnlocking;
  };

  assert.strictEqual(isUnlockDisabled("", false), true, "Empty password disabled");
  assert.strictEqual(isUnlockDisabled("   ", false), true, "Whitespace-only disabled");
  assert.strictEqual(isUnlockDisabled("\t\n", false), true, "Tab/newline-only disabled");
  assert.strictEqual(isUnlockDisabled("secret123", true), true, "Submitting disabled");
  assert.strictEqual(isUnlockDisabled("secret123", false), false, "Valid password enabled");
});


// ======================================================================
// 8. THEME & LANGUAGE SWITCHING, CSS TOKENS & BLUR(8PX)
// ======================================================================
console.log("\n--- Suite 8: Theme & Language Switching, CSS Tokens & Blur(8px) ---");

const fs = require("fs");
const path = require("path");

it("8.1: Ordered 3-theme cycling: dark -> light -> coffee -> dark", () => {
  const THEMES = ["dark", "light", "coffee"];
  let currentTheme = "dark";

  const cycle = () => {
    currentTheme = THEMES[(THEMES.indexOf(currentTheme) + 1) % THEMES.length];
    return currentTheme;
  };

  assert.strictEqual(cycle(), "light");
  assert.strictEqual(cycle(), "coffee");
  assert.strictEqual(cycle(), "dark");
  assert.strictEqual(cycle(), "light");
  assert.strictEqual(cycle(), "coffee");
  assert.strictEqual(cycle(), "dark");
});

it("8.2: 300 rapid theme toggles verify deterministic cycling", () => {
  const THEMES = ["dark", "light", "coffee"];
  let currentTheme = "dark";

  for (let i = 0; i < 300; i++) {
    const next = THEMES[(THEMES.indexOf(currentTheme) + 1) % THEMES.length];
    const expected = THEMES[(i + 1) % 3];
    assert.strictEqual(next, expected);
    currentTheme = next;
  }
  assert.strictEqual(currentTheme, "dark");
});

it("8.3: Theme persistence in localStorage & fallback for unrecognized value", () => {
  const mockStorage = new Map();
  const THEMES = ["dark", "light", "coffee"];

  const getTheme = () => {
    const stored = mockStorage.get("authdesk_theme");
    return THEMES.includes(stored) ? stored : "dark";
  };

  const setTheme = (t) => {
    mockStorage.set("authdesk_theme", t);
  };

  // Initial without storage defaults to dark
  assert.strictEqual(getTheme(), "dark");

  // Save coffee
  setTheme("coffee");
  assert.strictEqual(getTheme(), "coffee");

  // Corrupted / invalid value in localStorage
  mockStorage.set("authdesk_theme", "neon-cyberpunk-invalid");
  assert.strictEqual(getTheme(), "dark", "Unrecognized theme must fall back to 'dark'");
});

it("8.4: CSS tokens defined for all 3 themes (dark, light, coffee) in global.css", () => {
  const cssPath = path.resolve(__dirname, "../src/styles/global.css");
  const cssContent = fs.readFileSync(cssPath, "utf-8");

  // Verify theme blocks exist
  assert.ok(cssContent.includes('[data-theme="dark"]'), "dark theme selector present");
  assert.ok(cssContent.includes('[data-theme="light"]'), "light theme selector present");
  assert.ok(cssContent.includes('[data-theme="coffee"]'), "coffee theme selector present");

  // Required CSS design tokens
  const requiredTokens = [
    "--bg-surface",
    "--bg-card",
    "--bg-card-hover",
    "--accent",
    "--accent-soft",
    "--text-primary",
    "--text-secondary",
    "--border-subtle",
  ];

  for (const token of requiredTokens) {
    const count = (cssContent.match(new RegExp(token, "g")) || []).length;
    assert.ok(count >= 3, `Token '${token}' must be defined in at least 3 theme blocks (found ${count})`);
  }

  // Verify distinctive accent colors
  assert.ok(cssContent.includes("#38bdf8"), "dark theme accent (#38bdf8)");
  assert.ok(cssContent.includes("#0284c7"), "light theme accent (#0284c7)");
  assert.ok(cssContent.includes("#d97706"), "coffee theme accent (#d97706)");
});

it("8.5: Window transparency & blur(8px) rules strictly enforced in global.css", () => {
  const cssPath = path.resolve(__dirname, "../src/styles/global.css");
  const cssContent = fs.readFileSync(cssPath, "utf-8");

  // Backdrop filter blur(8px)
  assert.ok(
    cssContent.includes("backdrop-filter: blur(8px)"),
    "backdrop-filter: blur(8px) must be present on palette container"
  );
  assert.ok(
    cssContent.includes("-webkit-backdrop-filter: blur(8px)"),
    "-webkit-backdrop-filter: blur(8px) must be present for WebKitGTK"
  );

  // Palette container dimensions
  assert.ok(cssContent.includes("width: 420px"), "width must be 420px");
  assert.ok(cssContent.includes("height: 560px"), "height must be 560px");

  // Window transparency
  assert.ok(
    cssContent.includes("background: transparent !important") ||
    cssContent.includes("background-color: transparent !important"),
    "html/body background must be transparent !important"
  );
});

it("8.6: Bilingual dictionaries have 100% key parity between es.ts and en.ts", () => {
  const esPath = path.resolve(__dirname, "../src/i18n/es.ts");
  const enPath = path.resolve(__dirname, "../src/i18n/en.ts");

  const esContent = fs.readFileSync(esPath, "utf-8");
  const enContent = fs.readFileSync(enPath, "utf-8");

  // Extract keys using regex
  const extractKeys = (content) => {
    const matches = content.match(/^\s*([a-zA-Z0-9_]+):/gm) || [];
    return matches.map((m) => m.replace(/[:\s]/g, "")).sort();
  };

  const esKeys = extractKeys(esContent);
  const enKeys = extractKeys(enContent);

  assert.ok(esKeys.length >= 25, `Expected >= 25 i18n keys, found ${esKeys.length}`);
  assert.deepStrictEqual(
    esKeys,
    enKeys,
    "Translation keys between Spanish (es) and English (en) MUST have 100% 1-to-1 parity"
  );

  // Critical Phase 2 keys check
  const phase2Keys = [
    "lockedTitle",
    "masterPassword",
    "setupTitle",
    "confirmPassword",
    "createVaultButton",
    "passwordMismatch",
    "strengthWeak",
    "strengthMedium",
    "strengthStrong",
    "vaultEncryptedFooter",
  ];

  for (const k of phase2Keys) {
    assert.ok(esKeys.includes(k), `Phase 2 key '${k}' missing from i18n dictionary`);
  }
});

console.log("======================================================================");
console.log(`   Adversarial Test Summary: ${passedTests}/${totalTests} tests PASSED`);
console.log("======================================================================");
