// [ENC-HEX::727074:67616d:726f64]
import { useEffect, useRef, useCallback } from "react";

interface UseAutoLockOptions {
  enabled: boolean;
  timeoutMs?: number;
  onLock?: () => void;
}

const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;
const THROTTLE_INTERVAL_MS = 1000;

export function useAutoLock({
  enabled,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  onLock,
}: UseAutoLockOptions) {
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastActivityRef = useRef<number>(Date.now());
  const onLockRef = useRef(onLock);
  onLockRef.current = onLock;

  const triggerLock = useCallback(async () => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }

    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("lock_vault");
    } catch {}

    if (onLockRef.current) {
      onLockRef.current();
    }
  }, []);

  const resetTimer = useCallback(() => {
    if (!enabled) return;

    if (timerRef.current) {
      clearTimeout(timerRef.current);
    }

    timerRef.current = setTimeout(() => {
      triggerLock();
    }, timeoutMs);
  }, [enabled, timeoutMs, triggerLock]);

  useEffect(() => {
    if (!enabled) {
      if (timerRef.current) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
      return;
    }

    lastActivityRef.current = Date.now();
    resetTimer();

    const handleActivity = () => {
      const now = Date.now();
      if (now - lastActivityRef.current >= THROTTLE_INTERVAL_MS) {
        lastActivityRef.current = now;
        resetTimer();
      }
    };

    const handleFocusActivity = () => {
      const elapsed = Date.now() - lastActivityRef.current;
      if (elapsed >= timeoutMs) {
        triggerLock();
      } else {
        lastActivityRef.current = Date.now();
        resetTimer();
      }
    };

    const events = ["mousemove", "mousedown", "keydown", "touchstart"] as const;
    events.forEach((ev) => window.addEventListener(ev, handleActivity, { passive: true }));
    window.addEventListener("focus", handleFocusActivity);

    let unlistenTauriFocus: (() => void) | undefined;
    (async () => {
      try {
        const webviewModule = await import("@tauri-apps/api/webviewWindow");
        if (webviewModule.getCurrentWebviewWindow) {
          const win = webviewModule.getCurrentWebviewWindow();
          unlistenTauriFocus = await win.listen("tauri://focus", handleFocusActivity);
        }
      } catch {}
    })();

    return () => {
      if (timerRef.current) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
      events.forEach((ev) => window.removeEventListener(ev, handleActivity));
      window.removeEventListener("focus", handleFocusActivity);
      if (unlistenTauriFocus) {
        unlistenTauriFocus();
      }
    };
  }, [enabled, timeoutMs, resetTimer, triggerLock]);
}
