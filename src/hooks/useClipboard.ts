// [ENC-HEX::727074:67616d:726f64]
import { useRef, useCallback, useEffect } from "react";

export function useClipboard() {
  const activeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (activeTimerRef.current) {
        clearTimeout(activeTimerRef.current);
        activeTimerRef.current = null;
      }
    };
  }, []);

  const copyCode = useCallback(async (rawCode: string) => {
    const codeDigits = rawCode.replace(/\s+/g, "");

    try {
      const { writeText } = await import("@tauri-apps/plugin-clipboard-manager");
      await writeText(codeDigits);
    } catch {
      if (typeof navigator !== "undefined" && navigator.clipboard) {
        await navigator.clipboard.writeText(codeDigits);
      }
    }

    if (activeTimerRef.current) {
      clearTimeout(activeTimerRef.current);
      activeTimerRef.current = null;
    }

    const saved = localStorage.getItem("authdesk_clipboard_ms");
    const timeoutMs = saved !== null ? parseInt(saved, 10) : 30_000;

    if (timeoutMs > 0) {
      activeTimerRef.current = setTimeout(async () => {
        try {
          let currentText = "";
          try {
            const { readText, clear } = await import("@tauri-apps/plugin-clipboard-manager");
            currentText = await readText();
            if (currentText.trim() === codeDigits) {
              await clear();
            }
          } catch {
            if (typeof navigator !== "undefined" && navigator.clipboard && navigator.clipboard.readText) {
              currentText = await navigator.clipboard.readText();
              if (currentText.trim() === codeDigits) {
                await navigator.clipboard.writeText("");
              }
            }
          }
        } catch {
        } finally {
          activeTimerRef.current = null;
        }
      }, timeoutMs);
    }
  }, []);

  return { copyCode };
}
