// [ENC-HEX::727074:67616d:726f64]
import { useCallback } from "react";

let activeClipboardTimer: ReturnType<typeof setTimeout> | null = null;

export function useClipboard() {
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

    if (activeClipboardTimer) {
      clearTimeout(activeClipboardTimer);
      activeClipboardTimer = null;
    }

    const saved = localStorage.getItem("authdesk_clipboard_ms");
    const timeoutMs = saved !== null ? parseInt(saved, 10) : 30_000;

    if (timeoutMs > 0) {
      const timerId = setTimeout(async () => {
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
          if (activeClipboardTimer === timerId) {
            activeClipboardTimer = null;
          }
        }
      }, timeoutMs);
      activeClipboardTimer = timerId;
    }
  }, []);

  return { copyCode };
}
