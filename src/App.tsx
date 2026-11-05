// [ENC-HEX::727074:67616d:726f64]
import React, { useState, useEffect, useCallback } from "react";
import { PaletteView } from "./components/PaletteView";
import { LockScreen } from "./components/LockScreen";
import { useAutoLock } from "./hooks/useAutoLock";
import { VaultStatusDto, ThemeMode, Language } from "./types";
import "./styles/global.css";

const THEMES: ThemeMode[] = ["dark", "light", "coffee"];

export const App: React.FC = () => {
  const [theme, setTheme] = useState<ThemeMode>(() => {
    return (localStorage.getItem("authdesk_theme") as ThemeMode) || "dark";
  });
  const [lang, setLang] = useState<Language>(() => {
    return (localStorage.getItem("authdesk_lang") as Language) || "es";
  });
  const [vaultStatus, setVaultStatus] = useState<VaultStatusDto | null>(null);
  const [loading, setLoading] = useState(true);

  const cycleTheme = useCallback(() => {
    setTheme((prev) => {
      const next = THEMES[(THEMES.indexOf(prev) + 1) % THEMES.length];
      localStorage.setItem("authdesk_theme", next);
      return next;
    });
  }, []);

  const toggleLang = useCallback(() => {
    setLang((prev) => {
      const next = prev === "es" ? "en" : "es";
      localStorage.setItem("authdesk_lang", next);
      return next;
    });
  }, []);

  const refreshVaultStatus = useCallback(async () => {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const status = await invoke<VaultStatusDto>("get_vault_status");
      setVaultStatus(status);
    } catch {
      setVaultStatus({
        initialized: false,
        locked: true,
        account_count: 0,
        pin_available: false,
        pin_enabled: false,
        pin_attempts_remaining: null,
      });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshVaultStatus();

    window.addEventListener("focus", refreshVaultStatus);

    let unlistenFocus: (() => void) | undefined;
    let unlistenStatus: (() => void) | undefined;

    (async () => {
      try {
        const webviewModule = await import("@tauri-apps/api/webviewWindow");
        if (webviewModule.getCurrentWebviewWindow) {
          const win = webviewModule.getCurrentWebviewWindow();
          unlistenFocus = await win.listen("tauri://focus", refreshVaultStatus);
          unlistenStatus = await win.listen("vault-status-changed", refreshVaultStatus);
        }
      } catch {}
    })();

    return () => {
      window.removeEventListener("focus", refreshVaultStatus);
      if (unlistenFocus) unlistenFocus();
      if (unlistenStatus) unlistenStatus();
    };
  }, [refreshVaultStatus]);

  const isUnlocked = Boolean(vaultStatus?.initialized && !vaultStatus?.locked);

  useAutoLock({
    enabled: isUnlocked,
    timeoutMs: 5 * 60 * 1000,
    onLock: () => {
      setVaultStatus((prev) => (prev ? { ...prev, locked: true } : null));
    },
  });

  const handleVaultUnlocked = useCallback(() => {
    refreshVaultStatus();
  }, [refreshVaultStatus]);

  const handleManualLock = useCallback(async () => {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("lock_vault");
    } catch {}
    setVaultStatus((prev) => (prev ? { ...prev, locked: true } : null));
  }, []);

  return (
    <div className="palette-container" data-theme={theme}>
      {loading ? (
        <div className="skeleton-loading-view">
          <div className="skeleton-spinner" />
        </div>
      ) : !vaultStatus?.initialized || vaultStatus.locked ? (
        <LockScreen
          initialized={vaultStatus?.initialized ?? false}
          accountCount={vaultStatus?.account_count ?? 0}
          pinAvailable={vaultStatus?.pin_available ?? false}
          pinEnabled={vaultStatus?.pin_enabled ?? false}
          pinAttemptsRemaining={vaultStatus?.pin_attempts_remaining ?? null}
          theme={theme}
          lang={lang}
          onCycleTheme={cycleTheme}
          onToggleLang={toggleLang}
          onSuccess={handleVaultUnlocked}
        />
      ) : (
        <PaletteView
          theme={theme}
          lang={lang}
          pinAvailable={vaultStatus?.pin_available ?? false}
          pinEnabled={vaultStatus?.pin_enabled ?? false}
          onCycleTheme={cycleTheme}
          onLock={handleManualLock}
          onVaultStatusChanged={refreshVaultStatus}
        />
      )}
    </div>

  );
};

export default App;
