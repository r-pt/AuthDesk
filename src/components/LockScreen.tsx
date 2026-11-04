// [ENC-XOR2A::585a5e:4d4b47:58454e]
import React, { useEffect } from "react";
import { SetupVaultView } from "./SetupVaultView";
import { UnlockVaultView } from "./UnlockVaultView";
import { Language, getTranslation } from "../i18n";
import { ThemeMode } from "../types";

interface LockScreenProps {
  initialized: boolean;
  accountCount: number;
  theme: ThemeMode;
  lang: Language;
  onCycleTheme: () => void;
  onToggleLang: () => void;
  onSuccess: () => void;
}

export const LockScreen: React.FC<LockScreenProps> = ({
  initialized,
  accountCount,
  theme,
  lang,
  onCycleTheme,
  onToggleLang,
  onSuccess,
}) => {
  const t = getTranslation(lang);

  const hidePaletteWindow = async () => {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("hide_window");
    } catch {
      try {
        const { getCurrentWindow } = await import("@tauri-apps/api/window");
        await getCurrentWindow().hide();
      } catch {}
    }
  };

  useEffect(() => {
    const handleKeyDown = async (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        await hidePaletteWindow();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  return (
    <div className="lock-screen-shell">
      <div className="lock-screen-topbar">
        <div className="brand-mark">
          <span className="brand-dot" />
          <span>AuthDesk</span>
        </div>
        <div className="topbar-actions">
          <button
            type="button"
            className="header-pill-btn"
            onClick={onToggleLang}
            title="Language"
          >
            {lang.toUpperCase()}
          </button>
          <button
            type="button"
            className="theme-toggle"
            onClick={onCycleTheme}
            title={theme}
            aria-label="Theme"
          >
            {theme === "dark" ? "☾" : theme === "light" ? "☀" : "☕"}
          </button>
        </div>
      </div>

      <div className="lock-screen-body">
        {!initialized ? (
          <SetupVaultView lang={lang} onSuccess={onSuccess} />
        ) : (
          <UnlockVaultView
            lang={lang}
            accountCount={accountCount}
            onSuccess={onSuccess}
          />
        )}
      </div>

      <div className="lock-screen-footer">
        <span className="crypto-badge">{t.vaultEncryptedFooter}</span>
        <span className="key-hint-item">
          <span className="key-hint">Esc</span>
          <span>{t.pressEscToHide}</span>
        </span>
      </div>
    </div>
  );
};
