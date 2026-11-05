// [ENC-XOR2A::585a5e:4d4b47:58454e]
import React, { useState, useEffect } from "react";
import { SetupVaultView } from "./SetupVaultView";
import { UnlockVaultView } from "./UnlockVaultView";
import { PinKeypadView } from "./PinKeypadView";
import { BrandLogo } from "./BrandLogo";
import { IconMoon, IconSun, IconCoffee } from "./Icons";
import { Language, getTranslation } from "../i18n";
import { ThemeMode } from "../types";

interface LockScreenProps {
  initialized: boolean;
  accountCount: number;
  pinAvailable?: boolean;
  pinEnabled?: boolean;
  pinAttemptsRemaining?: number | null;
  theme: ThemeMode;
  lang: Language;
  onCycleTheme: () => void;
  onToggleLang: () => void;
  onSuccess: () => void;
}

export const LockScreen: React.FC<LockScreenProps> = ({
  initialized,
  accountCount,
  pinAvailable,
  pinEnabled,
  pinAttemptsRemaining,
  theme,
  lang,
  onCycleTheme,
  onToggleLang,
  onSuccess,
}) => {
  const t = getTranslation(lang);
  const canUsePin = Boolean(
    pinAvailable &&
      pinEnabled &&
      (pinAttemptsRemaining === null ||
        pinAttemptsRemaining === undefined ||
        pinAttemptsRemaining > 0)
  );
  const [usePinMode, setUsePinMode] = useState<boolean>(canUsePin);

  useEffect(() => {
    setUsePinMode(canUsePin);
  }, [canUsePin]);

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
      <div className="lock-screen-topbar" data-tauri-drag-region>
        <div className="brand-mark" style={{ display: "flex", alignItems: "center", gap: "8px" }}>
          <BrandLogo size={22} />
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
            {theme === "dark" ? (
              <IconMoon size={18} />
            ) : theme === "light" ? (
              <IconSun size={18} />
            ) : (
              <IconCoffee size={18} />
            )}
          </button>
        </div>
      </div>

      <div className="lock-screen-body">
        {!initialized ? (
          <SetupVaultView lang={lang} onSuccess={onSuccess} />
        ) : usePinMode && canUsePin ? (
          <PinKeypadView
            lang={lang}
            accountCount={accountCount}
            initialAttemptsRemaining={pinAttemptsRemaining ?? null}
            onSuccess={onSuccess}
            onSwitchToPassword={() => setUsePinMode(false)}
          />
        ) : (
          <UnlockVaultView
            lang={lang}
            accountCount={accountCount}
            onSuccess={onSuccess}
            onSwitchToPin={canUsePin ? () => setUsePinMode(true) : undefined}
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
