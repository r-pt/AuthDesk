// [ENC-B64::cnB0|Z2Ft|cm9k]
import React, { useState, useEffect, useCallback } from "react";
import { getTranslation, Language } from "../i18n";
import { BrandLogo } from "./BrandLogo";

interface PinKeypadViewProps {
  lang: Language;
  accountCount: number;
  initialAttemptsRemaining: number | null;
  onSuccess: () => void;
  onSwitchToPassword: () => void;
}

export const PinKeypadView: React.FC<PinKeypadViewProps> = ({
  lang,
  accountCount,
  initialAttemptsRemaining,
  onSuccess,
  onSwitchToPassword,
}) => {
  const [pin, setPin] = useState("");
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [hasError, setHasError] = useState(false);
  const [attemptsRemaining, setAttemptsRemaining] = useState<number | null>(
    initialAttemptsRemaining
  );
  const t = getTranslation(lang);

  const submitPin = useCallback(
    async (pinToSubmit: string) => {
      if (isUnlocking) return;
      setIsUnlocking(true);
      setHasError(false);

      try {
        const { invoke } = await import("@tauri-apps/api/core");
        await invoke("unlock_with_pin", { pin: pinToSubmit });
        onSuccess();
      } catch {
        setHasError(true);
        setPin("");
        setIsUnlocking(false);

        try {
          const { invoke } = await import("@tauri-apps/api/core");
          const status = await invoke<{
            pin_attempts_remaining: number | null;
            pin_enabled: boolean;
          }>("get_vault_status");
          setAttemptsRemaining(status.pin_attempts_remaining);
          if (!status.pin_enabled || status.pin_attempts_remaining === 0) {
            onSwitchToPassword();
          }
        } catch {}
      }
    },
    [isUnlocking, onSuccess, onSwitchToPassword]
  );

  const handleDigit = useCallback(
    (digit: string) => {
      if (isUnlocking || pin.length >= 6) return;
      const next = pin + digit;
      setPin(next);
      if (next.length === 6) {
        submitPin(next);
      }
    },
    [isUnlocking, pin, submitPin]
  );

  const handleBackspace = useCallback(() => {
    if (isUnlocking || pin.length === 0) return;
    setPin((prev) => prev.slice(0, -1));
  }, [isUnlocking]);

  const handleHide = useCallback(async () => {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("hide_window");
    } catch {}
  }, []);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key >= "0" && e.key <= "9") {
        e.preventDefault();
        handleDigit(e.key);
      } else if (e.key === "Backspace") {
        e.preventDefault();
        handleBackspace();
      } else if (e.key === "Escape") {
        e.preventDefault();
        handleHide();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [handleDigit, handleBackspace, handleHide]);

  return (
    <div
      className={`lock-form-container ${hasError ? "shake-animation" : ""}`}
      onAnimationEnd={() => setHasError(false)}
    >
      <div style={{ display: "flex", justifyContent: "center", marginBottom: "12px" }}>
        <BrandLogo size={48} />
      </div>

      <h2 className="lock-heading">{t.lockedTitle}</h2>
      <div className="account-count-pill">
        {accountCount} {accountCount === 1 ? t.accountProtected : t.accountsProtected}
      </div>

      <div className="pin-dots-row">
        {[0, 1, 2, 3, 4, 5].map((idx) => {
          const isFilled = idx < pin.length;
          return (
            <div
              key={idx}
              className={`pin-dot ${isFilled ? "filled" : ""} ${hasError ? "error" : ""}`}
            />
          );
        })}
      </div>

      {attemptsRemaining !== null && attemptsRemaining < 5 && (
        <div className="attempts-warning-pill">
          <span>
            {t.pinAttemptsRemaining} {attemptsRemaining} / 5
          </span>
        </div>
      )}

      <div className="pin-keypad-grid">
        {["1", "2", "3", "4", "5", "6", "7", "8", "9"].map((num) => (
          <button
            key={num}
            type="button"
            className="pin-key-btn"
            disabled={isUnlocking}
            onClick={() => handleDigit(num)}
          >
            {num}
          </button>
        ))}
        <div className="pin-key-btn empty-btn" />
        <button
          type="button"
          className="pin-key-btn"
          disabled={isUnlocking}
          onClick={() => handleDigit("0")}
        >
          0
        </button>
        <button
          type="button"
          className="pin-key-btn backspace-btn"
          disabled={isUnlocking || pin.length === 0}
          onClick={handleBackspace}
          aria-label="Borrar"
        >
          ⌫
        </button>
      </div>

      <button
        type="button"
        className="switch-mode-btn"
        onClick={onSwitchToPassword}
      >
        {t.usePassword}
      </button>
    </div>
  );
};
