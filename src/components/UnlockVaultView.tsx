// [ENC-ROT13::ecg|tnz|ebq]
import React, { useState, useRef, useEffect } from "react";
import { getTranslation, Language } from "../i18n";
import { BrandLogo } from "./BrandLogo";

interface UnlockVaultViewProps {
  lang: Language;
  accountCount: number;
  onSuccess: () => void;
  onSwitchToPin?: () => void;
}

export const UnlockVaultView: React.FC<UnlockVaultViewProps> = ({
  lang,
  accountCount,
  onSuccess,
  onSwitchToPin,
}) => {
  const [password, setPassword] = useState("");
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [hasError, setHasError] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const t = getTranslation(lang);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleSubmit = async (e: React.SyntheticEvent) => {
    e.preventDefault();
    if (!password || isUnlocking) return;

    setIsUnlocking(true);
    setHasError(false);
    setErrorMessage(null);

    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("unlock_vault", { password });
      onSuccess();
    } catch {
      setHasError(true);
      setErrorMessage(t.invalidPassword);
      setPassword("");
      setIsUnlocking(false);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  };

  return (
    <form
      className={`lock-form-container ${hasError ? "shake-animation" : ""}`}
      onSubmit={handleSubmit}
      onAnimationEnd={() => setHasError(false)}
    >
      <div style={{ display: "flex", justifyContent: "center", marginBottom: "12px" }}>
        <BrandLogo size={48} />
      </div>

      <h2 className="lock-heading">{t.lockedTitle}</h2>
      <div className="account-count-pill">
        {accountCount}{" "}
        {accountCount === 1 ? t.accountProtected : t.accountsProtected}
      </div>

      <div className="form-group" style={{ width: "100%", maxWidth: "300px" }}>
        <input
          ref={inputRef}
          type="password"
          className={`form-input ${hasError ? "input-invalid" : ""}`}
          value={password}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
            setPassword(e.target.value);
            if (hasError) setHasError(false);
            if (errorMessage) setErrorMessage(null);
          }}
          disabled={isUnlocking}
          placeholder={t.masterPassword}
        />
      </div>

      {errorMessage && <div className="form-error-feedback">{errorMessage}</div>}

      <button
        type="submit"
        className="primary-action-btn"
        disabled={!password.trim() || isUnlocking}
      >
        {isUnlocking ? t.unlocking : t.unlockButton}
      </button>

      {onSwitchToPin && (
        <button
          type="button"
          className="switch-mode-btn"
          onClick={onSwitchToPin}
        >
          {t.usePin}
        </button>
      )}
    </form>
  );
};
