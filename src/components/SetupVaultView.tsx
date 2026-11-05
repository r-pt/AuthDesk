// [ENC-B64::cnB0|Z2Ft|cm9k]
import React, { useState, useMemo, useRef, useEffect } from "react";
import { getTranslation, Language } from "../i18n";
import { BrandLogo } from "./BrandLogo";

interface SetupVaultViewProps {
  lang: Language;
  onSuccess: () => void;
}

export const SetupVaultView: React.FC<SetupVaultViewProps> = ({ lang, onSuccess }) => {
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const passwordInputRef = useRef<HTMLInputElement>(null);

  const t = getTranslation(lang);

  useEffect(() => {
    passwordInputRef.current?.focus();
  }, []);

  const strength = useMemo(() => {
    if (!password) return 0;
    if (password.length < 8) return 1;
    let score = 1;
    if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++;
    if (/\d/.test(password) && /[^A-Za-z0-9]/.test(password) && password.length >= 10) score++;
    return score;
  }, [password]);

  const passwordsMatch = password.length > 0 && password === confirmPassword;
  const canSubmit = password.length >= 8 && passwordsMatch && !isSubmitting;

  const handleSubmit = async (e: React.SyntheticEvent) => {
    e.preventDefault();
    if (!canSubmit) return;

    setIsSubmitting(true);
    setErrorMessage(null);

    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("init_vault", { password });
      onSuccess();
    } catch (err: unknown) {
      setErrorMessage(typeof err === "string" ? err : t.initVaultError);
      setIsSubmitting(false);
    }
  };

  return (
    <form className="lock-form-container" onSubmit={handleSubmit}>
      <div style={{ display: "flex", justifyContent: "center", marginBottom: "12px" }}>
        <BrandLogo size={48} />
      </div>

      <h2 className="lock-heading">{t.setupTitle}</h2>
      <p className="lock-subheading">{t.setupSubtitle}</p>

      <div className="form-group">
        <label className="form-label">{t.masterPassword}</label>
        <input
          ref={passwordInputRef}
          type="password"
          className="form-input"
          value={password}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
            setPassword(e.target.value);
            setErrorMessage(null);
          }}
          disabled={isSubmitting}
          placeholder="••••••••••••"
        />
        {password.length > 0 && (
          <div className="strength-bar-track">
            <div className={`strength-segment ${strength >= 1 ? "active-weak" : ""}`} />
            <div className={`strength-segment ${strength >= 2 ? "active-medium" : ""}`} />
            <div className={`strength-segment ${strength >= 3 ? "active-strong" : ""}`} />
            <span className="strength-label">
              {strength === 1 ? t.strengthWeak : strength === 2 ? t.strengthMedium : t.strengthStrong}
            </span>
          </div>
        )}
      </div>

      <div className="form-group">
        <label className="form-label">{t.confirmPassword}</label>
        <input
          type="password"
          className={`form-input ${confirmPassword && !passwordsMatch ? "input-invalid" : ""}`}
          value={confirmPassword}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => {
            setConfirmPassword(e.target.value);
            setErrorMessage(null);
          }}
          disabled={isSubmitting}
          placeholder="••••••••••••"
        />
        {confirmPassword.length > 0 && !passwordsMatch && (
          <span className="form-hint error-hint">{t.passwordMismatch}</span>
        )}
      </div>

      {errorMessage && <div className="form-error-banner">{errorMessage}</div>}

      <button type="submit" className="primary-action-btn" disabled={!canSubmit}>
        {isSubmitting ? t.creatingVault : t.createVaultButton}
      </button>
    </form>
  );
};
