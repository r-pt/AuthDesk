// [ENC-B64::cnB0|Z2Ft|cm9k]
import React, { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { AccountCodeDto, Language } from "../types";
import { es } from "../i18n/es";
import { en } from "../i18n/en";
import { validateBase32 } from "../utils/base32";
import { IconClose, IconEye, IconEyeOff, IconArrowDown, IconArrowUp } from "./Icons";

interface AccountFormModalProps {
  isOpen: boolean;
  mode: "add" | "edit";
  account: AccountCodeDto | null;
  existingAccounts: AccountCodeDto[];
  lang: Language;
  onClose: () => void;
  onSuccess: () => void;
}

export const AccountFormModal: React.FC<AccountFormModalProps> = ({
  isOpen,
  mode,
  account,
  existingAccounts,
  lang,
  onClose,
  onSuccess,
}) => {
  const t = lang === "es" ? es : en;

  const [issuer, setIssuer] = useState("");
  const [accountName, setAccountName] = useState("");
  const [secret, setSecret] = useState("");
  const [showSecret, setShowSecret] = useState(false);
  const [algorithm, setAlgorithm] = useState("SHA1");
  const [digits, setDigits] = useState(6);
  const [period, setPeriod] = useState(30);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      setErrorMessage(null);
      if (mode === "edit" && account) {
        setIssuer(account.issuer);
        setAccountName(account.account);
        setSecret("");
        setAlgorithm(account.algorithm || "SHA1");
        setDigits(account.digits || 6);
        setPeriod(account.period || 30);
        setShowAdvanced(
          (account.algorithm && account.algorithm !== "SHA1") ||
            account.digits !== 6 ||
            account.period !== 30
        );
      } else {
        setIssuer("");
        setAccountName("");
        setSecret("");
        setAlgorithm("SHA1");
        setDigits(6);
        setPeriod(30);
        setShowAdvanced(false);
      }
    }
  }, [isOpen, mode, account]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (!isOpen) return;
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const isDuplicatePreCheck = existingAccounts.some(
    (a) =>
      (mode === "add" || a.id !== account?.id) &&
      a.issuer.trim().toLowerCase() === issuer.trim().toLowerCase() &&
      a.account.trim().toLowerCase() === accountName.trim().toLowerCase() &&
      issuer.trim().length > 0 &&
      accountName.trim().length > 0
  );

  const base32Check = validateBase32(secret);
  const hasSecretInput = secret.trim().length > 0;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    if (!issuer.trim()) {
      setErrorMessage(t.issuerRequired);
      return;
    }
    if (!accountName.trim()) {
      setErrorMessage(t.accountRequired);
      return;
    }

    if (mode === "add") {
      if (!secret.trim()) {
        setErrorMessage(t.secretRequired);
        return;
      }
      if (!base32Check.valid) {
        if (base32Check.error === "invalid_char") {
          setErrorMessage(
            `${t.base32InvalidCharDetected} ${base32Check.invalidChar}`
          );
        } else {
          setErrorMessage(t.base32InvalidChars);
        }
        return;
      }
    } else if (hasSecretInput && !base32Check.valid) {
      if (base32Check.error === "invalid_char") {
        setErrorMessage(
          `${t.base32InvalidCharDetected} ${base32Check.invalidChar}`
        );
      } else {
        setErrorMessage(t.base32InvalidChars);
      }
      return;
    }

    setLoading(true);
    try {
      if (mode === "add") {
        await invoke("add_account", {
          req: {
            issuer: issuer.trim(),
            account: accountName.trim(),
            secret: secret.trim(),
            algorithm,
            digits: Number(digits),
            period: Number(period),
          },
        });
      } else if (account) {
        await invoke("update_account", {
          req: {
            id: account.id,
            issuer: issuer.trim(),
            account: accountName.trim(),
            secret: hasSecretInput ? secret.trim() : null,
            algorithm,
            digits: Number(digits),
            period: Number(period),
          },
        });
      }
      onSuccess();
      onClose();
    } catch (err: unknown) {
      const msg = typeof err === "string" ? err : String(err);
      if (
        msg.toLowerCase().includes("duplicad") ||
        msg.toLowerCase().includes("duplicate")
      ) {
        setErrorMessage(t.duplicateAccountError);
      } else {
        setErrorMessage(msg);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="settings-overlay">
      <div className="settings-header">
        <span style={{ fontWeight: 600, fontSize: "14px" }}>
          {mode === "add" ? t.addAccountTitle : t.editAccountTitle}
        </span>
        <button
          type="button"
          onClick={onClose}
          className="theme-toggle"
          title={t.closeButton}
          aria-label={t.closeButton}
        >
          <IconClose size={16} />
        </button>
      </div>

      <div className="settings-body">
        <form
          onSubmit={handleSubmit}
          style={{ display: "flex", flexDirection: "column", gap: "12px" }}
        >
          {errorMessage && (
            <div
              className="error-message"
              style={{
                background: "rgba(239, 68, 68, 0.15)",
                border: "1px solid rgba(239, 68, 68, 0.3)",
                color: "#ef4444",
                padding: "8px 12px",
                borderRadius: "8px",
                fontSize: "12px",
              }}
            >
              {errorMessage}
            </div>
          )}

          {isDuplicatePreCheck && (
            <div className="duplicate-warning-box">
              {t.duplicateAccountWarning}
            </div>
          )}

          <div className="form-field-row">
            <label className="form-label">{t.issuerLabel}</label>
            <input
              type="text"
              className="form-input"
              value={issuer}
              onChange={(e) => setIssuer(e.target.value)}
              placeholder={t.issuerPlaceholder}
              autoFocus
              disabled={loading}
            />
          </div>

          <div className="form-field-row">
            <label className="form-label">{t.accountLabel}</label>
            <input
              type="text"
              className="form-input"
              value={accountName}
              onChange={(e) => setAccountName(e.target.value)}
              placeholder={t.accountPlaceholder}
              disabled={loading}
            />
          </div>

          <div className="form-field-row">
            <label className="form-label">{t.secretLabel}</label>
            <div style={{ position: "relative" }}>
              <input
                type={showSecret ? "text" : "password"}
                className="form-input"
                style={{ paddingRight: "36px" }}
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                placeholder={
                  mode === "edit"
                    ? t.secretEditPlaceholder
                    : t.secretPlaceholder
                }
                disabled={loading}
              />
              <button
                type="button"
                onClick={() => setShowSecret(!showSecret)}
                style={{
                  position: "absolute",
                  right: "8px",
                  top: "50%",
                  transform: "translateY(-50%)",
                  background: "none",
                  border: "none",
                  cursor: "pointer",
                  color: "var(--text-secondary)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  padding: "4px",
                }}
                aria-label="Toggle secret visibility"
              >
                {showSecret ? <IconEyeOff size={16} /> : <IconEye size={16} />}
              </button>
            </div>
            {hasSecretInput && (
              <div
                className={`base32-feedback ${
                  base32Check.valid ? "valid" : "invalid"
                }`}
              >
                {base32Check.valid
                  ? t.base32Valid
                  : base32Check.invalidChar
                  ? `${t.base32InvalidCharDetected} '${base32Check.invalidChar}'`
                  : t.base32InvalidChars}
              </div>
            )}
          </div>

          <div>
            <button
              type="button"
              className="advanced-toggle-btn"
              onClick={() => setShowAdvanced(!showAdvanced)}
            >
              <span>{showAdvanced ? <IconArrowUp size={12} /> : <IconArrowDown size={12} />}</span>
              <span>{t.advancedOptions}</span>
            </button>

            {showAdvanced && (
              <div
                className="settings-card"
                style={{ marginTop: "8px", padding: "10px" }}
              >
                <div className="advanced-grid">
                  <div className="form-field-row">
                    <label className="form-label">{t.algorithmLabel}</label>
                    <select
                      className="form-select"
                      value={algorithm}
                      onChange={(e) => setAlgorithm(e.target.value)}
                      disabled={loading}
                    >
                      <option value="SHA1">SHA1 ({t.defaultLabel})</option>
                      <option value="SHA256">SHA256</option>
                      <option value="SHA512">SHA512</option>
                    </select>
                  </div>

                  <div className="form-field-row">
                    <label className="form-label">{t.digitsLabel}</label>
                    <select
                      className="form-select"
                      value={digits}
                      onChange={(e) => setDigits(Number(e.target.value))}
                      disabled={loading}
                    >
                      <option value={6}>6 ({t.defaultLabel})</option>
                      <option value={8}>8</option>
                    </select>
                  </div>
                </div>

                <div className="form-field-row" style={{ marginTop: "6px" }}>
                  <label className="form-label">{t.periodLabel}</label>
                  <input
                    type="number"
                    className="form-input"
                    value={period}
                    min={5}
                    max={300}
                    step={5}
                    onChange={(e) => setPeriod(Number(e.target.value))}
                    disabled={loading}
                  />
                </div>
              </div>
            )}
          </div>

          <div
            style={{
              display: "flex",
              gap: "10px",
              marginTop: "8px",
              justifyContent: "flex-end",
            }}
          >
            <button
              type="button"
              onClick={onClose}
              className="header-pill-btn"
              style={{ padding: "8px 14px", height: "auto" }}
              disabled={loading}
            >
              {t.cancelButton}
            </button>
            <button
              type="submit"
              className="primary-action-btn"
              style={{ width: "auto", padding: "8px 18px" }}
              disabled={loading}
            >
              {loading ? t.savingAccount : t.saveAccountButton}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
