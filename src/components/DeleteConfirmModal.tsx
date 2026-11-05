// [ENC-B64::cnB0|Z2Ft|cm9k]
import React, { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { AccountCodeDto, Language } from "../types";
import { es } from "../i18n/es";
import { en } from "../i18n/en";
import { IconTrash, IconAlertTriangle } from "./Icons";

interface DeleteConfirmModalProps {
  isOpen: boolean;
  account: AccountCodeDto | null;
  lang: Language;
  onClose: () => void;
  onSuccess: () => void;
}

export const DeleteConfirmModal: React.FC<DeleteConfirmModalProps> = ({
  isOpen,
  account,
  lang,
  onClose,
  onSuccess,
}) => {
  const t = lang === "es" ? es : en;
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      setErrorMessage(null);
    }
  }, [isOpen]);

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

  if (!isOpen || !account) return null;

  const handleDelete = async () => {
    setLoading(true);
    setErrorMessage(null);
    try {
      await invoke("delete_account", { accountId: account.id });
      onSuccess();
      onClose();
    } catch (err: unknown) {
      const msg = typeof err === "string" ? err : String(err);
      setErrorMessage(msg);
    } finally {
      setLoading(false);
    }
  };

  const accountDisplayName = `${account.issuer} (${account.account})`;
  const description = t.deleteConfirmDesc.replace("{name}", accountDisplayName);

  return (
    <div
      className="settings-overlay"
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "16px",
      }}
    >
      <div className="modal-dialog-center">
        <div style={{ textAlign: "center" }}>
          <div style={{ color: "#ef4444", marginBottom: "8px", display: "flex", justifyContent: "center" }}>
            <IconTrash size={36} />
          </div>
          <h3
            style={{
              margin: "0 0 8px 0",
              fontSize: "16px",
              fontWeight: 600,
              color: "var(--text-primary)",
            }}
          >
            {t.deleteConfirmTitle}
          </h3>
          <p
            style={{
              margin: 0,
              fontSize: "12.5px",
              lineHeight: 1.5,
              color: "var(--text-secondary)",
            }}
          >
            {description}
          </p>
        </div>

        {errorMessage && (
          <div
            className="error-message"
            style={{
              display: "flex",
              alignItems: "center",
              gap: "8px",
              background: "rgba(239, 68, 68, 0.15)",
              border: "1px solid rgba(239, 68, 68, 0.3)",
              color: "#ef4444",
              padding: "8px 12px",
              borderRadius: "8px",
              fontSize: "12px",
            }}
          >
            <IconAlertTriangle size={16} />
            <span>{errorMessage}</span>
          </div>
        )}

        <div style={{ display: "flex", gap: "10px", marginTop: "6px" }}>
          <button
            type="button"
            onClick={onClose}
            className="header-pill-btn"
            style={{ flex: 1, height: "38px", justifyContent: "center" }}
            disabled={loading}
          >
            {t.cancelButton}
          </button>
          <button
            type="button"
            onClick={handleDelete}
            className="danger-action-btn"
            style={{ flex: 1, padding: "8px" }}
            disabled={loading}
          >
            {t.deleteConfirmButton}
          </button>
        </div>
      </div>
    </div>
  );
};
