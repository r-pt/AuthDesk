// [ENC-ROT13::ecg|tnz|ebq]
import React, { useState, useEffect, useRef, useMemo } from "react";
import { useTotpCodes } from "../hooks/useTotpCodes";
import { useClipboard } from "../hooks/useClipboard";
import { AccountItem } from "./AccountItem";
import { AccountFormModal } from "./AccountFormModal";
import { DeleteConfirmModal } from "./DeleteConfirmModal";
import { BrandLogo } from "./BrandLogo";
import {
  IconEye,
  IconEyeOff,
  IconPlus,
  IconLock,
  IconSettings,
  IconMoon,
  IconSun,
  IconCoffee,
  IconClose,
} from "./Icons";
import { getTranslation, Language } from "../i18n";
import { ThemeMode, AccountCodeDto } from "../types";

export interface PaletteViewProps {
  theme?: ThemeMode;
  lang?: Language;
  pinAvailable?: boolean;
  pinEnabled?: boolean;
  onCycleTheme?: () => void;
  onLock?: () => void;
  onVaultStatusChanged?: () => void;
}

export const PaletteView: React.FC<PaletteViewProps> = ({
  theme: propTheme,
  lang: propLang,
  pinAvailable,
  pinEnabled,
  onCycleTheme,
  onLock,
  onVaultStatusChanged,
}) => {
  const [internalLang] = useState<Language>("es");
  const [internalTheme, setInternalTheme] = useState<ThemeMode>("dark");
  const lang = propLang ?? internalLang;
  const theme = propTheme ?? internalTheme;

  const [searchQuery, setSearchQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [showSettings, setShowSettings] = useState(false);
  const [shortcutEnabled, setShortcutEnabled] = useState<boolean>(() => {
    const saved = localStorage.getItem("authdesk_global_shortcut");
    return saved !== null ? saved === "true" : true;
  });
  const [maskCodes, setMaskCodes] = useState<boolean>(() => {
    return localStorage.getItem("authdesk_mask_codes") === "true";
  });

  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [editingAccount, setEditingAccount] = useState<AccountCodeDto | null>(null);
  const [deletingAccount, setDeletingAccount] = useState<AccountCodeDto | null>(null);

  const [configuringPin, setConfiguringPin] = useState(false);
  const [newPin, setNewPin] = useState("");
  const [confirmPin, setConfirmPin] = useState("");
  const [pinFeedback, setPinFeedback] = useState<string | null>(null);
  const [isSavingPin, setIsSavingPin] = useState(false);

  const searchInputRef = useRef<HTMLInputElement>(null);
  const listContainerRef = useRef<HTMLDivElement>(null);

  const t = getTranslation(lang);
  const { accounts, refresh } = useTotpCodes();
  const { copyCode } = useClipboard();

  const toggleMaskCodes = () => {
    setMaskCodes((prev) => {
      const next = !prev;
      localStorage.setItem("authdesk_mask_codes", String(next));
      return next;
    });
  };

  const cycleTheme = () => {
    if (onCycleTheme) {
      onCycleTheme();
    } else {
      const themes: ThemeMode[] = ["dark", "light", "coffee"];
      setInternalTheme((prev) => themes[(themes.indexOf(prev) + 1) % themes.length]);
    }
  };

  const filteredAccounts = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return accounts;
    return accounts.filter(
      (acc) =>
        acc.issuer.toLowerCase().includes(q) ||
        acc.account.toLowerCase().includes(q)
    );
  }, [accounts, searchQuery]);

  useEffect(() => {
    setSelectedIndex(0);
  }, [searchQuery]);

  useEffect(() => {
    const handleFocus = () => {
      setSearchQuery("");
      setSelectedIndex(0);
      setShowSettings(false);
      setIsAddModalOpen(false);
      setEditingAccount(null);
      setDeletingAccount(null);
      setConfiguringPin(false);
      searchInputRef.current?.focus();
    };

    window.addEventListener("focus", handleFocus);
    return () => window.removeEventListener("focus", handleFocus);
  }, []);

  const copyAndHide = async (code: string) => {
    if (!code) {
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        await invoke("hide_window");
      } catch {
        try {
          const { getCurrentWindow } = await import("@tauri-apps/api/window");
          await getCurrentWindow().hide();
        } catch {}
      }
      return;
    }

    await copyCode(code);
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

  const isModalActive =
    showSettings ||
    isAddModalOpen ||
    editingAccount !== null ||
    deletingAccount !== null;

  const handleMoveAccount = async (fromIndex: number, toIndex: number) => {
    if (searchQuery.trim()) return;
    if (
      fromIndex < 0 ||
      toIndex < 0 ||
      fromIndex >= accounts.length ||
      toIndex >= accounts.length
    )
      return;

    const updated = [...accounts];
    const [moved] = updated.splice(fromIndex, 1);
    updated.splice(toIndex, 0, moved);
    setSelectedIndex(toIndex);

    const accountIds = updated.map((a) => a.id);
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("reorder_accounts", { accountIds });
      await refresh();
    } catch (err) {
      console.error("Failed to reorder accounts", err);
    }
  };

  useEffect(() => {
    const handleKeyDown = async (e: KeyboardEvent) => {
      if (isModalActive) {
        return;
      }

      if (e.altKey && e.key === "ArrowUp") {
        e.preventDefault();
        if (!searchQuery.trim() && selectedIndex > 0) {
          handleMoveAccount(selectedIndex, selectedIndex - 1);
        }
        return;
      }

      if (e.altKey && e.key === "ArrowDown") {
        e.preventDefault();
        if (!searchQuery.trim() && selectedIndex < filteredAccounts.length - 1) {
          handleMoveAccount(selectedIndex, selectedIndex + 1);
        }
        return;
      }

      if (e.key === "Escape") {
        e.preventDefault();
        await copyAndHide("");
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        setSelectedIndex((prev) =>
          filteredAccounts.length > 0 ? (prev + 1) % filteredAccounts.length : 0
        );
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setSelectedIndex((prev) =>
          filteredAccounts.length > 0
            ? (prev - 1 + filteredAccounts.length) % filteredAccounts.length
            : 0
        );
      } else if (e.key === "Enter") {
        e.preventDefault();
        if (filteredAccounts[selectedIndex]) {
          await copyAndHide(filteredAccounts[selectedIndex].code);
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [filteredAccounts, selectedIndex, isModalActive, searchQuery, accounts]);

  useEffect(() => {
    if (!listContainerRef.current) return;
    const items = listContainerRef.current.querySelectorAll(".account-item");
    const activeItem = items[selectedIndex] as HTMLElement | undefined;
    if (activeItem) {
      activeItem.scrollIntoView({ block: "nearest" });
    }
  }, [selectedIndex]);

  const handleSavePin = async (e: React.SyntheticEvent) => {
    e.preventDefault();
    if (newPin.length !== 6 || !/^\d{6}$/.test(newPin)) {
      setPinFeedback(t.pinMustBe6Digits);
      return;
    }
    if (newPin !== confirmPin) {
      setPinFeedback(t.pinMismatch);
      return;
    }
    setIsSavingPin(true);
    setPinFeedback(null);
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("set_pin", { pin: newPin });
      setNewPin("");
      setConfirmPin("");
      setConfiguringPin(false);
      setPinFeedback(t.pinSavedSuccess);
      if (onVaultStatusChanged) onVaultStatusChanged();
    } catch (err) {
      setPinFeedback(String(err));
    } finally {
      setIsSavingPin(false);
    }
  };

  const handleToggleShortcut = async () => {
    const nextState = !shortcutEnabled;
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("toggle_global_shortcut", { enabled: nextState });
      setShortcutEnabled(nextState);
      localStorage.setItem("authdesk_global_shortcut", String(nextState));
    } catch (err) {
      console.error("Failed to toggle global shortcut:", err);
    }
  };

  const handleDisablePin = async () => {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("disable_pin");
      setConfiguringPin(false);
      setNewPin("");
      setConfirmPin("");
      setPinFeedback(t.pinDisabledSuccess);
      if (onVaultStatusChanged) onVaultStatusChanged();
    } catch (err) {
      setPinFeedback(String(err));
    }
  };

  return (
    <div
      className={propTheme !== undefined ? "palette-view-shell" : "palette-container"}
      data-theme={propTheme !== undefined ? undefined : theme}
    >
      <div className="search-header" data-tauri-drag-region>
        <BrandLogo size={26} />
        <input
          ref={searchInputRef}
          type="text"
          className="search-input"
          placeholder={t.searchPlaceholder}
          value={searchQuery}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchQuery(e.target.value)}
        />
        <button
          type="button"
          className="theme-toggle"
          onClick={toggleMaskCodes}
          title={maskCodes ? t.showCodes : t.hideCodes}
          aria-label="Toggle code masking"
        >
          {maskCodes ? <IconEyeOff size={18} /> : <IconEye size={18} />}
        </button>
        <button
          type="button"
          className="theme-toggle"
          onClick={() => setIsAddModalOpen(true)}
          title={t.addAccount}
          aria-label="Add account"
        >
          <IconPlus size={18} />
        </button>
        {onLock && (
          <button
            type="button"
            className="theme-toggle"
            onClick={onLock}
            title={t.trayLock}
            aria-label="Lock"
          >
            <IconLock size={18} />
          </button>
        )}
        <button
          type="button"
          className="theme-toggle"
          onClick={() => setShowSettings((prev) => !prev)}
          title={t.settingsTitle}
          aria-label="Settings"
        >
          <IconSettings size={18} />
        </button>
        <button
          type="button"
          className="theme-toggle"
          onClick={cycleTheme}
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

      <div className="account-list" ref={listContainerRef}>
        {filteredAccounts.length === 0 ? (
          <div
            style={{
              textAlign: "center",
              padding: "32px 16px",
              color: "var(--text-secondary)",
              fontSize: "13px",
            }}
          >
            {t.emptyAccounts}
          </div>
        ) : (
          filteredAccounts.map((acc, index) => (
            <AccountItem
              key={acc.id}
              account={acc}
              isSelected={index === selectedIndex}
              maskCodes={maskCodes}
              isFirst={index === 0}
              isLast={index === filteredAccounts.length - 1}
              canReorder={!searchQuery.trim()}
              onSelect={() => setSelectedIndex(index)}
              onCopy={() => copyAndHide(acc.code)}
              onEdit={() => setEditingAccount(acc)}
              onDelete={() => setDeletingAccount(acc)}
              onMoveUp={() => handleMoveAccount(index, index - 1)}
              onMoveDown={() => handleMoveAccount(index, index + 1)}
            />
          ))
        )}
      </div>

      <div className="palette-footer">
        <div>
          <span className="key-hint">↵</span>
          <span>{t.pressEnterToCopy}</span>
        </div>
        <div>
          <span className="key-hint">Esc</span>
          <span>{t.pressEscToHide}</span>
        </div>
      </div>

      {showSettings && (
        <div className="settings-overlay">
          <div className="settings-header">
            <div className="brand-mark" style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <BrandLogo size={20} />
              <span>{t.settingsTitle}</span>
            </div>
            <button
              type="button"
              className="theme-toggle"
              onClick={() => {
                setShowSettings(false);
                setConfiguringPin(false);
                setPinFeedback(null);
              }}
              title={t.closeButton}
              aria-label={t.closeButton}
            >
              <IconClose size={16} />
            </button>
          </div>
          <div className="settings-body">
            <div className="settings-card">
              <div style={{ fontWeight: 600, fontSize: "13px" }}>{t.pinSettingsTitle}</div>
              {!pinAvailable ? (
                <div className="form-hint" style={{ color: "var(--text-secondary)" }}>
                  {t.pinNotAvailable}
                </div>
              ) : pinEnabled ? (
                <>
                  <div style={{ fontSize: "12px", color: "var(--text-secondary)" }}>
                    {t.pinEnabledDesc}
                  </div>
                  <div style={{ display: "flex", gap: "8px", marginTop: "6px" }}>
                    <button
                      type="button"
                      className="header-pill-btn"
                      onClick={() => setConfiguringPin(true)}
                    >
                      {t.changePinButton}
                    </button>
                    <button
                      type="button"
                      className="header-pill-btn"
                      style={{ color: "#ef4444" }}
                      onClick={handleDisablePin}
                    >
                      {t.disablePinButton}
                    </button>
                  </div>
                </>
              ) : (
                <>
                  <div style={{ fontSize: "12px", color: "var(--text-secondary)" }}>
                    {t.pinDisabledDesc}
                  </div>
                  <div style={{ marginTop: "6px" }}>
                    <button
                      type="button"
                      className="primary-action-btn"
                      style={{ width: "auto", padding: "8px 14px", fontSize: "12px" }}
                      onClick={() => setConfiguringPin(true)}
                    >
                      {t.setupPinButton}
                    </button>
                  </div>
                </>
              )}

              {configuringPin && (
                <form
                  onSubmit={handleSavePin}
                  style={{ display: "flex", flexDirection: "column", gap: "8px", marginTop: "8px" }}
                >
                  <input
                    type="password"
                    inputMode="numeric"
                    maxLength={6}
                    className="form-input"
                    placeholder={t.newPinPlaceholder}
                    value={newPin}
                    onChange={(e) => setNewPin(e.target.value.replace(/\D/g, "").slice(0, 6))}
                    autoFocus
                  />
                  <input
                    type="password"
                    inputMode="numeric"
                    maxLength={6}
                    className="form-input"
                    placeholder={t.confirmPinPlaceholder}
                    value={confirmPin}
                    onChange={(e) => setConfirmPin(e.target.value.replace(/\D/g, "").slice(0, 6))}
                  />
                  <div style={{ display: "flex", gap: "8px" }}>
                    <button
                      type="submit"
                      className="primary-action-btn"
                      disabled={isSavingPin || newPin.length !== 6 || confirmPin.length !== 6}
                    >
                      {isSavingPin ? "..." : t.savePinButton}
                    </button>
                    <button
                      type="button"
                      className="header-pill-btn"
                      onClick={() => {
                        setConfiguringPin(false);
                        setNewPin("");
                        setConfirmPin("");
                      }}
                    >
                      {t.cancelButton}
                    </button>
                  </div>
                </form>
              )}

              {pinFeedback && (
                <div
                  className="form-hint"
                  style={{
                    color: pinFeedback.includes("correct") ? "#10b981" : "#ef4444",
                    fontSize: "11px",
                  }}
                >
                  {pinFeedback}
                </div>
              )}
            </div>

            <div className="settings-card" style={{ marginTop: "12px" }}>
              <div style={{ fontWeight: 600, fontSize: "13px" }}>{t.shortcutSettingsTitle}</div>
              <div style={{ fontSize: "12px", color: "var(--text-secondary)", marginTop: "4px" }}>
                {shortcutEnabled ? t.shortcutEnabledDesc : t.shortcutDisabledDesc}
              </div>
              <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "4px", opacity: 0.85 }}>
                {t.shortcutWaylandNote}
              </div>
              <div style={{ marginTop: "8px" }}>
                <button
                  type="button"
                  className={shortcutEnabled ? "header-pill-btn" : "primary-action-btn"}
                  style={{ width: "auto", padding: "6px 12px", fontSize: "12px" }}
                  onClick={handleToggleShortcut}
                >
                  {shortcutEnabled ? t.disableShortcutButton : t.enableShortcutButton}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      <AccountFormModal
        isOpen={isAddModalOpen}
        mode="add"
        account={null}
        existingAccounts={accounts}
        lang={lang}
        onClose={() => setIsAddModalOpen(false)}
        onSuccess={() => {
          refresh();
          if (onVaultStatusChanged) onVaultStatusChanged();
        }}
      />

      <AccountFormModal
        isOpen={editingAccount !== null}
        mode="edit"
        account={editingAccount}
        existingAccounts={accounts}
        lang={lang}
        onClose={() => setEditingAccount(null)}
        onSuccess={() => {
          refresh();
          if (onVaultStatusChanged) onVaultStatusChanged();
        }}
      />

      <DeleteConfirmModal
        isOpen={deletingAccount !== null}
        account={deletingAccount}
        lang={lang}
        onClose={() => setDeletingAccount(null)}
        onSuccess={() => {
          refresh();
          if (onVaultStatusChanged) onVaultStatusChanged();
        }}
      />
    </div>
  );
};
