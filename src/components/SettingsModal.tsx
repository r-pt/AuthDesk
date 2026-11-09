// [ENC-B64::cnB0|Z2Ft|cm9k]
import React, { useState, useEffect, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { isEnabled as isAutostartEnabled, enable as enableAutostart, disable as disableAutostart } from "@tauri-apps/plugin-autostart";
import { getTranslation, Language } from "../i18n";
import { ThemeMode, VaultStatusDto, WindowSettingsDto } from "../types";
import { DragBar } from "./DragBar";
import { BrandLogo } from "./BrandLogo";
import {
  IconClose,
  IconLock,
  IconLayout,
  IconClock,
  IconPalette,
  IconDatabase,
  IconShield,
  IconKey,
  IconCheck,
} from "./Icons";

type SettingsTab = "security" | "window" | "timers" | "appearance" | "demo";

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  lang: Language;
  theme: ThemeMode;
  onSelectTheme: (theme: ThemeMode) => void;
  onSelectLang: (lang: Language) => void;
  pinAvailable: boolean;
  pinEnabled: boolean;
  onVaultStatusChanged: () => void;
  onRefreshAccounts: () => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({
  isOpen,
  onClose,
  lang,
  theme,
  onSelectTheme,
  onSelectLang,
  pinAvailable,
  pinEnabled,
  onVaultStatusChanged,
  onRefreshAccounts,
}) => {
  const t = getTranslation(lang);
  const [activeTab, setActiveTab] = useState<SettingsTab>("security");

  const [vaultStatus, setVaultStatus] = useState<VaultStatusDto | null>(null);
  const [windowSettings, setWindowSettings] = useState<WindowSettingsDto>(() => {
    const defaults: WindowSettingsDto = {
      mode: "floating",
      popup_position: "top-right",
      always_on_top: true,
      auto_hide_on_blur: false,
      hide_on_copy: true,
    };
    const saved = localStorage.getItem("authdesk_window_settings");
    if (saved) {
      try {
        const val = JSON.parse(saved);
        if (val && typeof val === "object") {
          return { ...defaults, ...val };
        }
      } catch {}
    }
    return defaults;
  });

  const [autostartActive, setAutostartActive] = useState(false);
  const [hideOnCopy, setHideOnCopy] = useState<boolean>(() => {
    return localStorage.getItem("authdesk_hide_on_copy") !== "false";
  });
  const [autoLockMs, setAutoLockMs] = useState<number>(() => {
    const saved = localStorage.getItem("authdesk_autolock_ms");
    return saved !== null ? parseInt(saved, 10) : 5 * 60 * 1000;
  });
  const [clipboardMs, setClipboardMs] = useState<number>(() => {
    const saved = localStorage.getItem("authdesk_clipboard_ms");
    return saved !== null ? parseInt(saved, 10) : 30 * 1000;
  });
  const [shortcutEnabled, setShortcutEnabled] = useState<boolean>(() => {
    return localStorage.getItem("authdesk_global_shortcut") !== "false";
  });

  const [securityAction, setSecurityAction] = useState<"none" | "set_pw" | "change_pw" | "remove_pw" | "pin">("none");
  const [currentPasswordInput, setCurrentPasswordInput] = useState("");
  const [newPasswordInput, setNewPasswordInput] = useState("");
  const [confirmPasswordInput, setConfirmPasswordInput] = useState("");
  const [newPinInput, setNewPinInput] = useState("");
  const [confirmPinInput, setConfirmPinInput] = useState("");
  const [securityFeedback, setSecurityFeedback] = useState<{ message: string; isError: boolean } | null>(null);
  const [isSubmittingSecurity, setIsSubmittingSecurity] = useState(false);

  const [demoFeedback, setDemoFeedback] = useState<string | null>(null);
  const [isDemoBusy, setIsDemoBusy] = useState(false);

  const loadStatusAndSettings = useCallback(async () => {
    try {
      const status = await invoke<VaultStatusDto>("get_vault_status");
      setVaultStatus(status);
    } catch {}

    try {
      const winSettings = await invoke<WindowSettingsDto>("get_window_settings");
      const saved = localStorage.getItem("authdesk_window_settings");
      if (saved) {
        try {
          const val = JSON.parse(saved);
          if (val && typeof val === "object") {
            setWindowSettings({ ...winSettings, ...val });
          } else {
            setWindowSettings(winSettings);
            localStorage.setItem("authdesk_window_settings", JSON.stringify(winSettings));
          }
        } catch {
          setWindowSettings(winSettings);
          localStorage.setItem("authdesk_window_settings", JSON.stringify(winSettings));
        }
      } else {
        setWindowSettings(winSettings);
        localStorage.setItem("authdesk_window_settings", JSON.stringify(winSettings));
      }
    } catch {}

    try {
      const enabled = await isAutostartEnabled();
      setAutostartActive(enabled);
    } catch {
      setAutostartActive(false);
    }
  }, []);

  useEffect(() => {
    if (isOpen) {
      loadStatusAndSettings();
      setSecurityFeedback(null);
      setDemoFeedback(null);
      setSecurityAction("none");
      setCurrentPasswordInput("");
      setNewPasswordInput("");
      setConfirmPasswordInput("");
      setNewPinInput("");
      setConfirmPinInput("");
    }
  }, [isOpen, loadStatusAndSettings]);

  if (!isOpen) return null;

  const handleWindowModeChange = async (mode: string) => {
    try {
      await invoke("set_window_mode", { mode });
      setWindowSettings((prev) => {
        const next = { ...prev, mode };
        localStorage.setItem("authdesk_window_settings", JSON.stringify(next));
        return next;
      });
    } catch (e) {
      console.error(e);
    }
  };

  const handlePopupPositionChange = async (pos: string) => {
    try {
      await invoke("set_popup_position", { pos });
      setWindowSettings((prev) => {
        const next = { ...prev, popup_position: pos };
        localStorage.setItem("authdesk_window_settings", JSON.stringify(next));
        return next;
      });
    } catch (e) {
      console.error(e);
    }
  };

  const handleAlwaysOnTopToggle = async () => {
    const next = !windowSettings.always_on_top;
    try {
      await invoke("set_always_on_top", { enabled: next });
      setWindowSettings((prev) => {
        const updated = { ...prev, always_on_top: next };
        localStorage.setItem("authdesk_window_settings", JSON.stringify(updated));
        return updated;
      });
    } catch (e) {
      console.error(e);
    }
  };

  const handleAutoHideOnBlurToggle = async () => {
    const next = !windowSettings.auto_hide_on_blur;
    try {
      await invoke("set_auto_hide_on_blur", { enabled: next });
      setWindowSettings((prev) => {
        const updated = { ...prev, auto_hide_on_blur: next };
        localStorage.setItem("authdesk_window_settings", JSON.stringify(updated));
        return updated;
      });
    } catch (e) {
      console.error(e);
    }
  };

  const handleHideOnCopyToggle = () => {
    const next = !hideOnCopy;
    setHideOnCopy(next);
    localStorage.setItem("authdesk_hide_on_copy", String(next));
    setWindowSettings((prev) => {
      const updated = { ...prev, hide_on_copy: next };
      localStorage.setItem("authdesk_window_settings", JSON.stringify(updated));
      return updated;
    });
  };

  const handleAutostartToggle = async () => {
    try {
      if (autostartActive) {
        await disableAutostart();
        setAutostartActive(false);
      } else {
        await enableAutostart();
        setAutostartActive(true);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleAutoLockChange = (ms: number) => {
    setAutoLockMs(ms);
    localStorage.setItem("authdesk_autolock_ms", String(ms));
    window.dispatchEvent(new Event("authdesk-autolock-changed"));
  };

  const handleClipboardClearChange = (ms: number) => {
    setClipboardMs(ms);
    localStorage.setItem("authdesk_clipboard_ms", String(ms));
  };

  const handleToggleGlobalShortcut = async () => {
    const next = !shortcutEnabled;
    try {
      await invoke("toggle_global_shortcut", { enabled: next });
      setShortcutEnabled(next);
      localStorage.setItem("authdesk_global_shortcut", String(next));
    } catch (e) {
      console.error(e);
    }
  };

  const handleSetMasterPassword = async (e: React.SyntheticEvent) => {
    e.preventDefault();
    if (newPasswordInput.length < 8) {
      setSecurityFeedback({ message: t.passwordMinLength, isError: true });
      return;
    }
    if (newPasswordInput !== confirmPasswordInput) {
      setSecurityFeedback({ message: t.passwordMismatch, isError: true });
      return;
    }

    setIsSubmittingSecurity(true);
    setSecurityFeedback(null);
    try {
      await invoke("set_master_password", {
        currentPassword: null,
        newPassword: newPasswordInput,
      });
      setSecurityFeedback({ message: t.passwordSetSuccess, isError: false });
      setSecurityAction("none");
      setNewPasswordInput("");
      setConfirmPasswordInput("");
      await loadStatusAndSettings();
      onVaultStatusChanged();
    } catch (err) {
      setSecurityFeedback({ message: String(err), isError: true });
    } finally {
      setIsSubmittingSecurity(false);
    }
  };

  const handleChangeMasterPassword = async (e: React.SyntheticEvent) => {
    e.preventDefault();
    if (!currentPasswordInput) {
      setSecurityFeedback({ message: t.invalidPassword, isError: true });
      return;
    }
    if (newPasswordInput.length < 8) {
      setSecurityFeedback({ message: t.passwordMinLength, isError: true });
      return;
    }
    if (newPasswordInput !== confirmPasswordInput) {
      setSecurityFeedback({ message: t.passwordMismatch, isError: true });
      return;
    }

    setIsSubmittingSecurity(true);
    setSecurityFeedback(null);
    try {
      await invoke("change_master_password", {
        currentPassword: currentPasswordInput,
        newPassword: newPasswordInput,
      });
      setSecurityFeedback({ message: t.passwordChangedSuccess, isError: false });
      setSecurityAction("none");
      setCurrentPasswordInput("");
      setNewPasswordInput("");
      setConfirmPasswordInput("");
      await loadStatusAndSettings();
      onVaultStatusChanged();
    } catch (err) {
      setSecurityFeedback({ message: String(err), isError: true });
    } finally {
      setIsSubmittingSecurity(false);
    }
  };

  const handleRemoveMasterPassword = async (e: React.SyntheticEvent) => {
    e.preventDefault();
    if (!currentPasswordInput) {
      setSecurityFeedback({ message: t.invalidPassword, isError: true });
      return;
    }

    setIsSubmittingSecurity(true);
    setSecurityFeedback(null);
    try {
      await invoke("remove_master_password", {
        currentPassword: currentPasswordInput,
      });
      setSecurityFeedback({ message: t.passwordRemovedSuccess, isError: false });
      setSecurityAction("none");
      setCurrentPasswordInput("");
      await loadStatusAndSettings();
      onVaultStatusChanged();
    } catch (err) {
      setSecurityFeedback({ message: String(err), isError: true });
    } finally {
      setIsSubmittingSecurity(false);
    }
  };

  const handleSavePin = async (e: React.SyntheticEvent) => {
    e.preventDefault();
    if (newPinInput.length !== 6 || !/^\d{6}$/.test(newPinInput)) {
      setSecurityFeedback({ message: t.pinMustBe6Digits, isError: true });
      return;
    }
    if (newPinInput !== confirmPinInput) {
      setSecurityFeedback({ message: t.pinMismatch, isError: true });
      return;
    }

    setIsSubmittingSecurity(true);
    setSecurityFeedback(null);
    try {
      await invoke("set_pin", { pin: newPinInput });
      setSecurityFeedback({ message: t.pinSavedSuccess, isError: false });
      setSecurityAction("none");
      setNewPinInput("");
      setConfirmPinInput("");
      await loadStatusAndSettings();
      onVaultStatusChanged();
    } catch (err) {
      setSecurityFeedback({ message: String(err), isError: true });
    } finally {
      setIsSubmittingSecurity(false);
    }
  };

  const handleDisablePin = async () => {
    setIsSubmittingSecurity(true);
    setSecurityFeedback(null);
    try {
      await invoke("disable_pin");
      setSecurityFeedback({ message: t.pinDisabledSuccess, isError: false });
      setSecurityAction("none");
      setNewPinInput("");
      setConfirmPinInput("");
      await loadStatusAndSettings();
      onVaultStatusChanged();
    } catch (err) {
      setSecurityFeedback({ message: String(err), isError: true });
    } finally {
      setIsSubmittingSecurity(false);
    }
  };

  const handleLoadDemo = async () => {
    setIsDemoBusy(true);
    setDemoFeedback(null);
    try {
      const count = await invoke<number>("load_demo_accounts");
      setDemoFeedback(`${t.demoLoadedSuccess} (${count})`);
      onRefreshAccounts();
      onVaultStatusChanged();
    } catch (err) {
      setDemoFeedback(String(err));
    } finally {
      setIsDemoBusy(false);
    }
  };

  const handleRemoveDemo = async () => {
    setIsDemoBusy(true);
    setDemoFeedback(null);
    try {
      const count = await invoke<number>("remove_demo_accounts");
      setDemoFeedback(`${t.demoRemovedSuccess} (${count})`);
      onRefreshAccounts();
      onVaultStatusChanged();
    } catch (err) {
      setDemoFeedback(String(err));
    } finally {
      setIsDemoBusy(false);
    }
  };

  const isPasswordless = vaultStatus ? vaultStatus.passwordless : false;

  return (
    <div className="settings-modal-backdrop" onClick={onClose}>
      <div className="settings-modal-dialog" onClick={(e) => e.stopPropagation()}>
        <DragBar />

        <div className="settings-header">
          <div className="brand-mark" style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <BrandLogo size={20} />
            <span>{t.settingsTitle}</span>
          </div>
          <button
            type="button"
            className="theme-toggle"
            onClick={onClose}
            title={t.closeButton}
            aria-label={t.closeButton}
          >
            <IconClose size={16} />
          </button>
        </div>

        <div className="settings-tabs-bar">
          <button
            type="button"
            className={`settings-tab-btn ${activeTab === "security" ? "active" : ""}`}
            onClick={() => setActiveTab("security")}
          >
            <IconLock size={13} />
            <span>{t.tabSecurity}</span>
          </button>
          <button
            type="button"
            className={`settings-tab-btn ${activeTab === "window" ? "active" : ""}`}
            onClick={() => setActiveTab("window")}
          >
            <IconLayout size={13} />
            <span>{t.tabWindow}</span>
          </button>
          <button
            type="button"
            className={`settings-tab-btn ${activeTab === "timers" ? "active" : ""}`}
            onClick={() => setActiveTab("timers")}
          >
            <IconClock size={13} />
            <span>{t.tabTimers}</span>
          </button>
          <button
            type="button"
            className={`settings-tab-btn ${activeTab === "appearance" ? "active" : ""}`}
            onClick={() => setActiveTab("appearance")}
          >
            <IconPalette size={13} />
            <span>{t.tabAppearance}</span>
          </button>
          <button
            type="button"
            className={`settings-tab-btn ${activeTab === "demo" ? "active" : ""}`}
            onClick={() => setActiveTab("demo")}
          >
            <IconDatabase size={13} />
            <span>{t.tabDemo}</span>
          </button>
        </div>

        <div className="settings-body">
          {activeTab === "security" && (
            <div className="settings-section">
              <div className="settings-card">
                <div className="card-header-row">
                  <div>
                    <div className="card-title">{t.vaultModeTitle}</div>
                    <div className="card-desc">
                      {isPasswordless ? t.vaultModePasswordless : t.vaultModePassword}
                    </div>
                  </div>
                  <div className={`status-badge ${isPasswordless ? "badge-info" : "badge-success"}`}>
                    {isPasswordless ? (
                      <>
                        <IconShield size={12} />
                        <span>Keyring</span>
                      </>
                    ) : (
                      <>
                        <IconKey size={12} />
                        <span>Password</span>
                      </>
                    )}
                  </div>
                </div>

                <div className="card-actions-row">
                  {isPasswordless ? (
                    <button
                      type="button"
                      className="primary-action-btn"
                      style={{ width: "auto", padding: "7px 14px", fontSize: "12px" }}
                      onClick={() => {
                        setSecurityAction("set_pw");
                        setSecurityFeedback(null);
                      }}
                    >
                      {t.setPasswordButton}
                    </button>
                  ) : (
                    <>
                      <button
                        type="button"
                        className="header-pill-btn"
                        onClick={() => {
                          setSecurityAction("change_pw");
                          setSecurityFeedback(null);
                        }}
                      >
                        {t.changePasswordButton}
                      </button>
                      <button
                        type="button"
                        className="header-pill-btn"
                        style={{ color: "#ef4444" }}
                        onClick={() => {
                          setSecurityAction("remove_pw");
                          setSecurityFeedback(null);
                        }}
                      >
                        {t.removePasswordButton}
                      </button>
                    </>
                  )}
                </div>

                {securityAction === "set_pw" && (
                  <form onSubmit={handleSetMasterPassword} className="sub-flow-form">
                    <input
                      type="password"
                      className="form-input"
                      placeholder={t.newPassword}
                      value={newPasswordInput}
                      onChange={(e) => setNewPasswordInput(e.target.value)}
                      autoFocus
                    />
                    <input
                      type="password"
                      className="form-input"
                      placeholder={t.confirmNewPassword}
                      value={confirmPasswordInput}
                      onChange={(e) => setConfirmPasswordInput(e.target.value)}
                    />
                    <div style={{ display: "flex", gap: "8px" }}>
                      <button
                        type="submit"
                        className="primary-action-btn"
                        disabled={isSubmittingSecurity || !newPasswordInput}
                      >
                        {isSubmittingSecurity ? "..." : t.savePasswordButton}
                      </button>
                      <button
                        type="button"
                        className="header-pill-btn"
                        onClick={() => setSecurityAction("none")}
                      >
                        {t.cancelButton}
                      </button>
                    </div>
                  </form>
                )}

                {securityAction === "change_pw" && (
                  <form onSubmit={handleChangeMasterPassword} className="sub-flow-form">
                    <input
                      type="password"
                      className="form-input"
                      placeholder={t.currentPassword}
                      value={currentPasswordInput}
                      onChange={(e) => setCurrentPasswordInput(e.target.value)}
                      autoFocus
                    />
                    <input
                      type="password"
                      className="form-input"
                      placeholder={t.newPassword}
                      value={newPasswordInput}
                      onChange={(e) => setNewPasswordInput(e.target.value)}
                    />
                    <input
                      type="password"
                      className="form-input"
                      placeholder={t.confirmNewPassword}
                      value={confirmPasswordInput}
                      onChange={(e) => setConfirmPasswordInput(e.target.value)}
                    />
                    <div style={{ display: "flex", gap: "8px" }}>
                      <button
                        type="submit"
                        className="primary-action-btn"
                        disabled={isSubmittingSecurity || !currentPasswordInput || !newPasswordInput}
                      >
                        {isSubmittingSecurity ? "..." : t.savePasswordButton}
                      </button>
                      <button
                        type="button"
                        className="header-pill-btn"
                        onClick={() => setSecurityAction("none")}
                      >
                        {t.cancelButton}
                      </button>
                    </div>
                  </form>
                )}

                {securityAction === "remove_pw" && (
                  <form onSubmit={handleRemoveMasterPassword} className="sub-flow-form">
                    <input
                      type="password"
                      className="form-input"
                      placeholder={t.currentPassword}
                      value={currentPasswordInput}
                      onChange={(e) => setCurrentPasswordInput(e.target.value)}
                      autoFocus
                    />
                    <div style={{ display: "flex", gap: "8px" }}>
                      <button
                        type="submit"
                        className="danger-action-btn"
                        style={{ width: "auto", padding: "8px 14px", fontSize: "12px" }}
                        disabled={isSubmittingSecurity || !currentPasswordInput}
                      >
                        {isSubmittingSecurity ? "..." : t.removePasswordButton}
                      </button>
                      <button
                        type="button"
                        className="header-pill-btn"
                        onClick={() => setSecurityAction("none")}
                      >
                        {t.cancelButton}
                      </button>
                    </div>
                  </form>
                )}
              </div>

              <div className="settings-card" style={{ marginTop: "10px" }}>
                <div className="card-header-row">
                  <div>
                    <div className="card-title">{t.pinSettingsTitle}</div>
                    <div className="card-desc">
                      {!pinAvailable
                        ? t.pinNotAvailable
                        : pinEnabled
                        ? t.pinEnabledDesc
                        : t.pinDisabledDesc}
                    </div>
                  </div>
                  {pinAvailable && (
                    <div className={`status-badge ${pinEnabled ? "badge-success" : "badge-neutral"}`}>
                      {pinEnabled ? "PIN ON" : "PIN OFF"}
                    </div>
                  )}
                </div>

                {pinAvailable && (
                  <div className="card-actions-row">
                    {pinEnabled ? (
                      <>
                        <button
                          type="button"
                          className="header-pill-btn"
                          onClick={() => {
                            setSecurityAction("pin");
                            setSecurityFeedback(null);
                          }}
                        >
                          {t.changePinButton}
                        </button>
                        <button
                          type="button"
                          className="header-pill-btn"
                          style={{ color: "#ef4444" }}
                          onClick={handleDisablePin}
                          disabled={isSubmittingSecurity}
                        >
                          {t.disablePinButton}
                        </button>
                      </>
                    ) : (
                      <button
                        type="button"
                        className="primary-action-btn"
                        style={{ width: "auto", padding: "7px 14px", fontSize: "12px" }}
                        onClick={() => {
                          setSecurityAction("pin");
                          setSecurityFeedback(null);
                        }}
                      >
                        {t.setupPinButton}
                      </button>
                    )}
                  </div>
                )}

                {securityAction === "pin" && (
                  <form onSubmit={handleSavePin} className="sub-flow-form">
                    <input
                      type="password"
                      inputMode="numeric"
                      maxLength={6}
                      className="form-input"
                      placeholder={t.newPinPlaceholder}
                      value={newPinInput}
                      onChange={(e) => setNewPinInput(e.target.value.replace(/\D/g, "").slice(0, 6))}
                      autoFocus
                    />
                    <input
                      type="password"
                      inputMode="numeric"
                      maxLength={6}
                      className="form-input"
                      placeholder={t.confirmPinPlaceholder}
                      value={confirmPinInput}
                      onChange={(e) => setConfirmPinInput(e.target.value.replace(/\D/g, "").slice(0, 6))}
                    />
                    <div style={{ display: "flex", gap: "8px" }}>
                      <button
                        type="submit"
                        className="primary-action-btn"
                        disabled={isSubmittingSecurity || newPinInput.length !== 6 || confirmPinInput.length !== 6}
                      >
                        {isSubmittingSecurity ? "..." : t.savePinButton}
                      </button>
                      <button
                        type="button"
                        className="header-pill-btn"
                        onClick={() => setSecurityAction("none")}
                      >
                        {t.cancelButton}
                      </button>
                    </div>
                  </form>
                )}
              </div>

              {securityFeedback && (
                <div
                  className="form-hint"
                  style={{
                    color: securityFeedback.isError ? "#ef4444" : "#10b981",
                    fontSize: "11.5px",
                    marginTop: "8px",
                  }}
                >
                  {securityFeedback.message}
                </div>
              )}
            </div>
          )}

          {activeTab === "window" && (
            <div className="settings-section">
              <div className="settings-card">
                <div className="setting-block">
                  <div className="card-title">{t.windowModeTitle}</div>
                  <div className="segmented-control">
                    <button
                      type="button"
                      className={`segment-btn ${windowSettings.mode === "floating" ? "active" : ""}`}
                      onClick={() => handleWindowModeChange("floating")}
                    >
                      {t.windowModeFloating}
                    </button>
                    <button
                      type="button"
                      className={`segment-btn ${windowSettings.mode === "tray-popup" ? "active" : ""}`}
                      onClick={() => handleWindowModeChange("tray-popup")}
                    >
                      {t.windowModeTrayPopup}
                    </button>
                    <button
                      type="button"
                      className={`segment-btn ${windowSettings.mode === "taskbar" ? "active" : ""}`}
                      onClick={() => handleWindowModeChange("taskbar")}
                    >
                      {t.windowModeTaskbar}
                    </button>
                  </div>
                </div>

                <div className="setting-block" style={{ marginTop: "12px" }}>
                  <div className="card-title">{t.popupPositionTitle}</div>
                  <div className="segmented-control">
                    <button
                      type="button"
                      className={`segment-btn ${windowSettings.popup_position === "top-right" ? "active" : ""}`}
                      onClick={() => handlePopupPositionChange("top-right")}
                    >
                      {t.posTopRight}
                    </button>
                    <button
                      type="button"
                      className={`segment-btn ${windowSettings.popup_position === "bottom-right" ? "active" : ""}`}
                      onClick={() => handlePopupPositionChange("bottom-right")}
                    >
                      {t.posBottomRight}
                    </button>
                    <button
                      type="button"
                      className={`segment-btn ${windowSettings.popup_position === "center" ? "active" : ""}`}
                      onClick={() => handlePopupPositionChange("center")}
                    >
                      {t.posCenter}
                    </button>
                  </div>
                </div>
              </div>

              <div className="settings-card" style={{ marginTop: "10px" }}>
                <div className="setting-row">
                  <div>
                    <div className="card-title">{t.alwaysOnTopTitle}</div>
                  </div>
                  <label className="toggle-switch">
                    <input
                      type="checkbox"
                      checked={windowSettings.always_on_top}
                      onChange={handleAlwaysOnTopToggle}
                    />
                    <span className="toggle-slider" />
                  </label>
                </div>

                <div className="setting-row" style={{ marginTop: "12px" }}>
                  <div>
                    <div className="card-title">{t.hideOnCopyTitle}</div>
                  </div>
                  <label className="toggle-switch">
                    <input
                      type="checkbox"
                      checked={hideOnCopy}
                      onChange={handleHideOnCopyToggle}
                    />
                    <span className="toggle-slider" />
                  </label>
                </div>

                <div className="setting-row" style={{ marginTop: "12px" }}>
                  <div>
                    <div className="card-title">{t.hideOnBlurTitle}</div>
                  </div>
                  <label className="toggle-switch">
                    <input
                      type="checkbox"
                      checked={windowSettings.auto_hide_on_blur}
                      onChange={handleAutoHideOnBlurToggle}
                    />
                    <span className="toggle-slider" />
                  </label>
                </div>

                <div className="setting-row" style={{ marginTop: "12px" }}>
                  <div>
                    <div className="card-title">{t.autostartTitle}</div>
                  </div>
                  <label className="toggle-switch">
                    <input
                      type="checkbox"
                      checked={autostartActive}
                      onChange={handleAutostartToggle}
                    />
                    <span className="toggle-slider" />
                  </label>
                </div>
              </div>
            </div>
          )}

          {activeTab === "timers" && (
            <div className="settings-section">
              <div className="settings-card">
                <div className="setting-block">
                  <div className="card-title">{t.autoLockTitle}</div>
                  <div className="segmented-control">
                    {[
                      { ms: 0, label: t.timerNever },
                      { ms: 60 * 1000, label: t.timer1m },
                      { ms: 5 * 60 * 1000, label: t.timer5m },
                      { ms: 15 * 60 * 1000, label: t.timer15m },
                      { ms: 30 * 60 * 1000, label: t.timer30m },
                    ].map((item) => (
                      <button
                        key={item.ms}
                        type="button"
                        className={`segment-btn ${autoLockMs === item.ms ? "active" : ""}`}
                        onClick={() => handleAutoLockChange(item.ms)}
                      >
                        {item.label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              <div className="settings-card" style={{ marginTop: "10px" }}>
                <div className="setting-block">
                  <div className="card-title">{t.clipboardClearTitle}</div>
                  <div className="segmented-control">
                    {[
                      { ms: 10 * 1000, label: t.timer10s },
                      { ms: 30 * 1000, label: t.timer30s },
                      { ms: 60 * 1000, label: t.timer60s },
                      { ms: 0, label: t.timerNever },
                    ].map((item) => (
                      <button
                        key={item.ms}
                        type="button"
                        className={`segment-btn ${clipboardMs === item.ms ? "active" : ""}`}
                        onClick={() => handleClipboardClearChange(item.ms)}
                      >
                        {item.label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === "appearance" && (
            <div className="settings-section">
              <div className="settings-card">
                <div className="setting-block">
                  <div className="card-title">{t.themeTitle}</div>
                  <div className="segmented-control">
                    {(["dark", "light", "coffee"] as ThemeMode[]).map((m) => (
                      <button
                        key={m}
                        type="button"
                        className={`segment-btn ${theme === m ? "active" : ""}`}
                        onClick={() => onSelectTheme(m)}
                      >
                        {m === "dark" ? t.themeDark : m === "light" ? t.themeLight : t.themeCoffee}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="setting-block" style={{ marginTop: "12px" }}>
                  <div className="card-title">{t.langTitle}</div>
                  <div className="segmented-control">
                    {(["es", "en"] as Language[]).map((l) => (
                      <button
                        key={l}
                        type="button"
                        className={`segment-btn ${lang === l ? "active" : ""}`}
                        onClick={() => onSelectLang(l)}
                      >
                        {l.toUpperCase()}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              <div className="settings-card" style={{ marginTop: "10px" }}>
                <div className="setting-row">
                  <div>
                    <div className="card-title">{t.shortcutSettingsTitle}</div>
                    <div className="card-desc">
                      {shortcutEnabled ? t.shortcutEnabledDesc : t.shortcutDisabledDesc}
                    </div>
                  </div>
                  <label className="toggle-switch">
                    <input
                      type="checkbox"
                      checked={shortcutEnabled}
                      onChange={handleToggleGlobalShortcut}
                    />
                    <span className="toggle-slider" />
                  </label>
                </div>
                <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "6px", opacity: 0.85 }}>
                  {t.shortcutWaylandNote}
                </div>
              </div>
            </div>
          )}

          {activeTab === "demo" && (
            <div className="settings-section">
              <div className="settings-card">
                <div className="card-title">{t.demoTitle}</div>
                <div className="card-desc" style={{ marginTop: "4px" }}>
                  {t.demoDesc}
                </div>

                <div className="card-actions-row" style={{ marginTop: "12px" }}>
                  <button
                    type="button"
                    className="primary-action-btn"
                    style={{ width: "auto", padding: "8px 14px", fontSize: "12px", display: "inline-flex", alignItems: "center", gap: "6px" }}
                    onClick={handleLoadDemo}
                    disabled={isDemoBusy}
                  >
                    <IconCheck size={14} />
                    <span>{isDemoBusy ? "..." : t.loadDemoButton}</span>
                  </button>
                  <button
                    type="button"
                    className="header-pill-btn"
                    style={{ color: "#ef4444", padding: "8px 14px" }}
                    onClick={handleRemoveDemo}
                    disabled={isDemoBusy}
                  >
                    {isDemoBusy ? "..." : t.removeDemoButton}
                  </button>
                </div>

                {demoFeedback && (
                  <div
                    className="form-hint"
                    style={{
                      color: demoFeedback.includes("Error") ? "#ef4444" : "#10b981",
                      fontSize: "11.5px",
                      marginTop: "10px",
                    }}
                  >
                    {demoFeedback}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
