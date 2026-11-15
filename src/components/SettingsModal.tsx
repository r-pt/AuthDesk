// [ENC-B64::cnB0|Z2Ft|cm9k]
import React, { useState, useEffect, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { isEnabled as isAutostartEnabled, enable as enableAutostart, disable as disableAutostart } from "@tauri-apps/plugin-autostart";
import { getTranslation, Language } from "../i18n";
import {
  ThemeMode,
  VaultStatusDto,
  WindowSettingsDto,
  WindowMode,
  SettingsTab,
  QrImageInputDto,
  ImportPreviewResultDto,
  ImportConfirmResultDto,
  ExportQrBatchDto,
  ExportQrResultDto,
  DEFAULT_WINDOW_SETTINGS,
  normalizeWindowMode,
  parseStoredWindowSettings,
} from "../types";
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
  IconUpload,
  IconDownload,
  IconQrCode,
  IconAlertTriangle,
  IconChevronLeft,
  IconChevronRight,
} from "./Icons";

interface SettingsModalProps {
  isOpen: boolean;
  initialTab?: SettingsTab;
  onClose: () => void;
  lang: Language;
  theme: ThemeMode;
  onSelectTheme: (theme: ThemeMode) => void;
  onSelectLang: (lang: Language) => void;
  pinAvailable: boolean;
  pinEnabled: boolean;
  onVaultStatusChanged: () => void;
  onAccountsChanged?: () => void;
  onRefreshAccounts?: () => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({
  isOpen,
  initialTab = "security",
  onClose,
  lang,
  theme,
  onSelectTheme,
  onSelectLang,
  pinAvailable,
  pinEnabled,
  onVaultStatusChanged,
  onAccountsChanged,
  onRefreshAccounts,
}) => {
  const t = getTranslation(lang);
  const [activeTab, setActiveTab] = useState<SettingsTab>(initialTab);

  const [vaultStatus, setVaultStatus] = useState<VaultStatusDto | null>(null);
  const [isWayland, setIsWayland] = useState(false);
  const [windowSettings, setWindowSettings] = useState<WindowSettingsDto>(() => {
    return (
      parseStoredWindowSettings(localStorage.getItem("authdesk_window_settings")) ??
      DEFAULT_WINDOW_SETTINGS
    );
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

  const [urisText, setUrisText] = useState("");
  const [importPreview, setImportPreview] = useState<ImportPreviewResultDto | null>(null);
  const [selectedImportIndices, setSelectedImportIndices] = useState<number[]>([]);
  const [isStagingImport, setIsStagingImport] = useState(false);
  const [isConfirmingImport, setIsConfirmingImport] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [importFeedback, setImportFeedback] = useState<string | null>(null);

  const [exportWarningAccepted, setExportWarningAccepted] = useState(false);
  const [exportCredential, setExportCredential] = useState("");
  const [exportBatches, setExportBatches] = useState<ExportQrBatchDto[]>([]);
  const [exportTotalAccounts, setExportTotalAccounts] = useState(0);
  const [exportBatchIndex, setExportBatchIndex] = useState(0);
  const [isExporting, setIsExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const hasStagedImportRef = useRef(false);

  const clearExportState = useCallback(() => {
    setExportBatches([]);
    setExportTotalAccounts(0);
    setExportBatchIndex(0);
    setExportCredential("");
    setExportWarningAccepted(false);
    setExportError(null);
  }, []);

  const clearImportStagingState = useCallback(async (cancelRemote: boolean) => {
    const shouldCancel = cancelRemote && hasStagedImportRef.current;
    hasStagedImportRef.current = false;
    setImportPreview(null);
    setSelectedImportIndices([]);
    if (shouldCancel) {
      try {
        await invoke("cancel_staged_import");
      } catch {}
    }
  }, []);

  const notifyAccountsChanged = useCallback(() => {
    if (onAccountsChanged) {
      onAccountsChanged();
    } else if (onRefreshAccounts) {
      onRefreshAccounts();
    }
  }, [onAccountsChanged, onRefreshAccounts]);

  const handleClose = useCallback(() => {
    clearExportState();
    void clearImportStagingState(true);
    setUrisText("");
    setImportError(null);
    setImportFeedback(null);
    onClose();
  }, [clearExportState, clearImportStagingState, onClose]);

  const handleTabChange = useCallback(
    (nextTab: SettingsTab) => {
      if (activeTab === "import_export" && nextTab !== "import_export") {
        clearExportState();
        void clearImportStagingState(true);
        setImportError(null);
        setImportFeedback(null);
      }
      setActiveTab(nextTab);
    },
    [activeTab, clearExportState, clearImportStagingState]
  );

  const loadStatusAndSettings = useCallback(async () => {
    try {
      const status = await invoke<VaultStatusDto>("get_vault_status");
      setVaultStatus(status);
    } catch {}

    try {
      const winSettings = await invoke<WindowSettingsDto>("get_window_settings");
      const normalizedWinSettings: WindowSettingsDto = {
        ...winSettings,
        mode: normalizeWindowMode(winSettings.mode),
      };
      const parsed = parseStoredWindowSettings(
        localStorage.getItem("authdesk_window_settings"),
        normalizedWinSettings
      );
      const resolved = parsed ?? normalizedWinSettings;
      setWindowSettings(resolved);
      localStorage.setItem("authdesk_window_settings", JSON.stringify(resolved));
    } catch {}

    try {
      const enabled = await isAutostartEnabled();
      setAutostartActive(enabled);
    } catch {
      setAutostartActive(false);
    }
  }, []);

  useEffect(() => {
    invoke<boolean>("is_wayland")
      .then((val) => setIsWayland(Boolean(val)))
      .catch(() => setIsWayland(false));
  }, []);

  useEffect(() => {
    if (isOpen) {
      setActiveTab(initialTab);
      loadStatusAndSettings();
      setSecurityFeedback(null);
      setDemoFeedback(null);
      setSecurityAction("none");
      setCurrentPasswordInput("");
      setNewPasswordInput("");
      setConfirmPasswordInput("");
      setNewPinInput("");
      setConfirmPinInput("");
      clearExportState();
      setImportPreview(null);
      setSelectedImportIndices([]);
      hasStagedImportRef.current = false;
      setUrisText("");
      setImportError(null);
      setImportFeedback(null);
    } else {
      clearExportState();
      void clearImportStagingState(true);
      setUrisText("");
      setImportError(null);
      setImportFeedback(null);
    }
  }, [isOpen, initialTab, loadStatusAndSettings, clearExportState, clearImportStagingState]);

  useEffect(() => {
    if (vaultStatus?.locked) {
      clearExportState();
      void clearImportStagingState(true);
    }
  }, [vaultStatus?.locked, clearExportState, clearImportStagingState]);

  useEffect(() => {
    return () => {
      if (hasStagedImportRef.current) {
        hasStagedImportRef.current = false;
        invoke("cancel_staged_import").catch(() => {});
      }
    };
  }, []);

  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        handleClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, handleClose]);

  if (!isOpen) return null;

  const currentWindowMode = normalizeWindowMode(windowSettings.mode);
  const isNormalWindow = currentWindowMode === "normal";

  const handleWindowModeChange = async (mode: WindowMode) => {
    const normalized = normalizeWindowMode(mode);
    try {
      await invoke("set_window_mode", { mode: normalized });
      setWindowSettings((prev) => {
        const next = { ...prev, mode: normalized };
        localStorage.setItem("authdesk_window_settings", JSON.stringify(next));
        return next;
      });
      window.dispatchEvent(new CustomEvent("authdesk-window-mode-changed", { detail: normalized }));
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

  const handleResizableToggle = async () => {
    if (isNormalWindow === false) return;
    const next = !windowSettings.resizable;
    try {
      await invoke("set_window_resizable", { resizable: next });
      setWindowSettings((prev) => {
        const updated = { ...prev, resizable: next };
        localStorage.setItem("authdesk_window_settings", JSON.stringify(updated));
        return updated;
      });
    } catch (e) {
      console.error(e);
    }
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
      notifyAccountsChanged();
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
      notifyAccountsChanged();
      onVaultStatusChanged();
    } catch (err) {
      setDemoFeedback(String(err));
    } finally {
      setIsDemoBusy(false);
    }
  };

  const applyImportPreview = (preview: ImportPreviewResultDto) => {
    hasStagedImportRef.current = true;
    setImportPreview(preview);
    setSelectedImportIndices(
      preview.items.filter((item) => !item.is_duplicate).map((item) => item.index)
    );
  };

  const handleQrFilesChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files ?? []);
    e.target.value = "";
    if (files.length === 0) return;

    setIsStagingImport(true);
    setImportError(null);
    setImportFeedback(null);
    try {
      const images: QrImageInputDto[] = await Promise.all(
        files.map(async (file) => {
          const buffer = await file.arrayBuffer();
          return {
            name: file.name,
            bytes: Array.from(new Uint8Array(buffer)),
          };
        })
      );
      const preview = await invoke<ImportPreviewResultDto>("stage_import_qr_images", {
        images,
      });
      applyImportPreview(preview);
    } catch (err) {
      setImportError(typeof err === "string" ? err : t.importReadFileError);
    } finally {
      setIsStagingImport(false);
    }
  };

  const handleStageUris = async () => {
    if (!urisText.trim()) {
      setImportError(t.importNoInputError);
      return;
    }
    setIsStagingImport(true);
    setImportError(null);
    setImportFeedback(null);
    try {
      const preview = await invoke<ImportPreviewResultDto>("stage_import_uris", {
        urisText,
      });
      applyImportPreview(preview);
    } catch (err) {
      setImportError(String(err));
    } finally {
      setIsStagingImport(false);
    }
  };

  const handleToggleImportIndex = (index: number) => {
    setSelectedImportIndices((prev) =>
      prev.includes(index) ? prev.filter((item) => item !== index) : [...prev, index]
    );
  };

  const nonDuplicatePreviewIndices = importPreview
    ? importPreview.items.filter((item) => !item.is_duplicate).map((item) => item.index)
    : [];
  const allNonDuplicatesSelected =
    nonDuplicatePreviewIndices.length > 0 &&
    nonDuplicatePreviewIndices.every((idx) => selectedImportIndices.includes(idx));

  const handleToggleAllImport = () => {
    if (allNonDuplicatesSelected) {
      setSelectedImportIndices([]);
    } else {
      setSelectedImportIndices(nonDuplicatePreviewIndices);
    }
  };

  const handleConfirmImport = async () => {
    if (selectedImportIndices.length === 0) return;
    setIsConfirmingImport(true);
    setImportError(null);
    setImportFeedback(null);
    try {
      const result = await invoke<ImportConfirmResultDto>("confirm_staged_import", {
        selectedIndices: selectedImportIndices,
      });
      hasStagedImportRef.current = false;
      setImportPreview(null);
      setSelectedImportIndices([]);
      setUrisText("");
      setImportFeedback(
        t.importSuccessBanner
          .replace("{imported}", String(result.imported_count))
          .replace("{skipped}", String(result.skipped_duplicates))
      );
      notifyAccountsChanged();
      onVaultStatusChanged();
      await loadStatusAndSettings();
    } catch (err) {
      setImportError(String(err));
    } finally {
      setIsConfirmingImport(false);
    }
  };

  const handleCancelImport = async () => {
    setImportError(null);
    await clearImportStagingState(true);
  };

  const isPasswordless = vaultStatus ? vaultStatus.passwordless : false;
  const effectivePinEnabled = vaultStatus ? vaultStatus.pin_enabled : pinEnabled;
  const requiresPasswordForExport = !isPasswordless;
  const requiresPinForExport = isPasswordless && effectivePinEnabled;
  const requiresCredentialForExport = requiresPasswordForExport || requiresPinForExport;

  const handleExportQrBatches = async (e: React.FormEvent) => {
    e.preventDefault();
    setExportError(null);
    if (!exportWarningAccepted) {
      return;
    }
    if (requiresPasswordForExport && !exportCredential) {
      setExportError(t.exportCredentialRequired);
      return;
    }
    if (requiresPinForExport && !/^\d{6}$/.test(exportCredential)) {
      setExportError(t.pinMustBe6Digits);
      return;
    }

    setIsExporting(true);
    try {
      const result = await invoke<ExportQrResultDto>("export_vault_qr_batches", {
        credential: requiresCredentialForExport ? exportCredential : null,
        confirmedWarning: exportWarningAccepted,
      });
      setExportCredential("");
      setExportBatches(result.batches);
      setExportTotalAccounts(result.total_accounts);
      setExportBatchIndex(0);
    } catch (err) {
      setExportBatches([]);
      setExportTotalAccounts(0);
      setExportBatchIndex(0);
      setExportError(String(err));
    } finally {
      setIsExporting(false);
    }
  };

  const currentExportBatch = exportBatches[exportBatchIndex] ?? null;

  return (
    <div className="settings-modal-backdrop" onClick={handleClose}>
      <div className="settings-modal-dialog" onClick={(e) => e.stopPropagation()}>
        <DragBar />

        <div className="settings-header">
          <div className="brand-mark" style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <BrandLogo size={22} />
            <span>{t.settingsTitle}</span>
          </div>
          <button
            type="button"
            className="theme-toggle"
            onClick={handleClose}
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
            onClick={() => handleTabChange("security")}
          >
            <IconLock size={13} />
            <span>{t.tabSecurity}</span>
          </button>
          <button
            type="button"
            className={`settings-tab-btn ${activeTab === "window" ? "active" : ""}`}
            onClick={() => handleTabChange("window")}
          >
            <IconLayout size={13} />
            <span>{t.tabWindow}</span>
          </button>
          <button
            type="button"
            className={`settings-tab-btn ${activeTab === "timers" ? "active" : ""}`}
            onClick={() => handleTabChange("timers")}
          >
            <IconClock size={13} />
            <span>{t.tabTimers}</span>
          </button>
          <button
            type="button"
            className={`settings-tab-btn ${activeTab === "appearance" ? "active" : ""}`}
            onClick={() => handleTabChange("appearance")}
          >
            <IconPalette size={13} />
            <span>{t.tabAppearance}</span>
          </button>
          <button
            type="button"
            className={`settings-tab-btn ${activeTab === "import_export" ? "active" : ""}`}
            onClick={() => handleTabChange("import_export")}
          >
            <IconQrCode size={13} />
            <span>{t.tabImportExport}</span>
          </button>
          <button
            type="button"
            className={`settings-tab-btn ${activeTab === "demo" ? "active" : ""}`}
            onClick={() => handleTabChange("demo")}
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
                      style={{ width: "auto", padding: "7px 14px", fontSize: "var(--font-size-sm)" }}
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
                        style={{ width: "auto", padding: "8px 14px", fontSize: "var(--font-size-sm)" }}
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
                        style={{ width: "auto", padding: "7px 14px", fontSize: "var(--font-size-sm)" }}
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
                    fontSize: "var(--font-size-xs-plus)",
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
                      className={`segment-btn ${currentWindowMode === "popup" ? "active" : ""}`}
                      onClick={() => handleWindowModeChange("popup")}
                    >
                      {t.windowModePopup}
                    </button>
                    <button
                      type="button"
                      className={`segment-btn ${currentWindowMode === "normal" ? "active" : ""}`}
                      onClick={() => handleWindowModeChange("normal")}
                    >
                      {t.windowModeNormal}
                    </button>
                  </div>
                </div>

                <div
                  className={`setting-block ${isNormalWindow ? "setting-block-inactive" : ""}`}
                  style={{ marginTop: "12px" }}
                >
                  <div className="card-title">{t.popupPositionTitle}</div>
                  <div className="segmented-control">
                    <button
                      type="button"
                      disabled={isNormalWindow}
                      className={`segment-btn ${windowSettings.popup_position === "top-right" ? "active" : ""}`}
                      onClick={() => handlePopupPositionChange("top-right")}
                    >
                      {t.posTopRight}
                    </button>
                    <button
                      type="button"
                      disabled={isNormalWindow}
                      className={`segment-btn ${windowSettings.popup_position === "bottom-right" ? "active" : ""}`}
                      onClick={() => handlePopupPositionChange("bottom-right")}
                    >
                      {t.posBottomRight}
                    </button>
                    <button
                      type="button"
                      disabled={isNormalWindow}
                      className={`segment-btn ${windowSettings.popup_position === "center" ? "active" : ""}`}
                      onClick={() => handlePopupPositionChange("center")}
                    >
                      {t.posCenter}
                    </button>
                  </div>
                  {isNormalWindow && (
                    <div className="form-hint" style={{ color: "var(--text-secondary)" }}>
                      {t.popupPositionInactiveHint}
                    </div>
                  )}
                </div>

                {isWayland && (
                  <div className="wayland-info-note" style={{ marginTop: "12px" }}>
                    {t.windowWaylandNote}
                  </div>
                )}
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

                <div className={`setting-row ${!isNormalWindow ? "setting-row-inactive" : ""}`} style={{ marginTop: "12px" }}>
                  <div>
                    <div className="card-title">{t.windowResizableTitle}</div>
                  </div>
                  <label className="toggle-switch">
                    <input
                      type="checkbox"
                      disabled={!isNormalWindow}
                      checked={isNormalWindow && Boolean(windowSettings.resizable)}
                      onChange={handleResizableToggle}
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
                <div style={{ fontSize: "var(--font-size-xs)", color: "var(--text-secondary)", marginTop: "6px", opacity: 0.85 }}>
                  {t.shortcutWaylandNote}
                </div>
              </div>
            </div>
          )}

          {activeTab === "import_export" && (
            <div className="settings-section">
              <div className="settings-card">
                <div className="card-header-row">
                  <div>
                    <div className="card-title">{t.importTitle}</div>
                    <div className="card-desc">{t.importDesc}</div>
                  </div>
                </div>

                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/png,image/jpeg,image/webp"
                  multiple
                  style={{ display: "none" }}
                  onChange={handleQrFilesChange}
                />

                <button
                  type="button"
                  className="secondary-action-btn"
                  onClick={() => fileInputRef.current?.click()}
                  disabled={isStagingImport || isConfirmingImport}
                >
                  <IconUpload size={15} />
                  <span>{isStagingImport ? t.importProcessing : t.importSelectQrButton}</span>
                </button>

                <div className="form-field-row">
                  <label className="form-label">{t.importOrPasteUris}</label>
                  <textarea
                    className="form-input import-uris-textarea"
                    rows={3}
                    value={urisText}
                    onChange={(e) => setUrisText(e.target.value)}
                    placeholder={t.importUrisPlaceholder}
                    disabled={isStagingImport || isConfirmingImport}
                  />
                  <div className="card-actions-row" style={{ marginTop: "4px" }}>
                    <button
                      type="button"
                      className="header-pill-btn"
                      style={{ padding: "6px 12px" }}
                      onClick={handleStageUris}
                      disabled={isStagingImport || isConfirmingImport || !urisText.trim()}
                    >
                      {isStagingImport ? t.importProcessing : t.importAnalyzeUrisButton}
                    </button>
                  </div>
                </div>

                {importError && <div className="import-error-banner">{importError}</div>}

                {importFeedback && <div className="import-success-banner">{importFeedback}</div>}

                {importPreview && (
                  <div className="sub-flow-form" style={{ marginTop: "6px" }}>
                    <div className="import-preview-header">
                      <div>
                        <div className="card-title">{t.importPreviewTitle}</div>
                        <div className="card-desc">
                          {t.importFoundSummary
                            .replace("{ready}", String(importPreview.ready_count))
                            .replace("{dup}", String(importPreview.duplicate_count))
                            .replace("{skipped}", String(importPreview.skipped_count))}
                        </div>
                      </div>
                      {nonDuplicatePreviewIndices.length > 0 && (
                        <button
                          type="button"
                          className="header-pill-btn"
                          onClick={handleToggleAllImport}
                          disabled={isConfirmingImport}
                        >
                          {allNonDuplicatesSelected ? t.importDeselectAll : t.importSelectAll}
                        </button>
                      )}
                    </div>

                    {importPreview.items.length === 0 ? (
                      <div className="card-desc">{t.importNoValidItems}</div>
                    ) : (
                      <div className="import-preview-list">
                        {importPreview.items.map((item) => {
                          const isChecked =
                            !item.is_duplicate && selectedImportIndices.includes(item.index);
                          return (
                            <label
                              key={item.index}
                              className={`import-preview-item ${
                                item.is_duplicate ? "is-duplicate" : ""
                              }`}
                            >
                              <input
                                type="checkbox"
                                className="import-preview-checkbox"
                                checked={isChecked}
                                disabled={item.is_duplicate || isConfirmingImport}
                                onChange={() => handleToggleImportIndex(item.index)}
                              />
                              <div className="import-preview-meta">
                                <div className="import-preview-title-row">
                                  <span className="import-preview-issuer">
                                    {item.issuer || item.account}
                                  </span>
                                  {item.is_duplicate && (
                                    <span className="status-badge badge-neutral">
                                      {t.importDuplicateBadge}
                                    </span>
                                  )}
                                </div>
                                <span className="import-preview-account">{item.account}</span>
                                <span className="import-preview-specs">
                                  {item.algorithm} · {item.digits} · {item.period}s
                                </span>
                              </div>
                            </label>
                          );
                        })}
                      </div>
                    )}

                    {importPreview.skipped.length > 0 && (
                      <div className="import-skipped-box">
                        <div className="import-skipped-header">
                          <IconAlertTriangle size={14} />
                          <span>
                            {t.importSkippedTitle.replace(
                              "{count}",
                              String(importPreview.skipped.length)
                            )}
                          </span>
                        </div>
                        <div className="import-skipped-list">
                          {importPreview.skipped.map((sk, idx) => (
                            <div key={idx} className="import-skipped-item">
                              <strong>{sk.source}:</strong> {sk.reason}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    <div className="card-actions-row" style={{ marginTop: "4px" }}>
                      {importPreview.items.length > 0 && (
                        <button
                          type="button"
                          className="primary-action-btn"
                          style={{
                            width: "auto",
                            padding: "7px 14px",
                            fontSize: "var(--font-size-sm)",
                            marginTop: 0,
                          }}
                          onClick={handleConfirmImport}
                          disabled={isConfirmingImport || selectedImportIndices.length === 0}
                        >
                          {isConfirmingImport
                            ? t.importConfirming
                            : t.importConfirmButton.replace(
                                "{count}",
                                String(selectedImportIndices.length)
                              )}
                        </button>
                      )}
                      <button
                        type="button"
                        className="header-pill-btn"
                        style={{ padding: "7px 12px" }}
                        onClick={handleCancelImport}
                        disabled={isConfirmingImport}
                      >
                        {t.cancelButton}
                      </button>
                    </div>
                  </div>
                )}
              </div>

              <div className="settings-card" style={{ marginTop: "10px" }}>
                <div className="card-header-row">
                  <div>
                    <div className="card-title">{t.exportTitle}</div>
                    <div className="card-desc">{t.exportDesc}</div>
                  </div>
                </div>

                <div className="export-warning-box">
                  <IconAlertTriangle size={16} />
                  <div style={{ display: "flex", flexDirection: "column", gap: "3px", minWidth: 0 }}>
                    <div style={{ fontSize: "var(--font-size-xs-plus)", fontWeight: "var(--font-weight-bold)" }}>
                      {t.exportWarningTitle}
                    </div>
                    <div style={{ fontSize: "var(--font-size-xs)", color: "var(--text-primary)", lineHeight: 1.35 }}>
                      {t.exportWarningBody}
                    </div>
                  </div>
                </div>

                <form onSubmit={handleExportQrBatches} className="sub-flow-form" style={{ marginTop: "4px" }}>
                  <label className="export-ack-label">
                    <input
                      type="checkbox"
                      checked={exportWarningAccepted}
                      onChange={(e) => setExportWarningAccepted(e.target.checked)}
                      disabled={isExporting}
                    />
                    <span>{t.exportWarningAckLabel}</span>
                  </label>

                  {requiresPasswordForExport && (
                    <div className="form-field-row">
                      <label className="form-label">{t.exportCredentialPasswordLabel}</label>
                      <input
                        type="password"
                        className="form-input"
                        placeholder={t.exportCredentialPasswordPlaceholder}
                        value={exportCredential}
                        onChange={(e) => setExportCredential(e.target.value)}
                        disabled={isExporting}
                      />
                    </div>
                  )}

                  {requiresPinForExport && (
                    <div className="form-field-row">
                      <label className="form-label">{t.exportCredentialPinLabel}</label>
                      <input
                        type="password"
                        inputMode="numeric"
                        maxLength={6}
                        className="form-input"
                        placeholder={t.exportCredentialPinPlaceholder}
                        value={exportCredential}
                        onChange={(e) =>
                          setExportCredential(e.target.value.replace(/\D/g, "").slice(0, 6))
                        }
                        disabled={isExporting}
                      />
                    </div>
                  )}

                  {exportError && <div className="import-error-banner">{exportError}</div>}

                  <div className="card-actions-row" style={{ marginTop: "2px" }}>
                    <button
                      type="submit"
                      className="primary-action-btn"
                      style={{
                        width: "auto",
                        padding: "7px 14px",
                        fontSize: "var(--font-size-sm)",
                        display: "inline-flex",
                        alignItems: "center",
                        gap: "6px",
                        marginTop: 0,
                      }}
                      disabled={
                        isExporting ||
                        !exportWarningAccepted ||
                        (requiresPasswordForExport && !exportCredential) ||
                        (requiresPinForExport && exportCredential.length !== 6)
                      }
                    >
                      <IconDownload size={14} />
                      <span>{isExporting ? t.exportGenerating : t.exportGenerateButton}</span>
                    </button>

                    {exportBatches.length > 0 && (
                      <button
                        type="button"
                        className="header-pill-btn"
                        style={{ padding: "7px 12px" }}
                        onClick={clearExportState}
                      >
                        {t.exportClearButton}
                      </button>
                    )}
                  </div>
                </form>

                {currentExportBatch && (
                  <div className="qr-viewer-card">
                    <div className="qr-viewer-frame">
                      <img
                        src={`data:image/svg+xml;utf8,${encodeURIComponent(currentExportBatch.svg)}`}
                        alt={t.exportQrAlt.replace("{current}", String(exportBatchIndex + 1))}
                        className="qr-viewer-img"
                      />
                    </div>

                    <div className="card-desc" style={{ textAlign: "center" }}>
                      {t.exportBatchAccountsCount
                        .replace("{count}", String(currentExportBatch.account_count))
                        .replace("{total}", String(exportTotalAccounts))}
                    </div>

                    <div className="qr-pagination-row">
                      <button
                        type="button"
                        className="header-pill-btn qr-nav-btn"
                        disabled={exportBatchIndex <= 0}
                        onClick={() => setExportBatchIndex((idx) => Math.max(0, idx - 1))}
                      >
                        <IconChevronLeft size={14} />
                        <span>{t.exportPrevBatch}</span>
                      </button>

                      <span className="qr-pagination-label">
                        {t.exportBatchIndicator
                          .replace("{current}", String(exportBatchIndex + 1))
                          .replace("{total}", String(exportBatches.length))}
                      </span>

                      <button
                        type="button"
                        className="header-pill-btn qr-nav-btn"
                        disabled={exportBatchIndex >= exportBatches.length - 1}
                        onClick={() =>
                          setExportBatchIndex((idx) =>
                            Math.min(exportBatches.length - 1, idx + 1)
                          )
                        }
                      >
                        <span>{t.exportNextBatch}</span>
                        <IconChevronRight size={14} />
                      </button>
                    </div>
                  </div>
                )}
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
                    style={{ width: "auto", padding: "8px 14px", fontSize: "var(--font-size-sm)", display: "inline-flex", alignItems: "center", gap: "6px" }}
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
                      fontSize: "var(--font-size-xs-plus)",
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
