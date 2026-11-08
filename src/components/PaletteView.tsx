// [ENC-ROT13::ecg|tnz|ebq]
import React, { useState, useEffect, useRef, useMemo } from "react";
import { useTotpCodes } from "../hooks/useTotpCodes";
import { useClipboard } from "../hooks/useClipboard";
import { AccountItem } from "./AccountItem";
import { AccountFormModal } from "./AccountFormModal";
import { DeleteConfirmModal } from "./DeleteConfirmModal";
import { BrandLogo } from "./BrandLogo";
import { DragBar } from "./DragBar";
import { SettingsModal } from "./SettingsModal";
import {
  IconEye,
  IconEyeOff,
  IconPlus,
  IconLock,
  IconSettings,
  IconMoon,
  IconSun,
  IconCoffee,
} from "./Icons";
import { getTranslation, Language } from "../i18n";
import { ThemeMode, AccountCodeDto } from "../types";

export interface PaletteViewProps {
  theme?: ThemeMode;
  lang?: Language;
  pinAvailable?: boolean;
  pinEnabled?: boolean;
  onCycleTheme?: () => void;
  onSelectTheme?: (theme: ThemeMode) => void;
  onSelectLang?: (lang: Language) => void;
  onLock?: () => void;
  onVaultStatusChanged?: () => void;
}

export const PaletteView: React.FC<PaletteViewProps> = ({
  theme: propTheme,
  lang: propLang,
  pinAvailable,
  pinEnabled,
  onCycleTheme,
  onSelectTheme,
  onSelectLang,
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
  const [maskCodes, setMaskCodes] = useState<boolean>(() => {
    return localStorage.getItem("authdesk_mask_codes") === "true";
  });

  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [editingAccount, setEditingAccount] = useState<AccountCodeDto | null>(null);
  const [deletingAccount, setDeletingAccount] = useState<AccountCodeDto | null>(null);

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
      searchInputRef.current?.focus();
    };

    window.addEventListener("focus", handleFocus);
    return () => window.removeEventListener("focus", handleFocus);
  }, []);

  const copyAndHide = async (code: string) => {
    const hideOnCopy = localStorage.getItem("authdesk_hide_on_copy") !== "false";
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
    if (hideOnCopy) {
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        await invoke("hide_window");
      } catch {
        try {
          const { getCurrentWindow } = await import("@tauri-apps/api/window");
          await getCurrentWindow().hide();
        } catch {}
      }
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

  return (
    <div
      className={propTheme !== undefined ? "palette-view-shell" : "palette-container"}
      data-theme={propTheme !== undefined ? undefined : theme}
    >
      <DragBar />
      <div className="search-header">
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

      <SettingsModal
        isOpen={showSettings}
        onClose={() => setShowSettings(false)}
        lang={lang}
        theme={theme}
        onSelectTheme={(th) => {
          if (onSelectTheme) onSelectTheme(th);
          else if (onCycleTheme) onCycleTheme();
        }}
        onSelectLang={(lg) => {
          if (onSelectLang) onSelectLang(lg);
        }}
        pinAvailable={pinAvailable ?? false}
        pinEnabled={pinEnabled ?? false}
        onVaultStatusChanged={() => {
          if (onVaultStatusChanged) onVaultStatusChanged();
        }}
        onRefreshAccounts={() => {
          refresh();
        }}
      />

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
