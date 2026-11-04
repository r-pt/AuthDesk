// [ENC-ROT13::ecg|tnz|ebq]
import React, { useState, useEffect, useRef, useMemo } from "react";
import { useTotpCodes } from "../hooks/useTotpCodes";
import { useClipboard } from "../hooks/useClipboard";
import { AccountItem } from "./AccountItem";
import { getTranslation, Language } from "../i18n";

const THEMES = ["dark", "light", "coffee"] as const;
type ThemeMode = (typeof THEMES)[number];

export const PaletteView: React.FC = () => {
  const [lang] = useState<Language>("es");
  const [theme, setTheme] = useState<ThemeMode>("dark");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const listContainerRef = useRef<HTMLDivElement>(null);

  const t = getTranslation(lang);
  const { accounts } = useTotpCodes();
  const { copyCode } = useClipboard();

  const cycleTheme = () => {
    setTheme((prev) => THEMES[(THEMES.indexOf(prev) + 1) % THEMES.length]);
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
      searchInputRef.current?.focus();
    };

    window.addEventListener("focus", handleFocus);

    let unlistenFocus: (() => void) | undefined;
    (async () => {
      try {
        const webviewModule = await import("@tauri-apps/api/webviewWindow");
        if (webviewModule.getCurrentWebviewWindow) {
          const win = webviewModule.getCurrentWebviewWindow();
          unlistenFocus = await win.listen("tauri://focus", handleFocus);
          return;
        }
      } catch {}

      try {
        const windowModule = await import("@tauri-apps/api/window");
        if (windowModule.getCurrentWindow) {
          const win = windowModule.getCurrentWindow();
          unlistenFocus = await win.listen("tauri://focus", handleFocus);
        }
      } catch {}
    })();

    searchInputRef.current?.focus();

    return () => {
      window.removeEventListener("focus", handleFocus);
      if (unlistenFocus) {
        unlistenFocus();
      }
    };
  }, []);

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

  const copyAndHide = async (code: string) => {
    await copyCode(code);
    await hidePaletteWindow();
  };

  useEffect(() => {
    const handleKeyDown = async (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        await hidePaletteWindow();
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
  }, [filteredAccounts, selectedIndex]);

  useEffect(() => {
    if (!listContainerRef.current) return;
    const items = listContainerRef.current.querySelectorAll(".account-item");
    const activeItem = items[selectedIndex] as HTMLElement | undefined;
    if (activeItem) {
      activeItem.scrollIntoView({ block: "nearest" });
    }
  }, [selectedIndex]);

  return (
    <div className="palette-container" data-theme={theme}>
      <div className="search-header">
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
          onClick={cycleTheme}
          title={theme}
          aria-label="Theme"
        >
          {theme === "dark" ? "☾" : theme === "light" ? "☀" : "☕"}
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
              onSelect={() => setSelectedIndex(index)}
              onCopy={() => copyAndHide(acc.code)}
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
    </div>
  );
};
