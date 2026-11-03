import React, { useState, useEffect, useRef } from "react";
import { getTranslation, Language } from "./i18n";
import "./styles/global.css";

interface AccountPlaceholder {
  id: string;
  issuer: string;
  label: string;
  code: string;
  period: number;
}

const INITIAL_ACCOUNTS: AccountPlaceholder[] = [
  { id: "1", issuer: "GitHub", label: "rod@authdesk.local", code: "382 194", period: 30 },
  { id: "2", issuer: "Google Workspace", label: "admin@corp.io", code: "740 519", period: 30 },
  { id: "3", issuer: "AWS Production", label: "security-team", code: "912 841", period: 30 },
  { id: "4", issuer: "Cloudflare", label: "ops@domain.net", code: "105 628", period: 30 },
];

export const App: React.FC = () => {
  const [lang] = useState<Language>("es");
  const [search, setSearch] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const t = getTranslation(lang);

  const filteredAccounts = INITIAL_ACCOUNTS.filter(
    (acc) =>
      acc.issuer.toLowerCase().includes(search.toLowerCase()) ||
      acc.label.toLowerCase().includes(search.toLowerCase())
  );

  useEffect(() => {
    searchInputRef.current?.focus();
  }, []);

  useEffect(() => {
    setSelectedIndex(0);
  }, [search]);

  // Manejo de atajos de teclado locales: Esc, Enter, Flechas
  useEffect(() => {
    const handleKeyDown = async (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        try {
          const { invoke } = await import("@tauri-apps/api/core");
          await invoke("hide_window");
        } catch {
          // Entorno no-Tauri o modo navegador de desarrollo
        }
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
          const acc = filteredAccounts[selectedIndex];
          try {
            const { invoke } = await import("@tauri-apps/api/core");
            await invoke("copy_and_hide", {
              payload: {
                account_id: acc.id,
                code: acc.code.replace(/\s+/g, ""),
              },
            });
          } catch {
            // Entorno de prueba o navegador
            if (navigator.clipboard) {
              await navigator.clipboard.writeText(acc.code.replace(/\s+/g, ""));
            }
          }
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [filteredAccounts, selectedIndex]);

  return (
    <div className="palette-container">
      <div className="search-header">
        <input
          ref={searchInputRef}
          type="text"
          className="search-input"
          placeholder={t.searchPlaceholder}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      <div className="account-list">
        {filteredAccounts.length === 0 ? (
          <div style={{ textAlign: "center", padding: "24px", color: "#6b7280", fontSize: "13px" }}>
            {t.emptyAccounts}
          </div>
        ) : (
          filteredAccounts.map((acc, index) => (
            <div
              key={acc.id}
              className={`account-item ${index === selectedIndex ? "selected" : ""}`}
              onClick={() => setSelectedIndex(index)}
            >
              <div className="account-meta">
                <span className="account-issuer">{acc.issuer}</span>
                <span className="account-label">{acc.label}</span>
              </div>
              <div className="account-code">{acc.code}</div>
            </div>
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

export default App;
