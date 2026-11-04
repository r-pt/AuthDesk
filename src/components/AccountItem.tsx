// [ENC-XOR2A::585a5e:4d4b47:58454e]
import React from "react";
import { AccountCodeDto } from "../types";
import { CountdownRing } from "./CountdownRing";

interface AccountItemProps {
  account: AccountCodeDto;
  isSelected: boolean;
  onSelect: () => void;
  onCopy: () => void;
}

export const AccountItem: React.FC<AccountItemProps> = ({
  account,
  isSelected,
  onSelect,
  onCopy,
}) => {
  const formatCode = (code: string) => {
    const raw = code.replace(/\s+/g, "");
    if (raw.length === 6) return `${raw.slice(0, 3)} ${raw.slice(3)}`;
    if (raw.length === 8) return `${raw.slice(0, 4)} ${raw.slice(4)}`;
    return raw;
  };

  return (
    <div
      className={`account-item ${isSelected ? "selected" : ""}`}
      onClick={() => {
        onSelect();
        onCopy();
      }}
      role="button"
      tabIndex={0}
      onKeyDown={(e: React.KeyboardEvent<HTMLDivElement>) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect();
          onCopy();
        }
      }}
    >
      <div className="account-left">
        <div className="account-avatar" aria-hidden="true">
          {(account.issuer || "?").charAt(0).toUpperCase()}
        </div>
        <div className="account-meta">
          <span className="account-issuer">{account.issuer}</span>
          <span className="account-label">{account.account}</span>
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
        <div className="account-code">{formatCode(account.code)}</div>
        <CountdownRing
          remaining={account.seconds_remaining}
          period={account.period}
          size={28}
        />
      </div>
    </div>
  );
};
