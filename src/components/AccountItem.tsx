// [ENC-XOR2A::585a5e:4d4b47:58454e]
import React from "react";
import { AccountCodeDto } from "../types";
import { CountdownRing } from "./CountdownRing";
import { IconArrowUp, IconArrowDown, IconEdit, IconTrash } from "./Icons";
import { ServiceIcon } from "./ServiceIcon";

interface AccountItemProps {
  account: AccountCodeDto;
  isSelected: boolean;
  maskCodes?: boolean;
  isFirst?: boolean;
  isLast?: boolean;
  canReorder?: boolean;
  onSelect: () => void;
  onCopy: () => void;
  onEdit?: () => void;
  onDelete?: () => void;
  onMoveUp?: () => void;
  onMoveDown?: () => void;
}

export const AccountItem: React.FC<AccountItemProps> = ({
  account,
  isSelected,
  maskCodes = false,
  isFirst = false,
  isLast = false,
  canReorder = true,
  onSelect,
  onCopy,
  onEdit,
  onDelete,
  onMoveUp,
  onMoveDown,
}) => {
  const formatCode = (code: string) => {
    const raw = code.replace(/\s+/g, "");
    if (raw.length === 6) return `${raw.slice(0, 3)} ${raw.slice(3)}`;
    if (raw.length === 8) return `${raw.slice(0, 4)} ${raw.slice(4)}`;
    return raw;
  };

  const maskedDisplay = account.digits === 8 ? "•••• ••••" : "••• •••";

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
          <ServiceIcon issuer={account.issuer} size={18} />
        </div>
        <div className="account-meta">
          <span className="account-issuer">{account.issuer}</span>
          <span className="account-label">{account.account}</span>
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
        <div className="account-actions" onClick={(e) => e.stopPropagation()}>
          {onMoveUp && (
            <button
              type="button"
              className="action-icon-btn"
              disabled={isFirst || !canReorder}
              onClick={(e) => {
                e.stopPropagation();
                onMoveUp();
              }}
              title="Mover arriba"
              aria-label="Mover arriba"
            >
              <IconArrowUp size={14} />
            </button>
          )}
          {onMoveDown && (
            <button
              type="button"
              className="action-icon-btn"
              disabled={isLast || !canReorder}
              onClick={(e) => {
                e.stopPropagation();
                onMoveDown();
              }}
              title="Mover abajo"
              aria-label="Mover abajo"
            >
              <IconArrowDown size={14} />
            </button>
          )}
          {onEdit && (
            <button
              type="button"
              className="action-icon-btn"
              onClick={(e) => {
                e.stopPropagation();
                onEdit();
              }}
              title="Editar"
              aria-label="Editar"
            >
              <IconEdit size={14} />
            </button>
          )}
          {onDelete && (
            <button
              type="button"
              className="action-icon-btn action-danger"
              onClick={(e) => {
                e.stopPropagation();
                onDelete();
              }}
              title="Eliminar"
              aria-label="Eliminar"
            >
              <IconTrash size={14} />
            </button>
          )}
        </div>

        <div className={`account-code ${maskCodes ? "masked" : ""}`}>
          {maskCodes ? maskedDisplay : formatCode(account.code)}
        </div>

        <CountdownRing
          remaining={account.seconds_remaining}
          period={account.period}
          size={28}
        />
      </div>
    </div>
  );
};
