// [ENC-B64::cnB0|Z2Ft|cm9k]
export interface AccountCodeDto {
  id: string;
  issuer: string;
  account: string;
  code: string;
  seconds_remaining: number;
  period: number;
  digits: number;
  algorithm: string;
}

export interface AccountSummaryDto {
  id: string;
  issuer: string;
  account: string;
  digits: number;
  period: number;
  algorithm: string;
  account_type: string;
}

export interface AddAccountReq {
  issuer: string;
  account: string;
  secret: string;
  algorithm?: string;
  digits?: number;
  period?: number;
}

export interface UpdateAccountReq {
  id: string;
  issuer: string;
  account: string;
  secret?: string | null;
  algorithm?: string;
  digits?: number;
  period?: number;
}

export type Language = "es" | "en";

export type ThemeMode = "dark" | "light" | "coffee";

export type SettingsTab =
  | "security"
  | "window"
  | "timers"
  | "appearance"
  | "import_export"
  | "demo";

export interface QrImageInputDto {
  name: string;
  bytes: number[];
}

export interface ImportPreviewItemDto {
  index: number;
  issuer: string;
  account: string;
  algorithm: "SHA1" | "SHA256" | "SHA512";
  digits: number;
  period: number;
  is_duplicate: boolean;
}

export interface ImportSkippedItemDto {
  source: string;
  reason: string;
}

export interface ImportPreviewResultDto {
  items: ImportPreviewItemDto[];
  skipped: ImportSkippedItemDto[];
  total_found: number;
  ready_count: number;
  duplicate_count: number;
  skipped_count: number;
}

export interface ImportConfirmResultDto {
  imported_count: number;
  skipped_duplicates: number;
}

export interface ExportQrBatchDto {
  batch_index: number;
  batch_size: number;
  account_count: number;
  svg: string;
}

export interface ExportQrResultDto {
  batches: ExportQrBatchDto[];
  total_accounts: number;
}

export interface VaultStatusDto {
  initialized: boolean;
  locked: boolean;
  account_count: number;
  pin_available: boolean;
  pin_enabled: boolean;
  pin_attempts_remaining: number | null;
  passwordless: boolean;
}

export type WindowMode = "popup" | "normal";

export interface WindowSettingsDto {
  mode: WindowMode | string;
  popup_position: string;
  always_on_top: boolean;
  auto_hide_on_blur: boolean;
  hide_on_copy: boolean;
  resizable: boolean;
}

export const DEFAULT_WINDOW_SETTINGS: WindowSettingsDto = {
  mode: "popup",
  popup_position: "top-right",
  always_on_top: true,
  auto_hide_on_blur: false,
  hide_on_copy: true,
  resizable: false,
};

export function normalizeWindowMode(mode?: unknown): WindowMode {
  if (typeof mode !== "string") return "popup";
  const normalized = mode.trim().toLowerCase();
  if (normalized === "normal" || normalized === "taskbar") {
    return "normal";
  }
  if (normalized === "popup" || normalized === "floating" || normalized === "tray-popup") {
    return "popup";
  }
  return "popup";
}

export function parseStoredWindowSettings(
  raw: string | null,
  fallback: WindowSettingsDto = DEFAULT_WINDOW_SETTINGS
): WindowSettingsDto | null {
  if (!raw) return null;
  try {
    const val: unknown = JSON.parse(raw);
    if (!val || typeof val !== "object" || Array.isArray(val)) {
      return null;
    }
    const obj = val as Record<string, unknown>;
    return {
      mode: normalizeWindowMode(obj.mode),
      popup_position:
        typeof obj.popup_position === "string" && obj.popup_position.trim()
          ? obj.popup_position
          : fallback.popup_position,
      always_on_top:
        typeof obj.always_on_top === "boolean"
          ? obj.always_on_top
          : fallback.always_on_top,
      auto_hide_on_blur:
        typeof obj.auto_hide_on_blur === "boolean"
          ? obj.auto_hide_on_blur
          : fallback.auto_hide_on_blur,
      hide_on_copy:
        typeof obj.hide_on_copy === "boolean"
          ? obj.hide_on_copy
          : fallback.hide_on_copy,
      resizable:
        typeof obj.resizable === "boolean"
          ? obj.resizable
          : fallback.resizable,
    };
  } catch {
    return null;
  }
}
