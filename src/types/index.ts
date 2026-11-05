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

export interface VaultStatusDto {
  initialized: boolean;
  locked: boolean;
  account_count: number;
  pin_available: boolean;
  pin_enabled: boolean;
  pin_attempts_remaining: number | null;
}
