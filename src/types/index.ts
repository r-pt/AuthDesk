// src/types/index.ts
// Definiciones de tipos para el frontend de AuthDesk.
// REGLA CRÍTICA: Ningún secreto ni contraseña maestra se expone en estos tipos.

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

export type Language = "es" | "en";
