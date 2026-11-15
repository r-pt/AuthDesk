// [ENC-B64::cnB0|Z2Ft|cm9k]
export interface Base32ValidationResult {
  valid: boolean;
  cleanLength: number;
  error?: string;
  invalidChar?: string;
}

export function validateBase32(input: string): Base32ValidationResult {
  const trimmed = input.trim();
  if (!trimmed) {
    return { valid: false, cleanLength: 0 };
  }

  const cleaned = trimmed.replace(/[\s\t\r\n\-]/g, "").toUpperCase();
  const unpadded = cleaned.replace(/=+$/, "");

  if (unpadded.length === 0) {
    return { valid: false, cleanLength: 0, error: "empty" };
  }

  const invalidMatch = unpadded.match(/[^A-Z2-7]/);
  if (invalidMatch) {
    return {
      valid: false,
      cleanLength: unpadded.length,
      error: "invalid_char",
      invalidChar: invalidMatch[0],
    };
  }

  const rem = unpadded.length % 8;
  if (rem === 1 || rem === 3 || rem === 6) {
    return {
      valid: false,
      cleanLength: unpadded.length,
      error: "invalid_length",
    };
  }

  return { valid: true, cleanLength: unpadded.length };
}

export interface ParsedOtpAuthUri {
  issuer: string;
  account: string;
  secret: string;
  algorithm: "SHA1" | "SHA256" | "SHA512";
  digits: 6 | 8;
  period: number;
}

export function parseOtpAuthUri(input: string): ParsedOtpAuthUri | null {
  const trimmed = input.trim();
  if (!/^otpauth:\/\/totp\//i.test(trimmed)) {
    return null;
  }

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return null;
  }

  if (
    url.protocol.toLowerCase() !== "otpauth:" ||
    url.hostname.toLowerCase() !== "totp"
  ) {
    return null;
  }

  const getParam = (name: string): string | null => {
    const direct = url.searchParams.get(name);
    if (direct !== null) return direct;
    const lower = name.toLowerCase();
    for (const [k, v] of url.searchParams.entries()) {
      if (k.toLowerCase() === lower) return v;
    }
    return null;
  };

  const rawSecret = getParam("secret");
  if (!rawSecret) {
    return null;
  }

  const secret = rawSecret.replace(/[\s\t\r\n\-]/g, "").toUpperCase();
  if (!secret || secret.replace(/=+$/, "").length === 0) {
    return null;
  }

  const rawPath = url.pathname.startsWith("/") ? url.pathname.slice(1) : url.pathname;
  let decodedLabel = rawPath;
  try {
    decodedLabel = decodeURIComponent(rawPath);
  } catch {
    decodedLabel = rawPath;
  }

  const queryIssuer = (getParam("issuer") ?? "").trim();
  let labelIssuer = "";
  let labelAccount = decodedLabel.trim();

  if (queryIssuer && decodedLabel.startsWith(`${queryIssuer}:`)) {
    labelIssuer = queryIssuer;
    labelAccount = decodedLabel.slice(queryIssuer.length + 1).trim();
  } else {
    const colonIndex = decodedLabel.indexOf(":");
    if (colonIndex !== -1) {
      labelIssuer = decodedLabel.slice(0, colonIndex).trim();
      labelAccount = decodedLabel.slice(colonIndex + 1).trim();
    }
  }

  const issuer = queryIssuer || labelIssuer;
  const account = labelAccount;

  const rawAlgorithm = (getParam("algorithm") ?? "").trim().toUpperCase();
  const algorithm: "SHA1" | "SHA256" | "SHA512" =
    rawAlgorithm === "SHA256" || rawAlgorithm === "SHA512"
      ? rawAlgorithm
      : "SHA1";

  const rawDigits = (getParam("digits") ?? "").trim();
  const digits: 6 | 8 = rawDigits === "8" ? 8 : 6;

  const rawPeriod = (getParam("period") ?? "").trim();
  let period = 30;
  if (/^\d+$/.test(rawPeriod)) {
    const parsedPeriod = parseInt(rawPeriod, 10);
    if (parsedPeriod > 0) {
      period = Math.min(300, Math.max(5, parsedPeriod));
    }
  }

  return {
    issuer,
    account,
    secret,
    algorithm,
    digits,
    period,
  };
}
