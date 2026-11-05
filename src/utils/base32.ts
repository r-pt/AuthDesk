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
