// [ENC-ROT13::ecg|tnz|ebq]
import { useState, useEffect } from "react";
import { AccountCodeDto } from "../types";

export function useTotpCodes() {
  const [accounts, setAccounts] = useState<AccountCodeDto[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;

    const fetchCodes = async () => {
      try {
        const { invoke } = await import("@tauri-apps/api/core");
        const data = await invoke<AccountCodeDto[]>("current_codes");
        if (mounted && Array.isArray(data)) {
          setAccounts(data);
          setLoading(false);
        }
      } catch {
        if (mounted) {
          setLoading(false);
        }
      }
    };

    fetchCodes();
    const intervalId = setInterval(fetchCodes, 1000);

    return () => {
      mounted = false;
      clearInterval(intervalId);
    };
  }, []);

  return { accounts, loading };
}
