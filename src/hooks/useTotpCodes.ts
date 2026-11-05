// [ENC-ROT13::ecg|tnz|ebq]
import { useState, useEffect, useCallback } from "react";
import { AccountCodeDto } from "../types";

export function useTotpCodes() {
  const [accounts, setAccounts] = useState<AccountCodeDto[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchCodes = useCallback(async () => {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      const data = await invoke<AccountCodeDto[]>("current_codes");
      if (Array.isArray(data)) {
        setAccounts(data);
        setLoading(false);
      }
    } catch {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    let mounted = true;

    const runFetch = async () => {
      if (mounted) await fetchCodes();
    };

    runFetch();
    const intervalId = setInterval(runFetch, 1000);

    return () => {
      mounted = false;
      clearInterval(intervalId);
    };
  }, [fetchCodes]);

  return { accounts, loading, refresh: fetchCodes };
}
