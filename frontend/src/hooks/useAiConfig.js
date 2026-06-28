// useAiConfig() — read the AI-engine config and toggle engines on/off live.
import { useCallback, useEffect, useState } from 'react';
import { endpoints } from '../api/client.js';

export function useAiConfig() {
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [saving, setSaving] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const { data } = await endpoints.getAiConfig();
      setConfig(data);
    } catch (err) {
      setError(err.response?.data?.error || err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  // engine: 'ml' | 'llm' | 'osint' -> sends { <engine>_enabled: value }
  const toggle = useCallback(async (engine, value) => {
    setSaving(true);
    setError(null);
    try {
      const body = { [`${engine}_enabled`]: value };
      const { data } = await endpoints.setAiConfig(body);
      setConfig(data);
    } catch (err) {
      setError(err.response?.data?.error || err.message);
    } finally {
      setSaving(false);
    }
  }, []);

  return { config, loading, error, saving, refresh, toggle };
}
