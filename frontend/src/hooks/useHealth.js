// useHealth() — polls the gateway /health endpoint so the shell can show live
// system status (gateway, mongo, neo4j, ml-worker). Lightweight; 10s cadence.
import { useEffect, useState } from 'react';
import { endpoints } from '../api/client.js';

const POLL_MS = 10000;

export function useHealth() {
  const [health, setHealth] = useState(null);
  const [online, setOnline] = useState(false);

  useEffect(() => {
    let timer = null;
    let cancelled = false;

    async function tick() {
      try {
        const { data } = await endpoints.health();
        if (cancelled) return;
        setHealth(data);
        setOnline(true);
      } catch {
        if (cancelled) return;
        setHealth(null);
        setOnline(false);
      } finally {
        if (!cancelled) timer = setTimeout(tick, POLL_MS);
      }
    }

    tick();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, []);

  return { health, online };
}
