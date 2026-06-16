// useAnalysisData(jobId) — fetches a job and POLLS until it reaches a terminal
// status (Completed/Failed). Components stay free of fetch logic (PRD §5.3).
import { useEffect, useState } from 'react';
import { endpoints } from '../api/client.js';

const POLL_MS = parseInt(import.meta.env.VITE_POLL_INTERVAL_MS || '2000', 10);
const TERMINAL = new Set(['Completed', 'Failed']);

export function useAnalysisData(jobId) {
  const [job, setJob] = useState(null);
  const [loading, setLoading] = useState(Boolean(jobId));
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!jobId) return undefined;
    let timer = null;
    let cancelled = false;

    async function tick() {
      try {
        const { data } = await endpoints.getAnalysis(jobId);
        if (cancelled) return;
        setJob(data);
        setLoading(false);
        // Keep polling until terminal.
        if (!TERMINAL.has(data.status)) {
          timer = setTimeout(tick, POLL_MS);
        }
      } catch (err) {
        if (cancelled) return;
        setError(err.message);
        setLoading(false);
      }
    }

    setLoading(true);
    tick();

    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [jobId]);

  return { job, loading, error };
}
