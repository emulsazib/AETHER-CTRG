// useThreatGraph(id) — fetches the correlation subgraph for a sample/actor/job.
import { useEffect, useState } from 'react';
import { endpoints } from '../api/client.js';

export function useThreatGraph(id) {
  const [graph, setGraph] = useState({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!id) return undefined;
    let cancelled = false;
    setLoading(true);
    setError(null);

    endpoints
      .getThreatGraph(id)
      .then(({ data }) => {
        if (!cancelled) setGraph({ nodes: data.nodes || [], edges: data.edges || [] });
      })
      .catch((err) => !cancelled && setError(err.message))
      .finally(() => !cancelled && setLoading(false));

    return () => {
      cancelled = true;
    };
  }, [id]);

  return { graph, loading, error };
}
