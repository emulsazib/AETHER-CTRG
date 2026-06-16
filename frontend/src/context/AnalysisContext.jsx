// Global analysis state via Context API. Holds the recent-jobs list and exposes
// a refresh action. Component-level polling lives in hooks (useAnalysisData) so
// this stays lean — components consume state, hooks own fetching (PRD §5.3).
import { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { endpoints } from '../api/client.js';

const AnalysisContext = createContext(null);

export function AnalysisProvider({ children }) {
  const [jobs, setJobs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const refreshJobs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const { data } = await endpoints.listAnalyses(25);
      setJobs(data.jobs || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshJobs();
  }, [refreshJobs]);

  return (
    <AnalysisContext.Provider value={{ jobs, loading, error, refreshJobs }}>
      {children}
    </AnalysisContext.Provider>
  );
}

export function useAnalysisContext() {
  const ctx = useContext(AnalysisContext);
  if (!ctx) throw new Error('useAnalysisContext must be used within AnalysisProvider');
  return ctx;
}
