// useIngest() — encapsulates file upload + progress tracking. Returns an
// `upload(file, sandboxMode)` action and reactive progress/status state.
import { useCallback, useState } from 'react';
import { endpoints } from '../api/client.js';

export function useIngest() {
  const [progress, setProgress] = useState(0);
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState(null); // { job_id, status, file_type, yara_hits }
  const [error, setError] = useState(null);

  const upload = useCallback(async (file, sandboxMode = 'Immediate') => {
    setUploading(true);
    setError(null);
    setProgress(0);
    setResult(null);
    try {
      const { data } = await endpoints.ingest(file, sandboxMode, setProgress);
      setResult(data);
      return data;
    } catch (err) {
      setError(err.response?.data?.error || err.message);
      throw err;
    } finally {
      setUploading(false);
    }
  }, []);

  return { upload, progress, uploading, result, error };
}
