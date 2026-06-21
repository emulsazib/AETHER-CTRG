// Thin axios wrapper — the ONLY module that knows the API base URL.
// All network calls funnel through here so endpoints/auth can change in one place.
import axios from 'axios';

const baseURL = import.meta.env.VITE_API_BASE || 'http://localhost:4000/api/v1';

export const api = axios.create({ baseURL });

export const endpoints = {
  // Upload a file with progress callback. onProgress receives 0-100.
  ingest(file, sandboxMode, onProgress) {
    const form = new FormData();
    form.append('file', file);
    form.append('sandbox_mode', sandboxMode);
    return api.post('/ingest', form, {
      headers: { 'Content-Type': 'multipart/form-data' },
      onUploadProgress: (e) => {
        if (onProgress && e.total) onProgress(Math.round((e.loaded / e.total) * 100));
      },
    });
  },
  getAnalysis(id) {
    return api.get(`/analysis/${id}`);
  },
  listAnalyses(limit = 20) {
    return api.get('/analysis', { params: { limit } });
  },
  getThreatGraph(id) {
    return api.get(`/threat-graph/${id}`);
  },
  submitFeedback(payload) {
    return api.post('/feedback', payload);
  },
  health() {
    return api.get('/health');
  },
  getAiConfig() {
    return api.get('/ai-config');
  },
  setAiConfig(payload) {
    return api.post('/ai-config', payload);
  },
};
