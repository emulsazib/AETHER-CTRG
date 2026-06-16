// =============================================================================
// ML worker client — the ONLY place the gateway talks to the Python service.
// If you change transport (REST -> gRPC / queue), change just this file.
// =============================================================================
import axios from 'axios';
import { config } from '../config/env.js';

const client = axios.create({
  baseURL: config.mlWorkerUrl,
  timeout: config.mlWorkerTimeoutMs,
});

// POST /analyze on the FastAPI worker. Returns the combined analysis payload.
export async function requestAnalysis({ fileType, fileName, contentB64, sandboxMode }) {
  const { data } = await client.post('/analyze', {
    file_type: fileType,
    file_name: fileName,
    content_b64: contentB64,
    sandbox_mode: sandboxMode,
  });
  return data;
}

export async function workerHealth() {
  try {
    const { data } = await client.get('/health');
    return data;
  } catch (err) {
    return { status: 'unreachable', error: err.message };
  }
}
