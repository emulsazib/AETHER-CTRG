// GET/POST /api/v1/ai-config — proxy the worker's AI-engine config so the
// frontend (single origin) can read availability and toggle engines on/off.
import { getAiConfig, setAiConfig } from '../services/mlClient.js';

export async function readAiConfig(req, res, next) {
  try {
    return res.json(await getAiConfig());
  } catch (err) {
    return next(err);
  }
}

export async function updateAiConfig(req, res, next) {
  try {
    const { ml_enabled, llm_enabled, osint_enabled } = req.body || {};
    return res.json(await setAiConfig({ ml_enabled, llm_enabled, osint_enabled }));
  } catch (err) {
    return next(err);
  }
}
