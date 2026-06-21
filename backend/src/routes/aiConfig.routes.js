import { Router } from 'express';
import { readAiConfig, updateAiConfig } from '../controllers/aiConfigController.js';

const router = Router();

// GET  /api/v1/ai-config  -> available + enabled engines
// POST /api/v1/ai-config  -> toggle ml_enabled / llm_enabled
router.get('/', readAiConfig);
router.post('/', updateAiConfig);

export default router;
