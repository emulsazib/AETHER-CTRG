import { Router } from 'express';
import { getAnalysis, listAnalyses } from '../controllers/analysisController.js';

const router = Router();

// GET /api/v1/analysis        -> recent ingestions (dashboard)
router.get('/', listAnalyses);
// GET /api/v1/analysis/:id    -> single job status + results
router.get('/:id', getAnalysis);

export default router;
