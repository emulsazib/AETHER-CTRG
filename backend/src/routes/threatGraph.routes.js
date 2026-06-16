import { Router } from 'express';
import { getThreatGraph } from '../controllers/threatGraphController.js';

const router = Router();

// GET /api/v1/threat-graph/:id  -> nodes/edges subgraph for the explorer
router.get('/:id', getThreatGraph);

export default router;
