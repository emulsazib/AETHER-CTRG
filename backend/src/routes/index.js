// Aggregates all v1 routes under /api/v1.
import { Router } from 'express';
import ingestRoutes from './ingest.routes.js';
import analysisRoutes from './analysis.routes.js';
import threatGraphRoutes from './threatGraph.routes.js';
import feedbackRoutes from './feedback.routes.js';
import { workerHealth } from '../services/mlClient.js';
import { isMongoConnected } from '../config/mongo.js';
import { isNeo4jConnected } from '../config/neo4j.js';

const router = Router();

// Aggregated health/status — handy for the dashboard + debugging fallbacks.
router.get('/health', async (req, res) => {
  res.json({
    gateway: 'ok',
    mongo: isMongoConnected() ? 'connected' : 'in-memory-fallback',
    neo4j: isNeo4jConnected() ? 'connected' : 'in-memory-fallback',
    ml_worker: await workerHealth(),
  });
});

router.use('/ingest', ingestRoutes);
router.use('/analysis', analysisRoutes);
router.use('/threat-graph', threatGraphRoutes);
router.use('/feedback', feedbackRoutes);

export default router;
