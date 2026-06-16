// Express app assembly: middleware + routes + error handler.
// Kept separate from server.js so it can be imported in tests without binding
// a port.
import express from 'express';
import cors from 'cors';
import { config } from './config/env.js';
import apiRoutes from './routes/index.js';

export function createApp() {
  const app = express();

  app.use(cors({ origin: config.corsOrigins, credentials: true }));
  app.use(express.json({ limit: '5mb' }));

  app.get('/', (req, res) => res.json({ service: 'AETHER API Gateway', version: '0.1.0' }));

  app.use('/api/v1', apiRoutes);

  // 404
  app.use((req, res) => res.status(404).json({ error: 'Not found' }));

  // Centralized error handler.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    console.error('[error]', err);
    res.status(err.status || 500).json({ error: err.message || 'Internal server error' });
  });

  return app;
}
