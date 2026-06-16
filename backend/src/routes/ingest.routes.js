import { Router } from 'express';
import multer from 'multer';
import { ingest } from '../controllers/ingestController.js';

// In-memory upload (max 25MB) — buffer is forwarded to detection + ML worker.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 },
});

const router = Router();

// POST /api/v1/ingest  (multipart/form-data: file=<file>, sandbox_mode=Immediate|Deep)
router.post('/', upload.single('file'), ingest);

export default router;
