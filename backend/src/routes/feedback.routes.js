import { Router } from 'express';
import { submitFeedback } from '../controllers/feedbackController.js';

const router = Router();

// POST /api/v1/feedback  -> capture analyst correction (self-learning loop)
router.post('/', submitFeedback);

export default router;
