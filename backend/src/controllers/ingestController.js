// POST /api/v1/ingest — receives a multi-modal file, detects its type, runs a
// preliminary mock YARA scan, creates a Pending job, kicks off async analysis,
// and returns the job_id immediately.
import { v4 as uuidv4 } from 'uuid';
import { detectFileType } from '../services/fileTypeDetector.js';
import { yaraScan } from '../services/yaraScan.js';
import { jobRepository } from '../repositories/jobRepository.js';
import { runAnalysis } from '../services/analysisService.js';

export async function ingest(req, res, next) {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded (field name: "file").' });
    }

    const { buffer, originalname } = req.file;
    const sandboxMode = req.body.sandbox_mode === 'Deep' ? 'Deep' : 'Immediate';

    // 1. libmagic-style file-type detection.
    const typeInfo = await detectFileType(buffer, originalname);
    // 2. Preliminary YARA scan (mock).
    const yara = yaraScan(buffer);

    // 3. Create the job in Pending state.
    const jobId = uuidv4();
    await jobRepository.create({
      job_id: jobId,
      file_name: originalname,
      file_type: typeInfo.category,
      status: 'Pending',
      sandbox_mode: sandboxMode,
      metadata: { ...typeInfo, yara },
      extracted_iocs: [],
      ttps: [],
      xai_payload: null,
    });

    // 4. Fire-and-forget the ML pipeline. Frontend polls GET /analysis/:id.
    //    (Base64 included so REAL models can access the bytes; mocks ignore it.)
    runAnalysis(jobId, {
      fileType: typeInfo.category,
      fileName: originalname,
      contentB64: buffer.toString('base64'),
      sandboxMode,
    });

    return res.status(202).json({
      job_id: jobId,
      status: 'Pending',
      file_type: typeInfo.category,
      yara_hits: yara.matched_rules,
    });
  } catch (err) {
    return next(err);
  }
}
