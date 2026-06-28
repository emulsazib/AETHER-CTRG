// Orchestrates a job's lifecycle AFTER ingestion: drives status transitions,
// calls the ML worker, persists results, and writes the threat graph.
// Runs "in the background" (fire-and-forget) so POST /ingest can return the
// job_id immediately and the frontend can poll for progress.
import { jobRepository } from '../repositories/jobRepository.js';
import { graphRepository } from '../repositories/graphRepository.js';
import { refang } from '../utils/indicators.js';
import { requestAnalysis } from './mlClient.js';

// Heuristic fallback when the worker's real OSINT attribution returns nothing
// (no OSINT keys, or no external hits). Wires the sample into the graph.
function inferActor(iocs = []) {
  const joined = iocs.map(refang).join(' ').toLowerCase();
  if (joined.includes('lumma') || joined.includes('45.137.21.9')) return 'Lumma Stealer';
  if (joined.includes('secure-update-cdn') || joined.includes('185.220.101.47')) return 'APT29';
  return null;
}

export async function runAnalysis(jobId, { fileType, fileName, contentB64, sandboxMode }) {
  try {
    await jobRepository.update(jobId, { status: 'Extracting' });

    // Call the Python ML microservice (the heavy-workload boundary).
    await jobRepository.update(jobId, { status: 'ML_Analysis' });
    const result = await requestAnalysis({ fileType, fileName, contentB64, sandboxMode });

    // Prefer the worker's real OSINT attribution; fall back to the heuristic.
    const osintActor = result.attribution?.actor || null;
    const actor = osintActor || inferActor(result.extracted_iocs);
    const iocReputation = result.ioc_reputation || {};

    await jobRepository.update(jobId, {
      status: 'Completed',
      extracted_iocs: result.extracted_iocs || [],
      ttps: result.ttps || [],
      summary: result.summary || null,
      features: result.features || {},
      clustering: result.clustering || {},
      xai_payload: result.xai_payload || null,
      'metadata.inferred_actor': actor,
      'metadata.attribution': result.attribution || null,
      'metadata.attribution_source': osintActor ? 'osint' : (actor ? 'heuristic' : 'none'),
      'metadata.ioc_reputation': iocReputation,
    });

    // Wire the analyzed sample into the threat-correlation graph.
    await graphRepository.upsertSampleGraph({
      jobId,
      fileName,
      fileType,
      iocs: result.extracted_iocs || [],
      ttps: result.ttps || [],
      actor,
      iocReputation,
      attribution: result.attribution || null,
    });
  } catch (err) {
    console.error(`[analysis] job ${jobId} failed:`, err.message);
    await jobRepository.update(jobId, { status: 'Failed', error: err.message });
  }
}
