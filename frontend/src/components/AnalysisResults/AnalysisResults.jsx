// Analysis Results & XAI View. Polls a job via useAnalysisData and renders:
//   - status + summary, static/dynamic features, extracted IoCs & TTPs
//   - SHAP/LIME charts (XaiCharts)
// If no :jobId is in the route, shows a picker from recent jobs.
import { Link, useParams } from 'react-router-dom';
import { useAnalysisData } from '../../hooks/useAnalysisData.js';
import { useAnalysisContext } from '../../context/AnalysisContext.jsx';
import XaiCharts from './XaiCharts.jsx';

function JobPicker() {
  const { jobs } = useAnalysisContext();
  return (
    <div className="card">
      <h3>Select a job to inspect</h3>
      {jobs.length === 0 && <p className="muted">No jobs yet — ingest a file first.</p>}
      <ul className="ioc-list">
        {jobs.map((j) => (
          <li key={j.job_id}>
            <Link to={`/analysis/${j.job_id}`}>
              {j.file_name} — {j.file_type} <span className={`badge ${j.status}`}>{j.status}</span>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function AnalysisResults() {
  const { jobId } = useParams();
  const { job, loading, error } = useAnalysisData(jobId);

  if (!jobId) {
    return (
      <div>
        <h1 className="page-title">Analysis &amp; XAI</h1>
        <JobPicker />
      </div>
    );
  }

  if (loading && !job) return <p className="muted">Loading analysis…</p>;
  if (error) return <p style={{ color: 'var(--danger)' }}>Error: {error}</p>;
  if (!job) return <p className="muted">Job not found.</p>;

  const features = job.features || {};
  const clustering = job.clustering || {};

  return (
    <div>
      <h1 className="page-title">
        Analysis — <span className="mono">{job.file_name}</span>{' '}
        <span className={`badge ${job.status}`}>{job.status}</span>
      </h1>

      {job.status !== 'Completed' && job.status !== 'Failed' && (
        <p className="muted">Pipeline running… this view auto-refreshes.</p>
      )}

      <div className="grid cols-3">
        <div className="card">
          <h3>Verdict</h3>
          <div className={`metric ${job.xai_payload?.predicted_label === 'malicious' ? 'warn' : 'good'}`}>
            {job.xai_payload?.predicted_label || '—'}
          </div>
          <span className="muted">score {job.xai_payload?.prediction ?? '—'}</span>
        </div>
        <div className="card">
          <h3>Similarity (FAISS)</h3>
          <div className="metric">{clustering.neighbors?.[0]?.score ?? '—'}</div>
          <span className="muted">nearest: {clustering.neighbors?.[0]?.sample || '—'}</span>
        </div>
        <div className="card">
          <h3>Est. False Positive</h3>
          <div className="metric good">
            {clustering.false_positive_estimate != null
              ? `${(clustering.false_positive_estimate * 100).toFixed(1)}%`
              : '—'}
          </div>
          <span className="muted">cluster #{clustering.cluster_id ?? '—'}</span>
        </div>
      </div>

      <div className="spacer" />

      {job.summary && (
        <div className="card">
          <h3>Summary</h3>
          <p>{job.summary}</p>
        </div>
      )}

      <div className="spacer" />

      <div className="grid cols-2">
        <div className="card">
          <h3>Extracted IoCs</h3>
          <ul className="ioc-list">
            {(job.extracted_iocs || []).map((ioc) => <li key={ioc}>{ioc}</li>)}
            {(job.extracted_iocs || []).length === 0 && <li className="muted">none</li>}
          </ul>
        </div>
        <div className="card">
          <h3>MITRE ATT&amp;CK TTPs</h3>
          <div>
            {(job.ttps || []).map((t) => <span key={t} className="tag">{t}</span>)}
            {(job.ttps || []).length === 0 && <span className="muted">none</span>}
          </div>
          <div className="spacer" />
          <h3>Static / Dynamic Features</h3>
          <p className="mono" style={{ fontSize: 11 }}>
            {features.text_embedding && `behavioral embedding dim=${features.text_embedding.embedding_dim} · `}
            {features.image_embedding && `image embedding dim=${features.image_embedding.embedding_dim} · `}
            {features.steganography &&
              `stego=${features.steganography.has_stego} (${features.steganography.confidence})`}
          </p>
          {features.steganography?.hidden_text && (
            <p className="mono" style={{ color: 'var(--warn)' }}>
              hidden: {features.steganography.hidden_text}
            </p>
          )}
        </div>
      </div>

      <div className="spacer" />

      <XaiCharts xai={job.xai_payload} />

      <div className="spacer" />
      <Link className="btn secondary" to={`/graph/sample:job:${job.job_id}`}>
        View in Threat Graph →
      </Link>
    </div>
  );
}
