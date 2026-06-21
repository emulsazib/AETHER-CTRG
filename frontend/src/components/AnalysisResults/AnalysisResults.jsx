// Analysis & XAI — the full threat report for one sample. Surfaces every
// pipeline output: verdict + severity ring, AI engine source, forensic
// metadata, classified IoCs, MITRE ATT&CK coverage, CLIP steganography,
// FAISS similarity, SHAP/LIME explanations, and the analyst feedback loop.
import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useAnalysisData } from '../../hooks/useAnalysisData.js';
import { useAnalysisContext } from '../../context/AnalysisContext.jsx';
import { endpoints } from '../../api/client.js';
import XaiCharts from './XaiCharts.jsx';
import {
  severityFromScore, SEVERITY_COLOR, classifyIoC, mitreInfo, TACTIC_ORDER,
} from '../../lib/threatIntel.js';
import {
  IconScan, IconAlert, IconCheck, IconCrosshair, IconChip, IconEye,
  IconBrain, IconCopy, IconShield, IconGraph,
} from '../common/Icons.jsx';

function JobPicker() {
  const { jobs } = useAnalysisContext();
  return (
    <div>
      <div className="page-head"><div><h1 className="page-title"><span className="accenticon"><IconScan size={22} /></span>Analysis &amp; XAI</h1>
        <p className="page-sub">Select a sample to open its full threat report</p></div></div>
      <div className="card">
        {jobs.length === 0 && <div className="empty"><span className="eico"><IconScan size={34} /></span><div>No jobs yet — ingest a file first.</div></div>}
        {jobs.length > 0 && (
          <table className="data-table">
            <thead><tr><th>Sample</th><th>Type</th><th>Status</th><th /></tr></thead>
            <tbody>
              {jobs.map((j) => (
                <tr key={j.job_id}>
                  <td className="mono">{j.file_name}</td><td>{j.file_type}</td>
                  <td><span className={`badge ${j.status}`}>{j.status}</span></td>
                  <td><Link to={`/analysis/${j.job_id}`}>Open →</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function VerdictRing({ score, severity }) {
  const pct = severity.pct;
  const color = SEVERITY_COLOR[severity.level];
  return (
    <div className="ring-wrap">
      <div className="ring" style={{ background: `conic-gradient(${color} ${pct * 3.6}deg, var(--panel-2) 0deg)` }}>
        <div className="ring-inner">
          <div className="ring-score" style={{ color }}>{pct}%</div>
          <div className="ring-label">confidence</div>
        </div>
      </div>
      <div>
        <span className={`sev ${severity.level}`} style={{ fontSize: 13 }}>{severity.label}</span>
        <div className="metric" style={{ fontSize: 22, marginTop: 10, color }}>
          {score == null ? '—' : score >= 0.5 ? 'MALICIOUS' : 'BENIGN'}
        </div>
        <div className="muted-2" style={{ fontSize: 12, marginTop: 4 }}>model score {score ?? '—'}</div>
      </div>
    </div>
  );
}

function FeedbackForm({ jobId }) {
  const [label, setLabel] = useState('');
  const [actor, setActor] = useState('');
  const [notes, setNotes] = useState('');
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  async function submit(e) {
    e.preventDefault();
    setBusy(true); setErr(null);
    try {
      await endpoints.submitFeedback({
        job_id: jobId,
        correct_label: label || null,
        corrected_actor: actor || null,
        notes,
      });
      setDone(true);
    } catch (e2) { setErr(e2.response?.data?.error || e2.message); }
    finally { setBusy(false); }
  }

  if (done) return <div className="banner safe" style={{ marginBottom: 0 }}><span className="bico"><IconCheck size={18} /></span>Feedback recorded — queued for active-learning refinement.</div>;

  return (
    <form onSubmit={submit}>
      <p className="muted-2" style={{ fontSize: 12, marginTop: 0 }}>Correct the verdict to refine the model (self-learning loop).</p>
      <div className="grid cols-2" style={{ gap: 12 }}>
        <div className="field">
          <label>Correct label</label>
          <select className="input" value={label} onChange={(e) => setLabel(e.target.value)}>
            <option value="">— unchanged —</option>
            <option value="malicious">Malicious</option>
            <option value="benign">Benign</option>
          </select>
        </div>
        <div className="field">
          <label>Corrected actor</label>
          <input className="input" value={actor} onChange={(e) => setActor(e.target.value)} placeholder="e.g. APT29" />
        </div>
      </div>
      <div className="field">
        <label>Analyst notes</label>
        <textarea className="input" value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Context, IOC corrections, triage rationale…" />
      </div>
      {err && <p style={{ color: 'var(--danger)', fontSize: 12 }}>{err}</p>}
      <button className="btn" disabled={busy}>{busy ? 'Submitting…' : 'Submit Feedback'}</button>
    </form>
  );
}

export default function AnalysisResults() {
  const { jobId } = useParams();
  const { job, loading, error } = useAnalysisData(jobId);

  if (!jobId) return <JobPicker />;
  if (loading && !job) return <p className="muted"><span className="scanline">▮</span> Loading analysis…</p>;
  if (error) return <div className="banner crit"><span className="bico"><IconAlert size={18} /></span>{error}</div>;
  if (!job) return <p className="muted">Job not found.</p>;

  const features = job.features || {};
  const clustering = job.clustering || {};
  const meta = job.metadata || {};
  const stat = features.static || {};
  const score = job.xai_payload?.prediction;
  const severity = severityFromScore(score);
  const iocSource = features.ioc_extraction?.source;
  const signals = stat.signal_detail || [];
  const stego = features.steganography;
  const neighbors = clustering.neighbors || [];
  const running = job.status !== 'Completed' && job.status !== 'Failed';

  // Which AI engines produced this verdict (e.g. static / static+ml+llm).
  const engineTokens = (iocSource || 'static_engine')
    .replace('static_engine', 'static').split('+').filter(Boolean);

  // Group TTPs by ATT&CK tactic for the coverage matrix.
  const byTactic = {};
  (job.ttps || []).forEach((id) => {
    const info = mitreInfo(id);
    (byTactic[info.tactic] = byTactic[info.tactic] || []).push({ id, ...info });
  });
  const tacticCols = TACTIC_ORDER.filter((t) => byTactic[t]);

  return (
    <div>
      <div className="page-head">
        <div>
          <h1 className="page-title"><span className="accenticon"><IconScan size={22} /></span>Threat Report</h1>
          <p className="page-sub mono">{job.file_name} · {job.file_type} · {job.sandbox_mode} sandbox</p>
        </div>
        <span className={`badge ${job.status}`}>{job.status}</span>
      </div>

      {running && <div className="banner" style={{ borderColor: 'var(--border-bright)' }}><span className="bico scanline"><IconScan size={18} /></span>Pipeline running — this report auto-refreshes…</div>}

      {!running && (
        score >= 0.5
          ? <div className="banner crit"><span className="bico"><IconAlert size={18} /></span><strong>{severity.label} threat detected.</strong>&nbsp;{job.metadata?.inferred_actor ? `Attributed to ${job.metadata.inferred_actor}.` : 'No actor attribution.'}</div>
          : <div className="banner safe"><span className="bico"><IconShield size={18} /></span>No malicious behavior above threshold.</div>
      )}

      {/* Verdict + engine + forensic metadata */}
      <div className="grid sidebar-2">
        <div className="card glow">
          <div className="card-head"><span className="ci"><IconAlert size={16} /></span><h3>Verdict</h3>
            <span className="right">{engineTokens.map((t) => (
              <span key={t} className={`tag engine ${t !== 'static' ? 'live' : ''}`} style={{ marginLeft: 6 }}>{t.toUpperCase()}</span>
            ))}</span>
          </div>
          <VerdictRing score={score} severity={severity} />
        </div>

        <div className="card">
          <div className="card-head"><span className="ci"><IconChip size={16} /></span><h3>Forensic Metadata</h3></div>
          <div className="kv">
            <span className="k">SHA-256</span><span className="v">{stat.hashes?.sha256 || '—'}</span>
            <span className="k">Detected type</span><span className="v">{meta.category || job.file_type}{meta.detected_ext ? ` (.${meta.detected_ext})` : ''}</span>
            <span className="k">File size</span><span className="v">{(stat.size_bytes ?? meta.size_bytes) != null ? `${stat.size_bytes ?? meta.size_bytes} bytes` : '—'}</span>
            <span className="k">Entropy</span><span className="v">{stat.entropy != null ? `${stat.entropy} / 8.0${stat.entropy >= 7.2 ? ' (packed)' : ''}` : '—'}</span>
            <span className="k">YARA hits</span><span className="v">{(meta.yara?.matched_rules || []).join(', ') || 'none'}</span>
            <span className="k">Attribution</span><span className="v">{meta.inferred_actor || '—'}</span>
          </div>
        </div>
      </div>

      <div className="spacer" />

      {/* Real detection signals — the evidence behind the verdict */}
      <div className="card">
        <div className="card-head"><span className="ci"><IconAlert size={16} /></span><h3>Detection Signals</h3>
          <span className="right muted-2" style={{ fontSize: 11 }}>{signals.length} fired</span></div>
        {signals.length === 0 ? (
          <div className="row" style={{ gap: 8 }}><span className="sev benign">Clean</span><span className="muted">No malicious indicators matched in static analysis.</span></div>
        ) : (
          <table className="data-table">
            <thead><tr><th>Signal</th><th>Detail</th><th>TTPs</th><th style={{ width: 120 }}>Weight</th></tr></thead>
            <tbody>
              {signals.map((s, i) => (
                <tr key={`${s.feature}-${i}`}>
                  <td className="mono" style={{ color: 'var(--high)' }}>{s.feature}</td>
                  <td className="muted" style={{ fontSize: 12 }}>{s.note}</td>
                  <td>{(s.ttps || []).map((t) => <span key={t} className="tag" style={{ margin: '0 4px 4px 0' }}>{t}</span>)}</td>
                  <td><div className="simtrack"><div className="simfill" style={{ width: `${Math.round((s.weight || 0) * 100)}%`, background: s.weight >= 0.4 ? 'linear-gradient(90deg,#ff7a45,#ff3b5c)' : undefined }} /></div></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {job.summary && (
        <>
          <div className="spacer" />
          <div className="card"><div className="card-head"><span className="ci"><IconBrain size={16} /></span><h3>Analysis Summary</h3></div><p style={{ margin: 0, lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>{job.summary}</p></div>
        </>
      )}

      <div className="spacer" />

      {/* IoCs + ATT&CK */}
      <div className="grid sidebar-2">
        <div className="card">
          <div className="card-head"><span className="ci"><IconCrosshair size={16} /></span><h3>Indicators of Compromise</h3><span className="right muted-2" style={{ fontSize: 11 }}>{(job.extracted_iocs || []).length} found</span></div>
          <ul className="ioc-list">
            {(job.extracted_iocs || []).map((ioc) => {
              const t = classifyIoC(ioc);
              return (
                <li key={ioc} className="ioc-row">
                  <span className={`ioc-type ${t}`}>{t}</span>
                  <span className="val">{ioc}</span>
                  <button className="icon-btn" title="Copy" onClick={() => navigator.clipboard?.writeText(ioc)}><IconCopy size={13} /></button>
                </li>
              );
            })}
            {(job.extracted_iocs || []).length === 0 && <li className="muted">No indicators recovered.</li>}
          </ul>
        </div>

        <div className="card">
          <div className="card-head"><span className="ci"><IconChip size={16} /></span><h3>MITRE ATT&amp;CK Coverage</h3><span className="right muted-2" style={{ fontSize: 11 }}>{(job.ttps || []).length} techniques</span></div>
          {tacticCols.length === 0 ? <p className="muted">No techniques mapped.</p> : (
            <div className="attack-grid">
              {tacticCols.map((tactic) => (
                <div key={tactic} className="tactic-col">
                  <div className="tname">{tactic}</div>
                  {byTactic[tactic].map((tk) => (
                    <div key={tk.id} className="technique"><div className="tid">{tk.id}</div><div className="tdesc">{tk.name}</div></div>
                  ))}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="spacer" />

      {/* Stego (CLIP) + FAISS similarity */}
      <div className="grid cols-2">
        <div className="card">
          <div className="card-head"><span className="ci"><IconEye size={16} /></span><h3>Steganography (CLIP)</h3></div>
          {stego ? (
            <>
              <div className="row between" style={{ marginBottom: 10 }}>
                <span>Hidden payload</span>
                {stego.has_stego ? <span className="sev high">Detected</span> : <span className="sev benign">Clean</span>}
              </div>
              <div className="kv">
                <span className="k">Confidence</span><span className="v">{stego.confidence ?? '—'}</span>
                <span className="k">Technique</span><span className="v">{stego.technique || '—'}</span>
              </div>
              {stego.hidden_text && (
                <div className="banner crit" style={{ marginTop: 12, marginBottom: 0, fontFamily: 'var(--mono)', fontSize: 12 }}>
                  <span className="bico"><IconAlert size={16} /></span>{stego.hidden_text}
                </div>
              )}
            </>
          ) : <p className="muted">Not an image sample — steganography scan skipped.</p>}
          <div className="spacer-sm" />
          <p className="muted-2" style={{ fontSize: 11 }}>
            Embeddings: {features.text_embedding ? `behavioral(${features.text_embedding.embedding_dim}d)` : ''} {features.image_embedding ? `· image(${features.image_embedding.embedding_dim}d)` : ''}
          </p>
        </div>

        <div className="card">
          <div className="card-head"><span className="ci"><IconCrosshair size={16} /></span><h3>FAISS Similarity Clustering</h3></div>
          {neighbors.length === 0 ? <p className="muted">No nearest neighbors.</p> : neighbors.map((n) => (
            <div key={n.sample} className="simbar">
              <div className="simhead"><span className="name">{n.sample}</span><span className="score">{(n.score * 100).toFixed(0)}%</span></div>
              <div className="simtrack"><div className="simfill" style={{ width: `${n.score * 100}%` }} /></div>
            </div>
          ))}
          <div className="hr" />
          <div className="row between">
            <span className="muted">Est. false-positive</span>
            <span className="sev benign">{clustering.false_positive_estimate != null ? `${(clustering.false_positive_estimate * 100).toFixed(1)}%` : '—'}</span>
          </div>
          <div className="row between" style={{ marginTop: 8 }}>
            <span className="muted">Cluster</span><span className="mono">#{clustering.cluster_id ?? '—'}</span>
          </div>
        </div>
      </div>

      <div className="spacer" />

      {/* XAI */}
      <div className="card-head"><span className="ci"><IconBrain size={16} /></span><h3>Explainable AI — Feature Attribution</h3></div>
      <XaiCharts xai={job.xai_payload} />

      <div className="spacer" />

      {/* Feedback loop + graph link */}
      <div className="grid sidebar-2">
        <div className="card">
          <div className="card-head"><span className="ci"><IconCheck size={16} /></span><h3>Analyst Feedback · Self-Learning</h3></div>
          <FeedbackForm jobId={job.job_id} />
        </div>
        <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          <div className="card-head"><span className="ci"><IconGraph size={16} /></span><h3>Pivot</h3></div>
          <p className="muted" style={{ fontSize: 13 }}>Explore how this sample correlates to historical campaigns and actors in the graph.</p>
          <Link className="btn secondary" to={`/graph/sample:job:${job.job_id}`}><IconGraph size={16} />Open in Threat Graph</Link>
        </div>
      </div>
    </div>
  );
}
