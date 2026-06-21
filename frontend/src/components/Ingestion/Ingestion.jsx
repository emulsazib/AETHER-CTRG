// Ingestion — drag-and-drop multi-modal uploader with sandbox mode and a live
// pipeline stage indicator. Upload logic lives in useIngest().
import { useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useIngest } from '../../hooks/useIngest.js';
import { useAnalysisContext } from '../../context/AnalysisContext.jsx';
import { IconUpload, IconScan, IconCheck, IconAlert } from '../common/Icons.jsx';

const FORMATS = [
  { k: 'PDF', d: 'Embedded streams, JS actions' },
  { k: 'JavaScript', d: 'Deobfuscation, API calls' },
  { k: 'Images', d: 'CLIP steganography scan' },
  { k: 'Archives', d: 'Unpack + behavioral seq.' },
];

const PIPELINE = ['Upload', 'File-Type Detection', 'YARA Scan', 'Feature Extraction', 'AI / LLM Analysis', 'Attribution'];

export default function Ingestion() {
  const { upload, progress, uploading, result, error } = useIngest();
  const { refreshJobs } = useAnalysisContext();
  const navigate = useNavigate();

  const [dragging, setDragging] = useState(false);
  const [sandboxMode, setSandboxMode] = useState('Immediate');
  const [fileName, setFileName] = useState(null);
  const inputRef = useRef(null);

  async function handleFile(file) {
    if (!file) return;
    setFileName(file.name);
    const res = await upload(file, sandboxMode);
    await refreshJobs();
    if (res?.job_id) setTimeout(() => navigate(`/analysis/${res.job_id}`), 700);
  }

  function onDrop(e) {
    e.preventDefault();
    setDragging(false);
    handleFile(e.dataTransfer.files?.[0]);
  }

  return (
    <div>
      <div className="page-head">
        <div>
          <h1 className="page-title"><span className="accenticon"><IconUpload size={22} /></span>Sample Ingestion</h1>
          <p className="page-sub">Submit cross-format artifacts for automated static &amp; dynamic analysis</p>
        </div>
      </div>

      <div className="grid sidebar-2">
        <div className="card glow">
          <div className="row between" style={{ marginBottom: 16 }}>
            <span className="muted" style={{ fontSize: 12, fontWeight: 700, letterSpacing: .5, textTransform: 'uppercase' }}>Sandbox Detonation Mode</span>
            <div className="toggle">
              {['Immediate', 'Deep'].map((m) => (
                <button key={m} className={sandboxMode === m ? 'active' : ''} onClick={() => setSandboxMode(m)}>{m}</button>
              ))}
            </div>
          </div>

          <div
            className={`dropzone ${dragging ? 'drag' : ''}`}
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
            onClick={() => inputRef.current?.click()}
          >
            <input ref={inputRef} type="file" hidden onChange={(e) => handleFile(e.target.files?.[0])} />
            <span className="dz-ico"><IconUpload size={40} /></span>
            <p style={{ fontSize: 18, margin: 0, color: 'var(--text)', fontWeight: 600 }}>Drop a sample to begin analysis</p>
            <p className="muted">PDF · JavaScript · Images · Archives — or click to browse</p>
            {fileName && <p className="mono" style={{ color: 'var(--accent)' }}>{fileName}</p>}
          </div>

          {uploading && (
            <>
              <div className="spacer" />
              <div className="progress-track"><div className="progress-fill" style={{ width: `${progress}%` }} /></div>
              <p className="muted" style={{ marginBottom: 0 }}><span className="scanline">▮</span> Uploading &amp; dispatching to pipeline… {progress}%</p>
            </>
          )}

          {error && <div className="banner crit" style={{ marginTop: 16, marginBottom: 0 }}><span className="bico"><IconAlert size={18} /></span>Ingestion error: {error}</div>}

          {result && (
            <div className="banner safe" style={{ marginTop: 16, marginBottom: 0 }}>
              <span className="bico"><IconCheck size={18} /></span>
              <div>
                Accepted as <strong>{result.file_type}</strong> · job <span className="mono">{result.job_id?.slice(0, 8)}</span>
                {result.yara_hits?.length > 0 && (
                  <div style={{ marginTop: 6 }}>{result.yara_hits.map((r) => <span key={r} className="tag">{r}</span>)}</div>
                )}
              </div>
            </div>
          )}

          <div className="stages">
            {PIPELINE.map((s, i) => {
              const state = !result && !uploading ? '' : uploading && i === 0 ? 'active' : (result ? 'done' : '');
              return <span key={s} className={`stage ${state}`}><span className="sdot" />{s}</span>;
            })}
          </div>
        </div>

        <div className="card">
          <div className="card-head"><span className="ci"><IconScan size={16} /></span><h3>Supported Modalities</h3></div>
          {FORMATS.map((f) => (
            <div key={f.k} className="row between" style={{ padding: '11px 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ fontWeight: 600 }}>{f.k}</span>
              <span className="muted" style={{ fontSize: 12 }}>{f.d}</span>
            </div>
          ))}
          <div className="spacer" />
          <p className="muted-2" style={{ fontSize: 11.5, lineHeight: 1.6 }}>
            <strong>Immediate</strong> runs static + AI extraction. <strong>Deep</strong> additionally annotates for dynamic sandbox detonation. All processing is local except the configured external LLM endpoint.
          </p>
        </div>
      </div>
    </div>
  );
}
