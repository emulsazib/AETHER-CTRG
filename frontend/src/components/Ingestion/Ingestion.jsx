// Data Ingestion Interface — drag-and-drop upload, progress bar, and an
// Immediate/Deep sandbox toggle. Upload logic lives in useIngest().
import { useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useIngest } from '../../hooks/useIngest.js';
import { useAnalysisContext } from '../../context/AnalysisContext.jsx';

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
    // Jump to the live analysis view for the new job.
    if (res?.job_id) navigate(`/analysis/${res.job_id}`);
  }

  function onDrop(e) {
    e.preventDefault();
    setDragging(false);
    handleFile(e.dataTransfer.files?.[0]);
  }

  return (
    <div>
      <h1 className="page-title">Data Ingestion</h1>

      <div className="card">
        <div className="row" style={{ justifyContent: 'space-between', marginBottom: 16 }}>
          <span className="muted">Sandbox mode</span>
          <div className="toggle">
            {['Immediate', 'Deep'].map((m) => (
              <button
                key={m}
                className={sandboxMode === m ? 'active' : ''}
                onClick={() => setSandboxMode(m)}
              >
                {m}
              </button>
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
          <input
            ref={inputRef}
            type="file"
            hidden
            onChange={(e) => handleFile(e.target.files?.[0])}
          />
          <p style={{ fontSize: 18, margin: 0 }}>Drag &amp; drop a file here</p>
          <p className="muted">PDF · JavaScript · Images · Archives — or click to browse</p>
          {fileName && <p className="mono">{fileName}</p>}
        </div>

        {uploading && (
          <>
            <div className="spacer" />
            <div className="progress-track">
              <div className="progress-fill" style={{ width: `${progress}%` }} />
            </div>
            <p className="muted">Uploading… {progress}%</p>
          </>
        )}

        {error && <p style={{ color: 'var(--danger)' }}>Error: {error}</p>}

        {result && (
          <div style={{ marginTop: 16 }}>
            <p>
              Ingested as <span className="badge Completed">{result.file_type}</span>{' '}
              — job <span className="mono">{result.job_id}</span>
            </p>
            {result.yara_hits?.length > 0 && (
              <p className="muted">
                Preliminary YARA: {result.yara_hits.map((r) => <span key={r} className="tag">{r}</span>)}
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
