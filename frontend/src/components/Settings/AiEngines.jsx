// AI Engines — let the user choose which AI systems power detection and turn
// each on/off live. The static engine is always on; ML and LLM are toggleable
// when available (model mounted / API key set).
import { useAiConfig } from '../../hooks/useAiConfig.js';
import {
  IconBrain, IconShield, IconChip, IconRefresh, IconCheck, IconAlert,
} from '../common/Icons.jsx';

function Switch({ on, disabled, onChange }) {
  return (
    <button
      type="button"
      className={`switch ${on ? 'on' : ''} ${disabled ? 'disabled' : ''}`}
      onClick={() => !disabled && onChange(!on)}
      aria-pressed={on}
    >
      <span className="knob" />
    </button>
  );
}

const ICONS = { static: IconShield, ml: IconChip, llm: IconBrain };

export default function AiEngines() {
  const { config, loading, error, saving, refresh, toggle } = useAiConfig();
  const engines = config?.engines ? ['static', 'ml', 'llm'].map((k) => config.engines[k]).filter(Boolean) : [];
  const active = engines.filter((e) => e.enabled).map((e) => e.id);

  return (
    <div>
      <div className="page-head">
        <div>
          <h1 className="page-title"><span className="accenticon"><IconChip size={22} /></span>AI Engines</h1>
          <p className="page-sub">Choose which AI systems run and toggle each on or off — live, no restart</p>
        </div>
        <button className="btn secondary" onClick={refresh}><IconRefresh size={16} />Refresh</button>
      </div>

      {error && <div className="banner crit"><span className="bico"><IconAlert size={18} /></span>{error}</div>}
      {loading && <p className="muted"><span className="scanline">▮</span> Loading engine status…</p>}

      {!loading && (
        <>
          <div className="banner safe" style={{ marginBottom: 18 }}>
            <span className="bico"><IconCheck size={18} /></span>
            Active pipeline: {active.map((id) => <span key={id} className="tag engine" style={{ marginLeft: 6 }}>{id.toUpperCase()}</span>)}
            {saving && <span className="muted" style={{ marginLeft: 10 }}>· saving…</span>}
          </div>

          <div className="grid cols-3">
            {engines.map((e) => {
              const Icon = ICONS[e.id] || IconChip;
              return (
                <div key={e.id} className={`card glow engine-card ${e.enabled ? 'enabled' : ''}`}>
                  <div className="row between" style={{ alignItems: 'flex-start' }}>
                    <div className="kpi-ico" style={{ color: e.enabled ? 'var(--accent)' : 'var(--muted-2)' }}><Icon size={20} /></div>
                    <Switch
                      on={e.enabled}
                      disabled={e.locked || !e.available}
                      onChange={(v) => toggle(e.id, v)}
                    />
                  </div>
                  <h3 style={{ margin: '14px 0 4px', fontSize: 15, color: 'var(--text)' }}>{e.name}</h3>
                  <p className="muted" style={{ fontSize: 12.5, lineHeight: 1.5, minHeight: 54 }}>{e.description}</p>
                  <div className="hr" />
                  <div className="row between">
                    {e.locked
                      ? <span className="sev benign">Always On</span>
                      : e.available
                        ? <span className={`sev ${e.enabled ? 'low' : 'unknown'}`}>{e.enabled ? 'Enabled' : 'Disabled'}</span>
                        : <span className="sev medium">Unavailable</span>}
                    <span className="muted-2" style={{ fontSize: 11 }}>{e.reason || (e.locked ? 'built-in' : '')}</span>
                  </div>
                </div>
              );
            })}
          </div>

          <div className="spacer" />
          <div className="card">
            <div className="card-head"><span className="ci"><IconBrain size={16} /></span><h3>How verdicts combine</h3></div>
            <p className="muted" style={{ fontSize: 13, lineHeight: 1.7, margin: 0 }}>
              The <strong>Static Engine</strong> always produces a baseline verdict from the real file bytes.
              When enabled, the <strong>Trained ML Classifier</strong> score is <em>ensembled</em> with it
              (definitive signature hits are preserved; the model raises the score on what signatures miss).
              The <strong>External LLM</strong> enriches IoC/TTP extraction and the summary. Each analysis is
              tagged with the engines that ran (e.g. <span className="tag" style={{ margin: 0 }}>static+ml+llm</span>).
            </p>
            <div className="spacer-sm" />
            <p className="muted-2" style={{ fontSize: 11.5 }}>
              ML unavailable? Build the worker with <span className="mono">--build-arg INSTALL_ML=true</span>, mount your
              model under <span className="mono">ml-worker/models/</span>, and set <span className="mono">CLASSIFIER_PATH</span>.
              LLM unavailable? Set <span className="mono">AI_API_KEY</span> / <span className="mono">AI_BASE_URL</span> / <span className="mono">AI_MODEL</span>.
            </p>
          </div>
        </>
      )}
    </div>
  );
}
