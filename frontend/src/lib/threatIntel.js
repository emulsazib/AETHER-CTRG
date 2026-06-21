// Threat-intel helpers shared across views: MITRE ATT&CK technique lookup, IoC
// classification, and severity scoring. Pure functions, no network/state.

// --- MITRE ATT&CK: minimal local catalog for the techniques the pipeline emits.
// id -> { name, tactic }. Falls back gracefully for unknown ids.
export const MITRE = {
  'T1027': { name: 'Obfuscated Files or Information', tactic: 'Defense Evasion' },
  'T1027.003': { name: 'Steganography', tactic: 'Defense Evasion' },
  'T1055': { name: 'Process Injection', tactic: 'Defense Evasion' },
  'T1059.001': { name: 'PowerShell', tactic: 'Execution' },
  'T1059.007': { name: 'JavaScript', tactic: 'Execution' },
  'T1102': { name: 'Web Service', tactic: 'Command and Control' },
  'T1105': { name: 'Ingress Tool Transfer', tactic: 'Command and Control' },
  'T1204.002': { name: 'Malicious File', tactic: 'Execution' },
  'T1547.001': { name: 'Registry Run Keys / Startup Folder', tactic: 'Persistence' },
  'T1566.001': { name: 'Spearphishing Attachment', tactic: 'Initial Access' },
};

export function mitreInfo(id) {
  return MITRE[id] || { name: 'Unknown Technique', tactic: 'Unmapped' };
}

// Ordered ATT&CK tactics (kill-chain order) for grouping technique chips.
export const TACTIC_ORDER = [
  'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
  'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
  'Collection', 'Command and Control', 'Exfiltration', 'Impact', 'Unmapped',
];

// --- IoC classification (defanged-aware) -> a type tag for nice rendering.
export function classifyIoC(raw) {
  const v = String(raw)
    .replace(/hxxps/gi, 'https').replace(/hxxp/gi, 'http')
    .replace(/\[\.\]/g, '.').replace(/\[:\]/g, ':');
  if (/^https?:\/\//i.test(v)) return 'url';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return 'ip';
  if (/^[a-f0-9]{32}$/i.test(v)) return 'md5';
  if (/^[a-f0-9]{40}$/i.test(v)) return 'sha1';
  if (/^[a-f0-9]{64}$/i.test(v)) return 'sha256';
  if (/^\//.test(v)) return 'path';
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v)) return 'domain';
  return 'string';
}

// --- Severity from the model verdict score (0..1). Drives color + label.
export function severityFromScore(score) {
  if (score == null) return { label: 'Unknown', level: 'unknown', pct: 0 };
  const pct = Math.round(score * 100);
  if (score >= 0.8) return { label: 'Critical', level: 'critical', pct };
  if (score >= 0.6) return { label: 'High', level: 'high', pct };
  if (score >= 0.4) return { label: 'Medium', level: 'medium', pct };
  if (score >= 0.2) return { label: 'Low', level: 'low', pct };
  return { label: 'Benign', level: 'benign', pct };
}

// Color token per severity level (mirrors CSS custom props).
export const SEVERITY_COLOR = {
  critical: '#ff3b5c',
  high: '#ff7a45',
  medium: '#ffb703',
  low: '#4cc9f0',
  benign: '#2ecc71',
  unknown: '#8da2bd',
};

// Short relative-time formatter for feed timestamps.
export function timeAgo(iso) {
  if (!iso) return '—';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '—';
  const s = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
