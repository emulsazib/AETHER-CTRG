// =============================================================================
// MOCK YARA scanner.
// Real replacement: shell out to the `yara` binary or use a yara node binding,
// loading a ruleset directory. Keep the return shape { matched_rules, hits }.
// =============================================================================
// This mock applies a few naive regex "rules" over the raw bytes so ingestion
// produces believable preliminary signals before the ML pipeline runs.

const MOCK_RULES = [
  { name: 'SUSP_EncodedPowerShell', pattern: /powershell\s+-(?:enc|e|encodedcommand)/i },
  { name: 'SUSP_EvalObfuscation', pattern: /eval\s*\(\s*(?:atob|unescape|String\.fromCharCode)/i },
  { name: 'SUSP_PDF_OpenAction', pattern: /\/OpenAction|\/JavaScript/ },
  { name: 'SUSP_Base64Blob', pattern: /[A-Za-z0-9+/]{120,}={0,2}/ },
  { name: 'SUSP_KnownC2Marker', pattern: /(secure-update-cdn|lumma-gate|asyncrat-panel)/i },
];

export function yaraScan(buffer) {
  // Inspect a bounded text view of the file (first 256 KB) for performance.
  const text = buffer.slice(0, 262144).toString('latin1');
  const hits = [];
  for (const rule of MOCK_RULES) {
    if (rule.pattern.test(text)) hits.push(rule.name);
  }
  return {
    engine: 'mock-yara',
    matched_rules: hits,
    hit_count: hits.length,
  };
}
