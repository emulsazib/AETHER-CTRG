// Shared seed AnalysisJobs. Used by the MongoDB seeder (src/seed/seedMongo.js)
// and the in-memory job-store fallback so the Dashboard/recent-ingestions list
// is populated with or without MongoDB. These mirror data/malwarebazaar.json.

export const jobSeed = [
  {
    job_id: 'seed-job-0001',
    file_name: 'invoice_april.pdf',
    file_type: 'PDF',
    status: 'Completed',
    sandbox_mode: 'Deep',
    metadata: { size_bytes: 184320, sha256: 'a1b2c3d4...deadbeef' },
    extracted_iocs: ['lumma-gate[.]xyz', '45.137.21.9'],
    ttps: ['T1566.001', 'T1204.002', 'T1027'],
    summary: 'Weaponized PDF luring the user to execute an embedded stealer.',
    xai_payload: {
      prediction: 0.91,
      predicted_label: 'malicious',
      shap: {
        base_value: 0.5,
        features: [
          { feature: 'known_c2_domain', contribution: 0.34 },
          { feature: 'obfuscated_strings', contribution: 0.21 },
          { feature: 'suspicious_api_calls', contribution: 0.18 },
        ],
      },
      lime: { features: [{ feature: 'known_c2_domain', importance: 0.34 }] },
    },
  },
  {
    job_id: 'seed-job-0002',
    file_name: 'update.js',
    file_type: 'JS',
    status: 'Completed',
    sandbox_mode: 'Immediate',
    metadata: { size_bytes: 20480, sha256: 'f00dcafe...eeee' },
    extracted_iocs: ['secure-update-cdn[.]com', '185.220.101.47'],
    ttps: ['T1059.007', 'T1105', 'T1027'],
    summary: 'Obfuscated JScript downloader contacting a fake-update CDN.',
    xai_payload: {
      prediction: 0.87,
      predicted_label: 'malicious',
      shap: {
        base_value: 0.5,
        features: [
          { feature: 'encoded_powershell', contribution: 0.29 },
          { feature: 'network_beacon', contribution: 0.24 },
        ],
      },
      lime: { features: [{ feature: 'encoded_powershell', importance: 0.29 }] },
    },
  },
  {
    job_id: 'seed-job-0003',
    file_name: 'photo_album.zip',
    file_type: 'Archive',
    status: 'ML_Analysis',
    sandbox_mode: 'Deep',
    metadata: { size_bytes: 5242880, sha256: '01234567...cdef' },
    extracted_iocs: [],
    ttps: [],
    summary: null,
    xai_payload: null,
  },
];
