// Shared threat-graph seed data. Used BOTH by the Neo4j seeder
// (src/seed/seedNeo4j.js) and the in-memory graph fallback
// (src/services/store/memoryGraphStore.js) so the /threat-graph endpoint
// returns meaningful data with or without a real Neo4j instance.
//
// Models the PRD graph: nodes {MalwareSample, ThreatActor, TTP, IP_Address,
// MITRE_Tactic} and edges {USES_TTP, COMMUNICATES_WITH, BELONGS_TO_CAMPAIGN}.

export const graphSeed = {
  nodes: [
    // Threat actors
    { id: 'actor:apt29', label: 'ThreatActor', name: 'APT29', props: { aka: 'Cozy Bear' } },
    { id: 'actor:lumma', label: 'ThreatActor', name: 'Lumma Stealer', props: { type: 'MaaS' } },

    // Malware samples (sha256 prefixes mirror data/malwarebazaar.json)
    { id: 'sample:a1b2c3d4', label: 'MalwareSample', name: 'invoice_april.pdf', props: { file_type: 'PDF', sha256: 'a1b2c3d4...deadbeef' } },
    { id: 'sample:f00dcafe', label: 'MalwareSample', name: 'update.js', props: { file_type: 'JS', sha256: 'f00dcafe...eeee' } },
    { id: 'sample:01234567', label: 'MalwareSample', name: 'photo_album.zip', props: { file_type: 'Archive', sha256: '01234567...cdef' } },

    // MITRE tactics
    { id: 'tactic:execution', label: 'MITRE_Tactic', name: 'Execution', props: { tactic_id: 'TA0002' } },
    { id: 'tactic:defense-evasion', label: 'MITRE_Tactic', name: 'Defense Evasion', props: { tactic_id: 'TA0005' } },
    { id: 'tactic:c2', label: 'MITRE_Tactic', name: 'Command and Control', props: { tactic_id: 'TA0011' } },

    // TTPs (techniques)
    { id: 'ttp:T1059.007', label: 'TTP', name: 'T1059.007 JScript', props: { tactic: 'Execution' } },
    { id: 'ttp:T1027', label: 'TTP', name: 'T1027 Obfuscation', props: { tactic: 'Defense Evasion' } },
    { id: 'ttp:T1105', label: 'TTP', name: 'T1105 Ingress Tool Transfer', props: { tactic: 'Command and Control' } },
    { id: 'ttp:T1566.001', label: 'TTP', name: 'T1566.001 Spearphishing Attachment', props: { tactic: 'Initial Access' } },

    // Infrastructure
    { id: 'ip:185.220.101.47', label: 'IP_Address', name: '185.220.101.47', props: { abuse_confidence: 96 } },
    { id: 'ip:45.137.21.9', label: 'IP_Address', name: '45.137.21.9', props: { abuse_confidence: 88 } },
  ],
  edges: [
    // BELONGS_TO_CAMPAIGN (sample -> actor)
    { source: 'sample:a1b2c3d4', target: 'actor:lumma', type: 'BELONGS_TO_CAMPAIGN', props: { campaign: 'Lumma Logs Q2' } },
    { source: 'sample:f00dcafe', target: 'actor:apt29', type: 'BELONGS_TO_CAMPAIGN', props: { campaign: 'Operation NightDrop' } },
    { source: 'sample:01234567', target: 'actor:apt29', type: 'BELONGS_TO_CAMPAIGN', props: { campaign: 'Operation NightDrop' } },

    // USES_TTP (sample -> ttp)
    { source: 'sample:f00dcafe', target: 'ttp:T1059.007', type: 'USES_TTP', props: {} },
    { source: 'sample:f00dcafe', target: 'ttp:T1027', type: 'USES_TTP', props: {} },
    { source: 'sample:f00dcafe', target: 'ttp:T1105', type: 'USES_TTP', props: {} },
    { source: 'sample:a1b2c3d4', target: 'ttp:T1566.001', type: 'USES_TTP', props: {} },
    { source: 'sample:a1b2c3d4', target: 'ttp:T1027', type: 'USES_TTP', props: {} },
    { source: 'sample:01234567', target: 'ttp:T1059.007', type: 'USES_TTP', props: {} },

    // TTP -> MITRE_Tactic
    { source: 'ttp:T1059.007', target: 'tactic:execution', type: 'BELONGS_TO_TACTIC', props: {} },
    { source: 'ttp:T1027', target: 'tactic:defense-evasion', type: 'BELONGS_TO_TACTIC', props: {} },
    { source: 'ttp:T1105', target: 'tactic:c2', type: 'BELONGS_TO_TACTIC', props: {} },

    // COMMUNICATES_WITH (sample -> ip)
    { source: 'sample:f00dcafe', target: 'ip:185.220.101.47', type: 'COMMUNICATES_WITH', props: {} },
    { source: 'sample:a1b2c3d4', target: 'ip:45.137.21.9', type: 'COMMUNICATES_WITH', props: {} },

    // actor -> ip infrastructure
    { source: 'actor:apt29', target: 'ip:185.220.101.47', type: 'COMMUNICATES_WITH', props: { role: 'c2' } },
    { source: 'actor:lumma', target: 'ip:45.137.21.9', type: 'COMMUNICATES_WITH', props: { role: 'c2' } },
  ],
};
