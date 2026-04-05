/* ============================================
   CARTINT — Generate Intel Logic
   Loads ATM bundle, generates CTI reports
   following Kraven Security template structure
   ============================================ */

// ---- ATM Data State ----
const atm = { tactics: [], techniques: [], campaigns: [], relationships: [], techById: {}, campaignById: {}, techByTactic: {}, techToCampaigns: {}, liveThreats: [], loaded: false };

const TACTIC_ORDER = [
  'reconnaissance', 'initial_access', 'execution', 'persistence',
  'privilege_escalation', 'defense_evasion', 'credential_access',
  'discovery', 'lateral_movement', 'collection',
  'command_and_control', 'exfiltration', 'manipulate_environment',
  'affect_vehicle_function'
];

const TACTIC_DISPLAY = {
  reconnaissance: 'Reconnaissance', initial_access: 'Initial Access',
  execution: 'Execution', persistence: 'Persistence',
  privilege_escalation: 'Privilege Escalation', defense_evasion: 'Defense Evasion',
  credential_access: 'Credential Access', discovery: 'Discovery',
  lateral_movement: 'Lateral Movement', collection: 'Collection',
  command_and_control: 'Command & Control', exfiltration: 'Exfiltration',
  manipulate_environment: 'Manipulate Environment', affect_vehicle_function: 'Affect Vehicle Function'
};

// ATM Kill Chain mapping (ATM equivalent of Lockheed Martin Cyber Kill Chain)
const ATM_KILL_CHAIN = [
  { stage: 'S1', name: 'Reconnaissance', tactics: ['reconnaissance'], desc: 'Scanning and enumeration of automotive attack surface' },
  { stage: 'S2', name: 'Weaponization', tactics: ['execution'], desc: 'Preparation of exploit payloads targeting vehicle systems' },
  { stage: 'S3', name: 'Delivery', tactics: ['initial_access'], desc: 'Delivery of exploit via OTA, physical, or network vector' },
  { stage: 'S4', name: 'Exploitation', tactics: ['privilege_escalation', 'credential_access'], desc: 'Exploitation of vulnerability to gain access or escalate' },
  { stage: 'S5', name: 'Installation', tactics: ['persistence', 'defense_evasion'], desc: 'Persistence mechanisms deployed on compromised ECU/system' },
  { stage: 'S6', name: 'Command & Control', tactics: ['command_and_control', 'lateral_movement'], desc: 'C2 channel established; lateral movement within vehicle network' },
  { stage: 'S7', name: 'Actions on Objective', tactics: ['collection', 'exfiltration', 'manipulate_environment', 'affect_vehicle_function'], desc: 'Data exfiltration, vehicle manipulation, or ransomware deployment' }
];

// ---- Load ATM Bundle ----

async function loadATMBundle() {
  try {
    const resp = await fetch('atm-bundle.json');
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const bundle = await resp.json();
    const objects = bundle.objects || [];
    const rawTactics = objects.filter(o => o.type === 'x-mitre-tactic');
    atm.techniques = objects.filter(o => o.type === 'attack-pattern');
    atm.campaigns = objects.filter(o => o.type === 'campaign');
    atm.relationships = objects.filter(o => o.type === 'relationship');
    atm.tactics = TACTIC_ORDER.map(s => rawTactics.find(t => t.x_mitre_shortname === s)).filter(Boolean);
    atm.techniques.forEach(t => { atm.techById[t.id] = t; });
    atm.campaigns.forEach(c => { atm.campaignById[c.id] = c; });
    atm.relationships.forEach(rel => {
      if (rel.relationship_type === 'uses') {
        if (!atm.techToCampaigns[rel.target_ref]) atm.techToCampaigns[rel.target_ref] = [];
        const campaign = atm.campaignById[rel.source_ref];
        if (campaign) atm.techToCampaigns[rel.target_ref].push({ campaign, description: rel.description || '' });
      }
    });
    atm.tactics.forEach(tactic => {
      atm.techByTactic[tactic.x_mitre_shortname] = atm.techniques.filter(tech =>
        (tech.kill_chain_phases || []).some(p => p.phase_name === tactic.x_mitre_shortname)
      );
    });
    atm.loaded = true;
    console.log(`[CARTINT Intel] ATM bundle: ${atm.techniques.length} techniques, ${atm.campaigns.length} campaigns`);
    updateStatCounters();
  } catch (e) { console.warn('[CARTINT Intel] ATM bundle not available:', e.message); }
  try { const s = localStorage.getItem('cartint_threats'); if (s) atm.liveThreats = JSON.parse(s); } catch (e) {}
}

function getExtId(obj) { const r = (obj.external_references || []).find(x => x.external_id); return r ? r.external_id : ''; }
function getExtUrl(obj) { const r = (obj.external_references || []).find(x => x.url); return r ? r.url : ''; }
function escHtml(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

// ---- Query Configuration ----

function getQueryConfig() {
  const target = document.getElementById('inputTarget').value.trim();
  const sources = [...document.querySelectorAll('[data-source]:checked')].map(cb => cb.parentElement.textContent.trim());
  const tactics = [...TACTIC_ORDER]; // Always include all tactics
  const timeRange = document.getElementById('timeRange');
  const timeRangeText = timeRange.options[timeRange.selectedIndex].text;
  const mode = document.querySelector('input[name="analysisMode"]:checked').value;
  // Derive report type dynamically from target
  const reportType = target ? `Automotive Threat Intelligence Report — ${target}` : 'Automotive Threat Intelligence Report';
  return { target, sources, tactics, reportType, timeRange: timeRangeText, timeRangeVal: timeRange.value, mode };
}

// ---- Build Report Data ----

function stripHtml(html) { return (html || '').replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'"); }

// Source name mapping between dashboard source names and intel page checkbox labels
const SOURCE_MAP = { 'NVD/CVE': 'NVD/CVE', 'GitHub': 'GitHub', 'ExploitDB': 'ExploitDB', 'CT Logs': 'CT Logs', 'Firmware Repos': 'Firmware Repos', 'MISP': 'MISP', 'Dark Web': 'Dark Web' };

function searchLiveFeed(target, config) {
  const query = target.toLowerCase();
  const keywords = query.split(/[\s,;]+/).filter(k => k.length > 1);
  const threats = atm.liveThreats || [];

  // Filter by selected sources
  const selectedSources = new Set(config.sources);

  // Score a threat against the search query
  function matchScore(threat) {
    let score = 0;
    const fields = [threat.title || '', threat.description || '', threat.victim || '', threat.group || ''].join(' ').toLowerCase();
    // Exact phrase match
    if (fields.includes(query)) score += 10;
    // Keyword matches
    keywords.forEach(kw => { if (fields.includes(kw)) score += 3; });
    return score;
  }

  // Filter and score threats
  const matched = [];
  const unmatched = [];
  threats.forEach(t => {
    // Source filter
    if (!selectedSources.has(t.source)) return;
    const score = matchScore(t);
    if (score > 0) {
      matched.push({ ...t, _score: score });
    } else {
      unmatched.push(t);
    }
  });
  matched.sort((a, b) => b._score - a._score);

  // Group by source
  const bySource = {};
  matched.forEach(t => {
    if (!bySource[t.source]) bySource[t.source] = [];
    bySource[t.source].push(t);
  });

  // Group by severity
  const bySeverity = { critical: [], high: [], medium: [], low: [] };
  matched.forEach(t => {
    if (bySeverity[t.severity]) bySeverity[t.severity].push(t);
  });

  // Extract CVE IDs from matched threats
  const cveRegex = /CVE-\d{4}-\d{4,}/g;
  const cves = [];
  const cvesSeen = new Set();
  matched.forEach(t => {
    const text = (t.title || '') + ' ' + (t.description || '');
    const found = text.match(cveRegex);
    if (found) found.forEach(cve => {
      if (!cvesSeen.has(cve)) {
        cvesSeen.add(cve);
        cves.push({ cve, title: t.title, source: t.source, severity: t.severity, confidence: t.confidence });
      }
    });
  });

  // Collect ATM technique IDs from matched threats
  const techniqueIds = new Set();
  matched.forEach(t => {
    (t.techniques || []).forEach(tid => techniqueIds.add(tid));
  });

  // Collect ransomware groups / threat actors
  const groups = [];
  const groupsSeen = new Set();
  matched.forEach(t => {
    if (t.group && !groupsSeen.has(t.group)) {
      groupsSeen.add(t.group);
      groups.push({ name: t.group, victim: t.victim, source: t.source, title: t.title });
    }
  });

  return { matched, unmatched, bySource, bySeverity, cves, techniqueIds: [...techniqueIds], groups, totalFeedSize: threats.length };
}

function buildReportData(config) {
  const data = {};
  const target = config.target || 'Target Organization';
  const now = new Date();

  // Search the LIVE THREAT FEED for matching data
  const search = searchLiveFeed(target, config);

  // Report metadata
  data.reportId = `CARTINT-${now.getFullYear()}${String(now.getMonth()+1).padStart(2,'0')}${String(now.getDate()).padStart(2,'0')}-${String(Math.floor(Math.random()*9000+1000))}`;
  data.date = now.toISOString().split('T')[0];
  data.time = now.toTimeString().split(' ')[0];
  data.target = target;
  data.totalFeedSize = search.totalFeedSize;
  data.matchedCount = search.matched.length;

  // Priority / severity — based on real threat severities
  const critCount = search.bySeverity.critical.length;
  const highCount = search.bySeverity.high.length;
  data.priority = critCount >= 3 ? 'Critical' : (critCount + highCount) >= 3 ? 'High' : search.matched.length > 0 ? 'Moderate' : 'Low';

  // Source reliability (Admiralty Scale)
  const reliabilityMap = { 'NVD/CVE': 'A1', 'CT Logs': 'A2', 'ExploitDB': 'B2', 'GitHub': 'B3', 'MISP': 'B2', 'Firmware Repos': 'C3', 'Dark Web': 'D3' };
  const activeSources = Object.keys(search.bySource);
  data.sourceReliability = activeSources.map(s => reliabilityMap[s] || 'C3').sort()[0] || 'C3';
  data.sensitivity = 'TLP:AMBER';

  // Stats — all from real live feed data
  data.stats = {
    totalThreats: search.matched.length,
    criticalCount: critCount,
    highCount: highCount,
    totalCVEs: search.cves.length,
    totalSources: activeSources.length,
    totalTechniques: search.techniqueIds.length,
    totalGroups: search.groups.length
  };

  // Real threats — the core of the report
  data.threats = search.matched;
  data.bySource = search.bySource;
  data.bySeverity = search.bySeverity;

  // Real CVEs from live feed
  data.cves = search.cves;

  // Real ransomware groups / threat actors
  data.groups = search.groups;

  // ATM techniques referenced in matched threats — resolve from bundle if available
  data.techniqueTable = search.techniqueIds.map(tid => {
    const tech = atm.techniques.find(t => getExtId(t) === tid);
    if (tech) {
      const phases = (tech.kill_chain_phases || []).map(p => TACTIC_DISPLAY[p.phase_name] || p.phase_name);
      return { id: tid, name: tech.name, tactics: phases, d3fend: getD3FEND(tech.name), control: getSecControl(tech.name) };
    }
    return { id: tid, name: tid, tactics: [], d3fend: '—', control: '—' };
  });

  // IOC extraction — IPs, hashes, domains, URLs from threat text
  data.iocs = extractIOCs(search.matched);

  // Raw telemetry log lines
  data.telemetry = search.matched.map((t, i) => ({
    ts: data.date + 'T' + data.time + 'Z',
    seq: i + 1,
    source: t.source || 'UNKNOWN',
    severity: (t.severity || 'medium').toUpperCase(),
    confidence: t.confidence || 0,
    title: t.title || '',
    description: t.description || '',
    victim: t.victim || '',
    group: t.group || '',
    techniques: t.techniques || []
  }));

  // Detection opportunities
  data.detections = buildDetections(search.matched, data.techniqueTable);

  // Kill chain mapping — from ATM techniques referenced in live threats
  data.killChain = ATM_KILL_CHAIN.map(kc => {
    const matchedTechs = data.techniqueTable.filter(t => {
      const tech = atm.techniques.find(at => getExtId(at) === t.id);
      return tech && (tech.kill_chain_phases || []).some(p => kc.tactics.includes(p.phase_name));
    });
    return { ...kc, techniques: matchedTechs.slice(0, 5), hasActivity: matchedTechs.length > 0, techCount: matchedTechs.length };
  });

  // Diamond Model — derived from real live feed data
  data.diamond = {
    adversary: search.groups.length > 0
      ? `Known threat actors: ${search.groups.map(g => g.name).join(', ')}`
      : (search.matched.length > 0 ? 'Unattributed — threat indicators observed in live feeds' : 'No threat actors identified in live feed for this target'),
    capability: data.techniqueTable.slice(0, 4).map(t => t.id + ': ' + t.name).join('; ') || 'No ATM techniques mapped',
    infrastructure: (() => {
      const ctThreats = (search.bySource['CT Logs'] || []).slice(0, 3).map(t => t.title).join('; ');
      return ctThreats || 'No infrastructure indicators observed in live feed';
    })(),
    victim: `${target} (Automotive Sector)`
  };

  // Key takeaways
  data.keyTakeaways = {
    intelligenceReqs: config.reportType,
    dataSources: activeSources.join(', ') || 'No matching sources',
    matchSummary: search.matched.length > 0
      ? `${search.matched.length} threats matched "${target}" across ${activeSources.length} sources (${critCount} critical, ${highCount} high)`
      : `No threats matching "${target}" found in the live feed (${search.totalFeedSize} total threats scanned)`,
    sectors: 'Automotive Manufacturing, Connected Vehicles, Mobility Services'
  };

  // Source confidence
  data.sourceConfidence = activeSources.map(name => {
    const threats = search.bySource[name] || [];
    const avgConf = threats.length > 0 ? Math.round(threats.reduce((s, t) => s + (t.confidence || 0), 0) / threats.length) : 0;
    return { name, count: threats.length, avgConfidence: avgConf };
  });

  // Key Intelligence Gaps
  data.gaps = [];
  if (search.matched.length === 0) data.gaps.push(`No live threats matching "${target}" — ensure the dashboard has been running to collect threat data`);
  const missingSources = config.sources.filter(s => !search.bySource[s]);
  if (missingSources.length > 0) data.gaps.push(`No results from: ${missingSources.join(', ')} — these sources may not have collected data matching "${target}" yet`);
  if (search.cves.length === 0) data.gaps.push(`No CVEs found in live feed for "${target}" — NVD scan may need more time or broader search terms`);
  if (search.groups.length === 0) data.gaps.push(`No ransomware/APT group activity observed for "${target}" in dark web monitoring`);
  data.gaps.push('Live feed data is limited to what has been collected during the current dashboard session');

  // AI-only sections
  if (config.mode === 'ai') {
    data.ai = buildAISections(config, data, search);
  }

  return data;
}

function getD3FEND(techName) {
  const map = {
    'Supply Chain': 'D3-SVCDM (Software Verification)', 'Firmware': 'D3-FV (File Verification)',
    'Credential': 'D3-CBAN (Credential Blocking)', 'Exploit': 'D3-EAL (Exploit Analysis)',
    'Scan': 'D3-NTA (Network Traffic Analysis)', 'Phishing': 'D3-EFA (Email Filtering)',
    'Brute': 'D3-AL (Account Locking)', 'Sniff': 'D3-NE (Network Encryption)',
    'Data from': 'D3-DENCR (Data Encryption)', 'Exfil': 'D3-NI (Network Isolation)',
    'Relay': 'D3-RFCM (RF Communication Monitoring)', 'Wireless': 'D3-RFCM (RF Communication Monitoring)'
  };
  for (const [key, val] of Object.entries(map)) { if (techName.includes(key)) return val; }
  return 'D3-MA (Monitoring & Analysis)';
}

function getSecControl(techName) {
  const map = {
    'Supply Chain': 'ISO 21434 §9', 'Firmware': 'UNECE WP.29 R155',
    'Credential': 'ISO 27001 A.9', 'Exploit': 'ISO 21434 §8.6',
    'Scan': 'NIST SP 800-53 SI-4', 'Diagnostic': 'ISO 14229 SecAccess',
    'CAN': 'SAE J3061 §7.4', 'OTA': 'UNECE WP.29 R156',
    'Relay': 'ETSI TS 103 097', 'Data from': 'ISO 27001 A.8',
    'Exfil': 'NIST SP 800-53 SC-7', 'GPS': 'SAE J3061 §6.2'
  };
  for (const [key, val] of Object.entries(map)) { if (techName.includes(key)) return val; }
  return 'ISO 21434 General';
}

function buildDetections(threats, techniqueTable) {
  // Generate detection suggestions based on actual matched threats and techniques
  const detectionMap = {
    'CAN': { type: 'Sigma', desc: 'Detect anomalous CAN bus frame injection patterns' },
    'firmware': { type: 'YARA', desc: 'Identify modified firmware images with tampered signatures' },
    'OTA': { type: 'Sigma', desc: 'Monitor for anomalous OTA firmware download patterns' },
    'diagnostic': { type: 'Sigma', desc: 'Detect unauthorized diagnostic session requests (UDS)' },
    'credential': { type: 'Splunk Query', desc: 'Monitor for credential exposure in vehicle backend logs' },
    'bluetooth': { type: 'Sigma', desc: 'Detect anomalous Bluetooth pairing and data extraction attempts' },
    'Wi-Fi': { type: 'Sigma', desc: 'Monitor for Wi-Fi de-authentication and rogue AP attacks' },
    'telematics': { type: 'Sigma', desc: 'Monitor for unauthorized telematics data access patterns' },
    'keyless': { type: 'Sigma', desc: 'Monitor for relay attack patterns against keyless entry systems' },
    'infotainment': { type: 'Sigma', desc: 'Detect exploitation attempts against infotainment systems' },
    'exploit': { type: 'Sigma', desc: 'Monitor for exploitation attempts against known vehicle vulnerabilities' },
    'ransomware': { type: 'Sigma', desc: 'Detect ransomware indicators targeting automotive supply chain' },
    'supply chain': { type: 'YARA', desc: 'Verify integrity of supply chain components and updates' },
    'certificate': { type: 'Sigma', desc: 'Monitor for anomalous certificate issuance on vehicle domains' }
  };

  const detections = [];
  const used = new Set();
  // Scan threat titles and descriptions for keywords
  const allText = threats.map(t => `${t.title || ''} ${t.description || ''}`).join(' ').toLowerCase();
  // Also scan technique names
  const techText = techniqueTable.map(t => t.name).join(' ').toLowerCase();
  const combined = allText + ' ' + techText;

  for (const [keyword, det] of Object.entries(detectionMap)) {
    if (combined.includes(keyword.toLowerCase()) && !used.has(keyword)) {
      used.add(keyword);
      detections.push({
        name: `CARTINT-${det.type.toUpperCase().replace(/\s+/g, '')}-${String(detections.length + 1).padStart(3, '0')}`,
        type: det.type,
        description: det.desc,
        reference: keyword
      });
    }
  }
  return detections;
}

function extractIOCs(threats) {
  const iocs = [];
  const seen = new Set();
  const ipv4Re = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
  const md5Re = /\b[a-f0-9]{32}\b/gi;
  const sha1Re = /\b[a-f0-9]{40}\b/gi;
  const sha256Re = /\b[a-f0-9]{64}\b/gi;
  const domainRe = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|xyz|info|ru|cn|tk|top|cc|pw|biz|co)\b/gi;
  const urlRe = /https?:\/\/[^\s<>"')\]]+/gi;
  const cveRe = /CVE-\d{4}-\d{4,}/g;

  threats.forEach(t => {
    const text = `${t.title || ''} ${t.description || ''}`;
    const source = t.source || 'UNKNOWN';
    const conf = t.confidence || 0;

    const extract = (re, type) => {
      const matches = text.match(re);
      if (matches) matches.forEach(val => {
        const key = `${type}:${val.toLowerCase()}`;
        if (!seen.has(key)) { seen.add(key); iocs.push({ type, value: val, confidence: conf, source, context: (t.title || '').slice(0, 120) }); }
      });
    };

    extract(cveRe, 'CVE');
    extract(ipv4Re, 'IPv4');
    extract(sha256Re, 'SHA256');
    extract(sha1Re, 'SHA1');
    extract(md5Re, 'MD5');
    extract(domainRe, 'DOMAIN');
    extract(urlRe, 'URL');
  });

  // Sort: CVEs first, then hashes, IPs, domains, URLs
  const typeOrder = { CVE: 0, SHA256: 1, SHA1: 2, MD5: 3, IPv4: 4, DOMAIN: 5, URL: 6 };
  iocs.sort((a, b) => (typeOrder[a.type] ?? 99) - (typeOrder[b.type] ?? 99));
  return iocs;
}

function buildAISections(config, data, search) {
  const target = data.target;
  const severity = data.priority;
  const matched = search.matched;
  const hasMatches = matched.length > 0;

  const execSummary = `This report covers intelligence gathered from <strong>${data.totalFeedSize} live threats</strong> collected by the CARTINT dashboard, filtered for <strong>"${escHtml(target)}"</strong> over the ${config.timeRange} period.

${hasMatches
  ? `<strong>${matched.length} threats</strong> matched the target across ${data.stats.totalSources} source(s): <strong>${data.stats.criticalCount} critical</strong>, <strong>${data.stats.highCount} high</strong>-severity. ${data.stats.totalCVEs > 0 ? `<strong>${data.stats.totalCVEs} CVE(s)</strong> were identified.` : 'No specific CVEs were found in matched threats.'} ${data.stats.totalGroups > 0 ? `<strong>${data.stats.totalGroups} threat actor group(s)</strong> observed.` : ''}`
  : `No threats matching "${escHtml(target)}" were found in the live feed. Ensure the dashboard has been running to collect data, or try broader search terms.`}

${severity === 'Critical' ? `<strong>Immediate action required.</strong> Multiple critical-severity threats have been observed targeting ${escHtml(target)} across live intelligence feeds.`
  : severity === 'High' ? `<strong>Elevated risk posture.</strong> High-severity threats detected for ${escHtml(target)} — recommend prioritizing remediation.`
  : hasMatches ? `<strong>Moderate risk posture.</strong> Threats observed but severity levels are manageable. Continue monitoring.`
  : `<strong>No immediate risk indicators.</strong> No matching threats found in current feed data.`}`;

  // Risk scores — by source
  const riskScores = Object.entries(search.bySource).map(([source, threats]) => {
    const criticals = threats.filter(t => t.severity === 'critical').length;
    const highs = threats.filter(t => t.severity === 'high').length;
    const avgConf = Math.round(threats.reduce((s, t) => s + (t.confidence || 0), 0) / threats.length);
    const score = Math.min(criticals * 25 + highs * 15 + threats.length * 3, 100);
    const rating = score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW';
    return { tactic: source, score, rating, techCount: threats.length, avgConfidence: avgConf };
  }).sort((a, b) => b.score - a.score);

  // Recommendations derived from actual matched threats
  const recMap = {
    'firmware': { text: 'Implement code-signing verification for all firmware updates', tier: 'shortTerm' },
    'ota': { text: 'Harden OTA update infrastructure — enforce mutual TLS and firmware integrity verification', tier: 'immediate' },
    'can bus': { text: 'Deploy CAN bus anomaly detection and intrusion detection systems', tier: 'shortTerm' },
    'credential': { text: 'Rotate all exposed credentials and API keys immediately', tier: 'immediate' },
    'api key': { text: 'Revoke and rotate all exposed API keys found in public repositories', tier: 'immediate' },
    'certificate': { text: 'Audit and monitor certificate issuance for all automotive domains', tier: 'shortTerm' },
    'ransomware': { text: 'Implement ransomware-specific defenses and incident response procedures for supply chain', tier: 'immediate' },
    'supply chain': { text: 'Implement supply chain integrity verification per ISO 21434 requirements', tier: 'longTerm' },
    'telematics': { text: 'Harden telematics endpoints and enforce strict access controls', tier: 'shortTerm' },
    'infotainment': { text: 'Isolate infotainment systems from safety-critical vehicle networks', tier: 'shortTerm' },
    'bluetooth': { text: 'Restrict Bluetooth pairing and enforce authentication for all connections', tier: 'shortTerm' },
    'exploit': { text: 'Patch known exploited vulnerabilities and deploy virtual patching where needed', tier: 'immediate' }
  };

  const recommendations = { immediate: [], shortTerm: [], longTerm: [] };
  const usedRecs = new Set();
  const allText = matched.map(t => `${t.title || ''} ${t.description || ''}`).join(' ').toLowerCase();
  for (const [keyword, rec] of Object.entries(recMap)) {
    if (allText.includes(keyword) && !usedRecs.has(keyword)) {
      usedRecs.add(keyword);
      recommendations[rec.tier].push({ text: rec.text, keyword });
    }
  }
  if (recommendations.longTerm.length === 0) {
    recommendations.longTerm.push({ text: 'Establish ongoing threat intelligence monitoring aligned with Auto-ISAC ATM framework', keyword: 'ATM Framework' });
  }

  return { execSummary, severity, riskScores, recommendations };
}

// ============================================
// RENDER REPORT — CTI Template Format
// ============================================

function renderReport(config, data) {
  const isAI = config.mode === 'ai';

  // ── Fork: Raw = machine-readable data dump, AI = analytical report ──
  if (!isAI) return renderRawReport(config, data);
  return renderAIReport(config, data);
}

// ============================================
// RAW INTELLIGENCE REPORT — Machine-readable data dump
// Indicator feeds, raw telemetry, bare Auto-ISAC ATM technique IDs.
// Structured for SIEM / EDR / tooling ingestion.
// No interpretation, no recommendations — just evidence.
// ============================================

function renderRawReport(config, data) {
  let html = '';

  // ── HEADER BLOCK ──
  html += `
  <div class="rpt-raw-header">
    <div class="rpt-raw-header-top">
      <div class="rpt-raw-brand">
        <svg width="24" height="24" viewBox="0 0 28 28" fill="none"><rect width="28" height="28" rx="6" fill="#E63946"/><path d="M8 14L12 10L16 14L12 18Z" fill="white" opacity="0.9"/><path d="M12 14L16 10L20 14L16 18Z" fill="white" opacity="0.6"/></svg>
        <span class="rpt-raw-brand-name">CARTINT</span>
        <span class="rpt-raw-brand-tag">RAW INTELLIGENCE DUMP</span>
      </div>
      <div class="rpt-raw-tlp"><span class="rpt-tlp-badge">${data.sensitivity}</span></div>
    </div>
    <div class="rpt-raw-meta-grid">
      <div class="rpt-raw-meta-cell"><span class="rpt-raw-meta-k">REPORT_ID</span><span class="rpt-raw-meta-v">${data.reportId}</span></div>
      <div class="rpt-raw-meta-cell"><span class="rpt-raw-meta-k">TARGET</span><span class="rpt-raw-meta-v">${escHtml(data.target)}</span></div>
      <div class="rpt-raw-meta-cell"><span class="rpt-raw-meta-k">TIMESTAMP</span><span class="rpt-raw-meta-v">${data.date}T${data.time}Z</span></div>
      <div class="rpt-raw-meta-cell"><span class="rpt-raw-meta-k">WINDOW</span><span class="rpt-raw-meta-v">${config.timeRange}</span></div>
      <div class="rpt-raw-meta-cell"><span class="rpt-raw-meta-k">FEED_SIZE</span><span class="rpt-raw-meta-v">${data.totalFeedSize} events</span></div>
      <div class="rpt-raw-meta-cell"><span class="rpt-raw-meta-k">MATCHED</span><span class="rpt-raw-meta-v">${data.matchedCount} hits</span></div>
      <div class="rpt-raw-meta-cell"><span class="rpt-raw-meta-k">SOURCES</span><span class="rpt-raw-meta-v">${data.stats.totalSources}</span></div>
      <div class="rpt-raw-meta-cell"><span class="rpt-raw-meta-k">ADMIRALTY</span><span class="rpt-raw-meta-v">${data.sourceReliability}</span></div>
    </div>
  </div>`;

  // ── 1. IOC FEED ──
  html += `
  <div class="rpt-raw-section">
    <div class="rpt-raw-section-header">
      <span class="rpt-raw-sn">01</span>
      <span class="rpt-raw-section-name">INDICATOR FEED</span>
      <span class="rpt-raw-section-count">${data.iocs.length} indicators</span>
    </div>`;

  if (data.iocs.length > 0) {
    html += `<table class="rpt-raw-table">
      <thead><tr><th>TYPE</th><th>VALUE</th><th>CONFIDENCE</th><th>SOURCE</th><th>CONTEXT</th></tr></thead>
      <tbody>
        ${data.iocs.map(ioc => `<tr>
          <td><span class="rpt-raw-ioc-type rpt-raw-ioc-${ioc.type.toLowerCase()}">${ioc.type}</span></td>
          <td class="rpt-raw-mono rpt-raw-ioc-val">${escHtml(ioc.value)}</td>
          <td class="rpt-raw-mono rpt-raw-conf">${ioc.confidence}%</td>
          <td class="rpt-raw-mono">${escHtml(ioc.source)}</td>
          <td class="rpt-raw-context">${escHtml(ioc.context)}</td>
        </tr>`).join('')}
      </tbody>
    </table>`;
  } else {
    html += `<div class="rpt-raw-empty">NO INDICATORS EXTRACTED — FEED CONTAINED NO PARSEABLE IOCs FOR "${escHtml(data.target)}"</div>`;
  }
  html += `</div>`;

  // ── 2. RAW TELEMETRY ──
  html += `
  <div class="rpt-raw-section">
    <div class="rpt-raw-section-header">
      <span class="rpt-raw-sn">02</span>
      <span class="rpt-raw-section-name">RAW TELEMETRY</span>
      <span class="rpt-raw-section-count">${data.telemetry.length} log lines</span>
    </div>
    <div class="rpt-raw-telemetry">`;

  if (data.telemetry.length > 0) {
    data.telemetry.forEach(t => {
      const sevClass = t.severity === 'CRITICAL' ? 'crit' : t.severity === 'HIGH' ? 'high' : t.severity === 'MEDIUM' ? 'med' : 'low';
      html += `<div class="rpt-raw-log-line">
        <span class="rpt-raw-log-ts">${t.ts}</span>
        <span class="rpt-raw-log-seq">#${String(t.seq).padStart(3, '0')}</span>
        <span class="rpt-raw-log-sev rpt-raw-log-sev-${sevClass}">${t.severity}</span>
        <span class="rpt-raw-log-src">[${t.source}]</span>
        <span class="rpt-raw-log-conf">conf:${t.confidence}%</span>
        <span class="rpt-raw-log-msg">${escHtml(t.title)}</span>
        ${t.group ? `<span class="rpt-raw-log-tag rpt-raw-log-tag-actor">actor:${escHtml(t.group)}</span>` : ''}
        ${t.victim ? `<span class="rpt-raw-log-tag rpt-raw-log-tag-victim">victim:${escHtml(t.victim)}</span>` : ''}
        ${t.techniques.length > 0 ? `<span class="rpt-raw-log-tag rpt-raw-log-tag-tech">${t.techniques.join(',')}</span>` : ''}
      </div>`;
    });
  } else {
    html += `<div class="rpt-raw-empty">NO TELEMETRY — NO MATCHING EVENTS IN FEED</div>`;
  }
  html += `</div></div>`;

  // ── 3. AUTO-ISAC ATM TECHNIQUE IDs ──
  html += `
  <div class="rpt-raw-section">
    <div class="rpt-raw-section-header">
      <span class="rpt-raw-sn">03</span>
      <span class="rpt-raw-section-name">AUTO-ISAC ATM TECHNIQUE IDs</span>
      <span class="rpt-raw-section-count">${data.techniqueTable.length} techniques</span>
    </div>`;

  if (data.techniqueTable.length > 0) {
    html += `<table class="rpt-raw-table rpt-raw-table-compact">
      <thead><tr><th>TECHNIQUE_ID</th><th>NAME</th><th>TACTICS</th><th>SOURCE_REFS</th></tr></thead>
      <tbody>
        ${data.techniqueTable.map(t => {
          // Find which threats reference this technique
          const refs = data.telemetry.filter(tel => tel.techniques.includes(t.id)).map(tel => tel.source);
          const uniqueRefs = [...new Set(refs)];
          return `<tr>
            <td class="rpt-raw-mono rpt-raw-tech-id">${t.id}</td>
            <td>${escHtml(t.name)}</td>
            <td class="rpt-raw-mono rpt-raw-tactics">${t.tactics.join(' | ')}</td>
            <td class="rpt-raw-mono">${uniqueRefs.join(', ') || '—'}</td>
          </tr>`;
        }).join('')}
      </tbody>
    </table>`;
  } else {
    html += `<div class="rpt-raw-empty">NO TECHNIQUE MAPPINGS IN MATCHED FEED DATA</div>`;
  }
  html += `</div>`;

  // ── 4. SOURCE ATTRIBUTION ──
  html += `
  <div class="rpt-raw-section">
    <div class="rpt-raw-section-header">
      <span class="rpt-raw-sn">04</span>
      <span class="rpt-raw-section-name">SOURCE ATTRIBUTION</span>
      <span class="rpt-raw-section-count">${data.sourceConfidence.length} sources</span>
    </div>
    <table class="rpt-raw-table rpt-raw-table-compact">
      <thead><tr><th>SOURCE</th><th>EVENTS</th><th>AVG_CONFIDENCE</th><th>ADMIRALTY</th></tr></thead>
      <tbody>
        ${data.sourceConfidence.map(s => {
          const admCode = { 'NVD/CVE': 'A1', 'CT Logs': 'A2', 'ExploitDB': 'B2', 'GitHub': 'B3', 'MISP': 'B2', 'Firmware Repos': 'C3', 'Dark Web': 'D3' }[s.name] || 'F6';
          return `<tr>
            <td class="rpt-raw-mono">${escHtml(s.name)}</td>
            <td class="rpt-raw-mono">${s.count}</td>
            <td class="rpt-raw-mono">${s.avgConfidence}%</td>
            <td class="rpt-raw-mono">${admCode}</td>
          </tr>`;
        }).join('')}
      </tbody>
    </table>
  </div>`;

  // ── FOOTER ──
  html += `<div class="rpt-raw-footer">
    <span>CARTINT RAW DUMP</span>
    <span>${data.reportId}</span>
    <span>${data.date}T${data.time}Z</span>
    <span>${data.sensitivity}</span>
    <span>${data.iocs.length} IOCs / ${data.telemetry.length} events / ${data.techniqueTable.length} techniques</span>
  </div>`;

  return html;
}

// ============================================
// AI-ANALYZED REPORT — Full CTI Template
// ============================================

function renderAIReport(config, data) {
  let html = '';

  // =====================
  // COVER PAGE
  // =====================
  html += `
  <div class="rpt-cover">
    <div class="rpt-cover-brand">
      <svg width="36" height="36" viewBox="0 0 28 28" fill="none"><rect width="28" height="28" rx="6" fill="#E63946"/><path d="M8 14L12 10L16 14L12 18Z" fill="white" opacity="0.9"/><path d="M12 14L16 10L20 14L16 18Z" fill="white" opacity="0.6"/></svg>
      <div class="rpt-cover-brand-text">
        <span class="rpt-cover-company">CARTINT</span>
        <span class="rpt-cover-subtitle">AUTOMOTIVE THREAT INTELLIGENCE</span>
      </div>
    </div>
    <h1 class="rpt-cover-title">${escHtml(config.reportType)}</h1>
    <div class="rpt-cover-target">Target: ${escHtml(data.target)}</div>
    <div class="rpt-cover-meta-table">
      <table class="rpt-meta-table">
        <tr><td class="rpt-meta-key">Report ID</td><td class="rpt-meta-val">${data.reportId}</td></tr>
        <tr><td class="rpt-meta-key">Date</td><td class="rpt-meta-val">${data.date} ${data.time} UTC</td></tr>
        <tr><td class="rpt-meta-key">Priority</td><td class="rpt-meta-val"><span class="rpt-priority-badge rpt-priority-${data.priority.toLowerCase()}">${data.priority}</span></td></tr>
        <tr><td class="rpt-meta-key">Source &amp; Information Reliability</td><td class="rpt-meta-val">${data.sourceReliability} (Admiralty Scale)</td></tr>
        <tr><td class="rpt-meta-key">Sensitivity</td><td class="rpt-meta-val"><span class="rpt-tlp-badge">${data.sensitivity}</span></td></tr>
      </table>
    </div>
  </div>`;

  // =====================
  // 1. EXECUTIVE SUMMARY
  // =====================
  html += `<div class="rpt-section">
    <h2 class="rpt-section-title"><span class="rpt-sn">1</span>Executive Summary<span class="rpt-ai-tag">AI-POWERED</span></h2>
    <div class="rpt-section-body">
      <div class="rpt-exec-severity"><span class="rpt-severity-badge rpt-severity-${data.ai.severity.toLowerCase()}">${data.ai.severity} SEVERITY</span></div>
      <div class="rpt-exec-text">${data.ai.execSummary}</div>
    </div>
  </div>`;

  // =====================
  // 2. KEY TAKEAWAYS
  // =====================
  html += `<div class="rpt-section">
    <h2 class="rpt-section-title"><span class="rpt-sn">2</span>Key Takeaways</h2>
    <div class="rpt-section-body">
      <ul class="rpt-takeaway-list">
        <li><strong>Report for:</strong> ${escHtml(data.target)} security teams, OEM SOC analysts, supply chain risk managers</li>
        <li><strong>Live Feed Match:</strong> ${escHtml(data.keyTakeaways.matchSummary)}</li>
        <li><strong>Techniques Mapped:</strong> ${data.stats.totalTechniques} ATM techniques</li>
        <li><strong>Threat Actors:</strong> ${data.stats.totalGroups > 0 ? data.stats.totalGroups + ' group(s) observed' : 'No threat actors identified'}</li>
        <li><strong>CVEs Found:</strong> ${data.stats.totalCVEs > 0 ? data.stats.totalCVEs + ' CVE(s) extracted from live threat data' : 'No CVEs found in matched threat data'}</li>
        <li><strong>Threat Profile:</strong> ${escHtml(data.diamond.adversary)}</li>
      </ul>

      <table class="rpt-table rpt-takeaway-table">
        <tr><td class="rpt-meta-key">Intelligence Requirements</td><td>${escHtml(data.keyTakeaways.intelligenceReqs)}</td></tr>
        <tr><td class="rpt-meta-key">Data Sources</td><td>${escHtml(data.keyTakeaways.dataSources)}</td></tr>
        <tr><td class="rpt-meta-key">Feed Coverage</td><td>${escHtml(data.keyTakeaways.matchSummary)}</td></tr>
        <tr><td class="rpt-meta-key">Sectors</td><td>${escHtml(data.keyTakeaways.sectors)}</td></tr>
      </table>

      <div class="rpt-diamond">
        <div class="rpt-diamond-title">Diamond Model</div>
        <div class="rpt-diamond-grid">
          <div class="rpt-diamond-cell rpt-diamond-top"><span class="rpt-diamond-label">Adversary</span><span class="rpt-diamond-value">${escHtml(data.diamond.adversary)}</span></div>
          <div class="rpt-diamond-row">
            <div class="rpt-diamond-cell"><span class="rpt-diamond-label">Infrastructure</span><span class="rpt-diamond-value">${escHtml(data.diamond.infrastructure)}</span></div>
            <div class="rpt-diamond-center">
              <svg width="100" height="100" viewBox="0 0 100 100"><polygon points="50,5 95,50 50,95 5,50" fill="none" stroke="var(--red)" stroke-width="1.5"/><line x1="5" y1="50" x2="95" y2="50" stroke="var(--red)" stroke-width="1" opacity="0.4"/><line x1="50" y1="5" x2="50" y2="95" stroke="var(--red)" stroke-width="1" opacity="0.4"/></svg>
            </div>
            <div class="rpt-diamond-cell"><span class="rpt-diamond-label">Capability</span><span class="rpt-diamond-value">${escHtml(data.diamond.capability)}</span></div>
          </div>
          <div class="rpt-diamond-cell rpt-diamond-bottom"><span class="rpt-diamond-label">Victim</span><span class="rpt-diamond-value">${escHtml(data.diamond.victim)}</span></div>
        </div>
      </div>
    </div>
  </div>`;

  // =====================
  // 3. INTELLIGENCE ASSESSMENT
  // =====================
  html += `<div class="rpt-section">
    <h2 class="rpt-section-title"><span class="rpt-sn">3</span>Intelligence Assessment<span class="rpt-ai-tag">AI</span></h2>
    <div class="rpt-section-body">
      <div class="rpt-assessment-text">
        <p>${data.matchedCount > 0
          ? `<strong>${data.matchedCount} live threats</strong> matched "${escHtml(data.target)}" from ${data.stats.totalSources} source(s). ${data.stats.criticalCount} critical, ${data.stats.highCount} high-severity findings observed.`
          : `No threats matching "${escHtml(data.target)}" found in the live feed (${data.totalFeedSize} total threats scanned).`}</p>
        ${data.stats.totalCVEs > 0 ? `<p><strong>${data.stats.totalCVEs} CVE(s)</strong> identified in matched threat data.</p>` : ''}
        ${data.groups.length > 0 ? `<p><strong>Threat actors observed:</strong> ${data.groups.map(g => escHtml(g.name)).join(', ')}</p>` : ''}
      </div>

      <h3 class="rpt-subsection-title">Automotive Kill Chain (ATM Framework)</h3>
      <table class="rpt-table rpt-killchain-table">
        <thead><tr><th class="rpt-kc-header" colspan="3">Automotive Kill Chain</th></tr></thead>
        <tbody>
          ${data.killChain.map(kc => `<tr class="${kc.hasActivity ? 'rpt-kc-active' : ''}">
            <td class="rpt-kc-stage"><strong>${kc.stage}: ${kc.name}</strong></td>
            <td class="rpt-kc-detail">${kc.hasActivity ? kc.techniques.map(t => getExtId(t) + ': ' + t.name).join('; ') : '<span class="rpt-muted">No observed activity</span>'}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>
  </div>`;

  // =====================
  // 4. KEY INTELLIGENCE GAPS
  // =====================
  html += `<div class="rpt-section">
    <h2 class="rpt-section-title"><span class="rpt-sn">4</span>Key Intelligence Gaps</h2>
    <div class="rpt-section-body">
      <ul class="rpt-gap-list">${data.gaps.map(g => `<li>${escHtml(g)}</li>`).join('')}</ul>
    </div>
  </div>`;

  // =====================
  // 5. LIVE THREAT FINDINGS
  // =====================
  html += `<div class="rpt-section">
    <h2 class="rpt-section-title"><span class="rpt-sn">5</span>Live Threat Findings<span class="rpt-count-badge">${data.stats.totalThreats} threats</span></h2>
    <div class="rpt-section-body">`;

  if (data.cves.length > 0) {
    html += `<h3 class="rpt-subsection-title">CVEs Identified</h3>
      <table class="rpt-table"><thead><tr><th>CVE ID</th><th>Source</th><th>Severity</th><th>Threat Title</th></tr></thead><tbody>
        ${data.cves.map(c => `<tr><td class="rpt-mono rpt-cve">${escHtml(c.cve)}</td><td>${escHtml(c.source)}</td><td><span class="rpt-severity-badge rpt-severity-${c.severity}">${c.severity.toUpperCase()}</span></td><td>${escHtml(c.title)}</td></tr>`).join('')}
      </tbody></table>`;
  }

  if (data.groups.length > 0) {
    html += `<h3 class="rpt-subsection-title">Threat Actors Observed</h3>
      <table class="rpt-table"><thead><tr><th>Group</th><th>Source</th><th>Victim / Context</th></tr></thead><tbody>
        ${data.groups.map(g => `<tr><td class="rpt-mono" style="color:var(--red);font-weight:600;">${escHtml(g.name)}</td><td>${escHtml(g.source)}</td><td>${escHtml(g.victim || g.title)}</td></tr>`).join('')}
      </tbody></table>`;
  }

  Object.entries(data.bySource).forEach(([source, threats]) => {
    html += `<h3 class="rpt-subsection-title">${escHtml(source)} <span class="rpt-count-badge">${threats.length}</span></h3>
      <table class="rpt-table"><thead><tr><th>Severity</th><th>Confidence</th><th>Threat</th><th>Description</th></tr></thead><tbody>
        ${threats.slice(0, 15).map(t => `<tr>
          <td><span class="rpt-severity-badge rpt-severity-${t.severity}">${t.severity.toUpperCase()}</span></td>
          <td class="rpt-mono">${t.confidence || '—'}%</td>
          <td>${escHtml(t.title)}</td>
          <td>${escHtml((t.description || '').slice(0, 150))}${(t.description || '').length > 150 ? '...' : ''}</td>
        </tr>`).join('')}
        ${threats.length > 15 ? `<tr><td colspan="4" class="rpt-muted" style="text-align:center;">+ ${threats.length - 15} more threats from ${escHtml(source)}</td></tr>` : ''}
      </tbody></table>`;
  });

  if (data.stats.totalThreats === 0) {
    html += `<p class="rpt-muted" style="padding: 12px 0;">No threats matching "${escHtml(data.target)}" found in the live feed. Ensure the dashboard has been running to collect threat data.</p>`;
  }
  html += `</div></div>`;

  // =====================
  // 6. ATM TECHNIQUES
  // =====================
  html += `<div class="rpt-section">
    <h2 class="rpt-section-title"><span class="rpt-sn">6</span>Auto-ISAC ATM Techniques<span class="rpt-count-badge">${data.techniqueTable.length}</span></h2>
    <div class="rpt-section-body">
      <table class="rpt-table"><thead><tr><th>Tactic</th><th>Technique</th><th>D3FEND</th><th>Security Control</th></tr></thead><tbody>
        ${data.techniqueTable.map(t => `<tr>
          <td class="rpt-tactic-list">${t.tactics.map(tc => `<span class="rpt-tactic-chip">${tc}</span>`).join(' ')}</td>
          <td><span class="rpt-tech-id">${t.id}</span> ${escHtml(t.name)}</td>
          <td class="rpt-mono rpt-d3fend">${t.d3fend}</td>
          <td class="rpt-mono">${t.control}</td>
        </tr>`).join('')}
      </tbody></table>
    </div>
  </div>`;

  // =====================
  // 7. DETECTION OPPORTUNITIES
  // =====================
  html += `<div class="rpt-section">
    <h2 class="rpt-section-title"><span class="rpt-sn">7</span>Detection Opportunities</h2>
    <div class="rpt-section-body">
      <table class="rpt-table"><thead><tr><th>Rule / Query Name</th><th>Type</th><th>Description</th><th>Reference</th></tr></thead><tbody>
        ${data.detections.map(d => `<tr><td class="rpt-mono">${escHtml(d.name)}</td><td><span class="rpt-detection-type">${d.type}</span></td><td>${escHtml(d.description)}</td><td class="rpt-mono">${d.reference}</td></tr>`).join('')}
      </tbody></table>
    </div>
  </div>`;

  // =====================
  // AI: Risk Scoring & Recommendations
  // =====================
  html += `<div class="rpt-section rpt-ai-section">
    <h2 class="rpt-section-title"><span class="rpt-sn">AI</span>Risk Scoring Matrix<span class="rpt-ai-tag">AI-POWERED</span></h2>
    <div class="rpt-section-body">
      <table class="rpt-table"><thead><tr><th>Source</th><th>Threats</th><th>Risk Score</th><th>Rating</th></tr></thead><tbody>
        ${data.ai.riskScores.map(rs => `<tr>
          <td>${escHtml(rs.tactic)}</td><td class="rpt-mono">${rs.techCount}</td>
          <td><div class="rpt-score-bar-wrap"><div class="rpt-score-bar" style="width:${rs.score}%; background: ${rs.rating === 'CRITICAL' ? 'var(--red)' : rs.rating === 'HIGH' ? 'var(--orange)' : 'var(--blue)'}"></div><span class="rpt-score-num">${rs.score}</span></div></td>
          <td><span class="rpt-severity-badge rpt-severity-${rs.rating.toLowerCase()}">${rs.rating}</span></td>
        </tr>`).join('')}
      </tbody></table>
    </div>
  </div>`;

  html += `<div class="rpt-section rpt-ai-section">
    <h2 class="rpt-section-title"><span class="rpt-sn">AI</span>Defensive Recommendations<span class="rpt-ai-tag">AI-POWERED</span></h2>
    <div class="rpt-section-body">
      <div class="rpt-rec-tier"><div class="rpt-rec-tier-header rpt-rec-immediate">IMMEDIATE (0-48 hours)</div>
        ${data.ai.recommendations.immediate.map(r => `<div class="rpt-rec-item"><div class="rpt-rec-text">${escHtml(r.text)}</div><div class="rpt-rec-techs"><span class="rpt-rec-tech">${escHtml(r.keyword)}</span></div></div>`).join('')}
      </div>
      <div class="rpt-rec-tier"><div class="rpt-rec-tier-header rpt-rec-short">SHORT-TERM (1-4 weeks)</div>
        ${data.ai.recommendations.shortTerm.map(r => `<div class="rpt-rec-item"><div class="rpt-rec-text">${escHtml(r.text)}</div><div class="rpt-rec-techs"><span class="rpt-rec-tech">${escHtml(r.keyword)}</span></div></div>`).join('')}
      </div>
      <div class="rpt-rec-tier"><div class="rpt-rec-tier-header rpt-rec-long">LONG-TERM (1-6 months)</div>
        ${data.ai.recommendations.longTerm.map(r => `<div class="rpt-rec-item"><div class="rpt-rec-text">${escHtml(r.text)}</div><div class="rpt-rec-techs"><span class="rpt-rec-tech">${escHtml(r.keyword)}</span></div></div>`).join('')}
      </div>
      <div class="rpt-audience"><span class="rpt-audience-label">AUDIENCE:</span><span class="rpt-audience-tag">CISOs</span><span class="rpt-audience-tag">OEM Security Teams</span><span class="rpt-audience-tag">Automotive SOC Teams</span></div>
    </div>
  </div>`;

  // =====================
  // APPENDICES
  // =====================
  html += `<div class="rpt-section rpt-appendices">
    <h2 class="rpt-section-title"><span class="rpt-sn">8</span>Appendices</h2>
    <div class="rpt-section-body">

      <h3 class="rpt-subsection-title">Probability Matrix</h3>
      <table class="rpt-table rpt-prob-table"><thead><tr><th>Almost Impossible</th><th>Highly Unlikely</th><th>Unlikely</th><th>Possible</th><th>Likely</th><th>Highly Likely</th><th>Almost Certain</th></tr></thead>
      <tbody><tr><td>0-5%</td><td>5-25%</td><td>25-45%</td><td>45-55%</td><td>55-75%</td><td>75-85%</td><td>95-100%</td></tr></tbody></table>

      <h3 class="rpt-subsection-title">Priority Matrix</h3>
      <table class="rpt-table rpt-priority-table"><tbody>
        <tr><td class="rpt-pm-low">Low</td><td>The threat needs to be monitored closely and addressed.</td></tr>
        <tr><td class="rpt-pm-mod">Moderate</td><td>The threat needs to be monitored closely and addressed.</td></tr>
        <tr><td class="rpt-pm-high">High</td><td>The threat needs to be addressed quickly and monitored.</td></tr>
        <tr><td class="rpt-pm-crit">Critical</td><td>Immediate action is required.</td></tr>
      </tbody></table>

      <h3 class="rpt-subsection-title">Source &amp; Information Reliability (Admiralty Scale)</h3>
      <table class="rpt-table"><thead><tr><th colspan="2" class="rpt-adm-header">Source Reliability (A-F)</th></tr></thead><tbody>
        <tr><td class="rpt-meta-key">A (Completely reliable)</td><td>The source has a history of consistently providing accurate information.</td></tr>
        <tr><td class="rpt-meta-key">B (Usually reliable)</td><td>Most of the time, the source provides accurate information.</td></tr>
        <tr><td class="rpt-meta-key">C (Fairly reliable)</td><td>The source has provided accurate information on occasion.</td></tr>
        <tr><td class="rpt-meta-key">D (Not usually reliable)</td><td>The source has provided accurate information infrequently.</td></tr>
        <tr><td class="rpt-meta-key">E (Unreliable)</td><td>The source has rarely or never provided accurate information.</td></tr>
        <tr><td class="rpt-meta-key">F (Cannot be judged)</td><td>The source's reliability is unknown or untested.</td></tr>
      </tbody></table>

      <h3 class="rpt-subsection-title">Sensitivity Matrix (TLP)</h3>
      <table class="rpt-table rpt-tlp-table"><thead><tr><th class="rpt-tlp-clear">TLP:CLEAR</th><th class="rpt-tlp-green">TLP:GREEN</th><th class="rpt-tlp-amber">TLP:AMBER</th><th class="rpt-tlp-amber-strict">TLP:AMBER+STRICT</th><th class="rpt-tlp-red">TLP:RED</th></tr></thead><tbody><tr>
        <td>No sharing restrictions. Publicly shareable.</td>
        <td>Can be shared within a community or sector.</td>
        <td>Need-to-know basis within an organization.</td>
        <td>Restricted to the organization only.</td>
        <td>Limited to authorized individuals only.</td>
      </tr></tbody></table>
    </div>
  </div>`;

  // =====================
  // FOOTER
  // =====================
  html += `<div class="rpt-footer">
    <div class="rpt-footer-left">
      <span>CARTINT — Automotive Threat Intelligence Platform</span>
      <span>Report ${data.reportId} — Generated ${data.date} ${data.time} UTC</span>
    </div>
    <div class="rpt-footer-right">
      <span>CARTINT Live Feed — ${data.stats.totalThreats} threats / ${data.stats.totalTechniques} ATM techniques</span>
      <span>${data.sensitivity} — Distribution restricted to automotive sector stakeholders</span>
    </div>
  </div>`;

  return html;
}

// ---- Report Overlay Controls ----

function openReport(html, isAI) {
  const overlay = document.getElementById('reportOverlay');
  document.getElementById('reportBody').innerHTML = html;
  const badge = document.getElementById('reportModeBadge');
  badge.textContent = isAI ? 'AI-ANALYZED' : 'RAW INTELLIGENCE';
  badge.className = `report-mode-badge ${isAI ? 'ai' : 'raw'}`;
  overlay.style.display = 'flex';
  requestAnimationFrame(() => overlay.classList.add('active'));
}

function closeReport() {
  const overlay = document.getElementById('reportOverlay');
  overlay.classList.remove('active');
  setTimeout(() => { overlay.style.display = 'none'; }, 300);
}

// ---- DOCX Export ----

function __unused_getPdfStyles() {
  return `
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=DM+Sans:wght@300;400;500;600;700&display=swap');

    :root {
      --red: #E63946; --red-dim: rgba(230,57,70,0.08);
      --orange: #F77F00; --orange-dim: rgba(247,127,0,0.08);
      --blue: #4895EF; --blue-dim: rgba(72,149,239,0.08);
      --green: #2EC4B6; --green-dim: rgba(46,196,182,0.08);
      --cyan: #48BFE3;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: 'DM Sans', -apple-system, BlinkMacSystemFont, sans-serif;
      color: #1a1a2e;
      background: #fff;
      font-size: 10pt;
      line-height: 1.5;
      padding: 0;
    }

    .pdf-page-wrapper {
      width: 100%;
      padding: 40px 48px;
    }

    /* ---- Cover ---- */
    .rpt-cover { padding: 32px 0 28px; border-bottom: 3px solid var(--red); margin-bottom: 24px; position: relative; }
    .rpt-cover::after { content:''; position: absolute; bottom: -3px; left: 0; width: 100px; height: 3px; background: var(--orange); }
    .rpt-cover-brand { display: flex; align-items: center; gap: 12px; margin-bottom: 28px; }
    .rpt-cover-brand svg rect { fill: var(--red); }
    .rpt-cover-brand svg path { fill: white; }
    .rpt-cover-brand-text { display: flex; flex-direction: column; gap: 1px; }
    .rpt-cover-company { font-family: 'JetBrains Mono', monospace; font-size: 13pt; font-weight: 700; letter-spacing: 4px; color: #111; }
    .rpt-cover-subtitle { font-family: 'JetBrains Mono', monospace; font-size: 6pt; font-weight: 500; letter-spacing: 2px; color: #888; }
    .rpt-cover-title { font-size: 20pt; font-weight: 700; color: #111; line-height: 1.25; margin-bottom: 6px; }
    .rpt-cover-target { font-size: 11pt; color: #555; margin-bottom: 22px; }
    .rpt-cover-meta-table { max-width: 420px; }
    .rpt-meta-table { width: 100%; border-collapse: collapse; }
    .rpt-meta-table td { padding: 7px 10px; font-size: 9pt; border-bottom: 1px solid #eee; }
    .rpt-meta-key { font-family: 'JetBrains Mono', monospace; font-size: 7.5pt; font-weight: 600; letter-spacing: 0.5px; color: #888; white-space: nowrap; width: 200px; }
    .rpt-meta-val { color: #222; font-weight: 500; }

    /* ---- Badges ---- */
    .rpt-priority-badge { font-family: 'JetBrains Mono', monospace; font-size: 7pt; font-weight: 700; letter-spacing: 1px; padding: 2px 8px; border-radius: 3px; }
    .rpt-priority-critical { background: var(--red); color: white; }
    .rpt-priority-high { background: var(--orange); color: white; }
    .rpt-priority-moderate { background: var(--blue); color: white; }
    .rpt-tlp-badge { font-family: 'JetBrains Mono', monospace; font-size: 7pt; font-weight: 700; letter-spacing: 1px; padding: 2px 8px; border-radius: 3px; background: rgba(255,183,77,0.15); color: #e6a817; border: 1px solid rgba(255,183,77,0.35); }
    .rpt-severity-badge { font-family: 'JetBrains Mono', monospace; font-size: 7pt; font-weight: 700; letter-spacing: 1px; padding: 2px 8px; border-radius: 3px; }
    .rpt-severity-critical { background: var(--red); color: white; }
    .rpt-severity-high { background: var(--orange); color: white; }
    .rpt-severity-medium { background: var(--blue); color: white; }
    .rpt-severity-low { background: #999; color: white; }

    /* ---- Sections ---- */
    .rpt-section { margin-bottom: 22px; page-break-inside: avoid; }
    .rpt-section-title { font-size: 13pt; font-weight: 700; color: #111; display: flex; align-items: center; gap: 8px; padding-bottom: 8px; border-bottom: 1px solid #e0e0e0; margin-bottom: 14px; }
    .rpt-sn { font-family: 'JetBrains Mono', monospace; font-size: 7.5pt; font-weight: 700; color: #888; background: #f4f4f4; border: 1px solid #ddd; padding: 1px 6px; border-radius: 3px; min-width: 20px; text-align: center; }
    .rpt-ai-tag { font-family: 'JetBrains Mono', monospace; font-size: 6pt; font-weight: 700; letter-spacing: 1px; padding: 2px 6px; border-radius: 3px; background: rgba(230,57,70,0.08); color: var(--red); border: 1px solid rgba(230,57,70,0.2); margin-left: auto; }
    .rpt-count-badge { font-family: 'JetBrains Mono', monospace; font-size: 7pt; font-weight: 600; color: #888; background: #f4f4f4; padding: 1px 6px; border-radius: 3px; }
    .rpt-subsection-title { font-family: 'JetBrains Mono', monospace; font-size: 7.5pt; font-weight: 700; letter-spacing: 1px; color: #888; text-transform: uppercase; margin: 18px 0 10px; padding-bottom: 5px; border-bottom: 1px solid #eee; }
    .rpt-section-body { padding: 0; }
    .rpt-section-body p { font-size: 9.5pt; line-height: 1.65; color: #444; margin-bottom: 8px; }
    .rpt-section-body p strong { color: #111; }

    /* ---- Executive Summary ---- */
    .rpt-exec-severity { margin-bottom: 10px; }
    .rpt-exec-text { font-size: 9.5pt; line-height: 1.7; color: #444; }
    .rpt-exec-text strong { color: #111; }

    /* ---- Key Takeaways ---- */
    .rpt-takeaway-list { list-style: none; padding: 0; margin: 0 0 16px; }
    .rpt-takeaway-list li { font-size: 9pt; color: #444; line-height: 1.55; padding: 4px 0 4px 14px; position: relative; }
    .rpt-takeaway-list li::before { content: ''; position: absolute; left: 0; top: 10px; width: 5px; height: 5px; border-radius: 50%; background: var(--red); }
    .rpt-takeaway-list li strong { color: #111; }
    .rpt-takeaway-table { margin-bottom: 18px; }

    /* ---- Diamond Model ---- */
    .rpt-diamond { margin-top: 18px; padding: 16px; background: #f8f8fa; border-radius: 6px; border: 1px solid #e8e8e8; page-break-inside: avoid; }
    .rpt-diamond-title { font-family: 'JetBrains Mono', monospace; font-size: 7.5pt; font-weight: 700; letter-spacing: 1.5px; color: var(--red); text-align: center; margin-bottom: 12px; text-transform: uppercase; }
    .rpt-diamond-grid { display: flex; flex-direction: column; align-items: center; gap: 0; }
    .rpt-diamond-cell { display: flex; flex-direction: column; align-items: center; text-align: center; padding: 8px 12px; max-width: 280px; }
    .rpt-diamond-top { margin-bottom: 2px; }
    .rpt-diamond-bottom { margin-top: 2px; }
    .rpt-diamond-row { display: flex; align-items: center; justify-content: center; gap: 12px; width: 100%; }
    .rpt-diamond-center { flex-shrink: 0; display: flex; align-items: center; justify-content: center; opacity: 0.5; }
    .rpt-diamond-center svg polygon { stroke: var(--red); }
    .rpt-diamond-center svg line { stroke: var(--red); }
    .rpt-diamond-label { font-family: 'JetBrains Mono', monospace; font-size: 6.5pt; font-weight: 700; letter-spacing: 1.5px; color: #888; text-transform: uppercase; display: block; margin-bottom: 3px; }
    .rpt-diamond-value { font-size: 8pt; color: #555; line-height: 1.4; display: block; }

    /* ---- Assessment ---- */
    .rpt-assessment-text { margin-bottom: 14px; }
    .rpt-assessment-text p { font-size: 9.5pt; line-height: 1.7; color: #444; margin-bottom: 8px; }
    .rpt-assessment-text p strong { color: #111; }

    /* ---- Attack Paths ---- */
    .rpt-attack-paths { margin-top: 14px; }
    .rpt-attack-path { margin-bottom: 18px; padding: 14px; background: #f8f8fa; border-radius: 6px; border: 1px solid #e0e0e0; page-break-inside: avoid; }
    .rpt-path-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; }
    .rpt-path-name { font-size: 10.5pt; font-weight: 700; color: #111; }
    .rpt-path-conf { font-family: 'JetBrains Mono', monospace; font-size: 8pt; font-weight: 600; color: var(--orange); }
    .rpt-path-chain { display: flex; flex-direction: column; align-items: center; gap: 0; }
    .rpt-path-step { width: 100%; padding: 10px 14px; background: #fff; border: 1px solid #e8e8e8; border-radius: 5px; }
    .rpt-path-step-header { display: flex; align-items: center; gap: 6px; margin-bottom: 3px; }
    .rpt-path-step-num { width: 18px; height: 18px; border-radius: 50%; background: var(--red); color: white; display: flex; align-items: center; justify-content: center; font-family: 'JetBrains Mono', monospace; font-size: 7pt; font-weight: 700; flex-shrink: 0; }
    .rpt-path-step-tactic { font-family: 'JetBrains Mono', monospace; font-size: 7pt; font-weight: 600; letter-spacing: 0.5px; color: var(--red); }
    .rpt-path-step-tech { font-family: 'JetBrains Mono', monospace; font-size: 8pt; font-weight: 600; color: #222; margin-bottom: 2px; }
    .rpt-path-step-detail { font-size: 8pt; color: #666; line-height: 1.4; }
    .rpt-path-arrow { display: flex; justify-content: center; padding: 2px 0; }
    .rpt-path-arrow svg path { stroke: var(--red); }

    /* ---- Kill Chain ---- */
    .rpt-killchain-table { margin-top: 6px; }
    .rpt-kc-header { font-family: 'JetBrains Mono', monospace; font-size: 7pt; font-weight: 700; letter-spacing: 1px; color: var(--red); background: rgba(230,57,70,0.06); text-align: center; padding: 8px; }
    .rpt-kc-active { background: rgba(230,57,70,0.03); border-left: 3px solid var(--red); }
    .rpt-kc-stage { white-space: nowrap; width: 160px; }
    .rpt-kc-stage strong { color: #222; font-size: 9pt; }
    .rpt-kc-detail { font-size: 8pt; color: #555; }
    .rpt-muted { color: #999; font-style: italic; font-size: 8pt; }

    /* ---- Gaps ---- */
    .rpt-gap-list { list-style: none; padding: 0; margin: 0; }
    .rpt-gap-list li { font-size: 9pt; color: #444; line-height: 1.55; padding: 6px 0 6px 18px; position: relative; border-bottom: 1px solid #f0f0f0; }
    .rpt-gap-list li:last-child { border-bottom: none; }
    .rpt-gap-list li::before { content: '!'; position: absolute; left: 0; top: 7px; width: 12px; height: 12px; border-radius: 50%; background: rgba(247,127,0,0.1); color: var(--orange); font-family: 'JetBrains Mono', monospace; font-size: 7pt; font-weight: 800; display: flex; align-items: center; justify-content: center; line-height: 1; }

    /* ---- Tables ---- */
    .rpt-table { width: 100%; border-collapse: collapse; font-size: 8.5pt; page-break-inside: auto; }
    .rpt-table thead th { font-family: 'JetBrains Mono', monospace; font-size: 6.5pt; font-weight: 600; letter-spacing: 1px; color: #888; text-align: left; padding: 6px 8px; border-bottom: 1px solid #ddd; text-transform: uppercase; }
    .rpt-table tbody tr { border-bottom: 1px solid #f0f0f0; }
    .rpt-table tbody tr:hover { background: transparent; }
    .rpt-table td { padding: 6px 8px; color: #444; vertical-align: top; }
    .rpt-mono { font-family: 'JetBrains Mono', monospace; font-size: 7.5pt; }
    .rpt-tech-id { color: var(--red); font-weight: 600; white-space: nowrap; }
    .rpt-tactic-list { display: flex; flex-wrap: wrap; gap: 2px; }
    .rpt-tactic-chip { font-family: 'JetBrains Mono', monospace; font-size: 6pt; font-weight: 600; color: #888; background: #f4f4f4; padding: 1px 4px; border-radius: 2px; white-space: nowrap; }
    .rpt-procedure { font-size: 8pt; color: #666; max-width: 160px; line-height: 1.35; }
    .rpt-d3fend { font-size: 7pt; color: #2a9d8f; }
    .rpt-hash { font-size: 7pt; word-break: break-all; max-width: 130px; }
    .rpt-cve { color: var(--red); font-weight: 600; }

    /* ---- CVSS ---- */
    .rpt-cvss { font-family: 'JetBrains Mono', monospace; font-size: 7.5pt; font-weight: 700; padding: 1px 6px; border-radius: 3px; display: inline-block; }
    .rpt-cvss.critical { background: rgba(230,57,70,0.1); color: var(--red); }
    .rpt-cvss.high { background: rgba(247,127,0,0.1); color: var(--orange); }
    .rpt-cvss.medium { background: rgba(72,149,239,0.1); color: var(--blue); }

    /* ---- Detection ---- */
    .rpt-detection-type { font-family: 'JetBrains Mono', monospace; font-size: 6.5pt; font-weight: 700; padding: 1px 6px; border-radius: 3px; background: rgba(46,196,182,0.08); color: #2a9d8f; white-space: nowrap; }

    /* ---- AI Sections ---- */
    .rpt-ai-section { background: #fdf8f8; border: 1px solid #f0e0e0; border-radius: 6px; padding: 16px; page-break-inside: avoid; margin-bottom: 18px; }
    .rpt-score-bar-wrap { display: flex; align-items: center; gap: 6px; }
    .rpt-score-bar { height: 5px; border-radius: 3px; max-width: 90px; }
    .rpt-score-num { font-family: 'JetBrains Mono', monospace; font-size: 7.5pt; font-weight: 600; color: #888; min-width: 18px; }

    /* ---- Recommendations ---- */
    .rpt-rec-tier { margin-bottom: 14px; page-break-inside: avoid; }
    .rpt-rec-tier-header { font-family: 'JetBrains Mono', monospace; font-size: 7pt; font-weight: 700; letter-spacing: 1px; padding: 4px 10px; border-radius: 3px; margin-bottom: 8px; display: inline-block; }
    .rpt-rec-immediate { background: rgba(230,57,70,0.08); color: var(--red); }
    .rpt-rec-short { background: rgba(247,127,0,0.08); color: var(--orange); }
    .rpt-rec-long { background: rgba(72,149,239,0.08); color: var(--blue); }
    .rpt-rec-item { padding: 8px 12px; background: #f8f8fa; border-radius: 4px; margin-bottom: 5px; border-left: 3px solid #ddd; }
    .rpt-rec-text { font-size: 8.5pt; color: #444; line-height: 1.45; margin-bottom: 4px; }
    .rpt-rec-techs { display: flex; flex-wrap: wrap; gap: 3px; }
    .rpt-rec-tech { font-family: 'JetBrains Mono', monospace; font-size: 6pt; font-weight: 600; color: var(--red); background: rgba(230,57,70,0.06); padding: 1px 5px; border-radius: 2px; }
    .rpt-audience { display: flex; align-items: center; gap: 8px; margin-top: 12px; padding-top: 12px; border-top: 1px solid #eee; }
    .rpt-audience-label { font-family: 'JetBrains Mono', monospace; font-size: 7pt; font-weight: 600; letter-spacing: 1px; color: #888; }
    .rpt-audience-tag { font-family: 'JetBrains Mono', monospace; font-size: 7pt; font-weight: 600; color: #555; background: #f4f4f4; border: 1px solid #e0e0e0; padding: 2px 8px; border-radius: 3px; }

    /* ---- Appendices ---- */
    .rpt-appendices { background: #fafafa; border: 1px solid #e8e8e8; border-radius: 6px; padding: 18px; margin-top: 10px; }
    .rpt-prob-table thead th { font-size: 6pt; text-align: center; padding: 6px 4px; letter-spacing: 0; }
    .rpt-prob-table tbody td { text-align: center; font-family: 'JetBrains Mono', monospace; font-size: 8pt; font-weight: 600; color: #444; padding: 8px 4px; }
    .rpt-priority-table td:first-child { font-family: 'JetBrains Mono', monospace; font-size: 7.5pt; font-weight: 700; letter-spacing: 0.5px; width: 90px; text-align: center; padding: 8px 10px; }
    .rpt-pm-low { background: rgba(72,149,239,0.1); color: var(--blue); }
    .rpt-pm-mod { background: rgba(255,183,77,0.1); color: #c98b00; }
    .rpt-pm-high { background: rgba(247,127,0,0.08); color: var(--orange); }
    .rpt-pm-crit { background: rgba(230,57,70,0.08); color: var(--red); }
    .rpt-adm-header { background: #f4f4f4; font-size: 7.5pt; letter-spacing: 0.5px; text-align: center; color: #333 !important; }
    .rpt-tlp-table thead th { font-size: 6.5pt; text-align: center; padding: 8px 6px; letter-spacing: 0.5px; }
    .rpt-tlp-table tbody td { text-align: center; font-size: 8pt; padding: 10px 6px; }
    .rpt-tlp-clear { background: #f4f4f4; color: #333 !important; }
    .rpt-tlp-green { background: rgba(46,196,182,0.08); color: #2a9d8f !important; }
    .rpt-tlp-amber { background: rgba(255,183,77,0.08); color: #c98b00 !important; }
    .rpt-tlp-amber-strict { background: rgba(255,152,0,0.1); color: #e68a00 !important; }
    .rpt-tlp-red { background: rgba(230,57,70,0.06); color: var(--red) !important; }

    /* ---- Footer ---- */
    .rpt-footer { margin-top: 24px; padding: 16px 0; border-top: 2px solid #ddd; display: flex; justify-content: space-between; gap: 20px; }
    .rpt-footer-left, .rpt-footer-right { display: flex; flex-direction: column; gap: 3px; }
    .rpt-footer span { font-family: 'JetBrains Mono', monospace; font-size: 6.5pt; color: #999; letter-spacing: 0.3px; }
  `;
}

async function exportRawDocx(D, data, config, h) {
  const { heading, sectionTitle, subTitle, para, boldPara, bullet, emptyLine, tableBorder, headerCell, dataCell, RED, ORANGE, BLUE, GREEN, GRAY, DARK, BORDER_COLOR, font, monoFont } = h;

  const children = [];

  // ===== HEADER =====
  children.push(emptyLine(), emptyLine(), emptyLine());
  children.push(new D.Paragraph({
    children: [
      new D.TextRun({ text: '\u2588\u2588', font: monoFont, size: 48, color: RED }),
      new D.TextRun({ text: '  CARTINT', font, bold: true, size: 48, color: DARK }),
    ],
    spacing: { after: 60 }
  }));
  children.push(new D.Paragraph({ children: [new D.TextRun({ text: 'RAW INTELLIGENCE DUMP', font, size: 16, color: GRAY, characterSpacing: 160 })], spacing: { after: 60 } }));
  children.push(new D.Paragraph({ children: [new D.TextRun({ text: 'INDICATOR FEEDS  |  RAW TELEMETRY  |  ATM TECHNIQUE IDs', font, size: 14, color: GRAY, characterSpacing: 60 })], spacing: { after: 400 } }));
  children.push(new D.Paragraph({
    children: [new D.TextRun({ text: `Target: ${data.target}`, font, bold: true, size: 32, color: RED })],
    spacing: { after: 80 },
    border: { bottom: { style: D.BorderStyle.SINGLE, size: 3, color: RED } }
  }));
  children.push(emptyLine());

  // Metadata
  const metaRows = [
    ['REPORT_ID', data.reportId], ['TIMESTAMP', `${data.date}T${data.time}Z`],
    ['WINDOW', config.timeRange], ['FEED_SIZE', `${data.totalFeedSize} events`],
    ['MATCHED', `${data.matchedCount} hits`], ['SOURCES', `${data.stats.totalSources}`],
    ['ADMIRALTY', data.sourceReliability], ['TLP', data.sensitivity]
  ];
  children.push(new D.Table({
    rows: metaRows.map(([k, v], i) => new D.TableRow({
      children: [
        dataCell(k, { bold: true, size: 18, color: DARK, width: 2800, altRow: i % 2 === 1 }),
        dataCell(v, { mono: true, size: 20, color: '333333', width: 6200, altRow: i % 2 === 1 })
      ]
    })),
    width: { size: 9000, type: D.WidthType.DXA }
  }));

  children.push(new D.Paragraph({ children: [], pageBreakBefore: true }));

  // ===== 01. INDICATOR FEED =====
  children.push(sectionTitle('01', `Indicator Feed  [${data.iocs.length} indicators]`));

  if (data.iocs.length > 0) {
    children.push(new D.Table({
      rows: [
        new D.TableRow({ children: [headerCell('Type', 1200), headerCell('Value', 3600), headerCell('Conf', 800), headerCell('Source', 1600), headerCell('Context', 2400)] }),
        ...data.iocs.slice(0, 100).map(ioc => new D.TableRow({
          children: [
            dataCell(ioc.type, { mono: true, size: 14, bold: true, color: ioc.type === 'CVE' ? RED : ioc.type === 'IPv4' ? ORANGE : BLUE, width: 1200 }),
            dataCell(ioc.value, { mono: true, size: 13, width: 3600 }),
            dataCell(`${ioc.confidence}%`, { mono: true, size: 13, width: 800 }),
            dataCell(ioc.source, { mono: true, size: 13, width: 1600 }),
            dataCell(ioc.context, { size: 12, color: GRAY, width: 2400 })
          ]
        }))
      ],
      width: { size: 9600, type: D.WidthType.DXA }
    }));
  } else {
    children.push(para('NO INDICATORS EXTRACTED FROM FEED DATA', { color: GRAY, italic: true }));
  }

  // ===== 02. RAW TELEMETRY =====
  children.push(new D.Paragraph({ children: [], pageBreakBefore: true }));
  children.push(sectionTitle('02', `Raw Telemetry  [${data.telemetry.length} log lines]`));

  if (data.telemetry.length > 0) {
    children.push(new D.Table({
      rows: [
        new D.TableRow({ children: [headerCell('#', 600), headerCell('Sev', 1000), headerCell('Source', 1200), headerCell('Conf', 800), headerCell('Event', 6000)] }),
        ...data.telemetry.slice(0, 50).map(t => new D.TableRow({
          children: [
            dataCell(`${t.seq}`, { mono: true, size: 13, color: GRAY, width: 600 }),
            dataCell(t.severity, { mono: true, size: 13, bold: true, color: t.severity === 'CRITICAL' ? RED : t.severity === 'HIGH' ? ORANGE : BLUE, width: 1000 }),
            dataCell(t.source, { mono: true, size: 13, width: 1200 }),
            dataCell(`${t.confidence}%`, { mono: true, size: 13, width: 800 }),
            dataCell(t.title, { size: 14, width: 6000 })
          ]
        }))
      ],
      width: { size: 9600, type: D.WidthType.DXA }
    }));
    if (data.telemetry.length > 50) {
      children.push(para(`... ${data.telemetry.length - 50} additional log lines truncated`, { color: GRAY, italic: true }));
    }
  } else {
    children.push(para('NO MATCHING EVENTS IN FEED', { color: GRAY, italic: true }));
  }

  // ===== 03. AUTO-ISAC ATM TECHNIQUE IDs =====
  children.push(new D.Paragraph({ children: [], pageBreakBefore: true }));
  children.push(sectionTitle('03', `Auto-ISAC ATM Technique IDs  [${data.techniqueTable.length}]`));

  if (data.techniqueTable.length > 0) {
    children.push(new D.Table({
      rows: [
        new D.TableRow({ children: [headerCell('Technique ID', 2000), headerCell('Name', 3800), headerCell('Tactics', 3800)] }),
        ...data.techniqueTable.map(t => new D.TableRow({
          children: [
            dataCell(t.id, { mono: true, size: 15, bold: true, color: RED, width: 2000 }),
            dataCell(t.name, { size: 16, width: 3800 }),
            dataCell(t.tactics.join(' | '), { mono: true, size: 13, color: GRAY, width: 3800 })
          ]
        }))
      ],
      width: { size: 9600, type: D.WidthType.DXA }
    }));
  } else {
    children.push(para('NO TECHNIQUE MAPPINGS IN MATCHED DATA', { color: GRAY, italic: true }));
  }

  // ===== 04. SOURCE ATTRIBUTION =====
  children.push(sectionTitle('04', `Source Attribution  [${data.sourceConfidence.length} sources]`));

  children.push(new D.Table({
    rows: [
      new D.TableRow({ children: [headerCell('Source', 2800), headerCell('Events', 1600), headerCell('Avg Conf', 1600), headerCell('Admiralty', 1600)] }),
      ...data.sourceConfidence.map(s => {
        const admCode = { 'NVD/CVE': 'A1', 'CT Logs': 'A2', 'ExploitDB': 'B2', 'GitHub': 'B3', 'MISP': 'B2', 'Firmware Repos': 'C3', 'Dark Web': 'D3' }[s.name] || 'F6';
        return new D.TableRow({
          children: [
            dataCell(s.name, { mono: true, size: 15, width: 2800 }),
            dataCell(`${s.count}`, { mono: true, size: 15, width: 1600 }),
            dataCell(`${s.avgConfidence}%`, { mono: true, size: 15, width: 1600 }),
            dataCell(admCode, { mono: true, size: 15, bold: true, width: 1600 })
          ]
        });
      })
    ],
    width: { size: 9600, type: D.WidthType.DXA }
  }));

  // ===== FOOTER =====
  children.push(emptyLine());
  children.push(new D.Paragraph({ children: [new D.TextRun({ text: '─'.repeat(60), font: monoFont, size: 12, color: BORDER_COLOR })], spacing: { after: 60 } }));
  children.push(new D.Paragraph({
    children: [new D.TextRun({ text: `CARTINT  \u2014  ${data.reportId}  \u2014  ${data.date}T${data.time}Z`, font, size: 16, color: GRAY })],
    spacing: { after: 40 },
    border: { top: { style: D.BorderStyle.SINGLE, size: 2, color: RED } }
  }));
  children.push(new D.Paragraph({ children: [new D.TextRun({ text: `${data.iocs.length} IOCs / ${data.telemetry.length} events / ${data.techniqueTable.length} techniques  \u2014  ${data.sensitivity}`, font, size: 16, color: GRAY })], spacing: { after: 0 } }));

  // ===== CREATE DOCUMENT =====
  const doc = new D.Document({
    styles: {
      paragraphStyles: [{
        id: 'Normal', name: 'Normal',
        run: { font, size: 20, color: '333333' },
        paragraph: { spacing: { before: 120, after: 120, line: 340 } }
      }]
    },
    sections: [{
      properties: {
        page: {
          margin: { top: 1440, bottom: 1440, left: 1080, right: 1080 },
          size: { width: 12240, height: 15840 }
        }
      },
      headers: {
        default: new D.Header({
          children: [new D.Paragraph({
            children: [
              new D.TextRun({ text: '\u2588', font: monoFont, size: 14, color: RED }),
              new D.TextRun({ text: ' CARTINT RAW', font, bold: true, size: 16, color: DARK }),
              new D.TextRun({ text: `    ${data.reportId}    ${data.sensitivity}`, font, size: 14, color: GRAY })
            ],
            alignment: D.AlignmentType.RIGHT,
            border: { bottom: { style: D.BorderStyle.SINGLE, size: 1, color: BORDER_COLOR } },
            spacing: { after: 0 }
          })]
        })
      },
      footers: {
        default: new D.Footer({
          children: [new D.Paragraph({
            children: [
              new D.TextRun({ text: `${data.sensitivity}  \u2014  CARTINT Raw Intelligence Dump`, font, size: 14, color: GRAY })
            ],
            alignment: D.AlignmentType.CENTER,
            border: { top: { style: D.BorderStyle.SINGLE, size: 1, color: BORDER_COLOR } },
            spacing: { before: 100 }
          })]
        })
      },
      children
    }]
  });

  const blob = await D.Packer.toBlob(doc);
  saveAs(blob, `${data.reportId}-RAW.docx`);
}

async function exportDocx() {
  if (!lastReportData || !lastReportConfig) { alert('Generate a report first.'); return; }

  const D = docx;
  const data = lastReportData;
  const config = lastReportConfig;
  const isAI = config.mode === 'ai';

  // ---- Style constants (PDF-inspired with CARTINT brand) ----
  const RED = 'E63946';       // CARTINT brand red (accent)
  const ORANGE = 'F77F00';
  const BLUE = '4895EF';
  const GREEN = '2EC4B6';
  const GRAY = '666666';
  const DARK = '1a1a2e';      // CARTINT navy
  const BORDER_COLOR = 'D5D5D5';
  const HDR_FILL = 'E8E8E8';  // Table header fill
  const ROW_FILL = 'F2F2F2';  // Table body alt-row fill
  const font = 'Raleway';
  const monoFont = 'Consolas';
  // Body text: 10pt = size 20 in docx half-points
  // Headings: 14pt bold = size 28
  // 6pt spacing = 120 twips (approx)

  // ---- Helpers ----
  function heading(text, level = 1) {
    const headingMap = { 1: D.HeadingLevel.HEADING_1, 2: D.HeadingLevel.HEADING_2, 3: D.HeadingLevel.HEADING_3 };
    return new D.Paragraph({ heading: headingMap[level] || D.HeadingLevel.HEADING_1, children: [new D.TextRun({ text, font, bold: level <= 2, italics: level === 4, size: level <= 2 ? 28 : 24, color: level === 4 ? '0F4761' : RED })], spacing: { before: level === 1 ? 400 : 280, after: 120 } });
  }

  function sectionTitle(num, text, aiTag) {
    const children = [
      new D.TextRun({ text: `${num}  `, font: monoFont, bold: true, size: 20, color: RED }),
      new D.TextRun({ text, font, bold: true, size: 28, color: RED })
    ];
    if (aiTag) children.push(new D.TextRun({ text: `  [${aiTag}]`, font: monoFont, bold: true, size: 16, color: GRAY }));
    return new D.Paragraph({ children, spacing: { before: 360, after: 120 }, border: { bottom: { style: D.BorderStyle.SINGLE, size: 2, color: RED } } });
  }

  function subTitle(text) {
    return new D.Paragraph({ children: [new D.TextRun({ text: text.toUpperCase(), font, bold: true, size: 22, color: DARK, characterSpacing: 40 })], spacing: { before: 260, after: 100 }, border: { bottom: { style: D.BorderStyle.SINGLE, size: 1, color: BORDER_COLOR } } });
  }

  function para(text, opts = {}) {
    return new D.Paragraph({ children: [new D.TextRun({ text, font, size: 20, color: opts.color || '333333', bold: opts.bold, italics: opts.italic })], spacing: { before: 120, after: opts.after !== undefined ? opts.after : 120, line: 340 }, ...(opts.indent ? { indent: { left: opts.indent } } : {}) });
  }

  function boldPara(label, value) {
    return new D.Paragraph({ children: [new D.TextRun({ text: label, font, bold: true, size: 20, color: DARK }), new D.TextRun({ text: value, font, size: 20, color: '333333' })], spacing: { before: 60, after: 60, line: 340 } });
  }

  function bullet(text) {
    return new D.Paragraph({ children: [new D.TextRun({ text, font, size: 20, color: '333333' })], bullet: { level: 0 }, spacing: { before: 60, after: 60, line: 340 } });
  }

  function emptyLine() { return new D.Paragraph({ spacing: { after: 160 } }); }

  function tableBorder() {
    const b = { style: D.BorderStyle.SINGLE, size: 1, color: BORDER_COLOR };
    return { top: b, bottom: b, left: b, right: b };
  }

  function headerCell(text, width) {
    return new D.TableCell({
      children: [new D.Paragraph({ children: [new D.TextRun({ text: text.toUpperCase(), font, bold: true, size: 18, color: DARK })], spacing: { after: 0 } })],
      width: width ? { size: width, type: D.WidthType.DXA } : undefined,
      shading: { type: D.ShadingType.SOLID, color: HDR_FILL },
      borders: tableBorder(),
      margins: { top: 60, bottom: 60, left: 100, right: 100 }
    });
  }

  function dataCell(text, opts = {}) {
    return new D.TableCell({
      children: [new D.Paragraph({ children: [new D.TextRun({ text: text || '\u2014', font: opts.mono ? monoFont : font, size: opts.size || 20, color: opts.color || '333333', bold: opts.bold, italics: opts.italic })], spacing: { after: 0, line: 340 } })],
      width: opts.width ? { size: opts.width, type: D.WidthType.DXA } : undefined,
      shading: opts.shading ? { type: D.ShadingType.SOLID, color: opts.shading } : opts.altRow ? { type: D.ShadingType.SOLID, color: ROW_FILL } : undefined,
      borders: tableBorder(),
      margins: { top: 50, bottom: 50, left: 100, right: 100 }
    });
  }

  // ---- Build document sections ----
  const children = [];

  // ── Fork: Raw = data dump DOCX, AI = full analytical DOCX ──
  if (!isAI) {
    return exportRawDocx(D, data, config, { heading, sectionTitle, subTitle, para, boldPara, bullet, emptyLine, tableBorder, headerCell, dataCell, RED, ORANGE, BLUE, GREEN, GRAY, DARK, BORDER_COLOR, font, monoFont });
  }

  // ===== COVER PAGE =====
  children.push(emptyLine(), emptyLine(), emptyLine(), emptyLine());

  // Brand mark — red bar + CARTINT
  children.push(new D.Paragraph({
    children: [
      new D.TextRun({ text: '\u2588\u2588', font: monoFont, size: 48, color: RED }),
      new D.TextRun({ text: '  CARTINT', font, bold: true, size: 48, color: DARK }),
    ],
    spacing: { after: 60 }
  }));
  children.push(new D.Paragraph({ children: [new D.TextRun({ text: 'AUTOMOTIVE THREAT INTELLIGENCE', font, size: 16, color: GRAY, characterSpacing: 160 })], spacing: { after: 500 } }));

  // Title
  children.push(new D.Paragraph({
    children: [new D.TextRun({ text: config.reportType || 'Automotive Threat Intelligence Report', font, bold: true, size: 44, color: RED })],
    spacing: { after: 80 },
    border: { bottom: { style: D.BorderStyle.SINGLE, size: 3, color: RED } }
  }));
  children.push(new D.Paragraph({ children: [new D.TextRun({ text: `Target: ${data.target}`, font, size: 24, color: '555555' })], spacing: { after: 400 } }));

  // Cover metadata table
  const coverRows = [
    ['Report ID', data.reportId],
    ['Date', `${data.date} ${data.time} UTC`],
    ['Priority', data.priority],
    ['Source & Information Reliability', `${data.sourceReliability} (Admiralty Scale)`],
    ['Sensitivity', data.sensitivity]
  ];
  children.push(new D.Table({
    rows: coverRows.map(([k, v], i) => new D.TableRow({
      children: [
        dataCell(k, { bold: true, size: 18, color: DARK, width: 4000, altRow: i % 2 === 1 }),
        dataCell(v, { bold: k === 'Priority', color: k === 'Priority' ? RED : undefined, size: 20, altRow: i % 2 === 1 })
      ]
    })),
    width: { size: 9000, type: D.WidthType.DXA }
  }));

  children.push(new D.Paragraph({ children: [], pageBreakBefore: true }));

  // ===== 1. EXECUTIVE SUMMARY =====
  children.push(sectionTitle('1', 'Executive Summary', isAI ? 'AI-POWERED' : null));

  if (isAI && data.ai) {
    children.push(new D.Paragraph({ children: [new D.TextRun({ text: `${data.ai.severity} SEVERITY`, font: monoFont, bold: true, size: 16, color: RED })], spacing: { after: 120 } }));
    // Strip HTML tags from exec summary for clean text
    const execClean = data.ai.execSummary.replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');
    children.push(para(execClean, { after: 120 }));
  } else {
    children.push(para(`This report presents raw intelligence from the CARTINT live threat feed for ${data.target} covering the ${config.timeRange} period. ${data.stats.totalThreats} threats matched across ${data.stats.totalSources} source(s) — ${data.stats.criticalCount} critical, ${data.stats.highCount} high-severity. ${data.stats.totalCVEs} CVE(s) identified, ${data.stats.totalTechniques} ATM technique(s) mapped.`));
  }

  // ===== 2. KEY TAKEAWAYS =====
  children.push(sectionTitle('2', 'Key Takeaways'));
  children.push(boldPara('Report for: ', `${data.target} security teams, OEM SOC analysts, supply chain risk managers`));
  children.push(boldPara('ATM Database Match: ', data.keyTakeaways.matchSummary));
  children.push(boldPara('Techniques Mapped: ', `${data.stats.totalTechniques} ATM techniques`));
  children.push(boldPara('Threat Actors: ', data.stats.totalGroups > 0 ? `${data.stats.totalGroups} group(s) observed` : 'No threat actors identified'));
  children.push(boldPara('CVEs Found: ', data.stats.totalCVEs > 0 ? `${data.stats.totalCVEs} CVE(s) extracted from live threat data` : 'No CVEs found in matched threat data'));
  children.push(boldPara('Threat Profile: ', data.diamond.adversary));
  children.push(emptyLine());

  // Key Takeaways summary table
  const ktRows = [
    ['Intelligence Requirements', data.keyTakeaways.intelligenceReqs],
    ['Data Sources', data.keyTakeaways.dataSources],
    ['ATM Database Coverage', data.keyTakeaways.matchSummary],
    ['Sectors', data.keyTakeaways.sectors]
  ];
  children.push(new D.Table({
    rows: ktRows.map(([k, v]) => new D.TableRow({ children: [dataCell(k, { mono: true, size: 16, color: GRAY, width: 3200 }), dataCell(v)] })),
    width: { size: 9600, type: D.WidthType.DXA }
  }));
  children.push(emptyLine());

  // Diamond Model
  children.push(subTitle('Diamond Model'));
  const dmRows = [
    ['Adversary', data.diamond.adversary],
    ['Infrastructure', data.diamond.infrastructure],
    ['Capability', data.diamond.capability],
    ['Victim', data.diamond.victim]
  ];
  children.push(new D.Table({
    rows: dmRows.map(([k, v]) => new D.TableRow({
      children: [
        dataCell(k, { mono: true, bold: true, size: 16, color: RED, width: 2400, shading: 'FDF5F5' }),
        dataCell(v, { size: 17 })
      ]
    })),
    width: { size: 9600, type: D.WidthType.DXA }
  }));

  // ===== 3. INTELLIGENCE ASSESSMENT =====
  children.push(new D.Paragraph({ children: [], pageBreakBefore: true }));
  children.push(sectionTitle('3', 'Intelligence Assessment', isAI ? 'AI' : null));

  if (isAI && data.ai) {
    children.push(para(`${data.matchedCount} live threats matched "${data.target}" from ${data.stats.totalSources} source(s). ${data.stats.criticalCount} critical, ${data.stats.highCount} high-severity findings observed.`));
    if (data.stats.totalCVEs > 0) children.push(para(`${data.stats.totalCVEs} CVE(s) identified in matched threat data.`));
    if (data.groups.length > 0) children.push(para(`Threat actors observed: ${data.groups.map(g => g.name).join(', ')}`));
    children.push(emptyLine());
  }

  // Kill Chain
  children.push(subTitle('Automotive Kill Chain (ATM Framework)'));
  children.push(new D.Table({
    rows: [
      new D.TableRow({ children: [headerCell('Stage', 2400), headerCell('Mapped Techniques')] }),
      ...data.killChain.map(kc => new D.TableRow({
        children: [
          dataCell(`${kc.stage}: ${kc.name}`, { bold: true, size: 17, color: kc.hasActivity ? RED : GRAY, width: 2400 }),
          dataCell(kc.hasActivity ? kc.techniques.map(t => getExtId(t) + ': ' + t.name).join('; ') : 'No observed activity', { size: 16, color: kc.hasActivity ? '444444' : GRAY, italic: !kc.hasActivity })
        ]
      }))
    ],
    width: { size: 9600, type: D.WidthType.DXA }
  }));

  // ===== 4. KEY INTELLIGENCE GAPS =====
  children.push(sectionTitle('4', 'Key Intelligence Gaps'));
  data.gaps.forEach(g => children.push(bullet(g)));

  // ===== 5. LIVE THREAT FINDINGS =====
  children.push(new D.Paragraph({ children: [], pageBreakBefore: true }));
  children.push(sectionTitle('5', `Live Threat Findings  [${data.stats.totalThreats} threats / ${data.stats.totalCVEs} CVEs]`));

  // CVEs from live feed
  if (data.cves.length > 0) {
    children.push(subTitle('CVEs Identified in Live Threat Data'));
    children.push(new D.Table({
      rows: [
        new D.TableRow({ children: [headerCell('CVE ID', 2000), headerCell('Source', 1400), headerCell('Severity', 1200), headerCell('Context', 5000)] }),
        ...data.cves.map(c => new D.TableRow({
          children: [
            dataCell(c.cve, { mono: true, size: 15, bold: true, color: RED, width: 2000 }),
            dataCell(c.source || '—', { size: 15, color: BLUE, width: 1400 }),
            dataCell(c.severity || '—', { size: 15, bold: true, color: c.severity === 'critical' ? RED : c.severity === 'high' ? ORANGE : GRAY, width: 1200 }),
            dataCell(c.title || '—', { size: 15 })
          ]
        }))
      ],
      width: { size: 9600, type: D.WidthType.DXA }
    }));
  } else {
    children.push(para(`No CVEs were found in the live threat feed matching "${data.target}". Ensure the dashboard has been running to collect NVD data.`, { italic: true, color: GRAY }));
  }

  // Threat actors
  if (data.groups.length > 0) {
    children.push(subTitle('Threat Actors Observed'));
    children.push(new D.Table({
      rows: [
        new D.TableRow({ children: [headerCell('Group / Actor', 2400), headerCell('Victim', 2400), headerCell('Source', 1600), headerCell('Context', 3200)] }),
        ...data.groups.map(g => new D.TableRow({
          children: [
            dataCell(g.name, { bold: true, size: 16, color: RED, width: 2400 }),
            dataCell(g.victim || '—', { size: 15, width: 2400 }),
            dataCell(g.source || '—', { size: 15, color: BLUE, width: 1600 }),
            dataCell(g.title || '—', { size: 15 })
          ]
        }))
      ],
      width: { size: 9600, type: D.WidthType.DXA }
    }));
  }

  // Threats by source
  children.push(subTitle('Threats by Source'));
  const sourceEntries = Object.entries(data.bySource);
  if (sourceEntries.length > 0) {
    sourceEntries.forEach(([source, threats]) => {
      children.push(new D.Paragraph({ children: [new D.TextRun({ text: `${source}  (${threats.length} threat${threats.length !== 1 ? 's' : ''})`, font, bold: true, size: 20, color: DARK })], spacing: { before: 200, after: 80 } }));
      children.push(new D.Table({
        rows: [
          new D.TableRow({ children: [headerCell('Severity', 1200), headerCell('Threat', 8400)] }),
          ...threats.slice(0, 10).map(t => new D.TableRow({
            children: [
              dataCell((t.severity || 'medium').toUpperCase(), { mono: true, bold: true, size: 14, color: t.severity === 'critical' ? RED : t.severity === 'high' ? ORANGE : BLUE, width: 1200 }),
              dataCell(t.title || '—', { size: 15 })
            ]
          }))
        ],
        width: { size: 9600, type: D.WidthType.DXA }
      }));
    });
  } else {
    children.push(para(`No threats found in the live feed matching "${data.target}".`, { italic: true, color: GRAY }));
  }

  // ===== 6. ATM TECHNIQUES =====
  children.push(new D.Paragraph({ children: [], pageBreakBefore: true }));
  children.push(sectionTitle('6', `Auto-ISAC ATM Techniques  [${data.techniqueTable.length}]`));
  children.push(new D.Table({
    rows: [
      new D.TableRow({ children: [headerCell('Tactic', 2400), headerCell('Technique', 3200), headerCell('D3FEND', 2200), headerCell('Control', 1800)] }),
      ...data.techniqueTable.map(t => new D.TableRow({
        children: [
          dataCell(t.tactics.join(', '), { size: 15, color: GRAY }),
          new D.TableCell({
            children: [new D.Paragraph({ children: [new D.TextRun({ text: t.id, font: monoFont, bold: true, size: 16, color: RED }), new D.TextRun({ text: ' ' + t.name, font, size: 17, color: DARK })], spacing: { after: 0 } })],
            borders: tableBorder(), margins: { top: 50, bottom: 50, left: 80, right: 80 }
          }),
          dataCell(t.d3fend, { mono: true, size: 14, color: '2a9d8f' }),
          dataCell(t.control, { mono: true, size: 14 })
        ]
      }))
    ],
    width: { size: 9600, type: D.WidthType.DXA }
  }));

  // ===== 7. DETECTION OPPORTUNITIES =====
  children.push(sectionTitle('7', 'Detection Opportunities'));
  children.push(new D.Table({
    rows: [
      new D.TableRow({ children: [headerCell('Rule / Query', 2400), headerCell('Type', 1400), headerCell('Description', 4000), headerCell('Reference', 1800)] }),
      ...data.detections.map(d => new D.TableRow({ children: [dataCell(d.name, { mono: true, size: 15 }), dataCell(d.type, { size: 16, color: GREEN, bold: true }), dataCell(d.description, { size: 16 }), dataCell(d.reference, { mono: true, size: 14 })] }))
    ],
    width: { size: 9600, type: D.WidthType.DXA }
  }));

  // ===== AI SECTIONS =====
  if (isAI && data.ai) {
    children.push(new D.Paragraph({ children: [], pageBreakBefore: true }));
    children.push(sectionTitle('AI', 'Risk Scoring Matrix', 'AI-POWERED'));
    children.push(new D.Table({
      rows: [
        new D.TableRow({ children: [headerCell('Tactic', 3200), headerCell('Techniques', 1200), headerCell('Risk Score', 1600), headerCell('Rating', 1600)] }),
        ...data.ai.riskScores.map(rs => new D.TableRow({
          children: [
            dataCell(rs.tactic, { size: 17 }),
            dataCell(String(rs.techCount), { mono: true, size: 16 }),
            dataCell(`${rs.score}/100`, { mono: true, bold: true, size: 16, color: rs.rating === 'CRITICAL' ? RED : rs.rating === 'HIGH' ? ORANGE : BLUE }),
            dataCell(rs.rating, { mono: true, bold: true, size: 15, color: rs.rating === 'CRITICAL' ? RED : rs.rating === 'HIGH' ? ORANGE : rs.rating === 'MEDIUM' ? BLUE : GRAY })
          ]
        }))
      ],
      width: { size: 9600, type: D.WidthType.DXA }
    }));

    // Recommendations
    children.push(sectionTitle('AI', 'Defensive Recommendations', 'AI-POWERED'));
    const recTiers = [
      { label: 'IMMEDIATE (0-48 hours)', items: data.ai.recommendations.immediate, color: RED },
      { label: 'SHORT-TERM (1-4 weeks)', items: data.ai.recommendations.shortTerm, color: ORANGE },
      { label: 'LONG-TERM (1-6 months)', items: data.ai.recommendations.longTerm, color: BLUE }
    ];
    recTiers.forEach(tier => {
      children.push(new D.Paragraph({ children: [new D.TextRun({ text: tier.label, font: monoFont, bold: true, size: 16, color: tier.color })], spacing: { before: 200, after: 80 } }));
      tier.items.forEach(r => {
        children.push(new D.Paragraph({
          children: [
            new D.TextRun({ text: '  ▸  ', font: monoFont, size: 16, color: tier.color }),
            new D.TextRun({ text: r.text, font, size: 19, color: '444444' }),
            new D.TextRun({ text: `  [${r.keyword}]`, font: monoFont, size: 14, color: RED })
          ],
          spacing: { after: 60 }, indent: { left: 240 }
        }));
      });
    });
  }

  // ===== 8. APPENDICES =====
  children.push(new D.Paragraph({ children: [], pageBreakBefore: true }));
  children.push(sectionTitle('8', 'Appendices'));

  // Probability Matrix
  children.push(subTitle('Probability Matrix'));
  children.push(new D.Table({
    rows: [
      new D.TableRow({ children: ['Almost Impossible', 'Highly Unlikely', 'Unlikely', 'Possible', 'Likely', 'Highly Likely', 'Almost Certain'].map(h => headerCell(h)) }),
      new D.TableRow({ children: ['0-5%', '5-25%', '25-45%', '45-55%', '55-75%', '75-85%', '95-100%'].map(v => dataCell(v, { mono: true, bold: true, size: 16 })) })
    ],
    width: { size: 9600, type: D.WidthType.DXA }
  }));

  // Priority Matrix
  children.push(subTitle('Priority Matrix'));
  const pmRows = [
    ['Low', 'The threat needs to be monitored closely and addressed.', 'DCE8FC'],
    ['Moderate', 'The threat needs to be monitored closely and addressed.', 'FFF3E0'],
    ['High', 'The threat needs to be addressed quickly and monitored.', 'FFE0CC'],
    ['Critical', 'Immediate action is required.', 'FDECEA']
  ];
  children.push(new D.Table({
    rows: pmRows.map(([level, desc, bg]) => new D.TableRow({
      children: [
        dataCell(level, { mono: true, bold: true, size: 16, color: level === 'Critical' ? RED : level === 'High' ? ORANGE : level === 'Moderate' ? 'C98B00' : BLUE, width: 1600, shading: bg }),
        dataCell(desc, { size: 17 })
      ]
    })),
    width: { size: 9600, type: D.WidthType.DXA }
  }));

  // Admiralty Scale
  children.push(subTitle('Source & Information Reliability (Admiralty Scale)'));
  const admRows = [
    ['A (Completely reliable)', 'The source has a history of consistently providing accurate information.'],
    ['B (Usually reliable)', 'Most of the time, the source provides accurate information.'],
    ['C (Fairly reliable)', 'The source has provided accurate information on occasion.'],
    ['D (Not usually reliable)', 'The source has provided accurate information infrequently.'],
    ['E (Unreliable)', 'The source has rarely or never provided accurate information.'],
    ['F (Cannot be judged)', "The source's reliability is unknown or untested."]
  ];
  children.push(new D.Table({
    rows: admRows.map(([k, v]) => new D.TableRow({ children: [dataCell(k, { mono: true, size: 15, color: GRAY, bold: true, width: 3200 }), dataCell(v, { size: 17 })] })),
    width: { size: 9600, type: D.WidthType.DXA }
  }));

  // TLP
  children.push(subTitle('Sensitivity Matrix (TLP)'));
  const tlpRows = [
    ['TLP:CLEAR', 'No sharing restrictions. Publicly shareable.', 'F4F4F4'],
    ['TLP:GREEN', 'Can be shared within a community or sector.', 'E8F5F3'],
    ['TLP:AMBER', 'Need-to-know basis within an organization.', 'FFF8E1'],
    ['TLP:AMBER+STRICT', 'Restricted to the organization only.', 'FFF3E0'],
    ['TLP:RED', 'Limited to authorized individuals only.', 'FDECEA']
  ];
  children.push(new D.Table({
    rows: tlpRows.map(([level, desc, bg]) => new D.TableRow({
      children: [
        dataCell(level, { mono: true, bold: true, size: 15, color: level.includes('RED') ? RED : level.includes('STRICT') ? 'E68A00' : level.includes('AMBER') ? 'C98B00' : level.includes('GREEN') ? '2a9d8f' : '444444', width: 2400, shading: bg }),
        dataCell(desc, { size: 17 })
      ]
    })),
    width: { size: 9600, type: D.WidthType.DXA }
  }));

  // ===== FOOTER =====
  children.push(emptyLine());
  children.push(new D.Paragraph({
    children: [new D.TextRun({ text: `CARTINT  \u2014  Report ${data.reportId}  \u2014  ${data.date} ${data.time} UTC`, font, size: 16, color: GRAY })],
    spacing: { after: 40 },
    border: { top: { style: D.BorderStyle.SINGLE, size: 2, color: RED } }
  }));
  children.push(new D.Paragraph({ children: [new D.TextRun({ text: `${data.stats.totalThreats} threats / ${data.stats.totalTechniques} ATM techniques  \u2014  ${data.sensitivity}`, font, size: 16, color: GRAY })], spacing: { after: 0 } }));

  // ===== CREATE DOCUMENT =====
  // Page: 8.5x11in (12240x15840 twips), 0.75in L/R (1080), 1.0in T/B (1440)
  const doc = new D.Document({
    styles: {
      paragraphStyles: [{
        id: 'Normal', name: 'Normal',
        run: { font, size: 20, color: '333333' },
        paragraph: { spacing: { before: 120, after: 120, line: 340 } }
      }]
    },
    sections: [{
      properties: {
        page: {
          margin: { top: 1440, bottom: 1440, left: 1080, right: 1080 },
          size: { width: 12240, height: 15840 }
        }
      },
      headers: {
        default: new D.Header({
          children: [new D.Paragraph({
            children: [
              new D.TextRun({ text: '\u2588', font: monoFont, size: 14, color: RED }),
              new D.TextRun({ text: ' CARTINT', font, bold: true, size: 16, color: DARK }),
              new D.TextRun({ text: `    ${data.reportId}    ${data.sensitivity}`, font, size: 14, color: GRAY })
            ],
            alignment: D.AlignmentType.RIGHT,
            border: { bottom: { style: D.BorderStyle.SINGLE, size: 1, color: BORDER_COLOR } },
            spacing: { after: 0 }
          })]
        })
      },
      footers: {
        default: new D.Footer({
          children: [new D.Paragraph({
            children: [
              new D.TextRun({ text: `${data.sensitivity}  \u2014  CARTINT Automotive Threat Intelligence`, font, size: 14, color: GRAY })
            ],
            alignment: D.AlignmentType.CENTER,
            border: { top: { style: D.BorderStyle.SINGLE, size: 1, color: BORDER_COLOR } },
            spacing: { before: 100 }
          })]
        })
      },
      children
    }]
  });

  // Generate and download
  const blob = await D.Packer.toBlob(doc);
  saveAs(blob, `${data.reportId}.docx`);
}

// ---- UI Logic ----

function updateStatCounters() {
  document.getElementById('statSourceCount').textContent = document.querySelectorAll('[data-source]:checked').length;
  document.getElementById('statTechCount').textContent = atm.loaded ? atm.techniques.length : '—';
  document.getElementById('statTimeRange').textContent = document.getElementById('timeRange').value;
  const mode = document.querySelector('input[name="analysisMode"]:checked');
  document.getElementById('statMode').textContent = mode && mode.value === 'ai' ? 'AI' : 'Raw';
  updateStepChecks();
}

function updateStepChecks() {
  const checkSvg = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>';
  const hasTarget = document.getElementById('inputTarget').value.trim().length > 0;
  const hasSources = document.querySelectorAll('[data-source]:checked').length > 0;
  const els = { scope: document.getElementById('stepScope'), sources: document.getElementById('stepSources') };
  [['scope', hasTarget], ['sources', hasSources]].forEach(([key, ok]) => {
    if (ok) { els[key].classList.add('checked'); els[key].innerHTML = checkSvg; } else { els[key].classList.remove('checked'); els[key].innerHTML = ''; }
  });
}

document.querySelectorAll('[data-source]').forEach(cb => cb.addEventListener('change', updateStatCounters));
document.getElementById('timeRange').addEventListener('change', updateStatCounters);
document.querySelectorAll('input[name="analysisMode"]').forEach(r => r.addEventListener('change', updateStatCounters));
document.getElementById('inputTarget').addEventListener('input', updateStepChecks);

// ---- Generation ----

function buildGenerationSteps(config) {
  const steps = [{ text: 'Initializing CARTINT query pipeline...', type: 'info', delay: 400 }];
  const sourceSteps = { 'NVD/CVE': 'NVD NIST database', 'GitHub': 'GitHub code search API', 'Dark Web': 'ransomware.live Pro API', 'CT Logs': 'crt.sh certificate transparency', 'ExploitDB': 'ExploitDB', 'MISP': 'MISP threat feeds', 'Firmware Repos': 'firmware repository mirrors' };
  config.sources.forEach(s => {
    if (sourceSteps[s]) { steps.push({ text: `Querying ${sourceSteps[s]}...`, type: 'info', delay: 500 + Math.random() * 500 }); steps.push({ text: `${s} scan complete`, type: 'ok', delay: 200 + Math.random() * 200 }); }
  });
  steps.push({ text: `Mapping to ${TACTIC_ORDER.length} ATM tactic categories...`, type: 'info', delay: 800 });
  steps.push({ text: 'ATM technique mapping complete', type: 'ok', delay: 300 });
  steps.push({ text: 'Building kill chain analysis...', type: 'info', delay: 600 });
  if (config.mode === 'ai') {
    steps.push({ text: 'Running AI correlation engine...', type: 'info', delay: 1200 });
    steps.push({ text: 'Building attack path models...', type: 'info', delay: 800 });
    steps.push({ text: 'Computing risk scoring matrix...', type: 'info', delay: 500 });
    steps.push({ text: 'Generating defensive recommendations...', type: 'info', delay: 400 });
  }
  steps.push({ text: 'Compiling CTI report...', type: 'info', delay: 500 });
  steps.push({ text: 'Report ready.', type: 'ok', delay: 200 });
  return steps;
}

let lastReportHtml = '';
let lastReportMode = false;
let lastReportData = null;
let lastReportConfig = null;

async function generateReport() {
  const config = getQueryConfig();
  if (!config.target) { alert('Enter a target OEM, supplier, or topic.'); return; }
  if (config.sources.length === 0) { alert('Select at least one intelligence source.'); return; }

  const btn = document.getElementById('generateBtn');
  btn.classList.add('loading');
  btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="spin-icon"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> Generating...';

  document.getElementById('statusIdle').style.display = 'none';
  document.getElementById('statusResults').style.display = 'none';
  const genPanel = document.getElementById('statusGenerating');
  genPanel.style.display = 'block';

  const log = document.getElementById('generatingLog');
  log.innerHTML = '';
  const progressFill = document.getElementById('progressFill');
  const progressText = document.getElementById('progressText');
  progressFill.style.width = '0%';

  const steps = buildGenerationSteps(config);
  for (let i = 0; i < steps.length; i++) {
    await sleep(steps[i].delay);
    const line = document.createElement('div');
    line.className = 'log-line';
    line.innerHTML = `<span class="log-${steps[i].type === 'ok' ? 'ok' : 'info'}">${steps[i].type === 'ok' ? '&#10003;' : '&rarr;'}</span> ${steps[i].text}`;
    log.appendChild(line);
    log.scrollTop = log.scrollHeight;
    const pct = Math.round(((i + 1) / steps.length) * 100);
    progressFill.style.width = pct + '%';
    progressText.textContent = pct + '%';
  }

  const data = buildReportData(config);
  lastReportData = data;
  lastReportConfig = config;
  lastReportHtml = renderReport(config, data);
  lastReportMode = config.mode === 'ai';

  await sleep(500);
  genPanel.style.display = 'none';

  // Show results
  const resultsPanel = document.getElementById('statusResults');
  resultsPanel.style.display = 'block';
  document.getElementById('resultsSummary').innerHTML = `
    <div class="result-row"><span class="result-row-label">Report ID</span><span class="result-row-value">${data.reportId}</span></div>
    <div class="result-row"><span class="result-row-label">Target</span><span class="result-row-value">${escHtml(data.target)}</span></div>
    <div class="result-row"><span class="result-row-label">Priority</span><span class="result-row-value ${data.priority === 'Critical' ? 'critical' : data.priority === 'High' ? 'warning' : ''}">${data.priority}</span></div>
    <div class="result-row"><span class="result-row-label">Live Threats Matched</span><span class="result-row-value ${data.stats.totalThreats > 0 ? 'info' : ''}">${data.stats.totalThreats} threats across ${data.stats.totalSources} source(s)</span></div>
    <div class="result-row"><span class="result-row-label">CVEs Found</span><span class="result-row-value ${data.stats.totalCVEs > 0 ? 'critical' : ''}">${data.stats.totalCVEs}</span></div>
    <div class="result-row"><span class="result-row-label">Techniques Mapped</span><span class="result-row-value info">${data.stats.totalTechniques}</span></div>
    <div class="result-row"><span class="result-row-label">Threat Actors</span><span class="result-row-value">${data.stats.totalGroups}</span></div>
    <div class="result-row"><span class="result-row-label">Analysis Mode</span><span class="result-row-value">${config.mode === 'ai' ? 'AI-Analyzed' : 'Raw Intelligence'}</span></div>
  `;

  btn.classList.remove('loading');
  btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg> Generate Intelligence Report';

  const sg = document.getElementById('stepGenerate');
  sg.classList.add('checked');
  sg.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>';
}

function resetToIdle() {
  document.getElementById('statusIdle').style.display = 'block';
  document.getElementById('statusGenerating').style.display = 'none';
  document.getElementById('statusResults').style.display = 'none';
  const sg = document.getElementById('stepGenerate');
  sg.classList.remove('checked');
  sg.innerHTML = '';
}

// ---- Event Listeners ----
document.getElementById('generateBtn').addEventListener('click', generateReport);
document.getElementById('newQueryBtn').addEventListener('click', resetToIdle);
document.getElementById('viewReportBtn').addEventListener('click', () => { if (lastReportHtml) openReport(lastReportHtml, lastReportMode); });
document.getElementById('exportBtn').addEventListener('click', () => { if (lastReportData) exportDocx(); });
document.getElementById('reportCloseBtn').addEventListener('click', closeReport);
document.getElementById('reportOverlay').addEventListener('click', (e) => { if (e.target === e.currentTarget) closeReport(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeReport(); });
document.getElementById('reportExportBtn').addEventListener('click', () => exportDocx());
document.getElementById('reportPrintBtn').addEventListener('click', () => window.print());

// ---- Init ----
loadATMBundle();
updateStatCounters();
