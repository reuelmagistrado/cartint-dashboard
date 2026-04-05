/* ============================================
   CARTINT v2.0 — ATM Matrix Logic
   Parses STIX 2.1 bundle, renders 14-tactic grid,
   maps threats to techniques
   ============================================ */

// ---- State ----
const matrixState = {
  tactics: [],          // sorted tactic objects
  techniques: [],       // attack-pattern objects
  campaigns: [],        // campaign objects
  relationships: [],    // relationship objects
  techByTactic: {},     // tactic_shortname -> [technique]
  techById: {},         // stix id -> technique
  campaignById: {},     // stix id -> campaign
  techToCampaigns: {},  // technique stix id -> [campaign]
  liveThreats: [],      // threats from dashboard localStorage
  highlightedTechs: new Set(), // technique IDs currently highlighted
  selectedThreat: null
};

// Tactic display order (matches Auto-ISAC ATM kill chain)
const TACTIC_ORDER = [
  'reconnaissance',
  'initial_access',
  'execution',
  'persistence',
  'privilege_escalation',
  'defense_evasion',
  'credential_access',
  'discovery',
  'lateral_movement',
  'collection',
  'command_and_control',
  'exfiltration',
  'manipulate_environment',
  'affect_vehicle_function'
];

// Tactic short labels for compact headers
const TACTIC_LABELS = {
  'reconnaissance': 'Recon',
  'initial_access': 'Initial Access',
  'execution': 'Execution',
  'persistence': 'Persistence',
  'privilege_escalation': 'Priv Esc',
  'defense_evasion': 'Defense Evasion',
  'credential_access': 'Credential Access',
  'discovery': 'Discovery',
  'lateral_movement': 'Lateral Movement',
  'collection': 'Collection',
  'command_and_control': 'C2',
  'exfiltration': 'Exfiltration',
  'manipulate_environment': 'Manipulate Env',
  'affect_vehicle_function': 'Affect Vehicle'
};

// Tactic colors — cycled from design system
const TACTIC_COLORS = [
  '#e63946', '#f77f00', '#fcbf49', '#2ec4b6',
  '#4895ef', '#7b2cbf', '#e056a0', '#48bfe3',
  '#e63946', '#f77f00', '#2ec4b6', '#4895ef',
  '#7b2cbf', '#e056a0'
];

// ---- Load STIX Bundle ----

async function loadATMBundle() {
  try {
    const resp = await fetch('atm-bundle.json');
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const bundle = await resp.json();
    parseBundle(bundle);
    renderMatrix();
    loadLiveThreats();
    updateATMCount();
  } catch (e) {
    console.error('[ATM Matrix] Failed to load bundle:', e);
    document.getElementById('matrixGrid').innerHTML = `
      <div class="matrix-error">
        <p>Failed to load ATM bundle: ${e.message}</p>
        <p>Ensure <code>atm-bundle.json</code> is in the dashboard directory.</p>
      </div>
    `;
  }
}

function parseBundle(bundle) {
  const objects = bundle.objects || [];

  // Separate object types
  const rawTactics = objects.filter(o => o.type === 'x-mitre-tactic');
  matrixState.techniques = objects.filter(o => o.type === 'attack-pattern');
  matrixState.campaigns = objects.filter(o => o.type === 'campaign');
  matrixState.relationships = objects.filter(o => o.type === 'relationship');

  // Sort tactics by TACTIC_ORDER
  matrixState.tactics = TACTIC_ORDER.map(shortname =>
    rawTactics.find(t => t.x_mitre_shortname === shortname)
  ).filter(Boolean);

  // Index techniques by ID
  matrixState.techniques.forEach(t => {
    matrixState.techById[t.id] = t;
  });

  // Index campaigns by ID
  matrixState.campaigns.forEach(c => {
    matrixState.campaignById[c.id] = c;
  });

  // Build technique -> campaigns mapping via relationships
  matrixState.relationships.forEach(rel => {
    if (rel.relationship_type === 'uses') {
      const techId = rel.target_ref;
      if (!matrixState.techToCampaigns[techId]) {
        matrixState.techToCampaigns[techId] = [];
      }
      const campaign = matrixState.campaignById[rel.source_ref];
      if (campaign) {
        matrixState.techToCampaigns[techId].push({
          campaign,
          description: rel.description || ''
        });
      }
    }
  });

  // Group techniques by tactic
  matrixState.tactics.forEach(tactic => {
    const shortname = tactic.x_mitre_shortname;
    matrixState.techByTactic[shortname] = matrixState.techniques.filter(tech => {
      const phases = tech.kill_chain_phases || [];
      return phases.some(p => p.phase_name === shortname);
    });
  });

  console.log(`[ATM Matrix] Parsed: ${matrixState.tactics.length} tactics, ${matrixState.techniques.length} techniques, ${matrixState.campaigns.length} campaigns, ${matrixState.relationships.length} relationships`);
}

// ---- Get External ID ----

function getExternalId(obj) {
  const refs = obj.external_references || [];
  const ext = refs.find(r => r.external_id);
  return ext ? ext.external_id : '';
}

function getExternalUrl(obj) {
  const refs = obj.external_references || [];
  const ext = refs.find(r => r.url);
  return ext ? ext.url : '';
}

// ---- Render Matrix Grid ----

function renderMatrix() {
  const grid = document.getElementById('matrixGrid');
  grid.innerHTML = '';

  matrixState.tactics.forEach((tactic, tacticIndex) => {
    const shortname = tactic.x_mitre_shortname;
    const techniques = matrixState.techByTactic[shortname] || [];
    const color = TACTIC_COLORS[tacticIndex];
    const tacticId = getExternalId(tactic);

    const column = document.createElement('div');
    column.className = 'matrix-column';
    column.style.animationDelay = `${tacticIndex * 0.04}s`;

    // Tactic header
    const header = document.createElement('div');
    header.className = 'matrix-tactic-header';
    header.innerHTML = `
      <div class="tactic-color-bar" style="background: ${color};"></div>
      <div class="tactic-header-content">
        <span class="tactic-name">${TACTIC_LABELS[shortname] || tactic.name}</span>
        <span class="tactic-count">${techniques.length}</span>
      </div>
      <span class="tactic-id">${tacticId}</span>
    `;
    column.appendChild(header);

    // Technique cells
    const cellsContainer = document.createElement('div');
    cellsContainer.className = 'matrix-cells';

    techniques.forEach((tech, techIndex) => {
      const techId = getExternalId(tech);
      const cell = document.createElement('div');
      cell.className = 'matrix-cell';
      cell.dataset.techStixId = tech.id;
      cell.dataset.techId = techId;
      cell.style.animationDelay = `${(tacticIndex * 0.04) + (techIndex * 0.02)}s`;

      cell.innerHTML = `
        <span class="cell-id">${techId}</span>
        <span class="cell-name">${tech.name}</span>
      `;

      cell.addEventListener('click', () => showTechniqueDetail(tech));
      cellsContainer.appendChild(cell);
    });

    column.appendChild(cellsContainer);
    grid.appendChild(column);
  });
}

// ---- Technique Detail Panel ----

function showTechniqueDetail(tech) {
  const overlay = document.getElementById('techniqueOverlay');
  const techId = getExternalId(tech);
  const techUrl = getExternalUrl(tech);

  document.getElementById('detailId').textContent = techId;
  document.getElementById('detailName').textContent = tech.name;

  // Description
  const descEl = document.getElementById('detailDescription');
  descEl.textContent = tech.description || 'No description available.';

  // Tactics this technique maps to
  const tacticsEl = document.getElementById('detailTactics');
  const phases = tech.kill_chain_phases || [];
  tacticsEl.innerHTML = phases.map(p => {
    const tactic = matrixState.tactics.find(t => t.x_mitre_shortname === p.phase_name);
    const tacticIdx = TACTIC_ORDER.indexOf(p.phase_name);
    const color = TACTIC_COLORS[tacticIdx] || '#555';
    return `<span class="detail-tactic-tag" style="border-color: ${color}; color: ${color};">${TACTIC_LABELS[p.phase_name] || (tactic ? tactic.name : p.phase_name)}</span>`;
  }).join('');

  // Associated campaigns
  const campaignsEl = document.getElementById('detailCampaigns');
  const relatedCampaigns = matrixState.techToCampaigns[tech.id] || [];
  if (relatedCampaigns.length === 0) {
    campaignsEl.innerHTML = '<div class="detail-empty">No campaigns linked.</div>';
  } else {
    campaignsEl.innerHTML = relatedCampaigns.map(({ campaign, description }) => {
      const cId = getExternalId(campaign);
      const cUrl = getExternalUrl(campaign);
      return `
        <div class="detail-campaign">
          <div class="detail-campaign-header">
            <span class="detail-campaign-id">${cId}</span>
            <span class="detail-campaign-name">${campaign.name}</span>
          </div>
          <div class="detail-campaign-desc">${description || campaign.description || ''}</div>
          ${cUrl ? `<a class="detail-campaign-link" href="${cUrl}" target="_blank" rel="noopener">View on Auto-ISAC ATM &rarr;</a>` : ''}
        </div>
      `;
    }).join('');
  }

  // External references
  const refsEl = document.getElementById('detailRefs');
  const refs = (tech.external_references || []).filter(r => r.url);
  if (refs.length === 0) {
    refsEl.innerHTML = '<div class="detail-empty">No external references.</div>';
  } else {
    refsEl.innerHTML = refs.map(r => `
      <a class="detail-ref-link" href="${r.url}" target="_blank" rel="noopener">
        <span>${r.source_name || r.external_id || 'Reference'}</span>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
      </a>
    `).join('');
  }

  overlay.style.display = 'flex';
  // Animate in
  requestAnimationFrame(() => {
    overlay.classList.add('active');
  });
}

function closeTechniqueDetail() {
  const overlay = document.getElementById('techniqueOverlay');
  overlay.classList.remove('active');
  setTimeout(() => {
    overlay.style.display = 'none';
  }, 300);
}

// ---- Threat Selector & Highlighting ----

function loadLiveThreats() {
  // Try to load threats from dashboard localStorage
  try {
    // Read from full cache first, fall back to slim version
    const full = localStorage.getItem('cartint_cached_threats');
    const slim = localStorage.getItem('cartint_threats');
    const stored = full || slim;
    if (stored) {
      matrixState.liveThreats = JSON.parse(stored);
    }
  } catch (e) {
    console.warn('[ATM Matrix] Could not load live threats from localStorage');
  }

  // Also generate synthetic threat mappings from campaigns in the bundle
  buildThreatOptions();
}

function buildThreatOptions() {
  const selector = document.getElementById('threatSelector');

  // Build threat entries from campaigns that have relationships to techniques
  const threatEntries = [];

  // Group campaigns by name similarity to create meaningful threat scenarios
  const campaignsWithTechs = matrixState.campaigns.filter(c => {
    return matrixState.relationships.some(r => r.source_ref === c.id);
  });

  // Create entries from campaigns
  campaignsWithTechs.forEach(campaign => {
    const cId = getExternalId(campaign);
    const techIds = matrixState.relationships
      .filter(r => r.source_ref === campaign.id)
      .map(r => r.target_ref);

    if (techIds.length > 0) {
      threatEntries.push({
        id: campaign.id,
        label: `${cId}: ${campaign.name}`,
        techStixIds: techIds,
        group: campaign.name,
        type: 'campaign'
      });
    }
  });

  // Add live threats from dashboard, grouped by source
  if (matrixState.liveThreats.length > 0) {
    // Group threats by source
    const bySource = {};
    matrixState.liveThreats.forEach((threat, i) => {
      const src = threat.source || 'Live Feed';
      if (!bySource[src]) bySource[src] = [];
      bySource[src].push({ threat, index: i });
    });

    // Create an optgroup per source
    for (const [sourceName, entries] of Object.entries(bySource)) {
      const group = document.createElement('optgroup');
      group.label = `Live — ${sourceName} (${entries.length})`;

      entries.forEach(({ threat, index }) => {
        const matchedTechs = matchThreatToTechniques(threat);
        if (matchedTechs.length > 0) {
          const opt = document.createElement('option');
          opt.value = `live_${index}`;
          opt.textContent = threat.title || threat.victim || 'Unknown';
          opt.dataset.techIds = JSON.stringify(matchedTechs);
          opt.dataset.group = threat.group || threat.source || '';
          opt.dataset.target = threat.victim || threat.title || '';
          opt.dataset.confidence = threat.confidence || '75';
          opt.dataset.type = 'live';
          group.appendChild(opt);
        }
      });

      if (group.children.length > 0) {
        selector.appendChild(group);
      }
    }
  }

  // Add campaign entries
  if (threatEntries.length > 0) {
    const campaignGroup = document.createElement('optgroup');
    campaignGroup.label = 'ATM Campaigns / Examples';

    threatEntries.forEach(entry => {
      const opt = document.createElement('option');
      opt.value = entry.id;
      opt.textContent = entry.label;
      opt.dataset.techIds = JSON.stringify(entry.techStixIds);
      opt.dataset.group = entry.group;
      opt.dataset.target = '';
      opt.dataset.confidence = '92';
      opt.dataset.type = 'campaign';
      campaignGroup.appendChild(opt);
    });

    selector.appendChild(campaignGroup);
  }
}

function matchThreatToTechniques(threat) {
  const text = `${threat.title || ''} ${threat.description || ''} ${threat.victim || ''} ${threat.group || ''}`.toLowerCase();
  const matched = [];

  // Keyword mapping for common threat patterns to ATM techniques
  const keywordMap = {
    'ransomware': ['Data from Local System', 'Supply Chain Compromise', 'Exploit Public-Facing Application'],
    'phishing': ['Phishing', 'Spearphishing'],
    'supply chain': ['Supply Chain Compromise'],
    'firmware': ['Firmware Corruption', 'Modify System Image', 'Firmware Flashing'],
    'can bus': ['CAN Bus', 'Controller Area Network', 'Sniff Network Traffic'],
    'ota': ['OTA Update', 'Modify System Image'],
    'bluetooth': ['Bluetooth', 'Wireless'],
    'wifi': ['WiFi', 'Wireless'],
    'cellular': ['Cellular', 'Wireless'],
    'telematics': ['Telematics', 'Remote Service'],
    'ecu': ['ECU', 'Firmware'],
    'infotainment': ['Infotainment', 'Application Layer'],
    'key fob': ['Key Fob', 'Relay Attack'],
    'gps': ['GPS', 'Location Tracking'],
    'obd': ['OBD', 'Diagnostic'],
    'exploit': ['Exploit Public-Facing Application', 'Exploitation'],
    'credential': ['Credential Access', 'Brute Force', 'Default Credentials'],
    'data theft': ['Data from Local System', 'Exfiltration'],
    'denial': ['Denial of Service', 'Network Denial'],
  };

  for (const [keyword, techNames] of Object.entries(keywordMap)) {
    if (text.includes(keyword)) {
      techNames.forEach(tn => {
        const tech = matrixState.techniques.find(t =>
          t.name.toLowerCase().includes(tn.toLowerCase())
        );
        if (tech && !matched.includes(tech.id)) {
          matched.push(tech.id);
        }
      });
    }
  }

  // Fallback: if nothing matched, pick Supply Chain Compromise + Data from Local System
  if (matched.length === 0 && (text.includes('breach') || text.includes('attack') || text.includes('hack'))) {
    const fallbacks = matrixState.techniques.filter(t =>
      t.name === 'Supply Chain Compromise' || t.name === 'Data from Local System'
    );
    fallbacks.forEach(t => matched.push(t.id));
  }

  return matched;
}

function onThreatSelect(e) {
  const value = e.target.value;
  clearHighlights();

  if (!value) {
    document.getElementById('threatBannerMeta').style.display = 'none';
    matrixState.selectedThreat = null;
    return;
  }

  const option = e.target.selectedOptions[0];
  const techIds = JSON.parse(option.dataset.techIds || '[]');
  const group = option.dataset.group || '—';
  const target = option.dataset.target || option.textContent;
  const confidence = option.dataset.confidence || '—';

  // Update banner meta
  document.getElementById('bannerGroup').textContent = group;
  document.getElementById('bannerTarget').textContent = target;
  document.getElementById('bannerTechCount').textContent = techIds.length;
  document.getElementById('bannerConfidence').textContent = confidence + '%';
  document.getElementById('threatBannerMeta').style.display = 'flex';

  // Highlight technique cells
  highlightTechniques(techIds);
}

function highlightTechniques(techStixIds) {
  matrixState.highlightedTechs = new Set(techStixIds);

  const allCells = document.querySelectorAll('.matrix-cell');
  allCells.forEach(cell => {
    const stixId = cell.dataset.techStixId;
    if (matrixState.highlightedTechs.has(stixId)) {
      cell.classList.add('highlighted');
      cell.classList.remove('dimmed');
    } else {
      cell.classList.add('dimmed');
      cell.classList.remove('highlighted');
    }
  });

  // Also dim columns that have no highlighted techniques
  const allCols = document.querySelectorAll('.matrix-column');
  allCols.forEach(col => {
    const hasHighlight = col.querySelector('.matrix-cell.highlighted');
    if (hasHighlight) {
      col.classList.remove('dimmed');
    } else {
      col.classList.add('dimmed');
    }
  });
}

function clearHighlights() {
  matrixState.highlightedTechs.clear();
  document.querySelectorAll('.matrix-cell').forEach(cell => {
    cell.classList.remove('highlighted', 'dimmed');
  });
  document.querySelectorAll('.matrix-column').forEach(col => {
    col.classList.remove('dimmed');
  });
}

// ---- ATM Count ----

function updateATMCount() {
  const el = document.getElementById('atmCount');
  if (el) {
    const total = matrixState.tactics.length + matrixState.techniques.length + matrixState.campaigns.length;
    el.textContent = total;
  }
}

// ---- Event Listeners ----

document.getElementById('threatSelector').addEventListener('change', onThreatSelect);

document.getElementById('techniqueClose').addEventListener('click', closeTechniqueDetail);

document.getElementById('techniqueOverlay').addEventListener('click', (e) => {
  if (e.target === e.currentTarget) closeTechniqueDetail();
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeTechniqueDetail();
});

// ---- Init ----

loadATMBundle();
