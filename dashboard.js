/* ============================================
   CARTINT v2.0 — Dashboard Logic
   Live data from NVD, GitHub, ASRG, CISA, Dark Web
   ============================================ */

// ---- Configuration ----

const CONFIG = {
  nvd: {
    baseUrl: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    keywords: [
      'automotive vehicle', 'CAN bus vehicle', 'OBD automotive',
      'telematics vehicle', 'ECU automotive', 'AUTOSAR',
      'V2X vehicle', 'UDS diagnostic vehicle', 'J1939',
      'car hacking', 'connected car', 'ADAS vehicle',
      'automotive infotainment', 'DoIP vehicle', 'TPMS automotive'
    ],
    pollInterval: 120000 // 2 min
  },
  github: {
    baseUrl: 'https://api.github.com/search',
    // Credential leaks & secret exposure
    codeQueries: [
      'automotive API key',
      'telematics password',
      'OBD2 secret',
      'CAN bus exploit',
      'vehicle API token',
      'fleet management credentials',
      'AUTOSAR config secret',
      'ECU firmware key',
      'OTA server automotive token',
      'V2X certificate private',
      'DoIP diagnostic key',
      'immobilizer bypass code',
      'bootloader unlock key ECU',
      'SecOC key automotive',
      'HSM bypass vehicle'
    ],
    // Tools, exploits & offensive repos
    repoQueries: [
      'automotive security vulnerability',
      'car hacking tools',
      'CAN bus fuzzer',
      'OBD exploit',
      'vehicle penetration testing',
      'ECU reverse engineering',
      'UDS exploit automotive',
      'DoIP security tool',
      'automotive fuzzing framework',
      'V2X security attack',
      'TPMS exploit',
      'immobilizer bypass tool',
      'bootloader unlock ECU',
      'infotainment exploit',
      'telematics attack tool',
      'caringcaribou fork',
      'python-can exploit',
      'AUTOSAR vulnerability',
      'vehicle firmware extraction',
      'ECU flashing tool'
    ],
    // Known automotive security repos to track for surging activity
    watchRepos: [
      'linux-can/can-utils',
      'commaai/openpilot',
      'CaringCaribou/caringcaribou',
      'zombieCraig/UDSim',
      'atlas0fd00m/rfcat',
      'jgamblin/CarHackingTools'
    ],
    // Rotate queries across polls to stay under rate limits
    codeQueryIndex: 0,
    repoQueryIndex: 0,
    queriesPerPoll: 3, // queries per category per poll cycle
    pollInterval: 90000 // 90 sec
  },
  asrg: {
    // ASRG (Automotive Security Research Group) — automotive-specific advisories
    // API returns paginated docs with CVE, CVSS, affected products, CWE/CAPEC
    baseUrl: 'https://asrg.io/api/security-advisories',
    // Fetch all pages each poll cycle (39 advisories across 4 pages as of 2026-07)
    maxPages: 5,
    pollInterval: 600000 // 10 min
  },
  ransomwarelive: {
    // Target URLs (will be proxied automatically)
    recentVictimsUrl: 'https://api.ransomware.live/v2/recentvictims',
    groupsUrl: 'https://api.ransomware.live/v2/groups',
    fetchTimeout: 30000,
    pollInterval: 300000 // 5 min
  },
  darkweb: {
    // Ahmia dark web search — indexes .onion sites, accessible via clearweb
    ahmiaQueries: [
      'automotive ECU exploit',
      'CAN bus hack tool',
      'vehicle telematics credentials',
      'OBD2 diagnostic hack',
      'car firmware dump',
      'connected car vulnerability',
      'vehicle API key leak',
      'fleet management breach',
      'immobilizer bypass tool',
      'V2X security exploit',
      'AUTOSAR vulnerability',
      'infotainment system hack',
      'OTA update exploit',
      'key fob relay attack',
      'ransomware automotive dealer',
      'car dealership data breach',
      'auto parts supplier leak',
      'vehicle data breach',
      'ECU firmware dump',
      'car hacking tools',
      'telematics unit hack',
      'vehicle tracking exploit',
      'connected vehicle attack',
      'automotive credential leak',
      'OEM supplier ransomware'
    ],
    queryIndex: 0,
    queriesPerPoll: 4,
    // Paste site search queries
    pasteQueries: [
      'automotive API key',
      'telematics password',
      'CAN bus exploit',
      'OBD2 secret',
      'vehicle API token',
      'ECU firmware key',
      'fleet management credentials',
      'AUTOSAR config secret',
      'immobilizer bypass code',
      'OTA server automotive token',
      'V2X certificate private',
      'DoIP diagnostic key',
      'SecOC key automotive',
      'HSM bypass vehicle'
    ],
    pasteQueryIndex: 0,
    pasteQueriesPerPoll: 3,
    // Ransomware group detail fetch
    groupDetailInterval: 6, // every 6th poll cycle, fetch group details
    pollCount: 0,
    pollInterval: 300000 // 5 min
  },
  cisa: {
    // KEV (Known Exploited Vulnerabilities) — single JSON, no auth
    kevUrl: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    // CSAF ICS/OT advisories via GitHub API (recent year)
    csafBaseUrl: 'https://api.github.com/repos/cisagov/CSAF/contents/csaf_files/OT/white',
    csafRawBase: 'https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white',
    pollInterval: 600000 // 10 min
  },
  // Optional: Anthropic API key for AI-based relevance filtering
  anthropicApiKey: null,
  anthropicModel: 'claude-haiku-4-5-20251001'
};

// ---- CORS Proxy Helper ----
// Tries direct fetch first, then local proxy, then public CORS proxies
async function corsFetch(url, options = {}) {
  const timeout = options.timeout || 30000;
  const attempts = [
    url,
    `http://localhost:3001/proxy?url=${encodeURIComponent(url)}`,
    `https://corsproxy.io/?${encodeURIComponent(url)}`,
    `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`
  ];
  for (const attemptUrl of attempts) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);
      const resp = await fetch(attemptUrl, { signal: controller.signal });
      clearTimeout(timer);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      return resp;
    } catch (e) {
      // try next
    }
  }
  throw new Error(`All fetch attempts failed for ${url}`);
}

// ---- Automotive Relevance Classifier ----
// Multi-layer filter: word-boundary matching → false-positive rejection → context scoring → optional AI

const AUTO_CLASSIFIER = {
  // HIGH confidence: exact company names that are unambiguously automotive
  // These alone are enough to accept a result (score +10)
  exactOEMs: [
    'toyota', 'lexus', 'bmw', 'mini cooper', 'mercedes-benz', 'mercedes benz',
    'daimler', 'volkswagen', 'audi', 'porsche', 'lamborghini', 'bentley',
    'bugatti', 'ford motor', 'lincoln motor', 'general motors', 'chevrolet',
    'cadillac', 'buick', 'honda motor', 'acura', 'nissan motor', 'infiniti',
    'hyundai motor', 'kia motor', 'genesis motor', 'stellantis', 'chrysler',
    'jeep', 'dodge', 'ram truck', 'alfa romeo', 'fiat automobil', 'peugeot',
    'citroen', 'opel', 'renault', 'dacia', 'volvo car', 'mazda motor',
    'subaru', 'mitsubishi motors', 'suzuki motor', 'tesla motors', 'tesla inc',
    'rivian', 'lucid motors', 'byd auto', 'nio inc', 'xpeng', 'li auto',
    'geely auto', 'tata motors', 'jaguar land rover', 'maserati', 'ferrari',
    'rolls-royce motor', 'scania', 'man truck', 'iveco', 'daf trucks',
    'paccar', 'navistar', 'kenworth', 'peterbilt', 'freightliner',
    'mclaren', 'aston martin', 'lotus', 'polestar', 'cupra', 'seat',
    'skoda auto', 'isuzu', 'hino motors', 'great wall motor', 'chery',
    'haval', 'mahindra', 'maruti suzuki'
  ],

  // HIGH confidence: tier-1/tier-2 suppliers (score +10)
  exactSuppliers: [
    'robert bosch', 'bosch automotive', 'continental ag', 'continental automotive',
    'denso corporation', 'aptiv', 'delphi', 'magna international', 'lear corporation',
    'forvia', 'faurecia', 'valeo', 'zf friedrichshafen', 'zf group',
    'aisin seiki', 'yazaki', 'sumitomo electric', 'harman international',
    'visteon', 'hella', 'marelli', 'schaeffler', 'hyundai mobis',
    'panasonic automotive', 'samsung sdi', 'lg energy solution', 'catl',
    'brembo', 'akebono', 'dana incorporated', 'borgwarner', 'garrett motion',
    'sensata technologies', 'mobileye', 'luminar technologies', 'velodyne',
    'innoviz', 'blackberry qnx', 'wind river', 'elektrobit', 'vector informatik',
    'etas', 'dspace', 'cerence', 'cariad', 'waymo', 'cruise llc',
    'aurora innovation', 'torc robotics', 'tusimple', 'motional', 'zoox',
    'nxp semiconductors', 'infineon technologies', 'renesas electronics',
    'texas instruments auto', 'qualcomm automotive', 'nvidia drive'
  ],

  // MEDIUM confidence: require word-boundary match + context (score +5)
  // These are ambiguous alone — "ford" could be a surname, "continental" a hotel
  boundaryKeywords: [
    // OEM short names (ambiguous without context)
    { word: 'ford', requires: ['motor', 'dealer', 'vehicle', 'car', 'truck', 'auto', 'f-150', 'mustang', 'bronco', 'transit', 'explorer', 'escape'] },
    { word: 'honda', requires: ['motor', 'dealer', 'vehicle', 'car', 'civic', 'accord', 'cr-v', 'auto'] },
    { word: 'nissan', requires: ['motor', 'dealer', 'vehicle', 'car', 'auto', 'altima', 'rogue', 'pathfinder'] },
    { word: 'hyundai', requires: ['motor', 'dealer', 'vehicle', 'car', 'auto', 'tucson', 'santa fe', 'ioniq'] },
    { word: 'kia', requires: ['motor', 'dealer', 'vehicle', 'car', 'auto', 'sportage', 'telluride', 'ev6'] },
    { word: 'tesla', requires: ['motor', 'vehicle', 'car', 'auto', 'model s', 'model 3', 'model x', 'model y', 'cybertruck', 'supercharg', 'autopilot'] },
    { word: 'volvo', requires: ['car', 'truck', 'dealer', 'vehicle', 'auto', 'xc90', 'xc60'] },
    { word: 'bmw', requires: ['motor', 'dealer', 'vehicle', 'car', 'auto', 'serie'] },
    { word: 'gm', requires: ['motor', 'vehicle', 'auto', 'general motors'] },
    { word: 'ram', requires: ['truck', 'dealer', 'vehicle', 'auto', '1500', '2500', '3500'] },
    { word: 'jeep', requires: ['dealer', 'vehicle', 'auto', 'wrangler', 'cherokee', 'gladiator'] },
    { word: 'dodge', requires: ['dealer', 'vehicle', 'auto', 'charger', 'challenger', 'durango'] },
    { word: 'fiat', requires: ['auto', 'dealer', 'vehicle', '500', 'chrysler'] },

    // Supplier short names (very ambiguous)
    { word: 'bosch', requires: ['auto', 'vehicle', 'ecu', 'sensor', 'brake', 'injection'] },
    { word: 'continental', requires: ['auto', 'vehicle', 'tire', 'tyre', 'brake', 'sensor'] },
    { word: 'denso', requires: [] },  // fairly unique to automotive
    { word: 'magna', requires: ['auto', 'vehicle', 'part', 'mirror', 'seat'] },
    { word: 'lear', requires: ['auto', 'seat', 'vehicle', 'electric'] },
    { word: 'dana', requires: ['auto', 'vehicle', 'axle', 'drivetrain'] },
    { word: 'garrett', requires: ['turbo', 'auto', 'vehicle'] },
    { word: 'pioneer', requires: ['auto', 'car', 'stereo', 'head unit', 'navigation'] },
    { word: 'alpine', requires: ['auto', 'car', 'stereo', 'audio', 'head unit'] },
    { word: 'hella', requires: ['auto', 'light', 'vehicle', 'sensor'] },

    // Short OEM names — unique enough in context of victim names
    { word: 'honda', requires: [] },  // "Clawson Honda" is always a dealership
    { word: 'toyota', requires: [] },
    { word: 'bmw', requires: [] },
    { word: 'audi', requires: [] },
    { word: 'porsche', requires: [] },
    { word: 'ferrari', requires: [] },
    { word: 'lamborghini', requires: [] },
    { word: 'maserati', requires: [] },
    { word: 'volkswagen', requires: [] },
    { word: 'hyundai', requires: [] },
    { word: 'kia', requires: [] },
    { word: 'nissan', requires: [] },
    { word: 'subaru', requires: [] },
    { word: 'mazda', requires: [] },
    { word: 'tesla', requires: ['motor', 'vehicle', 'car', 'auto', 'model', 'supercharg', 'autopilot', 'gigafactory'] },
    { word: 'volvo', requires: [] },
    { word: 'lexus', requires: [] },
    { word: 'acura', requires: [] },
    { word: 'infiniti', requires: [] },

    // Generic automotive terms (need word boundary)
    { word: 'fleet', requires: ['vehicle', 'truck', 'auto', 'transport', 'logistics', 'management', 'equipment'] },
    { word: 'vehicle', requires: [] },
    { word: 'auto', requires: ['part', 'repair', 'body', 'service', 'insurance', 'dealer', 'motor', 'mobile', 'motive'] },
    { word: 'dealer', requires: ['auto', 'car', 'vehicle', 'motor'] },
    { word: 'dealership', requires: [] },
    { word: 'truck', requires: [] },
    { word: 'tire', requires: [] },
    { word: 'tyre', requires: [] },
    { word: 'motor', requires: [] },
    { word: 'brake', requires: [] },
  ],

  // STRONG signal keywords: these are specific enough to automotive (score +8)
  strongKeywords: [
    'automotive', 'automobile', 'automaker', 'autopart', 'auto parts',
    'telematics', 'connected car', 'ev charging', 'electric vehicle',
    'car dealer', 'auto dealer', 'motor dealer', 'vehicle dealer',
    'body shop', 'collision repair', 'aftermarket', 'carwash', 'car wash',
    'OBD', 'CAN bus', 'ECU', 'AUTOSAR', 'V2X', 'ADAS',
    'infotainment', 'powertrain', 'drivetrain', 'chassis',
    'motorsport', 'racing team', 'formula 1', 'nascar',
    'fuel injection', 'turbocharger', 'supercharger',
    'catalytic converter', 'exhaust system', 'muffler',
    'windshield', 'windscreen', 'wiper', 'headlight', 'taillight'
  ],

  // FALSE POSITIVE patterns: reject these even if keywords match
  falsePositives: [
    // Games / entertainment
    /\b(rom.?hack|nintendo|game|gaming|playstation|xbox|fossil fighters|pokemon)\b/i,
    /\b(minecraft|roblox|fortnite|steam|twitch|esport)\b/i,
    // Unrelated "ford" matches
    /\bford\s+(foundation|school|university|college|hospital|county|city)\b/i,
    /\b(harrison|gerald|henry|rob|betty)\s+ford\b/i,
    /\bford\s+(hall|building|road|street|avenue|bridge|park)\b/i,
    // Unrelated "continental" matches
    /\bcontinental\s+(hotel|breakfast|airline|flight|airlines|shelf|divide|congress|army)\b/i,
    // Unrelated "pioneer" matches
    /\bpioneer\s+(school|church|museum|bank|credit|natural|library|scout)\b/i,
    // Unrelated "alpine" matches
    /\balpine\s+(ski|resort|mountain|meadow|lake|school|church|linux)\b/i,
    // Unrelated "fleet" matches
    /\bfleet\s+(street|farm|foxes|week|management software)\b/i,
    /\bstarfleet\b/i,
    // Unrelated "magna" matches
    /\bmagna\s+(carta|cum laude|international school)\b/i,
    // Unrelated "cruise" matches
    /\bcruise\s+(ship|line|vacation|holiday|caribbean|tom)\b/i,
    /\btom\s+cruise\b/i,
    // Unrelated "ram" matches
    /\b(ram\s+dass|ramadan|rampage|rampart|ramsey|rampant)\b/i,
    /\b(dram|program|ram\s+memory|ram\s+stick|gb ram|mb ram)\b/i,
    // Unrelated "tesla" matches
    /\b(nikola\s+tesla|tesla\s+coil|tesla\s+tower|tesla\s+valve)\b/i,
    // Unrelated "gm" matches
    /\b(gm\s+diet|gmo|gmail)\b/i,
    // Unrelated "tire/tyre" — only reject words that CONTAIN tire but aren't tire
    /\b(retired?|tireless|entire|satire)\b/i,
    // Unrelated "engine" matches
    /\b(search engine|game engine|engine room|unreal engine|engine\.io)\b/i,
    // Unrelated "transmission" matches
    /\b(data transmission|transmission line|power transmission|disease transmission|radio transmission)\b/i,
    // Unrelated "mobility" matches
    /\b(social mobility|upward mobility|mobility scooter|mobility aid)\b/i,
    // Unrelated "aurora" matches
    /\baurora\s+(borealis|county|school|hospital|university|colorado|illinois|ohio)\b/i,
    // Unrelated "genesis" matches
    /\b(sega genesis|book of genesis|genesis block|genesis chapter)\b/i,
    // Software / tech that isn't automotive
    /\b(carbonizer|rom\s*hack|romhack)\b/i,
    // Random domain names (Cloudflare tunnels, DGA domains) — auto keywords are coincidental
    /\.trycloudflare\.com/i,
    /\.workers\.dev/i,
    /\.ngrok\.io/i,
    /\.pagekite\.me/i,
    // Dark-web-specific false positives (non-automotive dark web content)
    /\bauto\s+(mat|matic|responder|click|dial|complete|start|stop|login|submit)\b/i,
    /\bdrug\s+dealer\b/i,
    /\bdealer\s+(market|forum|network|zone)\b/i,
    /\bcredit\s+card\s+dump\b/i,
    /\bcarding\s+(forum|site|market|tutorial)\b/i,
    /\b(dating|escort|gambling|casino|poker)\b/i,
    /\b(counterfeit\s+(money|id|passport|bill))\b/i,
    /\b(weapon|gun\s+sale|ammo\s+sale|firearm)\b/i,
    /\b(hitman|murder\s+for\s+hire)\b/i,
    /\b(porn|adult|xxx|cam\s+girl)\b/i,
    /\b(bitcoin|monero|crypto\s+(mixer|tumbler|exchange|wallet))\b/i,
    /\b(stolen\s+(passport|id|license|ssn))\b/i,
    // Generic dark web marketplace terms that aren't automotive
    /\b(buy\s+cheap|wholesale|free\s+shipping|discount\s+code)\b/i,
    // Generic dark web marketplace terms that aren't automotive
    /\bKRVTZ-NET\b/i,
    /\bMaltrail\s+IOC\b/i,
    /\bIDS\s+alerts\s+for\s+\d{4}/i,
    /\bSuricata\s+ET\b/i,
    /\bEmergingThreats\b/i,
    /\bdaily\s+IOC/i,
    /\bdaily\s+malware/i,
    /\bphishing\s+kit\b/i,
    /\bspam\s+campaign\b/i,
  ],

  // Minimum score threshold to accept
  scoreThreshold: 5
};

/**
 * Normalize text for classification: expand domain names, strip TLDs,
 * split camelCase/compounds so word-boundary matching works.
 */
function normalizeForClassification(text) {
  let normalized = text;
  // Expand domain names: "kumhotire.com" → "kumho tire .com", "fordcountrymotors.mx" → "ford country motors .mx"
  normalized = normalized.replace(/([a-z0-9-]+\.(?:com|org|net|io|co|mx|de|jp|kr|cn|uk|eu|us|ca|au|fr|it|es|br|in|ru))\b/gi, (domain) => {
    // Split the hostname part into words
    const parts = domain.split('.');
    const host = parts[0];
    // Insert spaces before capital letters and between known word boundaries
    const expanded = host
      .replace(/([a-z])([A-Z])/g, '$1 $2')                        // camelCase
      .replace(/(auto|motor|car|fleet|tire|tyre|brake|vehicle|ford|honda|toyota|bmw|audi|kia|hyundai|nissan|volvo|mazda|subaru|dealer|truck|van)/gi, ' $1 ')  // known auto words
      .replace(/\s+/g, ' ')
      .trim();
    return `${expanded} .${parts.slice(1).join('.')}`;
  });
  // Also expand concatenated words that aren't domains
  normalized = normalized.replace(/([a-z])(auto|motor|car|fleet|tire|tyre|brake|vehicle|dealer|truck)/gi, '$1 $2');
  normalized = normalized.replace(/(auto|motor|car|fleet|tire|tyre|brake|vehicle|dealer|truck)([a-z])/gi, '$1 $2');
  return normalized;
}

/**
 * Scores how likely a text is automotive-related.
 * Returns { score, reasons, rejected, rejectReason }
 */
function classifyAutomotiveRelevance(text, extraContext = '') {
  const rawText = `${text} ${extraContext}`.trim();
  const fullText = normalizeForClassification(rawText);
  const lower = fullText.toLowerCase();
  const result = { score: 0, reasons: [], rejected: false, rejectReason: '' };

  // Step 1: Check false positives first — immediate rejection
  for (const pattern of AUTO_CLASSIFIER.falsePositives) {
    if (pattern.test(rawText) || pattern.test(fullText)) {
      result.rejected = true;
      result.rejectReason = `False positive: matched ${pattern}`;
      return result;
    }
  }

  // Step 2: Exact OEM match (highest confidence)
  for (const oem of AUTO_CLASSIFIER.exactOEMs) {
    const regex = new RegExp(`\\b${oem.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
    if (regex.test(fullText)) {
      result.score += 10;
      result.reasons.push(`Exact OEM: ${oem}`);
      break; // one is enough
    }
  }

  // Step 3: Exact supplier match
  if (result.score < 10) {
    for (const supplier of AUTO_CLASSIFIER.exactSuppliers) {
      const regex = new RegExp(`\\b${supplier.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
      if (regex.test(fullText)) {
        result.score += 10;
        result.reasons.push(`Exact supplier: ${supplier}`);
        break;
      }
    }
  }

  // Step 4: Strong keywords (fairly unambiguous)
  for (const kw of AUTO_CLASSIFIER.strongKeywords) {
    const regex = new RegExp(`\\b${kw.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
    if (regex.test(fullText)) {
      result.score += 8;
      result.reasons.push(`Strong keyword: ${kw}`);
      break; // cap at one strong keyword
    }
  }

  // Step 5: Boundary keywords with context requirements
  for (const rule of AUTO_CLASSIFIER.boundaryKeywords) {
    const wordRegex = new RegExp(`\\b${rule.word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
    if (wordRegex.test(fullText)) {
      if (rule.requires.length === 0) {
        // No context needed — word is specific enough
        result.score += 5;
        result.reasons.push(`Boundary keyword: ${rule.word}`);
      } else {
        // Check if any required context word is also present
        const hasContext = rule.requires.some(ctx => {
          const ctxRegex = new RegExp(`\\b${ctx.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
          return ctxRegex.test(fullText);
        });
        if (hasContext) {
          result.score += 5;
          result.reasons.push(`Boundary keyword with context: ${rule.word}`);
        }
      }
    }
  }

  return result;
}

/**
 * Optional AI-based classification via Anthropic API.
 * Falls back gracefully if no API key or on error.
 */
async function aiClassifyBatch(items) {
  if (!CONFIG.anthropicApiKey) return items;

  // Only send items with ambiguous scores (3-7) to AI
  const ambiguous = items.filter(i => i._autoScore >= 3 && i._autoScore < AUTO_CLASSIFIER.scoreThreshold);
  if (ambiguous.length === 0) return items;

  const prompt = `You are an automotive industry classifier. For each item below, respond with ONLY "yes" or "no" — is this related to the automotive industry (vehicle manufacturers, auto parts suppliers, car dealerships, fleet management, automotive technology, transportation vehicles)?

${ambiguous.map((item, i) => `${i + 1}. "${item._classifyText}"`).join('\n')}

Respond with one "yes" or "no" per line, nothing else.`;

  try {
    const resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': CONFIG.anthropicApiKey,
        'anthropic-version': '2023-06-01',
        'anthropic-dangerous-direct-browser-access': 'true'
      },
      body: JSON.stringify({
        model: CONFIG.anthropicModel,
        max_tokens: 256,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    if (!resp.ok) throw new Error(`API ${resp.status}`);
    const data = await resp.json();
    const text = data.content?.[0]?.text || '';
    const lines = text.trim().split('\n').map(l => l.trim().toLowerCase());

    ambiguous.forEach((item, i) => {
      if (lines[i] === 'yes') {
        item._autoScore = AUTO_CLASSIFIER.scoreThreshold; // promote to accepted
        item._aiClassified = true;
      } else if (lines[i] === 'no') {
        item._autoScore = 0; // demote to rejected
        item._aiRejected = true;
      }
    });

    console.log(`[CARTINT] AI classified ${ambiguous.length} ambiguous items`);
  } catch (e) {
    console.warn('[CARTINT] AI classification failed (using rule-based only):', e.message);
  }

  return items;
}

/**
 * Master filter: returns true if item should be included in dashboard.
 * Used by all sources.
 */
function isAutomotiveRelevant(text, extraContext = '') {
  const result = classifyAutomotiveRelevance(text, extraContext);
  if (result.rejected) return false;
  return result.score >= AUTO_CLASSIFIER.scoreThreshold;
}

// ---- Automotive keyword mapping for ATM techniques ----

const ATM_TECHNIQUE_MAP = {
  'authentication': ['ATM-T0033'],
  'bypass': ['ATM-T0033', 'ATM-T0067'],
  'injection': ['ATM-T0012'],
  'remote code': ['ATM-T0044'],
  'buffer overflow': ['ATM-T0044', 'ATM-T0033'],
  'credential': ['ATM-T0040'],
  'hardcoded': ['ATM-T0040', 'ATM-T0076'],
  'api key': ['ATM-T0040'],
  'token': ['ATM-T0040'],
  'password': ['ATM-T0040'],
  'secret': ['ATM-T0040', 'ATM-T0076'],
  'firmware': ['ATM-T0076'],
  'update': ['ATM-T0017'],
  'OTA': ['ATM-T0017'],
  'CAN': ['ATM-T0012'],
  'OBD': ['ATM-T0012', 'ATM-T0033'],
  'UDS': ['ATM-T0033', 'ATM-T0067'],
  'diagnostic': ['ATM-T0033'],
  'bluetooth': ['ATM-T0022'],
  'wifi': ['ATM-T0022'],
  'telematics': ['ATM-T0044'],
  'fleet': ['ATM-T0044', 'ATM-T0059'],
  'supply chain': ['ATM-T0059'],
  'AUTOSAR': ['ATM-T0076'],
  'V2X': ['ATM-T0022'],
  'infotainment': ['ATM-T0055'],
  'privilege': ['ATM-T0033'],
  'denial': ['ATM-T0067'],
  'overflow': ['ATM-T0044'],
  'memory': ['ATM-T0044'],
  'encryption': ['ATM-T0076'],
  'certificate': ['ATM-T0040'],
  'replay': ['ATM-T0012'],
  'spoof': ['ATM-T0012'],
  'MQTT': ['ATM-T0044'],
  'GPS': ['ATM-T0055'],
  'key fob': ['ATM-T0022'],
  'immobilizer': ['ATM-T0022', 'ATM-T0067']
};

const COMPONENT_MAP = {
  'CAN': 'CAN Bus',
  'OBD': 'OBD-II Interface',
  'UDS': 'Diagnostic Services',
  'ECU': 'Electronic Control Unit',
  'telematics': 'Telematics Control Unit',
  'infotainment': 'Infotainment System',
  'AUTOSAR': 'AUTOSAR Stack',
  'bluetooth': 'Bluetooth Module',
  'wifi': 'Wi-Fi Module',
  'GPS': 'GPS Module',
  'V2X': 'V2X Module',
  'OTA': 'OTA Infrastructure',
  'fleet': 'Fleet Management',
  'firmware': 'Firmware',
  'gateway': 'Gateway ECU',
  'ADAS': 'ADAS System',
  'MQTT': 'MQTT Broker',
  'API': 'Cloud API',
  'key fob': 'Key Fob',
  'immobilizer': 'Immobilizer',
  'camera': 'Camera System',
  'radar': 'Radar Module',
  'lidar': 'LiDAR Module'
};

const OEM_MAP = {
  'toyota': 'Toyota', 'bmw': 'BMW', 'ford': 'Ford', 'mercedes': 'Mercedes-Benz',
  'volkswagen': 'Volkswagen', 'vw': 'Volkswagen', 'audi': 'Audi', 'honda': 'Honda',
  'hyundai': 'Hyundai', 'kia': 'Kia', 'tesla': 'Tesla', 'nissan': 'Nissan',
  'gm': 'General Motors', 'chevrolet': 'General Motors', 'stellantis': 'Stellantis',
  'rivian': 'Rivian', 'bosch': 'Bosch', 'continental': 'Continental',
  'denso': 'DENSO', 'aptiv': 'Aptiv', 'harman': 'Harman', 'lucid': 'Lucid',
  'subaru': 'Subaru', 'mazda': 'Mazda', 'volvo': 'Volvo', 'jeep': 'Stellantis',
  'porsche': 'Porsche', 'jaguar': 'Jaguar Land Rover', 'land rover': 'Jaguar Land Rover'
};

// ---- State ----

const state = {
  threats: [],
  stats: { telematics: 0, ota: 0, github: 0, supplier: 0, techniques: 0 },
  techniqueCounts: {},
  sourceStatus: {},
  activeSourceFilter: null,  // null = show all, string = filter by source name
  seenIds: new Set(),
  totalATM: 0
};

// ---- Cache Infrastructure ----
// Per-source cache TTLs (how long before re-fetching from each source)
const SOURCE_CACHE_TTL = {
  'Dark Web':       2 * 60 * 60 * 1000,  // 2 hours (Ahmia + pastes + ransomware.live)
  'NVD/CVE':        1 * 60 * 60 * 1000,  // 1 hour
  'GitHub':         30 * 60 * 1000,       // 30 min
  'ASRG':           1 * 60 * 60 * 1000,  // 1 hour
  'CISA KEV':       2 * 60 * 60 * 1000,  // 2 hours
  'Firmware Repos': 3 * 60 * 60 * 1000,  // 3 hours (CISA)
  'Firmware Repos': 3 * 60 * 60 * 1000   // 3 hours
};

const CACHE_KEY_THREATS = 'cartint_cached_threats';
const CACHE_KEY_TIMESTAMPS = 'cartint_source_timestamps';

function getCachedThreats() {
  try {
    const raw = localStorage.getItem(CACHE_KEY_THREATS);
    return raw ? JSON.parse(raw) : null;
  } catch (e) { return null; }
}

function getCacheTimestamps() {
  try {
    const raw = localStorage.getItem(CACHE_KEY_TIMESTAMPS);
    return raw ? JSON.parse(raw) : {};
  } catch (e) { return {}; }
}

function setCacheTimestamp(sourceName) {
  const timestamps = getCacheTimestamps();
  timestamps[sourceName] = Date.now();
  try { localStorage.setItem(CACHE_KEY_TIMESTAMPS, JSON.stringify(timestamps)); } catch (e) {}
}

function isSourceCacheExpired(sourceName) {
  const timestamps = getCacheTimestamps();
  const lastFetch = timestamps[sourceName];
  if (!lastFetch) return true;
  const ttl = SOURCE_CACHE_TTL[sourceName] || 60 * 60 * 1000;
  return (Date.now() - lastFetch) > ttl;
}

function persistAllThreats() {
  try {
    // Store all threats (not just 50) for full cache restore
    const toStore = state.threats.map(t => ({
      id: t.id, title: t.title, victim: t.victim, group: t.group,
      source: t.source, severity: t.severity, confidence: t.confidence,
      description: t.description, techniques: t.techniques,
      time: t.time, rawDate: t.rawDate ? new Date(t.rawDate).toISOString() : null,
      link: t.link, sourceDetail: t.sourceDetail,
      cveId: t.cveId, cvssScore: t.cvssScore,
      oem: t.oem, component: t.component
    }));
    localStorage.setItem(CACHE_KEY_THREATS, JSON.stringify(toStore));
    // Also persist the slim version for intel page
    const slim = state.threats.slice(0, 50).map(t => ({
      title: t.title, victim: t.victim, group: t.group,
      source: t.source, severity: t.severity, confidence: t.confidence,
      description: t.description, techniques: t.techniques
    }));
    localStorage.setItem('cartint_threats', JSON.stringify(slim));
  } catch (e) { /* quota exceeded */ }
}

function restoreCachedThreats() {
  const cached = getCachedThreats();
  if (!cached || cached.length === 0) return false;
  let restored = 0;
  for (const t of cached) {
    if (t.rawDate) t.rawDate = new Date(t.rawDate);
    if (!state.seenIds.has(t.id)) {
      state.seenIds.add(t.id);
      state.threats.push(t);
      restored++;
      for (const tech of (t.techniques || [])) {
        state.techniqueCounts[tech] = (state.techniqueCounts[tech] || 0) + 1;
      }
    }
  }
  state.threats.sort((a, b) => (b.rawDate || 0) - (a.rawDate || 0));
  state.totalATM = Object.keys(state.techniqueCounts).length;
  console.log(`[CARTINT] Restored ${restored} cached threats`);
  return restored > 0;
}

// ---- Utility Functions ----

function extractTechniques(text) {
  const techniques = new Set();
  const lower = text.toLowerCase();
  for (const [keyword, techs] of Object.entries(ATM_TECHNIQUE_MAP)) {
    if (lower.includes(keyword.toLowerCase())) {
      techs.forEach(t => techniques.add(t));
    }
  }
  return techniques.size > 0 ? [...techniques].slice(0, 3) : ['ATM-T0076'];
}

function extractComponent(text) {
  const lower = text.toLowerCase();
  for (const [keyword, component] of Object.entries(COMPONENT_MAP)) {
    if (lower.includes(keyword.toLowerCase())) {
      return component;
    }
  }
  return 'Vehicle System';
}

function extractOEM(text) {
  const lower = text.toLowerCase();
  for (const [keyword, oem] of Object.entries(OEM_MAP)) {
    if (lower.includes(keyword)) {
      return oem;
    }
  }
  return 'Generic';
}

function cvssToSeverity(score) {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  return 'low';
}

function timeAgo(dateStr) {
  const now = new Date();
  const date = new Date(dateStr);
  const diffMs = now - date;
  const diffMin = Math.floor(diffMs / 60000);
  const diffHr = Math.floor(diffMs / 3600000);
  const diffDay = Math.floor(diffMs / 86400000);

  if (diffMin < 1) return 'Just now';
  if (diffMin < 60) return `${diffMin} min ago`;
  if (diffHr < 24) return `${diffHr} hr${diffHr > 1 ? 's' : ''} ago`;
  if (diffDay < 30) return `${diffDay} day${diffDay > 1 ? 's' : ''} ago`;
  return date.toLocaleDateString();
}

function generateId(source, identifier) {
  return `${source}-${identifier}`;
}

function sanitize(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ---- API Fetchers ----

async function fetchNVD() {
  const sourceKey = 'NVD/CVE';
  updateSourceStatus(sourceKey, 'fetching');

  const allCves = [];

  // Fetch multiple keyword searches in parallel (limit to 3 to stay within rate limits)
  const keywordsToFetch = CONFIG.nvd.keywords.slice(0, 6);
  const batchSize = 2;

  for (let i = 0; i < keywordsToFetch.length; i += batchSize) {
    const batch = keywordsToFetch.slice(i, i + batchSize);
    const promises = batch.map(async (keyword) => {
      try {
        const url = `${CONFIG.nvd.baseUrl}?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=5&startIndex=0`;
        const resp = await fetch(url);
        if (!resp.ok) throw new Error(`NVD ${resp.status}`);
        const data = await resp.json();
        return data.vulnerabilities || [];
      } catch (e) {
        console.warn(`NVD fetch failed for "${keyword}":`, e.message);
        return [];
      }
    });

    const results = await Promise.all(promises);
    results.forEach(r => allCves.push(...r));

    // Small delay between batches to respect NVD rate limits (no API key = 5 req/30sec)
    if (i + batchSize < keywordsToFetch.length) {
      await new Promise(resolve => setTimeout(resolve, 6500));
    }
  }

  // Deduplicate by CVE ID
  const seen = new Set();
  const uniqueCves = allCves.filter(item => {
    const id = item.cve?.id;
    if (!id || seen.has(id)) return false;
    seen.add(id);
    return true;
  });

  // Filter through automotive classifier
  const relevantCves = uniqueCves.filter(item => {
    const desc = item.cve?.descriptions?.find(d => d.lang === 'en')?.value || '';
    return isAutomotiveRelevant(desc);
  });

  const threats = relevantCves.map(item => {
    const cve = item.cve;
    const id = cve.id;
    const desc = cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description';
    const published = cve.published;

    // Extract CVSS score
    let cvssScore = 0;
    const metrics = cve.metrics;
    if (metrics?.cvssMetricV31?.[0]) {
      cvssScore = metrics.cvssMetricV31[0].cvssData?.baseScore || 0;
    } else if (metrics?.cvssMetricV2?.[0]) {
      cvssScore = metrics.cvssMetricV2[0].cvssData?.baseScore || 0;
    }

    const severity = cvssToSeverity(cvssScore);
    const techniques = extractTechniques(desc);
    const component = extractComponent(desc);
    const oem = extractOEM(desc);
    const threatId = generateId('nvd', id);

    return {
      id: threatId,
      title: `${id}: ${sanitize(desc.substring(0, 120))}${desc.length > 120 ? '...' : ''}`,
      fullDescription: desc,
      severity,
      oem,
      component,
      techniques,
      source: 'NVD/CVE',
      sourceDetail: 'NVD / CVE Feed',
      confidence: Math.min(95, Math.round(60 + cvssScore * 3.5)),
      sources: 1,
      time: timeAgo(published),
      rawDate: new Date(published),
      cvssScore,
      cveId: id,
      link: `https://nvd.nist.gov/vuln/detail/${id}`
    };
  });

  // Sort by date descending
  threats.sort((a, b) => b.rawDate - a.rawDate);

  updateSourceStatus(sourceKey, 'active', threats.length);
  return threats;
}

async function fetchGitHubLeaks() {
  const sourceKey = 'GitHub';
  updateSourceStatus(sourceKey, 'fetching');

  try {
    const allResults = [];
    const n = CONFIG.github.queriesPerPoll;

    // Rotate code queries across polls to cover all without hitting rate limits
    const codeStart = CONFIG.github.codeQueryIndex;
    const codeQueries = [];
    for (let i = 0; i < n; i++) {
      codeQueries.push(CONFIG.github.codeQueries[(codeStart + i) % CONFIG.github.codeQueries.length]);
    }
    CONFIG.github.codeQueryIndex = (codeStart + n) % CONFIG.github.codeQueries.length;

    // Code search — credential leaks, secrets, exploit code
    for (const query of codeQueries) {
      try {
        const url = `${CONFIG.github.baseUrl}/code?q=${encodeURIComponent(query)}&per_page=5&sort=indexed&order=desc`;
        const resp = await fetch(url, {
          headers: { 'Accept': 'application/vnd.github.v3+json' }
        });
        if (resp.status === 403 || resp.status === 429) {
          console.warn('[CARTINT] GitHub rate limited on code search');
          break;
        }
        if (!resp.ok) throw new Error(`GitHub ${resp.status}`);
        const data = await resp.json();
        if (data.items) {
          allResults.push(...data.items.map(item => ({ ...item, _query: query, _type: 'code' })));
        }
        await new Promise(resolve => setTimeout(resolve, 2500));
      } catch (e) {
        console.warn(`[CARTINT] GitHub code search failed for "${query}":`, e.message);
      }
    }

    // Rotate repo queries — tools, exploits, offensive repos
    const repoStart = CONFIG.github.repoQueryIndex;
    const repoQueries = [];
    for (let i = 0; i < n; i++) {
      repoQueries.push(CONFIG.github.repoQueries[(repoStart + i) % CONFIG.github.repoQueries.length]);
    }
    CONFIG.github.repoQueryIndex = (repoStart + n) % CONFIG.github.repoQueries.length;

    for (const query of repoQueries) {
      try {
        const url = `${CONFIG.github.baseUrl}/repositories?q=${encodeURIComponent(query)}&per_page=5&sort=updated&order=desc`;
        const resp = await fetch(url, {
          headers: { 'Accept': 'application/vnd.github.v3+json' }
        });
        if (resp.status === 403 || resp.status === 429) break;
        if (!resp.ok) throw new Error(`GitHub ${resp.status}`);
        const data = await resp.json();
        if (data.items) {
          allResults.push(...data.items.map(item => ({ ...item, _query: query, _type: 'repo' })));
        }
        await new Promise(resolve => setTimeout(resolve, 2500));
      } catch (e) {
        console.warn(`[CARTINT] GitHub repo search failed for "${query}":`, e.message);
      }
    }

    // Watch known automotive security repos for recent activity
    for (const repoPath of CONFIG.github.watchRepos.slice(0, 2)) {
      try {
        const url = `https://api.github.com/repos/${repoPath}`;
        const resp = await fetch(url, {
          headers: { 'Accept': 'application/vnd.github.v3+json' }
        });
        if (resp.status === 403 || resp.status === 429) break;
        if (!resp.ok) continue;
        const repo = await resp.json();

        // Flag if recently pushed (within 7 days)
        const pushed = new Date(repo.pushed_at);
        const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        if (pushed > weekAgo) {
          allResults.push({
            ...repo,
            _query: 'watched-repo',
            _type: 'watched',
            _recentPush: true
          });
        }
        await new Promise(resolve => setTimeout(resolve, 2000));
      } catch (e) {
        console.warn(`[CARTINT] GitHub watch check failed for ${repoPath}:`, e.message);
      }
    }
    // Rotate watched repos across polls
    CONFIG.github.watchRepos.push(CONFIG.github.watchRepos.shift());

    // Deduplicate
    const seen = new Set();
    const unique = allResults.filter(item => {
      const key = item._type === 'code'
        ? `${item.repository?.full_name}/${item.path}`
        : item.full_name;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    // Filter through automotive classifier
    const relevant = unique.filter(item => {
      // Watched repos are pre-validated automotive
      if (item._type === 'watched') return true;
      const textToCheck = item._type === 'code'
        ? `${item.repository?.full_name || ''} ${item.name || ''} ${item.path || ''} ${item.repository?.description || ''}`
        : `${item.full_name || ''} ${item.description || ''} ${(item.topics || []).join(' ')}`;
      return isAutomotiveRelevant(textToCheck, item._query || '');
    });

    const threats = relevant.map(item => {
      if (item._type === 'watched') {
        // Watched repo with recent activity
        const name = item.full_name || 'unknown';
        const desc = item.description || '';
        const stars = item.stargazers_count || 0;
        const forks = item.forks_count || 0;
        const fullText = `${name} ${desc}`;
        const techniques = extractTechniques(fullText);
        const component = extractComponent(fullText);
        const oem = extractOEM(fullText);
        const threatId = generateId('github-watch', name);

        return {
          id: threatId,
          title: `Tracked automotive tool active: ${sanitize(name)} — ${sanitize(desc.substring(0, 80))}`,
          severity: 'medium',
          oem,
          component,
          techniques,
          source: 'GitHub',
          sourceDetail: `GitHub Watch · ★${stars} · ${forks} forks`,
          confidence: 75,
          sources: 1,
          time: timeAgo(item.pushed_at),
          rawDate: new Date(item.pushed_at),
          link: item.html_url
        };
      } else if (item._type === 'code') {
        const repoName = item.repository?.full_name || 'unknown';
        const fileName = item.name || '';
        const path = item.path || '';
        const repoDesc = item.repository?.description || '';
        const fullText = `${repoName} ${fileName} ${path} ${item._query} ${repoDesc}`;
        const techniques = extractTechniques(fullText);
        const component = extractComponent(fullText);
        const oem = extractOEM(fullText);
        const threatId = generateId('github-code', `${repoName}/${path}`);
        const lowerQuery = item._query.toLowerCase();
        const lowerPath = (path + ' ' + fileName).toLowerCase();

        // Classify threat severity and type
        let severity = 'high';
        let title = '';
        let category = 'finding';

        if (/password|secret|token|private.key|credential/i.test(lowerQuery)) {
          severity = 'critical';
          category = 'leak';
          title = `Credential leak: ${sanitize(repoName)} — ${sanitize(fileName)}`;
        } else if (/api.key|api.token/i.test(lowerQuery)) {
          severity = 'critical';
          category = 'leak';
          title = `API key exposure: ${sanitize(repoName)} — ${sanitize(fileName)}`;
        } else if (/bypass|unlock|immobilizer/i.test(lowerQuery)) {
          severity = 'critical';
          category = 'exploit';
          title = `Bypass/unlock tool: ${sanitize(repoName)} — ${sanitize(fileName)}`;
        } else if (/exploit|fuzzer|attack/i.test(lowerQuery)) {
          severity = 'high';
          category = 'exploit';
          title = `Exploit/attack tool: ${sanitize(repoName)} — ${sanitize(fileName)}`;
        } else if (/firmware|bootloader|flash/i.test(lowerQuery)) {
          severity = 'high';
          category = 'firmware';
          title = `Firmware tool: ${sanitize(repoName)} — ${sanitize(fileName)}`;
        } else if (/HSM|SecOC|AUTOSAR/i.test(lowerQuery)) {
          severity = 'high';
          category = 'crypto';
          title = `Security mechanism target: ${sanitize(repoName)} — ${sanitize(fileName)}`;
        } else {
          title = `Automotive security finding: ${sanitize(repoName)} — ${sanitize(fileName)}`;
        }

        // New account pushing offensive tools = higher severity signal
        const repoCreated = item.repository?.created_at;
        const monthAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        const isNewRepo = repoCreated && new Date(repoCreated) > monthAgo;
        if (isNewRepo && (category === 'exploit' || category === 'leak')) {
          severity = 'critical';
          title = `⚠ New repo with ${category}: ${sanitize(repoName)} — ${sanitize(fileName)}`;
        }

        return {
          id: threatId,
          title,
          severity,
          oem,
          component,
          techniques,
          source: 'GitHub',
          sourceDetail: `GitHub Code · ${sanitize(category)}${isNewRepo ? ' · NEW REPO' : ''}`,
          confidence: category === 'leak' ? 90 : 85,
          sources: 1,
          time: 'Recent',
          rawDate: new Date(),
          link: item.html_url
        };
      } else {
        // Repo result — tools, exploits, research repos
        const name = item.full_name || 'unknown';
        const desc = item.description || '';
        const stars = item.stargazers_count || 0;
        const forks = item.forks_count || 0;
        const topics = (item.topics || []).join(', ');
        const fullText = `${name} ${desc} ${topics}`;
        const techniques = extractTechniques(fullText);
        const component = extractComponent(fullText);
        const oem = extractOEM(fullText);
        const threatId = generateId('github-repo', name);
        const updatedAt = item.updated_at || item.pushed_at;
        const lowerDesc = desc.toLowerCase();
        const lowerQuery = item._query.toLowerCase();

        // Classify repo type
        let severity = 'medium';
        let category = 'research';

        if (/bypass|unlock|immobilizer|jailbreak/i.test(lowerDesc + lowerQuery)) {
          severity = 'high';
          category = 'bypass-tool';
        } else if (/exploit|attack|offensive|pentest/i.test(lowerDesc + lowerQuery)) {
          severity = 'high';
          category = 'attack-tool';
        } else if (/fuzzer|fuzzing|fuzz/i.test(lowerDesc + lowerQuery)) {
          severity = 'high';
          category = 'fuzzer';
        } else if (/firmware|extract|dump|flash/i.test(lowerDesc + lowerQuery)) {
          severity = 'medium';
          category = 'firmware-tool';
        } else if (/reverse.engineer|disassembl|decompil/i.test(lowerDesc + lowerQuery)) {
          severity = 'medium';
          category = 'RE-tool';
        }

        // Surging activity detection
        let surgingNote = '';
        if (stars > 100 || forks > 30) {
          surgingNote = ` · ★${stars}`;
        }

        // New repo with offensive capability = threat actor signal
        const created = new Date(item.created_at);
        const monthAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        const isNewRepo = created > monthAgo;
        if (isNewRepo && (category === 'attack-tool' || category === 'bypass-tool')) {
          severity = 'critical';
        }

        return {
          id: threatId,
          title: `${isNewRepo ? '⚠ NEW: ' : ''}Automotive ${category}: ${sanitize(name)} — ${sanitize(desc.substring(0, 80))}`,
          severity,
          oem,
          component,
          techniques,
          source: 'GitHub',
          sourceDetail: `GitHub Repo · ${sanitize(category)}${surgingNote}${isNewRepo ? ' · NEW' : ''}`,
          confidence: isNewRepo ? 80 : 70,
          sources: 1,
          time: timeAgo(updatedAt),
          rawDate: new Date(updatedAt),
          link: item.html_url
        };
      }
    });

    updateSourceStatus(sourceKey, 'active', threats.length);
    return threats;
  } catch (e) {
    console.error('[CARTINT] GitHub fetch error:', e.message);
    updateSourceStatus(sourceKey, 'error');
    return [];
  }
}

// ---- ASRG Security Advisories ----
// Automotive Security Research Group — automotive-specific vulnerability disclosures
// Every advisory is automotive-relevant by design (no filtering needed)

async function fetchASRG() {
  const sourceKey = 'ASRG';
  updateSourceStatus(sourceKey, 'fetching');

  const allAdvisories = [];
  const maxPages = CONFIG.asrg.maxPages;

  for (let page = 1; page <= maxPages; page++) {
    try {
      const url = `${CONFIG.asrg.baseUrl}?page=${page}`;
      let data = null;

      // Try local proxy first (if running), then CORS proxies
      try {
        const resp = await fetch(`http://localhost:3001/proxy?url=${encodeURIComponent(url)}`, {
          signal: AbortSignal.timeout(15000)
        });
        if (resp.ok) {
          data = await resp.json();
        }
      } catch (e) {
        // Proxy not available — try CORS proxies
      }

      if (!data) {
        const resp = await corsFetch(url, { timeout: 15000 });
        if (resp) data = await resp.json();
      }

      if (!data || !data.docs || data.docs.length === 0) break;

      allAdvisories.push(...data.docs);
      console.log(`[CARTINT] ASRG page ${page}: ${data.docs.length} advisories`);

      // Stop if no more pages
      if (!data.hasNextPage) break;

      // Rate limit between pages
      await new Promise(resolve => setTimeout(resolve, 1000));
    } catch (e) {
      console.warn(`[CARTINT] ASRG page ${page} fetch failed:`, e.message);
      break;
    }
  }

  if (allAdvisories.length === 0) {
    console.warn('[CARTINT] ASRG: No advisories fetched');
    updateSourceStatus(sourceKey, 'error');
    return [];
  }

  // Convert ASRG advisories to threat objects
  // All ASRG advisories are automotive by definition — no classifier filtering needed
  const threats = allAdvisories.map(adv => {
    const title = adv.title || 'Unknown Advisory';
    const cveId = adv.cveId || '';
    const description = adv.description || '';
    const affectedProducts = adv.affectedProducts || '';
    const problemType = adv.problemType || '';
    const severity = (adv.severity || 'Medium').toLowerCase();
    const cvss31 = adv.cvss31 || '';
    const cvss40 = adv.cvss40 || '';
    const references = adv.references || '';
    const credits = adv.credits || '';
    const publishedDate = adv.publishedDate || adv.createdAt || '';

    const fullText = `${title} ${description} ${affectedProducts} ${problemType}`;
    const techniques = extractTechniques(fullText);
    const component = extractComponent(fullText);
    const oem = extractOEM(fullText);
    const threatId = generateId('asrg', adv.id?.toString() || cveId || title);

    // Determine severity level
    let sevLevel = 'medium';
    const sevLower = severity.toLowerCase();
    if (sevLower === 'critical') sevLevel = 'critical';
    else if (sevLower === 'high') sevLevel = 'high';
    else if (sevLower === 'low') sevLevel = 'low';

    // Extract CVSS score for confidence calibration
    const cvssMatch = (cvss31 || cvss40 || '').match(/^[\d.]+/);
    const cvssScore = cvssMatch ? parseFloat(cvssMatch[0]) : 0;

    // Higher confidence for ASRG (purpose-built automotive source, all entries relevant)
    let confidence = 95;
    if (cvssScore >= 7) confidence = 96;
    if (cvssScore >= 9) confidence = 98;

    // Build source detail
    let sourceDetail = 'ASRG Advisory';
    if (oem !== 'Generic') sourceDetail += ` · ${oem}`;
    if (cveId) sourceDetail += ` · ${cveId}`;

    // Build link
    const link = adv.slug ? `https://asrg.io/security-advisories/${adv.slug}` : 'https://asrg.io/security-advisories';

    // Extract CWE ID
    const cweMatch = problemType.match(/CWE-\d+/);
    const cweId = cweMatch ? cweMatch[0] : '';

    return {
      id: threatId,
      title: cveId ? `${cveId}: ${sanitize(title)}` : sanitize(title),
      severity: sevLevel,
      oem,
      component,
      techniques,
      source: 'ASRG',
      sourceDetail,
      confidence,
      sources: 1,
      time: publishedDate ? timeAgo(publishedDate) : 'Recent',
      rawDate: publishedDate ? new Date(publishedDate) : new Date(),
      link,
      _subSource: 'asrg',
      _classifyText: fullText,
      // Extra fields for richer display
      cveId,
      cweId,
      cvss31,
      cvss40,
      affectedProducts: sanitize(affectedProducts.substring(0, 200)),
      problemType: sanitize(problemType),
      credits: sanitize(credits.substring(0, 100))
    };
  });

  updateSourceStatus(sourceKey, 'active', threats.length);
  console.log(`[CARTINT] ASRG: ${threats.length} automotive advisories loaded`);
  return threats;
}

// ---- CISA KEV + CSAF (Firmware Repos / ICS Advisories) ----

async function fetchCISA() {
  const sourceKey = 'Firmware Repos';
  updateSourceStatus(sourceKey, 'fetching');

  const allThreats = [];

  // --- Part 1: KEV Catalog (Known Exploited Vulnerabilities) ---
  try {
    const resp = await corsFetch(CONFIG.cisa.kevUrl);
    const data = await resp.json();
    const vulns = data.vulnerabilities || [];

    // Filter for automotive-relevant entries
    const autoVulns = vulns.filter(v => {
      const text = `${v.vendorProject} ${v.product} ${v.vulnerabilityName} ${v.shortDescription || ''}`;
      return isAutomotiveRelevant(text);
    });

    console.log(`[CARTINT] CISA KEV: ${autoVulns.length} automotive entries out of ${vulns.length} total`);

    for (const v of autoVulns) {
      const text = `${v.vendorProject} ${v.product} ${v.vulnerabilityName} ${v.shortDescription || ''}`;
      const techniques = extractTechniques(text);
      const component = extractComponent(text);
      const oem = extractOEM(text);
      const threatId = generateId('kev', v.cveID);
      const isRansomware = v.knownRansomwareCampaignUse === 'Known';

      allThreats.push({
        id: threatId,
        title: `${v.cveID}: ${sanitize(v.vulnerabilityName)}${isRansomware ? ' [Ransomware Exploited]' : ''}`,
        severity: isRansomware ? 'critical' : 'high',
        oem,
        component,
        techniques,
        source: 'Firmware Repos',
        sourceDetail: `CISA KEV · ${sanitize(v.vendorProject)}`,
        confidence: isRansomware ? 98 : 92,
        sources: 1,
        time: timeAgo(v.dateAdded),
        rawDate: new Date(v.dateAdded),
        link: `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
        isRansomware
      });
    }
  } catch (e) {
    console.warn('[CARTINT] CISA KEV fetch failed:', e.message);
  }

  // --- Part 2: CSAF ICS/OT Advisories (recent year via GitHub API) ---
  try {
    // Try current year first, fall back to previous year
    const year = new Date().getFullYear();
    let url = `${CONFIG.cisa.csafBaseUrl}/${year}?ref=develop&per_page=30`;
    let resp = await fetch(url, {
      headers: { 'Accept': 'application/vnd.github.v3+json' }
    });
    // Fall back to previous year if current year folder doesn't exist yet
    if (!resp.ok) {
      url = `${CONFIG.cisa.csafBaseUrl}/${year - 1}?ref=develop&per_page=30`;
      resp = await fetch(url, {
        headers: { 'Accept': 'application/vnd.github.v3+json' }
      });
    }
    if (!resp.ok) throw new Error(`CSAF listing ${resp.status}`);
    const files = await resp.json();
    // Extract actual year used from the URL
    const actualYear = url.match(/white\/(\d{4})/)?.[1] || year;

    // Get the most recent 15 advisory files
    const jsonFiles = files
      .filter(f => f.name.endsWith('.json'))
      .sort((a, b) => b.name.localeCompare(a.name))
      .slice(0, 15);

    console.log(`[CARTINT] CSAF: fetching ${jsonFiles.length} recent ICS advisories`);

    // Fetch advisory details in small batches
    const batchSize = 5;
    for (let i = 0; i < jsonFiles.length; i += batchSize) {
      const batch = jsonFiles.slice(i, i + batchSize);
      const promises = batch.map(async (file) => {
        try {
          const rawUrl = `${CONFIG.cisa.csafRawBase}/${actualYear}/${file.name}`;
          const r = await fetch(rawUrl);
          if (!r.ok) return null;
          return await r.json();
        } catch { return null; }
      });
      const results = await Promise.all(promises);

      for (const advisory of results) {
        if (!advisory) continue;

        const doc = advisory.document || {};
        const title = doc.title || 'Unknown Advisory';
        const trackingId = doc.tracking?.id || '';
        const releaseDate = doc.tracking?.initial_release_date || doc.tracking?.current_release_date || '';
        const severityText = doc.aggregate_severity?.text || 'MEDIUM';
        const vulns = advisory.vulnerabilities || [];

        // Extract vendor/product from product_tree
        let vendor = '';
        let product = '';
        try {
          const branches = advisory.product_tree?.branches || [];
          if (branches[0]) {
            vendor = branches[0].name || '';
            if (branches[0].branches?.[0]) {
              product = branches[0].branches[0].name || '';
            }
          }
        } catch {}

        const fullText = `${title} ${vendor} ${product} ${vulns.map(v => v.cve || '').join(' ')}`;

        // Check automotive relevance
        if (!isAutomotiveRelevant(fullText)) continue;

        const severity = severityText.toLowerCase() === 'critical' ? 'critical'
          : severityText.toLowerCase() === 'high' ? 'high'
          : severityText.toLowerCase() === 'low' ? 'low' : 'medium';

        const techniques = extractTechniques(fullText);
        const component = extractComponent(fullText);
        const oem = extractOEM(`${vendor} ${product}`);
        const cveList = vulns.map(v => v.cve).filter(Boolean);
        const maxCvss = Math.max(0, ...vulns.map(v => v.scores?.[0]?.cvss_v3?.base_score || 0));
        const threatId = generateId('csaf', trackingId || title);

        allThreats.push({
          id: threatId,
          title: `${trackingId}: ${sanitize(title)}${cveList.length > 0 ? ` (${cveList[0]}${cveList.length > 1 ? ` +${cveList.length - 1}` : ''})` : ''}`,
          severity,
          oem: oem !== 'Generic' ? oem : (vendor || 'ICS Vendor'),
          component: component !== 'Vehicle System' ? component : (product || 'ICS/OT System'),
          techniques,
          source: 'Firmware Repos',
          sourceDetail: `CISA CSAF · ${sanitize(vendor || 'ICS')}`,
          confidence: Math.min(95, Math.round(70 + maxCvss * 2.5)),
          sources: 1,
          time: timeAgo(releaseDate),
          rawDate: new Date(releaseDate),
          link: `https://www.cisa.gov/news-events/ics-advisories/${trackingId.toLowerCase()}`
        });
      }

      // Rate limit respect
      if (i + batchSize < jsonFiles.length) {
        await new Promise(resolve => setTimeout(resolve, 1500));
      }
    }
  } catch (e) {
    console.warn('[CARTINT] CSAF fetch failed:', e.message);
  }

  // Sort by date
  allThreats.sort((a, b) => b.rawDate - a.rawDate);

  updateSourceStatus(sourceKey, 'active', allThreats.length);
  console.log(`[CARTINT] CISA total: ${allThreats.length} automotive-relevant advisories`);
  return allThreats;
}

// ---- Ransomware.live (Dark Web Intelligence) ----

async function fetchRansomwareLive() {
  const sourceKey = 'Dark Web';
  updateSourceStatus(sourceKey, 'fetching');

  let victims = [];
  let usedSource = '';

  try {
    const resp = await corsFetch(CONFIG.ransomwarelive.recentVictimsUrl, {
      timeout: CONFIG.ransomwarelive.fetchTimeout || 45000
    });
    const data = await resp.json();
    const list = Array.isArray(data) ? data : (data && Array.isArray(data.victims) ? data.victims : []);
    if (list.length > 0) {
      victims = list;
      usedSource = 'ransomware.live API';
      console.log(`[CARTINT] Dark Web: ${victims.length} victims loaded`);
    }
  } catch (e) {
    console.warn(`[CARTINT] Dark Web fetch failed:`, e.message);
  }

  if (victims.length === 0) {
    console.error('[CARTINT] Dark Web: All fetch methods failed');
    updateSourceStatus(sourceKey, 'error');
    return [];
  }

  // Normalize ransomwatch fields (post_title/group_name) to ransomware.live fields (victim/group)
  victims = victims.map(v => ({
    victim: v.victim || v.post_title || '',
    group: v.group || v.group_name || '',
    discovered: v.discovered || v.attackdate || '',
    domain: v.domain || '',
    description: v.description || '',
    activity: v.activity || '',
    country: v.country || '',
    url: v.url || '',
    ...v
  }));

  // Filter for automotive-relevant victims using the classifier
  const automotiveVictims = victims.filter(v => {
    const text = `${v.victim} ${v.domain} ${v.description} ${v.activity}`;
    return isAutomotiveRelevant(text, v.group);
  });

  console.log(`[CARTINT] Dark Web (${usedSource}): ${automotiveVictims.length} automotive-related victims out of ${victims.length} total`);

  // Sort by discovered date (most recent first)
  automotiveVictims.sort((a, b) => new Date(b.discovered || 0) - new Date(a.discovered || 0));

  // Convert to threat format
  const knownAPTGroups = ['lockbit', 'lockbit3', 'alphv', 'blackcat', 'clop', 'cl0p',
    'blackbasta', 'black basta', 'play', 'royal', 'akira', 'rhysida',
    'medusa', 'bianlian', 'hunters', '8base', 'cactus', 'ransomhub',
    'krybit', 'fog', 'qilin', 'inc', 'lynx', 'safepay', 'interlock'];

  const threats = automotiveVictims.map(v => {
    const victimName = v.victim || v.domain || 'Unknown victim';
    const groupName = v.group || 'unknown';
    const discovered = v.discovered || v.attackdate || '';
    const country = v.country || '';
    const sector = v.activity || '';
    const description = v.description || '';

    const isMajorGroup = knownAPTGroups.some(g => groupName.toLowerCase().includes(g));

    // Severity
    let severity = 'high';
    if (isMajorGroup) severity = 'critical';

    // Extract OEM/supplier from victim name and description
    const oem = extractOEM(`${victimName} ${description}`);

    // Determine component
    let component = 'Supply Chain';
    const lowerText = `${victimName} ${description} ${sector}`.toLowerCase();
    if (lowerText.includes('dealer') || lowerText.includes('dealership')) component = 'Dealer Network';
    else if (lowerText.includes('fleet')) component = 'Fleet Management';
    else if (lowerText.includes('part') || lowerText.includes('aftermarket')) component = 'Parts Supply Chain';
    else if (lowerText.includes('logistics') || lowerText.includes('transport')) component = 'Logistics';
    else if (lowerText.includes('software') || lowerText.includes('tech')) component = 'Software Vendor';
    else if (lowerText.includes('manufactur')) component = 'Manufacturing';
    else if (oem !== 'Generic') component = 'OEM / Tier-1';

    // ATM techniques
    const techniques = ['ATM-T0059'];
    techniques.push('ATM-T0040');
    if (isMajorGroup) techniques.push('ATM-T0076');

    // Confidence
    let confidence = 80;
    if (isMajorGroup) confidence += 10;
    if (description && description !== 'Not Found') confidence += 5;
    confidence = Math.min(confidence, 98);

    const threatId = generateId('rwlive', `${groupName}-${victimName}`);
    const countryInfo = country ? ` · ${country}` : '';
    const sectorInfo = sector && sector !== 'Not Found' ? ` · ${sector}` : '';

    return {
      id: threatId,
      title: `Ransomware group "${sanitize(groupName)}" claims automotive victim: ${sanitize(victimName)}`,
      severity,
      oem,
      component,
      techniques,
      source: 'Dark Web',
      sourceDetail: `Ransomware.live · ${sanitize(groupName)}${countryInfo}${sectorInfo}`,
      confidence,
      sources: 1,
      time: discovered ? timeAgo(discovered) : 'Unknown',
      rawDate: discovered ? new Date(discovered) : new Date(0),
      link: v.permalink || v.url || `https://www.ransomware.live/#/group/${encodeURIComponent(groupName)}`,
      groupName
    };
  });

  updateSourceStatus(sourceKey, 'active', threats.length);
  console.log(`[CARTINT] Dark Web (${usedSource}): ${threats.length} automotive threats generated`);
  return threats;
}

// ---- Ahmia Dark Web Search ----
// Searches Ahmia.fi (indexes .onion content) for automotive threats
// Uses local proxy if available, falls back to CORS proxies

function parseAhmiaHTML(html) {
  const results = [];
  const seen = new Set();

  // Extract .onion URLs with surrounding context
  const onionRegex = /https?:\/\/([a-z0-9]{16,56}\.onion)[^\s"'<>)\]]*/gi;
  let match;

  while ((match = onionRegex.exec(html)) !== null) {
    const url = match[0].replace(/[.,;!?]$/, '');
    const onion = match[1];
    if (seen.has(onion)) continue;
    seen.add(onion);

    const start = Math.max(0, match.index - 300);
    const end = Math.min(html.length, match.index + url.length + 300);
    const rawContext = html.substring(start, end);

    const context = rawContext
      .replace(/<[^>]+>/g, ' ')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/\s+/g, ' ')
      .trim();

    const beforeText = context.substring(0, Math.max(0, match.index - start)).trim();
    const afterText = context.substring(match.index - start + url.length).trim();

    let title = '';
    if (beforeText.length > 5) {
      title = beforeText.substring(0, 120);
    } else if (afterText.length > 5) {
      title = afterText.substring(0, 120);
    } else {
      title = onion;
    }

    results.push({
      url,
      title: title.trim(),
      description: context.substring(0, 400)
    });
  }

  return results;
}

async function fetchAhmiaDarkWeb() {
  const queries = CONFIG.darkweb.ahmiaQueries;
  const n = CONFIG.darkweb.queriesPerPoll;
  const start = CONFIG.darkweb.queryIndex;

  const batch = [];
  for (let i = 0; i < n; i++) {
    batch.push(queries[(start + i) % queries.length]);
  }
  CONFIG.darkweb.queryIndex = (start + n) % queries.length;

  const allResults = [];

  for (const query of batch) {
    try {
      let results = null;

      // Try local proxy API first (returns parsed JSON)
      try {
        const resp = await fetch(`http://localhost:3001/api/ahmia-search?q=${encodeURIComponent(query)}`, { signal: AbortSignal.timeout(30000) });
        if (resp.ok) {
          const data = await resp.json();
          results = data.results || [];
        }
      } catch (e) { /* proxy not available, try CORS */ }

      // Fallback: fetch Ahmia HTML via CORS proxy and parse client-side
      if (!results) {
        const ahmiaUrl = `https://ahmia.fi/search/?q=${encodeURIComponent(query)}`;
        const corsUrl = `https://corsproxy.io/?${encodeURIComponent(ahmiaUrl)}`;
        try {
          const resp = await fetch(corsUrl, { signal: AbortSignal.timeout(20000) });
          if (resp.ok) {
            const html = await resp.text();
            results = parseAhmiaHTML(html);
          }
        } catch (e2) { /* try next query */ }
      }

      if (results && results.length > 0) {
        allResults.push(...results.map(r => ({ ...r, _query: query })));
      }

      // Rate limit between queries
      await new Promise(resolve => setTimeout(resolve, 2500));
    } catch (e) {
      console.warn(`[CARTINT] Ahmia search failed for "${query}":`, e.message);
    }
  }

  // Filter through automotive classifier — stricter for dark web content
  const relevant = allResults.filter(r => {
    const text = `${r.title || ''} ${r.description || ''} ${r.url || ''}`;
    const result = classifyAutomotiveRelevance(text, r._query || '');
    if (result.rejected) return false;
    // Higher threshold for dark web results (require score >= 8)
    // to reduce false positives from dark web marketplace listings
    return result.score >= 8;
  });

  const threats = relevant.map(r => {
    const fullText = `${r.title} ${r.description} ${r._query}`;
    const techniques = extractTechniques(fullText);
    const component = extractComponent(fullText);
    const oem = extractOEM(fullText);
    const threatId = generateId('ahmia', r.url || r.title);

    // Determine severity from content
    let severity = 'medium';
    const lowerDesc = (r.description || '').toLowerCase();
    if (/exploit|vulnerability|breach|leak|dump|ransomware/i.test(lowerDesc)) severity = 'high';
    if (/credential|password|api.?key|secret|token|private.?key/i.test(lowerDesc)) severity = 'critical';
    if (/bypass|unlock|immobilizer|backdoor/i.test(lowerDesc)) severity = 'critical';

    return {
      id: threatId,
      title: `Dark Web: ${sanitize(r.title || r.url)}`,
      severity,
      oem,
      component,
      techniques,
      source: 'Dark Web',
      sourceDetail: `Ahmia Dark Web Search · "${sanitize(r._query)}"`,
      confidence: 70,
      sources: 1,
      time: 'Recent',
      rawDate: new Date(),
      link: r.url || '#',
      _subSource: 'ahmia',
      _classifyText: `${r.title} ${r.description}`
    };
  });

  console.log(`[CARTINT] Ahmia: ${threats.length} automotive results from ${allResults.length} total dark web hits`);
  return threats;
}

// ---- Paste Site Monitoring ----
// Searches paste sites (psbdmp.ws) for automotive credential/code leaks

async function fetchDarkWebPastes() {
  const queries = CONFIG.darkweb.pasteQueries;
  const n = CONFIG.darkweb.pasteQueriesPerPoll;
  const start = CONFIG.darkweb.pasteQueryIndex;

  const batch = [];
  for (let i = 0; i < n; i++) {
    batch.push(queries[(start + i) % queries.length]);
  }
  CONFIG.darkweb.pasteQueryIndex = (start + n) % queries.length;

  const allResults = [];

  for (const query of batch) {
    try {
      let results = null;

      // Try local proxy API first
      try {
        const resp = await fetch(`http://localhost:3001/api/paste-search?q=${encodeURIComponent(query)}`, { signal: AbortSignal.timeout(15000) });
        if (resp.ok) {
          const data = await resp.json();
          results = data.results || [];
        }
      } catch (e) { /* proxy not available */ }

      // Fallback: CORS proxy to psbdmp.ws API
      if (!results) {
        const apiUrl = `https://psbdmp.ws/api/search/${encodeURIComponent(query)}`;
        const corsUrl = `https://corsproxy.io/?${encodeURIComponent(apiUrl)}`;
        try {
          const resp = await fetch(corsUrl, { signal: AbortSignal.timeout(15000) });
          if (resp.ok) {
            results = await resp.json();
            if (!Array.isArray(results)) results = [];
          }
        } catch (e2) { /* try next */ }
      }

      if (results && results.length > 0) {
        allResults.push(...results.slice(0, 10).map(r => ({ ...r, _query: query })));
      }

      await new Promise(resolve => setTimeout(resolve, 2000));
    } catch (e) {
      console.warn(`[CARTINT] Paste search failed for "${query}":`, e.message);
    }
  }

  // Filter through automotive classifier
  const relevant = allResults.filter(r => {
    const text = `${r.content || ''} ${r._query}`;
    return isAutomotiveRelevant(text);
  });

  const threats = relevant.map(r => {
    const content = (r.content || '').substring(0, 500);
    const fullText = `${content} ${r._query}`;
    const techniques = extractTechniques(fullText);
    const component = extractComponent(fullText);
    const oem = extractOEM(fullText);
    const threatId = generateId('paste', r.id || content.substring(0, 50));

    let severity = 'high';
    if (/password|secret|token|private.?key|credential/i.test(content)) severity = 'critical';
    else if (/api.?key|api.?token/i.test(content)) severity = 'critical';
    else if (/exploit|attack|bypass/i.test(content)) severity = 'high';

    return {
      id: threatId,
      title: `Paste leak: ${sanitize(content.substring(0, 100))}${content.length > 100 ? '...' : ''}`,
      severity,
      oem,
      component,
      techniques,
      source: 'Dark Web',
      sourceDetail: `Paste Dump · "${sanitize(r._query)}"`,
      confidence: 80,
      sources: 1,
      time: r.time ? timeAgo(r.time) : 'Recent',
      rawDate: r.time ? new Date(r.time) : new Date(),
      link: r.id ? `https://psbdmp.ws/${r.id}` : '#',
      _subSource: 'paste',
      _classifyText: content
    };
  });

  console.log(`[CARTINT] Pastes: ${threats.length} automotive results from ${allResults.length} total pastes`);
  return threats;
}

// ---- Ransomware Group Details (Enhanced) ----
// Fetches group-specific data from ransomware.live for deeper context

async function fetchRansomwareGroupDetails() {
  const groupsUrl = CONFIG.ransomwarelive.groupsUrl;
  let groups = [];

  try {
    const resp = await corsFetch(groupsUrl, { timeout: 20000 });
    if (resp) {
      const data = await resp.json();
      groups = Array.isArray(data) ? data : (data && Array.isArray(data.groups) ? data.groups : []);
    }
  } catch (e) {
    console.warn('[CARTINT] Ransomware groups fetch failed:', e.message);
    return [];
  }

  // Filter groups that have automotive-related victims
  const autoGroupThreats = [];

  for (const group of groups.slice(0, 50)) { // Limit to avoid rate limits
    try {
      const groupName = group.name || group.group || '';
      if (!groupName) continue;

      // Fetch group-specific victims
      const groupUrl = `https://api.ransomware.live/v2/group/${encodeURIComponent(groupName)}`;
      const resp = await corsFetch(groupUrl, { timeout: 15000 });
      if (!resp) continue;
      const data = await resp.json();
      const victims = Array.isArray(data) ? data : (data && Array.isArray(data.victims) ? data.victims : []);

      // Filter for automotive victims
      const autoVictims = victims.filter(v => {
        const text = `${v.victim || v.post_title || ''} ${v.domain || ''} ${v.description || ''} ${v.activity || ''}`;
        return isAutomotiveRelevant(text, groupName);
      });

      for (const v of autoVictims.slice(0, 5)) { // Max 5 per group
        const victimName = v.victim || v.post_title || v.domain || 'Unknown';
        const discovered = v.discovered || v.attackdate || '';
        const threatId = generateId('rwgroup', `${groupName}-${victimName}`);

        autoGroupThreats.push({
          id: threatId,
          title: `Ransomware group "${sanitize(groupName)}" claims automotive victim: ${sanitize(victimName)}`,
          severity: 'critical',
          oem: extractOEM(`${victimName} ${v.description || ''}`),
          component: 'Supply Chain',
          techniques: ['ATM-T0059', 'ATM-T0040', 'ATM-T0076'],
          source: 'Dark Web',
          sourceDetail: `Ransomware.live · Group: ${sanitize(groupName)} · ${v.country || 'Unknown'}`,
          confidence: 88,
          sources: 1,
          time: discovered ? timeAgo(discovered) : 'Unknown',
          rawDate: discovered ? new Date(discovered) : new Date(0),
          link: v.permalink || v.url || `https://www.ransomware.live/#/group/${encodeURIComponent(groupName)}`,
          groupName,
          _subSource: 'ransomware-group',
          _classifyText: `${victimName} ${v.description || ''} ${groupName}`
        });
      }

      // Rate limit between group fetches
      await new Promise(resolve => setTimeout(resolve, 1500));
    } catch (e) {
      // Skip this group on error
    }
  }

  console.log(`[CARTINT] Ransomware groups: ${autoGroupThreats.length} automotive victims across ${groups.length} groups`);
  return autoGroupThreats;
}

// ---- Multi-Source Corroboration ----
// Boosts confidence for threats confirmed by multiple dark web sub-sources

function corroborateDarkWebThreats(threats) {
  const groups = {};

  for (const t of threats) {
    // Create a normalized key for matching similar threats
    const baseText = (t._classifyText || t.title || '').toLowerCase();
    // Extract key entity name (first significant word)
    const keyMatch = baseText.match(/([a-z]{3,})/g);
    const key = keyMatch ? keyMatch.sort((a, b) => b.length - a.length)[0] : baseText.substring(0, 20);

    if (!groups[key]) groups[key] = [];
    groups[key].push(t);
  }

  // Boost confidence for threats confirmed by multiple sub-sources
  for (const [key, group] of Object.entries(groups)) {
    if (group.length > 1) {
      const subSources = new Set(group.map(t => t._subSource || 'ransomware'));
      if (subSources.size > 1) {
 // Only boost if different sub-sources
        const corroborationBoost = (subSources.size - 1) * 8;
        for (const t of group) {
          t.confidence = Math.min(98, t.confidence + corroborationBoost);
          t.sources = subSources.size;
          t.sourceDetail = t.sourceDetail + ` · corroborated by ${subSources.size} sources`;
        }
      }
    }
  }

  return threats;
}

// ---- Unified Dark Web Threat Fetcher ----
// Combines: ransomware.live + Ahmia dark web search + paste monitoring + group details

async function fetchDarkWebThreats() {
  const sourceKey = 'Dark Web';
  updateSourceStatus(sourceKey, 'fetching');

  CONFIG.darkweb.pollCount = (CONFIG.darkweb.pollCount || 0) + 1;

  // Fetch from all dark web sub-sources concurrently
  const fetchPromises = [
    fetchRansomwareLive(),
    fetchAhmiaDarkWeb(),
    fetchDarkWebPastes()
  ];

  // Fetch group details every Nth poll (expensive — many API calls)
  if (CONFIG.darkweb.pollCount % CONFIG.darkweb.groupDetailInterval === 0) {
    fetchPromises.push(fetchRansomwareGroupDetails());
  }

  const results = await Promise.allSettled(fetchPromises);

  const allThreats = [];
  const subCounts = {};

  for (const result of results) {
    if (result.status === 'fulfilled' && result.value) {
      for (const t of result.value) {
        const sub = t._subSource || 'ransomware';
        subCounts[sub] = (subCounts[sub] || 0) + 1;
        allThreats.push(t);
      }
    }
  }

  // Apply multi-source corroboration
  corroborateDarkWebThreats(allThreats);

  const activeCount = allThreats.length;
  updateSourceStatus(sourceKey, 'active', activeCount);

  console.log(`[CARTINT] Dark Web (combined): ${activeCount} threats — ${JSON.stringify(subCounts)}`);
  return allThreats;
}

// ---- Fetch Status Bar ----

function updateFetchStatus(message, type = '') {
  const bar = document.getElementById('fetchStatus');
  const text = document.getElementById('fetchStatusText');
  if (!bar || !text) return;
  bar.classList.remove('hidden', 'error', 'done');
  if (type) bar.classList.add(type);
  text.textContent = message;
}

// ---- Source Status Management ----

function updateSourceStatus(name, status, count) {
  state.sourceStatus[name] = { status, count: count || 0, lastUpdated: new Date() };
  renderDataSources();
}

// ---- Threat Processing ----

function addThreats(newThreats) {
  let added = 0;
  for (const threat of newThreats) {
    if (!state.seenIds.has(threat.id)) {
      state.seenIds.add(threat.id);
      state.threats.push(threat);
      added++;

      // Count techniques
      for (const tech of threat.techniques) {
        state.techniqueCounts[tech] = (state.techniqueCounts[tech] || 0) + 1;
      }
    }
  }

  // Sort all threats by date
  state.threats.sort((a, b) => (b.rawDate || 0) - (a.rawDate || 0));

  // Update stats
  state.totalATM = Object.keys(state.techniqueCounts).length;

  // Persist to localStorage for cache restore + intel page
  persistAllThreats();

  return added;
}

// ---- Rendering Functions ----

function animateCounter(element, target, duration = 1200) {
  const start = parseInt(element.textContent) || 0;
  if (start === target) return;
  const startTime = performance.now();

  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = Math.round(start + (target - start) * eased);
    element.textContent = current;
    if (progress < 1) {
      requestAnimationFrame(update);
    }
  }

  requestAnimationFrame(update);
}

function renderSparklines() {
  const sparklineIds = ['sparkTelematics', 'sparkOTA', 'sparkGithub', 'sparkSupplier', 'sparkTechniques'];
  sparklineIds.forEach(id => {
    const container = document.getElementById(id);
    if (!container || container.children.length > 0) return;
    const barCount = 14;
    for (let i = 0; i < barCount; i++) {
      const bar = document.createElement('div');
      bar.className = 'spark-bar';
      const height = Math.random() * 80 + 20;
      bar.style.height = '0%';
      container.appendChild(bar);
      setTimeout(() => {
        bar.style.height = height + '%';
      }, 200 + i * 60);
    }
  });
}

function updateStatCards() {
  // All counts derived directly from state.threats — single source of truth
  const counts = {};
  for (const t of state.threats) {
    counts[t.source] = (counts[t.source] || 0) + 1;
  }

  // Sync source status counts with actual state.threats counts
  for (const [sourceName, count] of Object.entries(counts)) {
    if (state.sourceStatus[sourceName]) {
      state.sourceStatus[sourceName].count = count;
    }
  }
  renderDataSources();

  const criticalHighCount = state.threats.filter(t => t.severity === 'critical' || t.severity === 'high').length;
  const ctCount = counts['ASRG'] || 0;
  const githubCount = counts['GitHub'] || 0;
  const darkWebCount = counts['Dark Web'] || 0;
  const firmwareCount = counts['Firmware Repos'] || 0;

  const targets = {
    Telematics: criticalHighCount,
    OTA: ctCount,
    Github: githubCount,
    Supplier: darkWebCount,
    Techniques: state.totalATM
  };

  Object.entries(targets).forEach(([key, target]) => {
    const el = document.getElementById('stat' + key);
    if (el) {
      animateCounter(el, target);
    }
  });

  // Update trends
  const trendMap = {
    telematics: criticalHighCount > 0 ? `${criticalHighCount} found` : 'Scanning...',
    ota: ctCount > 0 ? `${ctCount} certs` : 'Scanning...',
    github: githubCount > 0 ? `${githubCount} results` : 'Scanning...',
    supplier: darkWebCount > 0 ? `${darkWebCount} victims` : 'Scanning...',
    techniques: state.totalATM > 0 ? `${state.totalATM} mapped` : 'Scanning...',
  };

  document.querySelectorAll('.stat-card').forEach(card => {
    const stat = card.dataset.stat;
    const trendEl = card.querySelector('.stat-trend');
    if (trendEl && trendMap[stat]) {
      const val = parseInt(card.querySelector('.stat-value')?.textContent) || 0;
      trendEl.textContent = trendMap[stat];
      trendEl.className = 'stat-trend ' + (val > 0 ? 'up' : 'neutral');
    }
  });

  // ATM counter
  const atmEl = document.getElementById('atmCount');
  if (atmEl) {
    animateCounter(atmEl, state.totalATM > 0 ? 200 + state.totalATM : 302);
  }
}

function renderThreatItem(threat, isNew = false) {
  const item = document.createElement('div');
  item.className = `threat-item${isNew ? ' new-threat' : ''}`;
  item.dataset.id = threat.id;

  const severityLabel = threat.severity.toUpperCase();
  const confidenceClass = threat.confidence >= 85 ? 'high' : threat.confidence >= 70 ? 'medium' : 'low';

  item.innerHTML = `
    <div class="threat-item-header">
      <div class="threat-severity-dot ${threat.severity}"></div>
      <div class="threat-title">${threat.title}</div>
      <div class="threat-time">${threat.time}</div>
    </div>
    <div class="threat-tags">
      <span class="threat-tag severity-${threat.severity}">${severityLabel}</span>
      <span class="threat-tag oem">${threat.oem}</span>
      <span class="threat-tag component">${threat.component}</span>
      ${threat.techniques.map(t => `<span class="threat-tag technique">${t}</span>`).join('')}
    </div>
    <div class="threat-meta">
      <div class="threat-meta-item">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
        ${threat.sourceDetail}
      </div>
      <div class="threat-confidence">
        <div class="confidence-bar">
          <div class="confidence-fill ${confidenceClass}" style="width: ${threat.confidence}%"></div>
        </div>
        Confidence: ${threat.confidence}%
      </div>
      <div class="threat-meta-item">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        ${threat.sources} source${threat.sources > 1 ? 's' : ''}
      </div>
      ${threat.link ? `
      <a href="${threat.link}" target="_blank" rel="noopener" class="threat-matrix-link">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
        View Source
      </a>` : ''}
    </div>
  `;

  return item;
}

function getFilteredThreats() {
  if (!state.activeSourceFilter) return state.threats;
  return state.threats.filter(t => t.source === state.activeSourceFilter);
}

function renderThreatFeed(fullRefresh = false) {
  const feed = document.getElementById('threatFeed');
  if (!feed) return;

  const filtered = getFilteredThreats();

  if (fullRefresh) {
    feed.innerHTML = '';
  }

  // Show loading state if no threats yet
  // Update loading text to show new dark web sources
  if (state.threats.length === 0 && feed.children.length === 0) {
    feed.innerHTML = `
      <div class="threat-item" style="text-align: center; padding: 40px 20px;">
        <div class="streaming-indicator" style="justify-content: center; margin-bottom: 12px;">
          <span class="streaming-dot"></span>
          <span style="color: var(--text-secondary); font-family: var(--font-mono); font-size: 0.8rem;">Fetching live threat data from sources...</span>
        </div>
        <div style="color: var(--text-muted); font-size: 0.75rem;">Querying ASRG, Ahmia Dark Web, Paste Dumps, Ransomware.live, NVD, GitHub, CISA KEV, CSAF</div>
      </div>
    `;
    return;
  }

  // Show empty state when filter returns no results
  if (filtered.length === 0 && fullRefresh) {
    feed.innerHTML = `
      <div class="threat-item" style="text-align: center; padding: 40px 20px;">
        <div style="color: var(--text-secondary); font-family: var(--font-mono); font-size: 0.8rem; margin-bottom: 8px;">No threats from "${state.activeSourceFilter}"</div>
        <div style="color: var(--text-muted); font-size: 0.75rem;">This source may still be loading or returned no automotive-relevant results.</div>
      </div>
    `;
    return;
  }

  const existingIds = new Set();
  feed.querySelectorAll('.threat-item[data-id]').forEach(el => existingIds.add(el.dataset.id));

  if (fullRefresh) {
    const threatsToShow = filtered.slice(0, 50);
    threatsToShow.forEach((threat, index) => {
      const item = renderThreatItem(threat);
      item.style.animationDelay = `${Math.min(index, 15) * 0.04}s`;
      feed.appendChild(item);
    });
  } else {
    // Insert only new threats at top (that match current filter)
    const newThreats = filtered.filter(t => !existingIds.has(t.id));
    newThreats.slice(0, 5).reverse().forEach(threat => {
      const item = renderThreatItem(threat, true);
      feed.insertBefore(item, feed.firstChild);
    });

    // Trim if too many
    const items = feed.querySelectorAll('.threat-item');
    if (items.length > 50) {
      for (let i = items.length - 1; i >= 50; i--) {
        feed.removeChild(items[i]);
      }
    }
  }
}

// ATM tactic to technique mapping for the chart
const TACTIC_TECHNIQUE_MAPPING = {
  'Reconnaissance': ['ATM-T0001', 'ATM-T0002', 'ATM-T0003'],
  'Manipulate Environment': ['ATM-T0012', 'ATM-T0013', 'ATM-T0014', 'ATM-T0015'],
  'Initial Access': ['ATM-T0017', 'ATM-T0022', 'ATM-T0023', 'ATM-T0024'],
  'Execution': ['ATM-T0033', 'ATM-T0034', 'ATM-T0035'],
  'Persistence': ['ATM-T0040', 'ATM-T0041', 'ATM-T0042'],
  'Privilege Escalation': ['ATM-T0044', 'ATM-T0045', 'ATM-T0046'],
  'Defense Evasion': ['ATM-T0050', 'ATM-T0051', 'ATM-T0052'],
  'Credential Access': ['ATM-T0055', 'ATM-T0056', 'ATM-T0057'],
  'Discovery': ['ATM-T0059', 'ATM-T0060', 'ATM-T0061'],
  'Lateral Movement': ['ATM-T0063', 'ATM-T0064', 'ATM-T0065'],
  'Collection': ['ATM-T0067', 'ATM-T0068', 'ATM-T0069'],
  'Command and Control': ['ATM-T0071', 'ATM-T0072', 'ATM-T0073'],
  'Exfiltration': ['ATM-T0075', 'ATM-T0076', 'ATM-T0077'],
  'Affect Vehicle Function': ['ATM-T0080', 'ATM-T0081', 'ATM-T0082']
};

const TACTIC_COLORS = [
  '#e63946', '#f77f00', '#f77f00', '#e63946',
  '#7b2cbf', '#4895ef', '#2ec4b6', '#e056a0',
  '#4895ef', '#fcbf49', '#2ec4b6', '#7b2cbf',
  '#4895ef', '#e63946'
];

function renderTechniquesChart() {
  const chart = document.getElementById('techniquesChart');
  if (!chart) return;
  chart.innerHTML = '';

  const tacticNames = Object.keys(TACTIC_TECHNIQUE_MAPPING);

  // Count techniques per tactic from real data
  const tacticCounts = tacticNames.map(tactic => {
    const relatedTechs = TACTIC_TECHNIQUE_MAPPING[tactic];
    let count = 0;
    for (const tech of relatedTechs) {
      count += state.techniqueCounts[tech] || 0;
    }
    // Also count any techniques that contain the tactic-related IDs
    for (const [tech, techCount] of Object.entries(state.techniqueCounts)) {
      if (relatedTechs.some(rt => tech === rt)) continue; // already counted
      // Check range-based matching
      const techNum = parseInt(tech.replace('ATM-T', ''));
      const rangeStart = parseInt(relatedTechs[0]?.replace('ATM-T', ''));
      const rangeEnd = parseInt(relatedTechs[relatedTechs.length - 1]?.replace('ATM-T', ''));
      if (techNum >= rangeStart && techNum <= rangeEnd) {
        count += techCount;
      }
    }
    return Math.max(count, 1); // minimum 1 for visual
  });

  const maxCount = Math.max(...tacticCounts, 1);

  tacticNames.forEach((tactic, index) => {
    const row = document.createElement('div');
    row.className = 'technique-row';
    row.style.animationDelay = `${index * 0.05}s`;

    const count = tacticCounts[index];
    const widthPercent = (count / maxCount) * 100;
    const color = TACTIC_COLORS[index];

    row.innerHTML = `
      <div class="technique-label">${tactic}</div>
      <div class="technique-bar-track">
        <div class="technique-bar-fill" style="background: ${color};" data-width="${widthPercent}">
          <span class="technique-count">${count}</span>
        </div>
      </div>
    `;

    chart.appendChild(row);
  });

  // Animate bars
  setTimeout(() => {
    document.querySelectorAll('.technique-bar-fill').forEach(bar => {
      bar.style.width = bar.dataset.width + '%';
    });
  }, 200);
}

function renderDataSources() {
  const container = document.getElementById('dataSources');
  if (!container) return;
  container.innerHTML = '';

  const ALL_SOURCES = [
    { name: 'Dark Web', color: '#e63946' },
    { name: 'GitHub', color: '#2ec4b6' },
    { name: 'NVD/CVE', color: '#f77f00' },
    { name: 'ASRG', color: '#7b2cbf' },
    { name: 'CISA KEV', color: '#4895ef' },
    { name: 'Firmware Repos', color: '#2ec4b6' }
  ];

  ALL_SOURCES.forEach((source, index) => {
    const badge = document.createElement('div');
    badge.className = 'source-badge';
    badge.style.animationDelay = `${index * 0.06}s`;
    badge.dataset.source = source.name;

    const status = state.sourceStatus[source.name];
    const isOnline = status && status.status === 'active';
    const isFetching = status && status.status === 'fetching';
    const isError = status && status.status === 'error';

    let statusClass = 'offline';
    let dotColor = 'var(--text-muted)';

    if (isOnline) {
      statusClass = 'online';
      dotColor = '#00e676'; // green
    } else if (isFetching) {
      statusClass = 'fetching';
      dotColor = '#fcbf49';
    } else if (isError) {
      statusClass = 'offline';
      dotColor = 'var(--text-muted)';
    }

    // Active filter highlight
    if (state.activeSourceFilter === source.name) {
      badge.classList.add('active-filter');
    }

    badge.innerHTML = `
      <span class="source-dot ${statusClass}" style="background: ${dotColor}; box-shadow: 0 0 6px ${dotColor}50;"></span>
      <span>${source.name}</span>
    `;

    // Click handler — toggle filter
    badge.addEventListener('click', () => {
      if (state.activeSourceFilter === source.name) {
        // Clicking active filter clears it
        setSourceFilter(null);
      } else {
        setSourceFilter(source.name);
      }
    });

    container.appendChild(badge);
  });
}

// ---- Source Filter ----

function setSourceFilter(sourceName) {
  state.activeSourceFilter = sourceName;

  // Update filter tag in feed header
  const filterTag = document.getElementById('feedFilterTag');
  const filterName = document.getElementById('feedFilterName');
  if (filterTag && filterName) {
    if (sourceName) {
      const count = state.threats.filter(t => t.source === sourceName).length;
      filterName.textContent = `${sourceName} (${count})`;
      filterTag.style.display = 'flex';
    } else {
      filterTag.style.display = 'none';
    }
  }

  // Re-render the feed with filter applied
  renderThreatFeed(true);

  // Re-render source badges to update active state
  renderDataSources();
}

// ---- Main Data Pipeline ----

// Map source display names to their fetch functions and status keys
const SOURCE_FETCH_MAP = [
  { name: 'Dark Web', statusName: 'Dark Web', fetchFn: () => fetchDarkWebThreats(), label: 'Dark Web (Ahmia + Pastes + Ransomware)' },
  { name: 'ASRG', statusName: 'ASRG', fetchFn: () => fetchASRG(), label: 'ASRG' },
  { name: 'NVD/CVE', statusName: 'NVD/CVE', fetchFn: () => fetchNVD(), label: 'NVD' },
  { name: 'GitHub', statusName: 'GitHub', fetchFn: () => fetchGitHubLeaks(), label: 'GitHub' },
  { name: 'CISA KEV', statusName: 'CISA KEV', fetchFn: () => fetchCISA(), label: 'CISA' },
  { name: 'Firmware Repos', statusName: 'Firmware Repos', fetchFn: () => fetchCISA(), label: 'CISA CSAF' }
];

async function fetchAllSources(forceRefresh = false) {
  // Determine which sources need fetching
  const toFetch = SOURCE_FETCH_MAP.filter(s => forceRefresh || isSourceCacheExpired(s.name));
  const skipped = SOURCE_FETCH_MAP.filter(s => !forceRefresh && !isSourceCacheExpired(s.name));

  // Mark skipped sources as active (they have cached data) with correct counts
  skipped.forEach(s => {
    const timestamps = getCacheTimestamps();
    const lastFetch = timestamps[s.name];
    const ago = lastFetch ? Math.round((Date.now() - lastFetch) / 60000) : 0;
    const count = state.threats.filter(t => t.source === s.statusName).length;
    console.log(`[CARTINT] ${s.label}: cache valid (fetched ${ago}m ago), skipping`);
    updateSourceStatus(s.statusName, 'active', count);
  });

  if (toFetch.length === 0) {
    console.log('[CARTINT] All sources cached. No fetching needed.');
    const activeSources = Object.values(state.sourceStatus).filter(s => s.status === 'active').length;
    updateFetchStatus(`Live — ${state.threats.length} threats from ${activeSources} sources (cached). Click refresh to re-fetch.`, 'done');
    return;
  }

  const fetchingNames = toFetch.map(s => s.label).join(', ');
  console.log(`[CARTINT] Fetching from: ${fetchingNames} (${skipped.length} cached)`);
  updateFetchStatus(`Connecting to ${fetchingNames}...`);

  // Mark fetching sources as 'fetching'
  toFetch.forEach(s => updateSourceStatus(s.statusName, 'fetching'));

  // Show loading state only if we have no cached data at all
  if (state.threats.length === 0) renderThreatFeed();

  // Fetch only expired sources concurrently
  const results = await Promise.allSettled(toFetch.map(s => s.fetchFn()));

  let totalAdded = 0;
  results.forEach((result, i) => {
    const src = toFetch[i];
    if (result.status === 'fulfilled' && result.value) {
      const added = addThreats(result.value);
      totalAdded += added;
      setCacheTimestamp(src.name);
      // Update source status with actual count in state (not raw fetch count)
      const actualCount = state.threats.filter(t => t.source === src.statusName).length;
      updateSourceStatus(src.statusName, 'active', actualCount);
      console.log(`[CARTINT] ${src.label}: ${result.value.length} fetched, ${added} new, ${actualCount} total in feed`);
    } else {
      console.warn(`[CARTINT] ${src.label} fetch failed:`, result.reason);
      updateSourceStatus(src.statusName, 'error');
    }
  });

  console.log(`[CARTINT] Total: ${state.threats.length} threats (${totalAdded} new from ${toFetch.length} sources)`);

  // Update UI
  renderThreatFeed(true);
  renderTechniquesChart();
  updateStatCards();

  // Update status bar
  if (state.threats.length > 0) {
    const activeSources = Object.values(state.sourceStatus).filter(s => s.status === 'active').length;
    updateFetchStatus(`Live — ${state.threats.length} threats from ${activeSources} sources. Click refresh to re-fetch.`, 'done');
  } else {
    updateFetchStatus('No results returned. APIs may be rate-limited — will retry automatically.', 'error');
  }
}

async function pollSource(fetchFn, sourceName, interval) {
  while (true) {
    await new Promise(resolve => setTimeout(resolve, interval));
    try {
      console.log(`[CARTINT] Polling ${sourceName}...`);
      const threats = await fetchFn();
      if (threats && threats.length > 0) {
        const added = addThreats(threats);
        if (added > 0) {
          renderThreatFeed(false);
          renderTechniquesChart();
          updateStatCards();
          console.log(`[CARTINT] ${sourceName}: ${added} new threats`);
        }
      }
    } catch (e) {
      console.warn(`[CARTINT] ${sourceName} poll failed:`, e.message);
    }
  }
}

// ---- Initialize ----

document.addEventListener('DOMContentLoaded', async () => {
  // Setup feed filter clear button
  const feedFilterClear = document.getElementById('feedFilterClear');
  if (feedFilterClear) {
    feedFilterClear.addEventListener('click', () => setSourceFilter(null));
  }

  // Setup AI config panel
  const aiToggle = document.getElementById('aiConfigToggle');
  const aiPanel = document.getElementById('aiConfigPanel');
  const aiSave = document.getElementById('aiConfigSave');
  const aiInput = document.getElementById('anthropicKeyInput');

  if (aiToggle && aiPanel) {
    aiToggle.addEventListener('click', () => {
      aiPanel.style.display = aiPanel.style.display === 'none' ? 'block' : 'none';
    });
  }

  // Load saved key from localStorage
  const savedKey = localStorage.getItem('cartint_anthropic_key');
  if (savedKey) {
    CONFIG.anthropicApiKey = savedKey;
    if (aiInput) aiInput.value = savedKey;
  }

  if (aiSave && aiInput) {
    aiSave.addEventListener('click', () => {
      const key = aiInput.value.trim();
      if (key) {
        CONFIG.anthropicApiKey = key;
        localStorage.setItem('cartint_anthropic_key', key);
        aiSave.textContent = 'Saved';
        setTimeout(() => { aiSave.textContent = 'Save'; }, 2000);
      } else {
        CONFIG.anthropicApiKey = null;
        localStorage.removeItem('cartint_anthropic_key');
        aiSave.textContent = 'Cleared';
        setTimeout(() => { aiSave.textContent = 'Save'; }, 2000);
      }
    });
  }

  // Setup refresh button
  const refreshBtn = document.getElementById('fetchRefreshBtn');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', async () => {
      refreshBtn.classList.add('spin');
      const liveSources = ['Dark Web', 'ASRG', 'GitHub', 'NVD/CVE', 'CISA KEV', 'Firmware Repos'];
      liveSources.forEach(name => updateSourceStatus(name, 'fetching'));
      renderDataSources();
      await fetchAllSources(true); // force refresh all
      refreshBtn.classList.remove('spin');
    });
  }

  // Render sparklines immediately
  renderSparklines();

  // Try to restore cached threats first
  const hadCache = restoreCachedThreats();
  if (hadCache) {
    // Immediately show cached data — no loading skeleton
    const timestamps = getCacheTimestamps();
    const liveSources = ['Dark Web', 'ASRG', 'GitHub', 'NVD/CVE', 'CISA KEV', 'Firmware Repos'];
    liveSources.forEach(name => {
      const count = state.threats.filter(t => t.source === name).length;
      updateSourceStatus(name, count > 0 ? 'active' : 'error', count);
    });
    renderDataSources();
    renderThreatFeed(true);
    renderTechniquesChart();
    updateStatCards();

    const activeSources = Object.values(state.sourceStatus).filter(s => s.status === 'active').length;
    updateFetchStatus(`Restored ${state.threats.length} cached threats from ${activeSources} sources. Checking for updates...`, 'done');
    console.log(`[CARTINT] Restored cache, now checking for expired sources...`);

    // Fetch only expired sources in background
    await fetchAllSources(false);
  } else {
    // No cache — full fresh fetch
    const liveSources = ['Dark Web', 'ASRG', 'GitHub', 'NVD/CVE', 'CISA KEV', 'Firmware Repos'];
    liveSources.forEach(name => updateSourceStatus(name, 'fetching'));
    renderDataSources();
    await fetchAllSources(false);
  }

  // Start polling loops for live updates
  pollSource(fetchDarkWebThreats, 'Dark Web (Ahmia + Pastes + Ransomware)', CONFIG.darkweb.pollInterval);
  pollSource(fetchASRG, 'ASRG', CONFIG.asrg.pollInterval);
  pollSource(fetchNVD, 'NVD', CONFIG.nvd.pollInterval);
  pollSource(fetchGitHubLeaks, 'GitHub', CONFIG.github.pollInterval);
  pollSource(fetchCISA, 'CISA/Firmware', CONFIG.cisa.pollInterval);
});
