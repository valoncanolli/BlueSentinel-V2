/**
 * mitre_heatmap.js — BlueSentinel v2.0
 * Full MITRE ATT&CK matrix renderer using Canvas API.
 * 14 tactics × N techniques per tactic.
 * Color: #1e3a5f (not detected) → cyan gradient (detected, intensity = confidence).
 * Click handler shows tooltip with technique details.
 * Export as PNG function.
 */

'use strict';

/* ─────────────────────────────────────────────────────────────────────────
   MITRE ATT&CK Tactic & Technique definitions
   ───────────────────────────────────────────────────────────────────────── */

const MITRE_TACTICS = [
  {
    id:    'TA0043',
    name:  'Reconnaissance',
    short: 'RECON',
    techniques: [
      { id: 'T1595', name: 'Active Scanning' },
      { id: 'T1592', name: 'Gather Host Info' },
      { id: 'T1589', name: 'Gather Identity Info' },
      { id: 'T1590', name: 'Gather Network Info' },
      { id: 'T1591', name: 'Gather Org Info' },
      { id: 'T1598', name: 'Phishing for Info' },
      { id: 'T1597', name: 'Search Closed Sources' },
      { id: 'T1596', name: 'Search Open Sources' },
    ],
  },
  {
    id:    'TA0042',
    name:  'Resource Development',
    short: 'RESOURCE',
    techniques: [
      { id: 'T1583', name: 'Acquire Infrastructure' },
      { id: 'T1586', name: 'Compromise Accounts' },
      { id: 'T1584', name: 'Compromise Infrastructure' },
      { id: 'T1587', name: 'Develop Capabilities' },
      { id: 'T1585', name: 'Establish Accounts' },
      { id: 'T1588', name: 'Obtain Capabilities' },
      { id: 'T1608', name: 'Stage Capabilities' },
    ],
  },
  {
    id:    'TA0001',
    name:  'Initial Access',
    short: 'INITIAL',
    techniques: [
      { id: 'T1189', name: 'Drive-by Compromise' },
      { id: 'T1190', name: 'Exploit Public-Facing App' },
      { id: 'T1133', name: 'External Remote Services' },
      { id: 'T1200', name: 'Hardware Additions' },
      { id: 'T1566', name: 'Phishing' },
      { id: 'T1091', name: 'Removable Media' },
      { id: 'T1195', name: 'Supply Chain Compromise' },
      { id: 'T1199', name: 'Trusted Relationship' },
      { id: 'T1078', name: 'Valid Accounts' },
    ],
  },
  {
    id:    'TA0002',
    name:  'Execution',
    short: 'EXEC',
    techniques: [
      { id: 'T1059', name: 'Command & Scripting' },
      { id: 'T1609', name: 'Container Admin Command' },
      { id: 'T1203', name: 'Exploitation for Exec' },
      { id: 'T1559', name: 'Inter-Process Comms' },
      { id: 'T1106', name: 'Native API' },
      { id: 'T1053', name: 'Scheduled Task/Job' },
      { id: 'T1129', name: 'Shared Modules' },
      { id: 'T1072', name: 'Software Deployment' },
      { id: 'T1569', name: 'System Services' },
      { id: 'T1204', name: 'User Execution' },
      { id: 'T1047', name: 'WMI' },
    ],
  },
  {
    id:    'TA0003',
    name:  'Persistence',
    short: 'PERSIST',
    techniques: [
      { id: 'T1098', name: 'Account Manipulation' },
      { id: 'T1197', name: 'BITS Jobs' },
      { id: 'T1547', name: 'Boot/Logon Autostart' },
      { id: 'T1037', name: 'Boot/Logon Init Scripts' },
      { id: 'T1176', name: 'Browser Extensions' },
      { id: 'T1554', name: 'Compromise Client Software' },
      { id: 'T1136', name: 'Create Account' },
      { id: 'T1543', name: 'Create or Modify Services' },
      { id: 'T1546', name: 'Event-Triggered Execution' },
      { id: 'T1133', name: 'External Remote Services' },
      { id: 'T1574', name: 'Hijack Exec Flow' },
      { id: 'T1505', name: 'Server Software Component' },
    ],
  },
  {
    id:    'TA0004',
    name:  'Privilege Escalation',
    short: 'PRIV ESC',
    techniques: [
      { id: 'T1548', name: 'Abuse Elevation Control' },
      { id: 'T1134', name: 'Access Token Manipulation' },
      { id: 'T1547', name: 'Boot/Logon Autostart' },
      { id: 'T1543', name: 'Create/Modify Services' },
      { id: 'T1546', name: 'Event-Triggered Exec' },
      { id: 'T1574', name: 'Hijack Exec Flow' },
      { id: 'T1055', name: 'Process Injection' },
      { id: 'T1053', name: 'Scheduled Task' },
      { id: 'T1078', name: 'Valid Accounts' },
    ],
  },
  {
    id:    'TA0005',
    name:  'Defense Evasion',
    short: 'DEF EVAS',
    techniques: [
      { id: 'T1548', name: 'Abuse Elevation Control' },
      { id: 'T1134', name: 'Access Token Manipulation' },
      { id: 'T1197', name: 'BITS Jobs' },
      { id: 'T1140', name: 'Deobfuscate/Decode Files' },
      { id: 'T1006', name: 'Direct Volume Access' },
      { id: 'T1484', name: 'Domain Policy Modification' },
      { id: 'T1562', name: 'Impair Defenses' },
      { id: 'T1070', name: 'Indicator Removal' },
      { id: 'T1202', name: 'Indirect Command Exec' },
      { id: 'T1036', name: 'Masquerading' },
      { id: 'T1218', name: 'Signed Binary Proxy Exec' },
      { id: 'T1497', name: 'Virtualization/Sandbox Evasion' },
    ],
  },
  {
    id:    'TA0006',
    name:  'Credential Access',
    short: 'CRED ACC',
    techniques: [
      { id: 'T1110', name: 'Brute Force' },
      { id: 'T1555', name: 'Credentials from Store' },
      { id: 'T1212', name: 'Exploitation for Cred Access' },
      { id: 'T1187', name: 'Forced Authentication' },
      { id: 'T1606', name: 'Forge Web Credentials' },
      { id: 'T1056', name: 'Input Capture' },
      { id: 'T1557', name: 'MitM' },
      { id: 'T1556', name: 'Modify Auth Process' },
      { id: 'T1040', name: 'Network Sniffing' },
      { id: 'T1003', name: 'OS Credential Dumping' },
    ],
  },
  {
    id:    'TA0007',
    name:  'Discovery',
    short: 'DISCOVER',
    techniques: [
      { id: 'T1087', name: 'Account Discovery' },
      { id: 'T1010', name: 'App Window Discovery' },
      { id: 'T1217', name: 'Browser Bookmark Discovery' },
      { id: 'T1580', name: 'Cloud Infrastructure Discovery' },
      { id: 'T1538', name: 'Cloud Service Dashboard' },
      { id: 'T1526', name: 'Cloud Service Discovery' },
      { id: 'T1482', name: 'Domain Trust Discovery' },
      { id: 'T1083', name: 'File and Directory Discovery' },
      { id: 'T1046', name: 'Network Service Discovery' },
      { id: 'T1135', name: 'Network Share Discovery' },
      { id: 'T1040', name: 'Network Sniffing' },
      { id: 'T1057', name: 'Process Discovery' },
      { id: 'T1012', name: 'Query Registry' },
      { id: 'T1018', name: 'Remote System Discovery' },
      { id: 'T1518', name: 'Software Discovery' },
      { id: 'T1082', name: 'System Info Discovery' },
    ],
  },
  {
    id:    'TA0008',
    name:  'Lateral Movement',
    short: 'LATERAL',
    techniques: [
      { id: 'T1210', name: 'Exploitation of Remote Svcs' },
      { id: 'T1534', name: 'Internal Spearphishing' },
      { id: 'T1570', name: 'Lateral Tool Transfer' },
      { id: 'T1563', name: 'Remote Service Session Hijack' },
      { id: 'T1021', name: 'Remote Services' },
      { id: 'T1091', name: 'Removable Media' },
      { id: 'T1072', name: 'Software Deployment Tools' },
      { id: 'T1550', name: 'Use Alternative Auth Material' },
    ],
  },
  {
    id:    'TA0009',
    name:  'Collection',
    short: 'COLLECT',
    techniques: [
      { id: 'T1557', name: 'Adversary-in-the-Middle' },
      { id: 'T1560', name: 'Archive Collected Data' },
      { id: 'T1123', name: 'Audio Capture' },
      { id: 'T1119', name: 'Automated Collection' },
      { id: 'T1115', name: 'Clipboard Data' },
      { id: 'T1530', name: 'Data from Cloud Storage' },
      { id: 'T1602', name: 'Data from Config Repos' },
      { id: 'T1213', name: 'Data from Info Repositories' },
      { id: 'T1005', name: 'Data from Local System' },
      { id: 'T1039', name: 'Data from Network Shared Drive' },
      { id: 'T1025', name: 'Data from Removable Media' },
      { id: 'T1074', name: 'Data Staged' },
      { id: 'T1114', name: 'Email Collection' },
      { id: 'T1056', name: 'Input Capture' },
      { id: 'T1113', name: 'Screen Capture' },
    ],
  },
  {
    id:    'TA0011',
    name:  'Command and Control',
    short: 'C2',
    techniques: [
      { id: 'T1071', name: 'App Layer Protocol' },
      { id: 'T1092', name: 'Communication via Removable Media' },
      { id: 'T1132', name: 'Data Encoding' },
      { id: 'T1001', name: 'Data Obfuscation' },
      { id: 'T1568', name: 'Dynamic Resolution' },
      { id: 'T1573', name: 'Encrypted Channel' },
      { id: 'T1008', name: 'Fallback Channels' },
      { id: 'T1105', name: 'Ingress Tool Transfer' },
      { id: 'T1104', name: 'Multi-Stage Channels' },
      { id: 'T1095', name: 'Non-App Layer Protocol' },
      { id: 'T1571', name: 'Non-Standard Port' },
      { id: 'T1572', name: 'Protocol Tunneling' },
      { id: 'T1090', name: 'Proxy' },
      { id: 'T1219', name: 'Remote Access Software' },
      { id: 'T1205', name: 'Traffic Signaling' },
      { id: 'T1102', name: 'Web Service' },
    ],
  },
  {
    id:    'TA0010',
    name:  'Exfiltration',
    short: 'EXFIL',
    techniques: [
      { id: 'T1020', name: 'Automated Exfiltration' },
      { id: 'T1030', name: 'Data Transfer Size Limits' },
      { id: 'T1048', name: 'Exfiltration Over Alt Protocol' },
      { id: 'T1041', name: 'Exfiltration Over C2 Channel' },
      { id: 'T1011', name: 'Exfiltration Over Other Comms' },
      { id: 'T1052', name: 'Exfiltration Over Physical Medium' },
      { id: 'T1567', name: 'Exfiltration Over Web Services' },
      { id: 'T1029', name: 'Scheduled Transfer' },
      { id: 'T1537', name: 'Transfer Data to Cloud Account' },
    ],
  },
  {
    id:    'TA0040',
    name:  'Impact',
    short: 'IMPACT',
    techniques: [
      { id: 'T1531', name: 'Account Access Removal' },
      { id: 'T1485', name: 'Data Destruction' },
      { id: 'T1486', name: 'Data Encrypted for Impact' },
      { id: 'T1565', name: 'Data Manipulation' },
      { id: 'T1491', name: 'Defacement' },
      { id: 'T1561', name: 'Disk Wipe' },
      { id: 'T1499', name: 'Endpoint Denial of Service' },
      { id: 'T1495', name: 'Firmware Corruption' },
      { id: 'T1490', name: 'Inhibit System Recovery' },
      { id: 'T1498', name: 'Network Denial of Service' },
      { id: 'T1496', name: 'Resource Hijacking' },
      { id: 'T1489', name: 'Service Stop' },
      { id: 'T1529', name: 'System Shutdown/Reboot' },
    ],
  },
];

/* ─────────────────────────────────────────────────────────────────────────
   Heatmap renderer class
   ───────────────────────────────────────────────────────────────────────── */

class MitreHeatmap {
  constructor(canvasId, options = {}) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) {
      console.error(`[MITRE] Canvas not found: ${canvasId}`);
      return;
    }
    this.ctx = this.canvas.getContext('2d');

    // Options
    this.cellW     = options.cellWidth    || 80;
    this.cellH     = options.cellHeight   || 24;
    this.headerH   = options.headerHeight || 40;
    this.padding   = options.padding      || 8;
    this.fontSize  = options.fontSize     || 9;

    // Colours
    this.colorEmpty    = '#1e3a5f';
    this.colorHover    = '#2a5080';
    this.colorBg       = '#0f1629';
    this.colorHeader   = '#0d1930';
    this.colorText     = '#c8d8e8';
    this.colorTextDim  = '#7a9ab8';
    this.colorBorder   = '#162040';
    this.colorCyan     = '#00d4ff';

    // State
    this.detectedTechniques = {};  // { 'T1071': { confidence: 85, source: 'beaconing' }, ... }
    this.hoveredCell = null;
    this.selectedTactic = null;

    // Tooltip element
    this.tooltip = this._createTooltip();

    // Layout computed on render
    this._layout = [];

    this._bindEvents();
  }

  /* ── Tooltip DOM ── */

  _createTooltip() {
    let el = document.getElementById('mitre-tooltip');
    if (!el) {
      el = document.createElement('div');
      el.id        = 'mitre-tooltip';
      el.className = 'mitre-tooltip';
      el.setAttribute('aria-live', 'polite');
      document.body.appendChild(el);
    }
    return el;
  }

  _showTooltip(x, y, technique, tactic, confidence) {
    const desc = technique.description || `Detected via ${technique.source || 'automated analysis'}.`;
    this.tooltip.innerHTML = `
      <div class="mitre-tooltip__id">${technique.id}</div>
      <div class="mitre-tooltip__name">${technique.name}</div>
      <div class="mitre-tooltip__tactic">${tactic.name} (${tactic.id})</div>
      ${confidence ? `<div class="mitre-tooltip__desc">Confidence: <strong style="color:#00d4ff">${confidence.toFixed(1)}%</strong></div>` : ''}
      <div class="mitre-tooltip__desc">${desc}</div>
    `;
    // Position tooltip, keep within viewport
    const pad   = 12;
    const tw    = 280;
    const th    = 140;
    let tx = x + pad;
    let ty = y + pad;
    if (tx + tw > window.innerWidth)  tx = x - tw - pad;
    if (ty + th > window.innerHeight) ty = y - th - pad;

    this.tooltip.style.left    = tx + 'px';
    this.tooltip.style.top     = ty + 'px';
    this.tooltip.classList.add('visible');
  }

  _hideTooltip() {
    this.tooltip.classList.remove('visible');
  }

  /* ── Colour interpolation ── */

  _confidenceToColor(confidence) {
    // 0 → #1e3a5f, 100 → #00d4ff with intermediate steps
    const t = Math.max(0, Math.min(1, confidence / 100));
    if (t < 0.3)  return this._lerp('#1e3a5f', '#1a5580', t / 0.3);
    if (t < 0.6)  return this._lerp('#1a5580', '#00a8cc', (t - 0.3) / 0.3);
    return this._lerp('#00a8cc', '#00d4ff', (t - 0.6) / 0.4);
  }

  _lerp(hexA, hexB, t) {
    const a = this._hexToRgb(hexA);
    const b = this._hexToRgb(hexB);
    const r = Math.round(a.r + (b.r - a.r) * t);
    const g = Math.round(a.g + (b.g - a.g) * t);
    const bl = Math.round(a.b + (b.b - a.b) * t);
    return `rgb(${r},${g},${bl})`;
  }

  _hexToRgb(hex) {
    const clean = hex.replace('#', '');
    return {
      r: parseInt(clean.substring(0, 2), 16),
      g: parseInt(clean.substring(2, 4), 16),
      b: parseInt(clean.substring(4, 6), 16),
    };
  }

  /* ── Layout computation ── */

  _computeLayout() {
    this._layout = [];
    const numTactics = MITRE_TACTICS.length;
    const totalW = numTactics * (this.cellW + 1) + this.padding * 2;

    // Resize canvas
    const maxTechs = Math.max(...MITRE_TACTICS.map(t => t.techniques.length));
    const totalH = this.headerH + maxTechs * (this.cellH + 1) + this.padding * 2;

    this.canvas.width  = totalW;
    this.canvas.height = totalH;
    this.canvas.style.width  = '100%';
    this.canvas.style.maxWidth = totalW + 'px';

    MITRE_TACTICS.forEach((tactic, ti) => {
      const x = this.padding + ti * (this.cellW + 1);
      tactic.techniques.forEach((tech, techIdx) => {
        const y = this.headerH + techIdx * (this.cellH + 1);
        this._layout.push({ tactic, tech, x, y, w: this.cellW, h: this.cellH, ti, techIdx });
      });
    });
  }

  /* ── Drawing ── */

  render(detectedTechniques = {}) {
    this.detectedTechniques = detectedTechniques;
    this._computeLayout();
    this._draw();
  }

  _draw() {
    const ctx = this.ctx;
    const W = this.canvas.width;
    const H = this.canvas.height;

    // Background
    ctx.fillStyle = this.colorBg;
    ctx.fillRect(0, 0, W, H);

    // Tactic headers
    MITRE_TACTICS.forEach((tactic, ti) => {
      const x = this.padding + ti * (this.cellW + 1);
      ctx.fillStyle = this.colorHeader;
      ctx.fillRect(x, 0, this.cellW, this.headerH);

      // Header border bottom
      ctx.strokeStyle = this.colorBorder;
      ctx.lineWidth   = 1;
      ctx.strokeRect(x + 0.5, 0.5, this.cellW - 1, this.headerH - 1);

      // Tactic ID
      ctx.font      = `bold 8px 'JetBrains Mono', monospace`;
      ctx.fillStyle = this.colorCyan;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.fillText(tactic.id, x + this.cellW / 2, 6);

      // Tactic name (shortened)
      ctx.font      = `8px 'Inter', sans-serif`;
      ctx.fillStyle = this.colorText;
      this._drawWrappedText(tactic.short, x + this.cellW / 2, 18, this.cellW - 4, 10);
    });

    // Technique cells
    this._layout.forEach(cell => {
      const detected = this.detectedTechniques[cell.tech.id];
      const isHovered = this.hoveredCell && this.hoveredCell.tech.id === cell.tech.id;

      let bgColor = this.colorEmpty;
      if (detected) {
        bgColor = this._confidenceToColor(detected.confidence || 70);
      } else if (isHovered) {
        bgColor = this.colorHover;
      }

      // Cell background
      ctx.fillStyle = bgColor;
      ctx.fillRect(cell.x, cell.y, cell.w, cell.h);

      // Cell border
      ctx.strokeStyle = this.colorBorder;
      ctx.lineWidth   = 0.5;
      ctx.strokeRect(cell.x + 0.5, cell.y + 0.5, cell.w - 1, cell.h - 1);

      // Technique text
      ctx.font      = `${this.fontSize}px 'JetBrains Mono', monospace`;
      ctx.fillStyle = detected
        ? (detected.confidence >= 70 ? '#0a0e1a' : this.colorText)
        : this.colorTextDim;
      ctx.textAlign    = 'left';
      ctx.textBaseline = 'middle';
      ctx.fillText(
        this._truncate(cell.tech.id + ' ' + cell.tech.name, Math.floor(cell.w / 5.5)),
        cell.x + 4,
        cell.y + cell.h / 2,
      );

      // Confidence badge for detected
      if (detected && detected.confidence) {
        const conf  = Math.round(detected.confidence);
        const badge = conf + '%';
        ctx.font      = `bold 8px 'JetBrains Mono', monospace`;
        ctx.fillStyle = '#0a0e1a';
        ctx.textAlign = 'right';
        ctx.fillText(badge, cell.x + cell.w - 3, cell.y + cell.h / 2);
      }
    });

    // Legend
    this._drawLegend();
  }

  _drawLegend() {
    const ctx = this.ctx;
    const y   = this.canvas.height - 0; // below all content
    // Already drawn via CSS legend outside canvas
  }

  _drawWrappedText(text, cx, y, maxW, lineH) {
    const ctx    = this.ctx;
    const words  = text.split(' ');
    let line     = '';
    let lineY    = y;
    for (const word of words) {
      const test = line ? line + ' ' + word : word;
      const measured = ctx.measureText(test).width;
      if (measured > maxW - 4 && line) {
        ctx.fillText(line, cx, lineY);
        lineY += lineH;
        line = word;
      } else {
        line = test;
      }
    }
    if (line) ctx.fillText(line, cx, lineY);
  }

  _truncate(str, maxChars) {
    return str.length > maxChars ? str.slice(0, maxChars - 1) + '…' : str;
  }

  /* ── Hit testing ── */

  _hitTest(mouseX, mouseY) {
    const rect  = this.canvas.getBoundingClientRect();
    const scaleX = this.canvas.width  / rect.width;
    const scaleY = this.canvas.height / rect.height;
    const cx     = (mouseX - rect.left) * scaleX;
    const cy     = (mouseY - rect.top)  * scaleY;

    for (const cell of this._layout) {
      if (cx >= cell.x && cx <= cell.x + cell.w &&
          cy >= cell.y && cy <= cell.y + cell.h) {
        return cell;
      }
    }
    return null;
  }

  /* ── Event binding ── */

  _bindEvents() {
    if (!this.canvas) return;

    this.canvas.addEventListener('mousemove', e => {
      const cell = this._hitTest(e.clientX, e.clientY);
      if (cell !== this.hoveredCell) {
        this.hoveredCell = cell;
        this._draw();
      }
      if (cell) {
        const detected = this.detectedTechniques[cell.tech.id];
        this._showTooltip(e.clientX, e.clientY, {
          ...cell.tech,
          source: detected ? detected.source : null,
        }, cell.tactic, detected ? detected.confidence : null);
        this.canvas.style.cursor = 'pointer';
      } else {
        this._hideTooltip();
        this.canvas.style.cursor = 'crosshair';
      }
    });

    this.canvas.addEventListener('mouseleave', () => {
      this.hoveredCell = null;
      this._hideTooltip();
      this._draw();
    });

    this.canvas.addEventListener('click', e => {
      const cell = this._hitTest(e.clientX, e.clientY);
      if (!cell) return;

      // Dispatch custom event for sidebar update
      const event = new CustomEvent('mitre:techniqueSelected', {
        detail: {
          techniqueId:   cell.tech.id,
          techniqueName: cell.tech.name,
          tacticId:      cell.tactic.id,
          tacticName:    cell.tactic.name,
          detected:      !!this.detectedTechniques[cell.tech.id],
          confidence:    this.detectedTechniques[cell.tech.id]?.confidence || 0,
        },
        bubbles: true,
      });
      this.canvas.dispatchEvent(event);
    });
  }

  /* ── Public methods ── */

  /**
   * Load detected techniques from a scan result's mitre_coverage object.
   * @param {Object} mitreCoverage - The mitre_coverage dict from ScanResult.to_dict()
   */
  loadFromScanResult(mitreCoverage) {
    const detected = {};
    if (!mitreCoverage) {
      this.render(detected);
      return;
    }

    // Format: techniques array from mitre_mapper.generate_navigator_layer()
    const techniques = mitreCoverage.techniques || [];
    techniques.forEach(t => {
      const techId = t.technique_id || t.techniqueID || '';
      if (techId) {
        detected[techId] = {
          confidence: t.confidence || t.score || 70,
          source:     t.source || t.comment || 'BlueSentinel',
        };
      }
    });

    // Also process flat dict format { "T1071": 85, ... }
    Object.entries(mitreCoverage).forEach(([k, v]) => {
      if (k.startsWith('T') && typeof v === 'number') {
        detected[k] = { confidence: v, source: 'BlueSentinel' };
      }
    });

    this.render(detected);
  }

  /**
   * Highlight a specific tactic column.
   * @param {string} tacticId - e.g. "TA0011"
   */
  highlightTactic(tacticId) {
    this.selectedTactic = tacticId;
    this._draw();
  }

  /**
   * Export the current heatmap as a PNG file download.
   */
  exportPng() {
    if (!this.canvas) return;
    // Draw title bar first
    const ctx  = this.ctx;
    const origH = this.canvas.height;
    const titleH = 36;

    this.canvas.height = origH + titleH;

    // Re-draw background for title area
    ctx.fillStyle = '#060b14';
    ctx.fillRect(0, 0, this.canvas.width, titleH);

    ctx.font      = 'bold 14px "Inter", sans-serif';
    ctx.fillStyle = '#00d4ff';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';
    ctx.fillText('BlueSentinel v2.0 — MITRE ATT&CK Coverage', 12, titleH / 2);

    ctx.font      = '11px "JetBrains Mono", monospace';
    ctx.fillStyle = '#7a9ab8';
    ctx.textAlign = 'right';
    ctx.fillText(new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC', this.canvas.width - 12, titleH / 2);

    // Shift existing content down by redrawing (translate approach)
    const imageData = ctx.getImageData(0, titleH, this.canvas.width, origH);
    this._draw();
    ctx.putImageData(imageData, 0, titleH);

    // Export
    const link  = document.createElement('a');
    link.download = `bluesentinel_mitre_${Date.now()}.png`;
    link.href     = this.canvas.toDataURL('image/png', 1.0);
    link.click();

    // Restore
    this.canvas.height = origH;
    this._draw();
  }

  /**
   * Get a summary of detected tactics for the sidebar.
   * @returns {Array} - Array of { tacticId, tacticName, count, techniques }
   */
  getDetectedTactics() {
    const result = [];
    MITRE_TACTICS.forEach(tactic => {
      const detectedTechs = tactic.techniques.filter(
        t => this.detectedTechniques[t.id]
      );
      if (detectedTechs.length > 0) {
        result.push({
          tacticId:   tactic.id,
          tacticName: tactic.name,
          count:      detectedTechs.length,
          total:      tactic.techniques.length,
          techniques: detectedTechs.map(t => ({
            id:         t.id,
            name:       t.name,
            confidence: this.detectedTechniques[t.id].confidence,
            source:     this.detectedTechniques[t.id].source,
          })),
        });
      }
    });
    return result;
  }
}

/* ─────────────────────────────────────────────────────────────────────────
   Factory / export
   ───────────────────────────────────────────────────────────────────────── */

window.MitreHeatmap  = MitreHeatmap;
window.MITRE_TACTICS = MITRE_TACTICS;

/**
 * Convenience initialiser for inline usage.
 * @param {string} canvasId      - Canvas element ID
 * @param {Object} mitreCoverage - From /api/mitre-coverage
 * @param {Object} [options]     - Optional cell size overrides
 * @returns {MitreHeatmap}
 */
window.initMitreHeatmap = function(canvasId, mitreCoverage, options) {
  const heatmap = new MitreHeatmap(canvasId, options || {});
  heatmap.loadFromScanResult(mitreCoverage || {});
  return heatmap;
};
