/**
 * charts.js — BlueSentinel v2.0 Chart.js definitions
 * All dashboard chart initialisation and live-update functions.
 * Requires Chart.js 4.x (loaded via CDN in base.html).
 */

'use strict';

/* ── Shared palette (mirrors CSS custom properties) ────────────────────── */
const BS_COLORS = {
  cyan:     '#00d4ff',
  cyanDim:  '#009bbf',
  cyanFill: 'rgba(0,212,255,0.12)',
  danger:   '#ff3b5c',
  warning:  '#ffb800',
  success:  '#00ff88',
  info:     '#4da6ff',
  amber:    '#ffb84d',
  purple:   '#a855f7',
  text:     '#c8d8e8',
  textMuted:'#7a9ab8',
  gridLine: 'rgba(30,58,95,0.6)',
  bg:       '#0f1629',
};

const SEVERITY_COLORS = {
  Critical: BS_COLORS.danger,
  High:     '#ff7c3a',
  Medium:   BS_COLORS.warning,
  Low:      BS_COLORS.info,
};

/* ── Global Chart.js defaults ───────────────────────────────────────────── */
Chart.defaults.color            = BS_COLORS.textMuted;
Chart.defaults.font.family      = "'JetBrains Mono', monospace";
Chart.defaults.font.size        = 11;
Chart.defaults.borderColor      = BS_COLORS.gridLine;
Chart.defaults.plugins.legend.labels.boxWidth  = 10;
Chart.defaults.plugins.legend.labels.padding   = 16;
Chart.defaults.plugins.tooltip.backgroundColor = '#0f1629';
Chart.defaults.plugins.tooltip.borderColor     = '#1e3a5f';
Chart.defaults.plugins.tooltip.borderWidth     = 1;
Chart.defaults.plugins.tooltip.titleColor      = '#c8d8e8';
Chart.defaults.plugins.tooltip.bodyColor       = '#7a9ab8';
Chart.defaults.plugins.tooltip.padding         = 10;
Chart.defaults.plugins.tooltip.cornerRadius    = 6;
Chart.defaults.plugins.tooltip.displayColors   = true;


/* ─────────────────────────────────────────────────────────────────────────
   1. Risk Gauge — animated doughnut with colour zones
   ───────────────────────────────────────────────────────────────────────── */

/**
 * Initialise the risk gauge doughnut chart.
 * @param {string} canvasId  - Canvas element ID
 * @param {number} score     - Risk score 0–100
 * @returns {Chart}
 */
function initRiskGauge(canvasId, score) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) { console.warn(`[Charts] Canvas not found: ${canvasId}`); return null; }

  const safeScore = Math.max(0, Math.min(100, score || 0));
  const remainder = 100 - safeScore;

  function scoreColor(s) {
    if (s >= 86) return BS_COLORS.danger;
    if (s >= 61) return '#ff7c3a';
    if (s >= 31) return BS_COLORS.warning;
    if (s > 0)   return BS_COLORS.info;
    return BS_COLORS.success;
  }

  const color = scoreColor(safeScore);

  const chart = new Chart(canvas, {
    type: 'doughnut',
    data: {
      datasets: [{
        data:            [safeScore, remainder],
        backgroundColor: [color, 'rgba(30,58,95,0.35)'],
        borderColor:     ['transparent', 'transparent'],
        borderWidth:     0,
        hoverBackgroundColor: [color, 'rgba(30,58,95,0.5)'],
      }],
    },
    options: {
      cutout: '78%',
      rotation: -90,
      circumference: 180,
      responsive: true,
      maintainAspectRatio: true,
      animation: {
        animateRotate: true,
        duration:      1200,
        easing:        'easeInOutQuart',
      },
      plugins: {
        legend:  { display: false },
        tooltip: { enabled: false },
      },
    },
    plugins: [{
      id: 'gaugeNeedle',
      afterDraw(chart) {
        const { ctx, chartArea } = chart;
        if (!chartArea) return;
        const cx = (chartArea.left + chartArea.right)  / 2;
        const cy = (chartArea.top  + chartArea.bottom) / 2 + (chartArea.bottom - chartArea.top) * 0.12;
        const r  = (Math.min(chartArea.width, chartArea.height) / 2) * 0.65;

        // Score text in the centre
        ctx.save();
        ctx.font        = `bold 2rem 'JetBrains Mono', monospace`;
        ctx.fillStyle   = '#e8f4ff';
        ctx.textAlign   = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(chart.data.datasets[0].data[0], cx, cy + 8);

        ctx.font      = `0.6rem 'JetBrains Mono', monospace`;
        ctx.fillStyle = BS_COLORS.textMuted;
        ctx.fillText('/100', cx, cy + 26);
        ctx.restore();
      },
    }],
  });

  // Store score for update function
  chart._bsScore = safeScore;
  return chart;
}

/**
 * Animate the gauge to a new score value.
 * @param {Chart}  chart    - Gauge chart instance
 * @param {number} newScore - New risk score 0–100
 */
function updateRiskGauge(chart, newScore) {
  if (!chart) return;
  const safeScore = Math.max(0, Math.min(100, newScore || 0));
  const remainder = 100 - safeScore;

  function scoreColor(s) {
    if (s >= 86) return BS_COLORS.danger;
    if (s >= 61) return '#ff7c3a';
    if (s >= 31) return BS_COLORS.warning;
    if (s > 0)   return BS_COLORS.info;
    return BS_COLORS.success;
  }

  const color = scoreColor(safeScore);
  chart.data.datasets[0].data            = [safeScore, remainder];
  chart.data.datasets[0].backgroundColor = [color, 'rgba(30,58,95,0.35)'];
  chart._bsScore = safeScore;
  chart.update('active');
}


/* ─────────────────────────────────────────────────────────────────────────
   2. Threat Timeline — dual-line (risk score + alert count)
   ───────────────────────────────────────────────────────────────────────── */

/**
 * Initialise the threat timeline chart.
 * @param {string} canvasId     - Canvas element ID
 * @param {Array}  timelineData - Array of { time, risk_score, alert_count }
 * @returns {Chart}
 */
function initThreatTimeline(canvasId, timelineData) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) { console.warn(`[Charts] Canvas not found: ${canvasId}`); return null; }

  const data = Array.isArray(timelineData) ? timelineData : [];
  const labels      = data.map(d => d.time || '');
  const riskScores  = data.map(d => d.risk_score || 0);
  const alertCounts = data.map(d => d.alert_count || 0);

  // Cyan gradient fill for risk score
  const ctxEl = canvas.getContext('2d');
  const gradRisk = ctxEl.createLinearGradient(0, 0, 0, canvas.offsetHeight || 200);
  gradRisk.addColorStop(0,   'rgba(0,212,255,0.22)');
  gradRisk.addColorStop(0.7, 'rgba(0,212,255,0.04)');
  gradRisk.addColorStop(1,   'rgba(0,212,255,0)');

  const chart = new Chart(canvas, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label:            'Risk Score',
          data:             riskScores,
          borderColor:      BS_COLORS.cyan,
          borderWidth:      2,
          backgroundColor:  gradRisk,
          tension:          0.4,
          fill:             true,
          pointRadius:      0,
          pointHoverRadius: 4,
          pointHoverBackgroundColor: BS_COLORS.cyan,
          yAxisID: 'yScore',
        },
        {
          label:            'Alert Count',
          data:             alertCounts,
          borderColor:      BS_COLORS.amber,
          borderWidth:      1.5,
          borderDash:       [4, 4],
          backgroundColor:  'transparent',
          tension:          0.3,
          fill:             false,
          pointRadius:      0,
          pointHoverRadius: 3,
          pointHoverBackgroundColor: BS_COLORS.amber,
          yAxisID: 'yCount',
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      animation:   { duration: 400, easing: 'easeInOutQuad' },
      plugins: {
        legend: {
          position: 'top',
          align:    'end',
          labels:   { pointStyle: 'line', usePointStyle: true },
        },
      },
      scales: {
        x: {
          grid:  { color: BS_COLORS.gridLine },
          ticks: {
            color:   BS_COLORS.textMuted,
            maxRotation: 0,
            maxTicksLimit: 12,
          },
        },
        yScore: {
          type:     'linear',
          position: 'left',
          min:      0,
          max:      100,
          grid:     { color: BS_COLORS.gridLine },
          ticks:    { color: BS_COLORS.textMuted },
          title:    { display: true, text: 'Risk', color: BS_COLORS.cyan, font: { size: 10 } },
        },
        yCount: {
          type:     'linear',
          position: 'right',
          min:      0,
          grid:     { display: false },
          ticks:    { color: BS_COLORS.amber },
          title:    { display: true, text: 'Alerts', color: BS_COLORS.amber, font: { size: 10 } },
        },
      },
    },
  });

  return chart;
}

/**
 * Add a new data point to the timeline and remove the oldest.
 * @param {Chart}  chart    - Timeline chart instance
 * @param {Object} newPoint - { time, risk_score, alert_count }
 */
function updateTimeline(chart, newPoint) {
  if (!chart) return;
  const MAX_POINTS = 120;

  chart.data.labels.push(newPoint.time || new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' }));
  chart.data.datasets[0].data.push(newPoint.risk_score  || 0);
  chart.data.datasets[1].data.push(newPoint.alert_count || 0);

  if (chart.data.labels.length > MAX_POINTS) {
    chart.data.labels.shift();
    chart.data.datasets[0].data.shift();
    chart.data.datasets[1].data.shift();
  }

  chart.update('none'); // skip animation for smooth streaming
}


/* ─────────────────────────────────────────────────────────────────────────
   3. Threat Donut — category breakdown
   ───────────────────────────────────────────────────────────────────────── */

/**
 * Initialise the threat category donut chart.
 * @param {string} canvasId   - Canvas element ID
 * @param {Object} categories - { "YARA Match": 4, "Beaconing": 2, ... }
 * @returns {Chart}
 */
function initThreatDonut(canvasId, categories) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) { console.warn(`[Charts] Canvas not found: ${canvasId}`); return null; }

  const palette = [
    BS_COLORS.danger, '#ff7c3a', BS_COLORS.warning, BS_COLORS.info,
    BS_COLORS.cyan, BS_COLORS.success, BS_COLORS.purple, '#e879f9',
  ];

  const labels = Object.keys(categories || {});
  const values = Object.values(categories || {});
  const colors = labels.map((_, i) => palette[i % palette.length]);

  const chart = new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data:            values,
        backgroundColor: colors.map(c => c + 'cc'),
        borderColor:     colors,
        borderWidth:     1.5,
        hoverBorderWidth: 2,
        hoverOffset:     6,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      cutout: '65%',
      animation: { animateRotate: true, duration: 800 },
      plugins: {
        legend: {
          position:  'right',
          align:     'center',
          labels: {
            padding:   10,
            boxWidth:  10,
            font:      { size: 10 },
          },
        },
        tooltip: {
          callbacks: {
            label(ctx) {
              const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
              const pct   = total ? ((ctx.parsed / total) * 100).toFixed(1) : 0;
              return ` ${ctx.label}: ${ctx.parsed} (${pct}%)`;
            },
          },
        },
      },
    },
  });

  return chart;
}


/* ─────────────────────────────────────────────────────────────────────────
   4. Beaconing Chart — horizontal bar chart for top 8 suspicious IPs
   ───────────────────────────────────────────────────────────────────────── */

/**
 * Initialise the beaconing horizontal bar chart.
 * @param {string} canvasId    - Canvas element ID
 * @param {Array}  beaconData  - Array of { dst_ip, confidence, connection_count, mean_iat_seconds }
 * @returns {Chart}
 */
function initBeaconingChart(canvasId, beaconData) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) { console.warn(`[Charts] Canvas not found: ${canvasId}`); return null; }

  const data = Array.isArray(beaconData) ? beaconData.slice(0, 8) : [];
  const labels      = data.map(d => `${d.dst_ip || 'Unknown'}:${d.dst_port || '?'}`);
  const confidences = data.map(d => d.confidence || 0);
  const connCounts  = data.map(d => d.connection_count || 0);

  // Color by confidence level
  const barColors = confidences.map(c => {
    if (c >= 85) return BS_COLORS.danger;
    if (c >= 70) return '#ff7c3a';
    if (c >= 50) return BS_COLORS.warning;
    return BS_COLORS.info;
  });

  const chart = new Chart(canvas, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label:            'Confidence %',
        data:             confidences,
        backgroundColor:  barColors.map(c => c + 'bb'),
        borderColor:      barColors,
        borderWidth:      1,
        borderRadius:     3,
        borderSkipped:    false,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 700, easing: 'easeOutQuart' },
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            title(ctx)    { return ctx[0].label; },
            afterBody(ctx) {
              const idx = ctx[0].dataIndex;
              return [`Connections: ${connCounts[idx]}`, `IAT: ${(data[idx].mean_iat_seconds || 0).toFixed(1)}s`];
            },
          },
        },
      },
      scales: {
        x: {
          min:   0,
          max:   100,
          grid:  { color: BS_COLORS.gridLine },
          ticks: { color: BS_COLORS.textMuted, callback: v => v + '%' },
        },
        y: {
          grid:  { display: false },
          ticks: {
            color: BS_COLORS.text,
            font:  { family: "'JetBrains Mono', monospace", size: 10 },
          },
        },
      },
    },
  });

  return chart;
}


/* ─────────────────────────────────────────────────────────────────────────
   5. Sparklines — 4 mini cards for top suspicious IPs
   ───────────────────────────────────────────────────────────────────────── */

/**
 * Render 4 sparkline mini-cards into a container.
 * @param {string} containerId - ID of container element
 * @param {Array}  ipData      - Array of { ip, connection_count, confidence, time_series: [n,...] }
 * @returns {Array<Chart>}     - Array of Chart instances
 */
function initSparklines(containerId, ipData) {
  const container = document.getElementById(containerId);
  if (!container) { console.warn(`[Charts] Container not found: ${containerId}`); return []; }

  const data   = Array.isArray(ipData) ? ipData.slice(0, 4) : [];
  const charts = [];

  // Clear existing content
  container.innerHTML = '';

  data.forEach((entry, idx) => {
    const cardEl = document.createElement('div');
    cardEl.className = 'sparkline-card';

    const ip         = entry.dst_ip || entry.ip || `Unknown IP ${idx + 1}`;
    const confidence = (entry.confidence || 0).toFixed(1);
    const connCount  = entry.connection_count || 0;
    const iat        = (entry.mean_iat_seconds || 0).toFixed(1);
    const severity   = entry.confidence >= 85 ? 'text-danger' : entry.confidence >= 70 ? 'text-warn' : 'text-cyan';

    const canvasId = `sparkline-canvas-${idx}`;
    cardEl.innerHTML = `
      <div class="sparkline-card__ip ${severity}">${ip}</div>
      <div class="sparkline-card__meta">
        <span>Confidence: <strong>${confidence}%</strong></span>
        <span>${connCount} conns</span>
      </div>
      <div class="sparkline-card__meta">
        <span>Avg IAT: ${iat}s</span>
        <span>${entry.dst_port ? 'Port ' + entry.dst_port : ''}</span>
      </div>
      <canvas id="${canvasId}" class="sparkline-card__canvas" width="260" height="55"></canvas>
    `;
    container.appendChild(cardEl);

    // Build synthetic or real time series
    const series = Array.isArray(entry.time_series) && entry.time_series.length >= 3
      ? entry.time_series
      : _generateSyntheticBeaconSeries(connCount, entry.mean_iat_seconds || 60, entry.jitter || 0.05);

    const sparkCanvas = document.getElementById(canvasId);
    if (!sparkCanvas) return;

    const sparkCtx = sparkCanvas.getContext('2d');
    const grad = sparkCtx.createLinearGradient(0, 0, 0, 48);
    const baseColor = entry.confidence >= 85 ? BS_COLORS.danger : entry.confidence >= 70 ? '#ff7c3a' : BS_COLORS.cyan;
    grad.addColorStop(0,   baseColor + '44');
    grad.addColorStop(1,   baseColor + '00');

    const sparkChart = new Chart(sparkCanvas, {
      type: 'line',
      data: {
        labels:   series.map((_, i) => i),
        datasets: [{
          data:            series,
          borderColor:     baseColor,
          borderWidth:     1.5,
          backgroundColor: grad,
          fill:            true,
          tension:         0.4,
          pointRadius:     0,
        }],
      },
      options: {
        responsive: false,
        maintainAspectRatio: false,
        animation:  { duration: 0 },
        plugins:    { legend: { display: false }, tooltip: { enabled: false } },
        scales:     { x: { display: false }, y: { display: false } },
      },
    });

    charts.push(sparkChart);
  });

  return charts;
}

/**
 * Internal: generate a synthetic beacon-like time-series for sparklines.
 */
function _generateSyntheticBeaconSeries(count, iatSeconds, jitter) {
  const n = Math.min(Math.max(count || 10, 5), 40);
  const series = [];
  for (let i = 0; i < n; i++) {
    const base = iatSeconds * (1 + (Math.random() - 0.5) * jitter * 2);
    series.push(Math.max(0, base + (Math.random() - 0.5) * iatSeconds * 0.05));
  }
  return series;
}


/* ─────────────────────────────────────────────────────────────────────────
   Exports (for modules) — also attached to window for inline script access
   ───────────────────────────────────────────────────────────────────────── */

window.BS_Charts = {
  initRiskGauge,
  initThreatTimeline,
  initThreatDonut,
  initBeaconingChart,
  initSparklines,
  updateRiskGauge,
  updateTimeline,
};
