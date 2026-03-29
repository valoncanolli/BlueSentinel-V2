/**
 * realtime.js — BlueSentinel v2.0 Socket.IO real-time event handlers
 * Connects to the Flask-SocketIO server, handles all live-update events,
 * drives toast notifications, gauge animation, progress bar and chart refresh.
 */

'use strict';

/* ── Reconnection config ───────────────────────────────────────────────── */
const RECONNECT_DELAY_MIN  = 1000;   // ms
const RECONNECT_DELAY_MAX  = 30000;  // ms
const RECONNECT_MAX_TRIES  = 10;

/* ── Module state ──────────────────────────────────────────────────────── */
let _socket        = null;
let _riskGauge     = null;   // Chart instance (injected via BS_Realtime.setGauge)
let _timeline      = null;   // Chart instance (injected via BS_Realtime.setTimeline)
let _reconnectTries = 0;
let _scanActive    = false;
let _alertCounter  = 0;
let _critCounter   = 0;
let _highCounter   = 0;

/* ── Toast management ──────────────────────────────────────────────────── */

function _ensureToastContainer() {
  let el = document.getElementById('toast-container');
  if (!el) {
    el = document.createElement('div');
    el.id = 'toast-container';
    el.className = 'toast-container';
    document.body.appendChild(el);
  }
  return el;
}

function _showToast(severity, title, message, duration = 5000) {
  const container = _ensureToastContainer();

  const severityIcon = {
    Critical: '🔴',
    High:     '🟠',
    Medium:   '🟡',
    Low:      '🔵',
    Info:     'ℹ',
    Success:  '✅',
  }[severity] || '⚠';

  const toast = document.createElement('div');
  toast.className = `toast toast--${severity.toLowerCase()}`;
  toast.innerHTML = `
    <span class="toast__icon">${severityIcon}</span>
    <div class="toast__body">
      <div class="toast__title">${_esc(title)}</div>
      <div class="toast__msg">${_esc(message)}</div>
      <div class="toast__time">${new Date().toLocaleTimeString()}</div>
    </div>
  `;

  toast.addEventListener('click', () => toast.remove());
  container.appendChild(toast);

  // Auto-remove after duration
  setTimeout(() => {
    toast.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
    toast.style.opacity    = '0';
    toast.style.transform  = 'translateX(110%)';
    setTimeout(() => toast.remove(), 400);
  }, duration);
}

function _esc(str) {
  const d = document.createElement('div');
  d.textContent = String(str || '');
  return d.innerHTML;
}

/* ── Counter DOM helpers ───────────────────────────────────────────────── */

function _updateCounter(id, value, animate = true) {
  const el = document.getElementById(id);
  if (!el) return;
  const prev = parseInt(el.textContent, 10) || 0;
  el.textContent = value;
  if (animate && value !== prev) {
    el.classList.remove('kpi-update');
    void el.offsetWidth; // Force reflow
    el.classList.add('kpi-update');
    setTimeout(() => el.classList.remove('kpi-update'), 600);
  }
}

function _refreshCounters() {
  fetch('/api/metrics', { credentials: 'same-origin' })
    .then(r => r.json())
    .then(d => {
      _updateCounter('kpi-score',    d.risk_score   ?? 0);
      _updateCounter('kpi-critical', d.critical     ?? 0);
      _updateCounter('kpi-high',     d.high         ?? 0);
      _updateCounter('kpi-total',    d.total_alerts ?? 0);
      _updateCounter('kpi-yara',     d.yara_matches ?? 0);
      _updateCounter('kpi-beacon',   d.beaconing    ?? 0);
      _updateCounter('kpi-ioc',      d.ioc_matches  ?? 0);

      const aiEl = document.getElementById('kpi-ai-provider');
      if (aiEl && d.ai_provider) aiEl.textContent = d.ai_provider.toUpperCase();
    })
    .catch(err => console.warn('[RT] Failed to refresh counters:', err));
}

/* ── Progress bar helpers ──────────────────────────────────────────────── */

function _setProgress(percent, phase, module, currentFile) {
  const bar    = document.getElementById('scan-progress-bar');
  const label  = document.getElementById('scan-progress-phase');
  const modEl  = document.getElementById('scan-progress-module');
  const panel  = document.getElementById('scan-progress-panel');
  const pctEl  = document.getElementById('scan-progress-pct');
  const fileEl = document.getElementById('scan-progress-file');

  const pct = Math.max(0, Math.min(100, percent));
  if (bar) {
    bar.style.width = pct + '%';
    bar.style.background = pct >= 100 ? '#00ff88' : '#00d4ff';
  }
  if (pctEl)  pctEl.textContent  = Math.round(pct) + '%';
  if (label && phase)  label.textContent  = phase;
  if (modEl && module) modEl.textContent  = module;

  // File label — shown only during file-scanning modules
  if (fileEl) {
    if (currentFile) {
      fileEl.textContent = 'File: ' + currentFile;
      fileEl.style.display = 'block';
    } else {
      fileEl.style.display = 'none';
    }
  }

  if (panel) {
    if (pct >= 100) {
      setTimeout(() => panel.classList.remove('active'), 1500);
    } else {
      panel.classList.add('active');
    }
  }
}

/* ── News ticker helpers ───────────────────────────────────────────────── */

function _appendTickerItems(items) {
  const track = document.getElementById('ticker-content');
  if (!track || !Array.isArray(items)) return;
  items.forEach(item => {
    const span = document.createElement('span');
    span.className = 'ticker__item';
    const dotClass = item.severity === 'Critical' ? 'danger'
                   : item.severity === 'High'     ? 'warning'
                   : 'success';
    span.innerHTML = `
      <span class="ticker__item-dot ${dotClass}"></span>
      <span>${_esc(item.title || 'No title')} — ${_esc(item.source || 'FEED')}</span>
    `;
    track.appendChild(span);
  });
}

/* ── Alert table row injection ─────────────────────────────────────────── */

function _injectAlertRow(alert) {
  const tbody = document.getElementById('alerts-tbody');
  if (!tbody) return;

  const severityBadge = `<span class="badge badge--${(alert.severity || 'Low').toLowerCase()}">${_esc(alert.severity)}</span>`;
  const time = alert.timestamp
    ? new Date(alert.timestamp).toLocaleTimeString()
    : new Date().toLocaleTimeString();
  const mitre = alert.mitre_technique
    ? `<span class="text-mono text-xs text-cyan">${_esc(alert.mitre_technique)}</span>`
    : '—';

  const tr = document.createElement('tr');
  tr.className = 'new-alert';
  tr.setAttribute('data-alert-id', alert.alert_id || '');
  tr.innerHTML = `
    <td>${severityBadge}</td>
    <td class="truncate" style="max-width:300px" title="${_esc(alert.message)}">${_esc(alert.message)}</td>
    <td class="text-mono text-xs">${_esc(alert.alert_type || '')}</td>
    <td>${mitre}</td>
    <td class="text-mono text-xs text-muted">${time}</td>
    <td>
      <button class="btn btn--sm btn--primary" onclick="acknowledgeAlert('${_esc(alert.alert_id || '')}', this)">ACK</button>
    </td>
  `;

  // Insert at top of table
  if (tbody.firstChild) {
    tbody.insertBefore(tr, tbody.firstChild);
  } else {
    tbody.appendChild(tr);
  }

  // Trim table to 100 rows max
  while (tbody.children.length > 100) {
    tbody.removeChild(tbody.lastChild);
  }
}

/* ── Chart refresh (full reload from API) ──────────────────────────────── */

function _refreshAllCharts() {
  // Refresh timeline
  if (window.BS_Charts && _timeline) {
    fetch('/api/timeline', { credentials: 'same-origin' })
      .then(r => r.json())
      .then(points => {
        if (!_timeline) return;
        _timeline.data.labels              = points.map(p => p.time || '');
        _timeline.data.datasets[0].data    = points.map(p => p.risk_score || 0);
        _timeline.data.datasets[1].data    = points.map(p => p.alert_count || 0);
        _timeline.update('none');
      })
      .catch(err => console.warn('[RT] Failed to refresh timeline:', err));
  }

  // Refresh beaconing chart
  fetch('/api/beaconing', { credentials: 'same-origin' })
    .then(r => r.json())
    .then(beacons => {
      if (window.BS_Charts && window._beaconingChart) {
        const labels     = beacons.map(b => `${b.dst_ip}:${b.dst_port}`);
        const confidences = beacons.map(b => b.confidence || 0);
        window._beaconingChart.data.labels              = labels;
        window._beaconingChart.data.datasets[0].data    = confidences;
        window._beaconingChart.update('active');
      }
    })
    .catch(err => console.warn('[RT] Failed to refresh beaconing:', err));
}

/* ── Main connect function ─────────────────────────────────────────────── */

/**
 * Connect to the Socket.IO server and register all event handlers.
 * Called once on page load.
 * @param {string} [namespace='/'] - Socket.IO namespace
 * @returns {Socket}
 */
function connectRealtime(namespace) {
  if (_socket) return _socket;

  const opts = {
    transports:       ['websocket', 'polling'],
    reconnection:     true,
    reconnectionDelay:      RECONNECT_DELAY_MIN,
    reconnectionDelayMax:   RECONNECT_DELAY_MAX,
    reconnectionAttempts:   RECONNECT_MAX_TRIES,
  };

  _socket = namespace ? io(namespace, opts) : io(opts);
  window._bsSocket = _socket; // expose for notification handlers

  /* ── Connection events ── */

  _socket.on('connect', () => {
    console.info('[RT] Socket.IO connected:', _socket.id);
    _reconnectTries = 0;
    _updateStatusIndicator(true);
    _socket.emit('request_metrics');
  });

  _socket.on('disconnect', reason => {
    console.warn('[RT] Socket.IO disconnected:', reason);
    _updateStatusIndicator(false);
  });

  _socket.on('connect_error', err => {
    _reconnectTries++;
    console.warn(`[RT] Connection error (try ${_reconnectTries}):`, err.message);
    if (_reconnectTries >= RECONNECT_MAX_TRIES) {
      console.error('[RT] Max reconnection attempts reached. Check server.');
      _showToast('High', 'Connection Lost', 'Real-time updates unavailable. Dashboard showing cached data.', 10000);
    }
  });

  _socket.on('reconnect', attempt => {
    console.info(`[RT] Reconnected after ${attempt} attempt(s)`);
    _updateStatusIndicator(true);
    _refreshCounters();
    _showToast('Info', 'Reconnected', 'Real-time connection restored.', 3000);
  });

  /* ── Business events ── */

  /**
   * scan_started: show progress panel, toast notification
   */
  _socket.on('scan_started', data => {
    console.info('[RT] Scan started:', data);
    _scanActive = true;
    _setProgress(0, 'INITIALISING', data.module || 'orchestrator');
    _showToast('Info', 'Scan Started',
      `Mode: ${data.mode || 'unknown'} | Host: ${data.hostname || 'unknown'}`, 4000);

    const panel = document.getElementById('scan-progress-panel');
    if (panel) panel.classList.add('active');
  });

  /**
   * new_alert: inject row into table, show toast, update counters
   */
  _socket.on('new_alert', data => {
    _alertCounter++;
    if (data.severity === 'Critical') _critCounter++;
    if (data.severity === 'High')     _highCounter++;

    // Flash the alert badge in sidebar
    const badge = document.getElementById('nav-alerts-badge');
    if (badge) {
      badge.textContent = _alertCounter;
      badge.style.display = 'inline-block';
    }

    _injectAlertRow(data);

    const duration = data.severity === 'Critical' ? 8000 : 5000;
    _showToast(
      data.severity || 'Medium',
      `${data.severity || 'Alert'} — ${data.alert_type || ''}`,
      (data.message || '').slice(0, 120),
      duration,
    );
  });

  /**
   * scan_progress: update progress bar and phase indicator
   */
  _socket.on('scan_progress', data => {
    _setProgress(data.percent || 0, data.phase || '', data.module || '', data.current_file || '');
  });

  /**
   * risk_score_update: animate the gauge and KPI score
   */
  _socket.on('risk_score_update', data => {
    const score = data.score || 0;
    if (window.BS_Charts && _riskGauge) {
      BS_Charts.updateRiskGauge(_riskGauge, score);
    }
    _updateCounter('kpi-score', score, true);

    // Update the risk level badge text and class
    const levelEl = document.getElementById('risk-gauge-level');
    if (levelEl && data.risk_level) {
      levelEl.textContent = data.risk_level.toUpperCase();
      levelEl.className   = `risk-gauge-level risk-level--${data.risk_level.toLowerCase()}`;
    }

    // Add a point to the timeline
    if (window.BS_Charts && _timeline) {
      BS_Charts.updateTimeline(_timeline, {
        time:        new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' }),
        risk_score:  score,
        alert_count: _alertCounter,
      });
    }
  });

  /**
   * scan_complete: finalise progress, refresh all charts, show summary toast
   */
  _socket.on('scan_complete', data => {
    console.info('[RT] Scan complete:', data);
    _scanActive = false;
    _setProgress(100, 'COMPLETE', 'Scan complete', '');

    if (data.error) {
      _showToast('High', 'Scan Error', data.error, 10000);
      return;
    }

    // Refresh all counters and charts
    setTimeout(() => {
      _refreshCounters();
      _refreshAllCharts();
    }, 500);

    const scoreColor = (data.threat_score || 0) >= 86 ? 'text-danger'
                     : (data.threat_score || 0) >= 61 ? 'text-warn' : 'text-ok';

    _showToast(
      'Info',
      'Scan Complete',
      `Score: ${data.threat_score || 0}/100 | Alerts: ${data.total_alerts || 0} (${data.critical_count || 0} critical) | ${(data.duration_seconds || 0).toFixed(1)}s`,
      8000,
    );

    // Reset counters for next scan
    _alertCounter = 0;
    _critCounter  = 0;
    _highCounter  = 0;
  });

  /**
   * news_feed: append items to the news ticker
   */
  _socket.on('news_feed', data => {
    if (data && data.items) {
      _appendTickerItems(data.items);
    }
  });

  /**
   * ai_analysis_ready: update the expandable row in the alerts table
   */
  _socket.on('ai_analysis_ready', data => {
    const alertId = data.alert_id;
    if (!alertId || !data.analysis) return;

    const row = document.querySelector(`tr[data-alert-id="${alertId}"]`);
    if (!row) return;

    const expandRow = row.nextElementSibling;
    if (expandRow && expandRow.classList.contains('data-table__expand')) {
      const aiCard = expandRow.querySelector('.ai-card__body');
      if (aiCard) {
        const analysis = data.analysis;
        aiCard.innerHTML = `
          <p>${_esc(analysis.explanation || analysis.summary || '')}</p>
          ${analysis.mitre_technique ? `<p class="mt-sm text-xs text-cyan">MITRE: ${_esc(analysis.mitre_technique)}</p>` : ''}
          ${analysis.recommendation  ? `<p class="mt-sm text-xs text-warn">→ ${_esc(analysis.recommendation)}</p>` : ''}
        `;
      }
    }
  });

  /**
   * metrics_update: bulk counter refresh
   */
  _socket.on('metrics_update', data => {
    if (data.risk_score   !== undefined) _updateCounter('kpi-score',    data.risk_score);
    if (data.total_alerts !== undefined) _updateCounter('kpi-total',    data.total_alerts);
    if (data.critical     !== undefined) _updateCounter('kpi-critical', data.critical);
  });

  return _socket;
}

/* ── Connection status indicator ───────────────────────────────────────── */

function _updateStatusIndicator(online) {
  const dot   = document.getElementById('rt-status-dot');
  const label = document.getElementById('rt-status-label');
  if (dot) {
    dot.className = `status-dot${online ? '' : ' offline'}`;
  }
  if (label) {
    label.textContent = online ? 'Live' : 'Offline';
  }
}

/* ── Public API ────────────────────────────────────────────────────────── */

/**
 * Start a scan via the API and show progress.
 * @param {string} mode - "quick-scan" | "full-scan" | "network-only" | "file-only"
 */
function startScan(mode) {
  fetch('/api/start-scan', {
    method:      'POST',
    credentials: 'same-origin',
    headers:     { 'Content-Type': 'application/json' },
    body:        JSON.stringify({ mode: mode || 'quick-scan' }),
  })
    .then(r => r.json())
    .then(d => {
      if (d.success || d.status === 'started') {
        _showToast('Info', 'Scan Queued', `Mode: ${d.mode}`, 3000);
        _setProgress(1, 'STARTING', 'orchestrator');
        const panel = document.getElementById('scan-progress-panel');
        if (panel) panel.classList.add('active');
      } else if (d.error) {
        _showToast('High', 'Scan Error', d.error, 8000);
      }
    })
    .catch(err => {
      console.error('[RT] startScan error:', err);
      _showToast('High', 'Scan Error', 'Could not start scan. Check server logs.', 8000);
    });
}

/**
 * Acknowledge an alert via the API.
 * @param {string}      alertId - Alert ID
 * @param {HTMLElement} btn     - The ACK button element (for UI feedback)
 */
function acknowledgeAlert(alertId, btn) {
  if (!alertId) return;
  fetch(`/api/acknowledge-alert/${encodeURIComponent(alertId)}`, {
    method:      'POST',
    credentials: 'same-origin',
  })
    .then(r => r.json())
    .then(() => {
      if (btn) {
        btn.textContent  = 'ACKED';
        btn.disabled     = true;
        btn.className    = 'btn btn--sm';
        btn.style.opacity = '0.5';
      }
      const row = btn ? btn.closest('tr') : null;
      if (row) {
        const badge = row.querySelector('.badge');
        if (badge) badge.classList.add('badge--ack');
      }
    })
    .catch(err => console.warn('[RT] Acknowledge error:', err));
}

/* ── Chart instance setters (called from inline scripts after chart init) ─ */

function setGaugeInstance(chart)    { _riskGauge = chart; }
function setTimelineInstance(chart) { _timeline  = chart; }

/* ── Auto-clock update ──────────────────────────────────────────────────── */

function startClock() {
  const el = document.getElementById('header-clock');
  if (!el) return;
  function tick() {
    el.textContent = new Date().toLocaleTimeString('en-US', {
      hour12:  false,
      hour:    '2-digit',
      minute:  '2-digit',
      second:  '2-digit',
    });
  }
  tick();
  setInterval(tick, 1000);
}

/* ── Export ─────────────────────────────────────────────────────────────── */

window.BS_Realtime = {
  connect:          connectRealtime,
  startScan,
  acknowledgeAlert,
  setGaugeInstance,
  setTimelineInstance,
  startClock,
  showToast:        _showToast,
  refreshCounters:  _refreshCounters,
};

// Auto-init clock on DOM ready
document.addEventListener('DOMContentLoaded', startClock);

/* ════════════════════════════════════════════════════════════════
   THREAT NOTIFICATION SYSTEM
   ════════════════════════════════════════════════════════════════ */

var _notifStore = [];
var _unreadCount = 0;

function toggleNotifDrawer() {
  var drawer  = document.getElementById('notifDrawer');
  var overlay = document.getElementById('notifOverlay');
  if (!drawer || !overlay) return;
  var isOpen = drawer.classList.contains('open');
  if (isOpen) {
    drawer.classList.remove('open');
    overlay.classList.remove('visible');
  } else {
    drawer.classList.add('open');
    overlay.classList.add('visible');
    _markAllSeen();
  }
}

function _markAllSeen() {
  _unreadCount = 0;
  _updateNotifBadge();
}

function _updateNotifBadge() {
  var badge = document.getElementById('notifBadge');
  if (!badge) return;
  if (_unreadCount > 0) {
    badge.style.display = 'flex';
    badge.textContent = _unreadCount > 99 ? '99+' : String(_unreadCount);
  } else {
    badge.style.display = 'none';
  }
}

function renderNotification(n) {
  var empty = document.getElementById('notifEmpty');
  if (empty) empty.style.display = 'none';

  var body = document.getElementById('notifDrawerBody');
  if (!body) return;
  if (document.getElementById('notif-' + n.id)) return; // already rendered

  var timeStr = n.timestamp ? new Date(n.timestamp).toLocaleTimeString() : '';
  var breachBanner = n.is_confirmed_breach
    ? '<div class="notif-breach-banner">&#9888; ACTIVE BREACH CONFIRMED &#8212; Immediate action required</div>'
    : '<div class="notif-safe-banner">&#9873; Suspicious activity &#8212; Not yet confirmed as breach</div>';

  var mitre = n.mitre_technique
    ? '<div class="notif-mitre">MITRE ' + _esc(n.mitre_technique) + ' &#8212; ' + _esc(n.mitre_tactic) + '</div>'
    : '';

  var killBtn = (n.process_pid && n.can_kill_process)
    ? '<button class="notif-action-btn btn-kill" id="kill-' + n.id + '" onclick="notifKillProcess(' + n.process_pid + ',\'' + n.id + '\')">'
      + '&#8855; Kill ' + _esc(n.process_name || 'Process') + ' (PID ' + n.process_pid + ')</button>'
    : '';

  var blacklistBtn = (n.remote_ip && n.can_blacklist_ip)
    ? '<button class="notif-action-btn btn-blacklist" id="bl-' + n.id + '" onclick="notifBlacklistIP(\'' + _esc(n.remote_ip) + '\',\'' + n.id + '\')">'
      + '&#8856; Blacklist ' + _esc(n.remote_ip) + '</button>'
    : '';

  var card = document.createElement('div');
  card.id = 'notif-' + n.id;
  card.className = 'notif-card severity-' + _esc(n.severity) + (n.is_acknowledged ? '' : ' unread');
  card.innerHTML = [
    '<div class="notif-card-header" onclick="toggleNotifCard(\'' + n.id + '\')">',
    '  <div class="notif-severity-dot"></div>',
    '  <div class="notif-title">' + _esc(n.title) + '</div>',
    '  <div class="notif-time">' + timeStr + '</div>',
    '</div>',
    '<div class="notif-card-body" id="notif-body-' + n.id + '">',
    breachBanner,
    '  <div class="notif-description">' + _esc(n.description) + '</div>',
    '  <div class="notif-description" style="color:#4a6a88;font-style:italic;margin-bottom:8px;">' + _esc(n.verdict_reason) + '</div>',
    '  <div class="notif-tech-detail">' + _esc(n.technical_detail) + '</div>',
    mitre,
    '  <div class="notif-actions">',
    killBtn,
    blacklistBtn,
    '    <button class="notif-action-btn btn-ack" onclick="notifAcknowledge(\'' + n.id + '\')">&#10003; Acknowledge</button>',
    '  </div>',
    '</div>',
  ].join('\n');

  body.insertBefore(card, body.firstChild);
}

function toggleNotifCard(id) {
  var body = document.getElementById('notif-body-' + id);
  if (body) body.classList.toggle('expanded');
}

function notifKillProcess(pid, notifId) {
  if (!confirm('Kill process PID ' + pid + '? This cannot be undone.')) return;
  var btn = document.getElementById('kill-' + notifId);
  if (btn) { btn.disabled = true; btn.textContent = 'Killing\u2026'; }

  fetch('/api/kill-process/' + pid, { method: 'POST', credentials: 'same-origin' })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.success) {
        if (btn) btn.textContent = '\u2713 Killed';
        showToast('success', 'Process Killed', 'Process ' + data.process_name + ' (PID ' + pid + ') terminated.');
      } else {
        if (btn) { btn.disabled = false; btn.textContent = '\u2297 Kill Process'; }
        showToast('error', 'Kill Failed', data.error || 'Unknown error');
      }
    })
    .catch(function() {
      if (btn) btn.disabled = false;
      showToast('error', 'Kill Failed', 'Request failed. Check server.');
    });
}

function notifBlacklistIP(ip, notifId) {
  if (!confirm('Add ' + ip + ' to blacklist? Future connections will be flagged.')) return;
  var btn = document.getElementById('bl-' + notifId);
  if (btn) { btn.disabled = true; btn.textContent = 'Blacklisting\u2026'; }

  fetch('/api/blacklist-ip', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip: ip }),
  })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.success) {
        if (btn) btn.textContent = '\u2713 Blacklisted';
        showToast('success', 'IP Blacklisted', 'IP ' + ip + ' added to blacklist.');
      } else {
        if (btn) btn.disabled = false;
        showToast('error', 'Blacklist Failed', data.error || 'Unknown error');
      }
    })
    .catch(function() {
      if (btn) btn.disabled = false;
      showToast('error', 'Blacklist Failed', 'Request failed.');
    });
}

function notifAcknowledge(id) {
  fetch('/api/notifications/acknowledge/' + id, { method: 'POST', credentials: 'same-origin' });
  var card = document.getElementById('notif-' + id);
  if (card) card.classList.remove('unread');
}

function acknowledgeAll() {
  _notifStore.forEach(function(n) { notifAcknowledge(n.id); });
  _unreadCount = 0;
  _updateNotifBadge();
}

function showToast(type, title, message) {
  var toast = document.createElement('div');
  var isSuccess = type === 'success';
  toast.style.cssText = [
    'position:fixed;bottom:20px;right:20px;z-index:9999;',
    'background:' + (isSuccess ? '#00ff8822' : '#ff3b5c22') + ';',
    'border:1px solid ' + (isSuccess ? '#00ff8866' : '#ff3b5c66') + ';',
    'color:' + (isSuccess ? '#00ff88' : '#ff3b5c') + ';',
    'padding:10px 16px;border-radius:6px;font-size:13px;',
    'max-width:320px;word-break:break-word;line-height:1.5;',
  ].join('');
  toast.innerHTML = '<strong>' + _esc(title) + '</strong><br>' + _esc(message);
  document.body.appendChild(toast);
  setTimeout(function() { toast.remove(); }, 3500);
}

/* ── Socket.IO: receive threat notifications ──────────────────── */
document.addEventListener('DOMContentLoaded', function() {
  // Wait for the socket created by BS_Realtime.connect() in base.html
  setTimeout(function() {
    var sock = window._bsSocket;
    if (!sock) return;

    sock.on('demo_cleared', function(data) {
      showToast('success', 'Demo Cleared', 'All demo data has been removed.');
      // Force full page reload to clear all client-side state
      setTimeout(function() {
        window.location.href = window.location.href.split('?')[0] + '?t=' + Date.now();
      }, 800);
    });

    sock.on('threat_notification', function(data) {
      _notifStore.unshift(data);
      _unreadCount++;
      _updateNotifBadge();
      renderNotification(data);

      // Flash bell
      var bell = document.getElementById('notifBellBtn');
      if (bell) {
        bell.style.color = '#ff3b5c';
        setTimeout(function() { bell.style.color = ''; }, 1200);
      }
    });
  }, 500);

  // Load persisted notifications from server on page load
  fetch('/api/notifications', { credentials: 'same-origin' })
    .then(function(r) { return r.ok ? r.json() : []; })
    .then(function(data) {
      (data || []).forEach(function(n) {
        _notifStore.push(n);
        renderNotification(n);
      });
      _unreadCount = (data || []).filter(function(n) { return !n.is_acknowledged; }).length;
      _updateNotifBadge();
    })
    .catch(function() {});
});

/* ── Demo data loader ──────────────────────────────────────────────────── */

function loadDemoData() {
  var btn = document.getElementById('loadDemoBtn') || document.querySelector('[onclick="loadDemoData()"]');
  if (btn) { btn.disabled = true; btn.textContent = 'Loading…'; }

  fetch('/api/load-demo-data', { method: 'POST', credentials: 'same-origin' })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.success) {
        showDemoToast('Demo data loaded — ' + (data.alerts || 0) + ' alerts. Refreshing…');
        var bar = document.getElementById('demoBar');
        if (bar) { bar.style.display = 'none'; }
        setTimeout(function() { window.location.reload(); }, 1400);
      } else {
        showDemoToast('Failed: ' + (data.error || 'unknown error'), true);
        if (btn) { btn.disabled = false; btn.textContent = '⬇ Load Demo Data'; }
      }
    })
    .catch(function(err) {
      showDemoToast('Request failed: ' + err, true);
      if (btn) { btn.disabled = false; btn.textContent = '⬇ Load Demo Data'; }
    });
}

function showDemoToast(msg, isError) {
  var el = document.createElement('div');
  el.textContent = msg;
  el.style.cssText = [
    'position:fixed', 'bottom:1.5rem', 'right:1.5rem', 'z-index:9999',
    'padding:0.7rem 1.2rem', 'border-radius:6px', 'font-size:0.85rem',
    'background:' + (isError ? '#ff3b5c33' : '#00d4ff22'),
    'border:1px solid ' + (isError ? '#ff3b5c88' : '#00d4ff88'),
    'color:' + (isError ? '#ff3b5c' : '#00d4ff'),
    'box-shadow:0 4px 20px rgba(0,0,0,0.4)',
    'transition:opacity 0.4s',
  ].join(';');
  document.body.appendChild(el);
  setTimeout(function() { el.style.opacity = '0'; }, 2600);
  setTimeout(function() { el.remove(); }, 3000);
}

function clearDemoData() {
  if (!confirm('Clear all demo data from the dashboard?\n\nThe page will refresh.')) return;

  var btn = document.querySelector('[onclick="clearDemoData()"]');
  if (btn) { btn.disabled = true; btn.textContent = 'Clearing...'; }

  fetch('/api/clear-demo-data', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
  })
  .then(function(r) { return r.json(); })
  .then(function(data) {
    if (data.success) {
      showDemoToast('Demo data cleared — refreshing...');
      // Force full reload to clear all client state
      setTimeout(function() {
        window.location.href = window.location.href.split('?')[0] + '?t=' + Date.now();
      }, 1000);
    } else {
      if (btn) { btn.disabled = false; btn.textContent = '\u2715 Clear Demo'; }
      showDemoToast('Clear failed: ' + (data.error || 'Unknown error'), true);
    }
  })
  .catch(function(err) {
    if (btn) { btn.disabled = false; btn.textContent = '\u2715 Clear Demo'; }
    showDemoToast('Request failed', true);
  });
}

function startScan(mode) {
  var modeNames = {
    'quick-scan': 'Quick Scan',
    'file-only': 'File Scan',
    'network-only': 'Network Scan',
    'full-scan': 'Full Scan',
  };
  if (!confirm('Start ' + (modeNames[mode] || mode) + '?')) return;

  ['btn-quick','btn-file','btn-network','btn-full'].forEach(function(id) {
    var btn = document.getElementById(id);
    if (btn) { btn.disabled = true; btn.style.opacity = '0.5'; }
  });

  var statusLine = document.getElementById('scanStatusLine');
  var statusText = document.getElementById('scanStatusText');
  if (statusLine) statusLine.style.display = 'flex';
  if (statusText) statusText.textContent = 'Starting ' + mode + '...';

  fetch('/api/start-scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ mode: mode })
  })
  .then(function(r) { return r.json(); })
  .then(function(data) {
    if (!data.success) {
      showDemoToast('Scan failed: ' + (data.error || 'unknown'), true);
      _resetScanButtons();
    } else {
      showDemoToast('Scan started: ' + mode);
    }
  })
  .catch(function() {
    showDemoToast('Failed to start scan', true);
    _resetScanButtons();
  });
}

function _resetScanButtons() {
  ['btn-quick','btn-file','btn-network','btn-full'].forEach(function(id) {
    var btn = document.getElementById(id);
    if (btn) { btn.disabled = false; btn.style.opacity = '1'; }
  });
  var statusLine = document.getElementById('scanStatusLine');
  if (statusLine) statusLine.style.display = 'none';
}

// Socket.IO scan progress — bind after socket init (mini bar + reset buttons)
document.addEventListener('DOMContentLoaded', function() {
  setTimeout(function() {
    var sock = (typeof _socket !== 'undefined') ? _socket : null;
    if (!sock) return;
    sock.on('scan_progress', function(data) {
      // Update mini status bar in scan control panel
      var statusText = document.getElementById('scanStatusText');
      var fill = document.getElementById('scanMiniBarFill');
      var file = data.current_file || '';
      if (statusText) statusText.textContent = (data.module || '') + (file ? ' → ' + file : '');
      if (fill) fill.style.width = (data.percent || 0) + '%';
    });
    sock.on('scan_complete', function(data) {
      showDemoToast('Scan complete — Risk: ' + (data.risk_score || 0) + '/100');
      _resetScanButtons();
      setTimeout(function() { location.reload(); }, 2000);
    });
    sock.on('scan_error', function(data) {
      showDemoToast('Scan error: ' + (data.error || 'unknown'), true);
      _resetScanButtons();
    });
  }, 500);
});

/* ── News Ticker ─────────────────────────────────────────────────────────── */

var _NEWS_TTL_MS = 30 * 60 * 1000; // 30 minutes

function initNewsTicker() {
    // 1. Try sessionStorage — instant (< 1ms)
    try {
        var cached   = sessionStorage.getItem('bs_news_items');
        var cachedAt = parseInt(sessionStorage.getItem('bs_news_ts') || '0');
        if (cached && (Date.now() - cachedAt) < _NEWS_TTL_MS) {
            var items = JSON.parse(cached);
            if (items && items.length > 0) {
                renderTickerItems(items);
                var remaining = _NEWS_TTL_MS - (Date.now() - cachedAt);
                setTimeout(fetchAndRenderNews, Math.max(remaining, 5 * 60 * 1000));
                return;
            }
        }
    } catch(e) {}
    // 2. Static fallback immediately visible
    renderTickerFallback();
    // 3. Fetch real data (replaces fallback)
    fetchAndRenderNews();
}

function fetchAndRenderNews() {
    var ctrl    = new AbortController();
    var timeout = setTimeout(function() { ctrl.abort(); }, 6000);
    fetch('/api/news', { credentials: 'same-origin', signal: ctrl.signal })
    .then(function(r) { clearTimeout(timeout); return r.json(); })
    .then(function(data) {
        if (data.success && data.headlines && data.headlines.length > 0) {
            try {
                sessionStorage.setItem('bs_news_items', JSON.stringify(data.headlines));
                sessionStorage.setItem('bs_news_ts', String(Date.now()));
            } catch(e) {}
            renderTickerItems(data.headlines);
        }
    })
    .catch(function() { clearTimeout(timeout); });
}

function renderTickerItems(headlines) {
  var track = document.getElementById('newsTickerTrack');
  if (!track) return;

  // Build ticker HTML — duplicate items for seamless loop
  var items = buildTickerHTML(headlines);
  track.innerHTML = items + items;

  // Calculate duration proportional to content: ~80px per second
  var estimatedWidth = headlines.length * 420 * 2; // x2 for duplicate
  var duration = Math.max(40, Math.round(estimatedWidth / 80)); // min 40s
  track.style.animation = 'none';
  track.offsetHeight; // force reflow
  track.style.animationDuration = duration + 's';
  track.style.animationName = 'news-ticker-scroll';
  track.style.animationTimingFunction = 'linear';
  track.style.animationIterationCount = 'infinite';
}

function buildTickerHTML(headlines) {
  return headlines.map(function(item) {
    var safeTitle = escapeHtml(item.title || '');
    var safeUrl   = (item.url || '#').replace(/"/g, '%22');
    var color     = item.source_color || '#00d4ff';

    return [
      '<a class="news-ticker-item" href="' + safeUrl + '"',
      '   target="_blank" rel="noopener noreferrer"',
      '   title="' + safeTitle + '">',
      '  <span class="news-ticker-source" style="color:' + color + ';border:1px solid ' + color + '22">',
      '    ' + escapeHtml(item.source || 'NEWS'),
      '  </span>',
      '  <span class="news-ticker-title">' + safeTitle + '</span>',
      '</a>',
      '<span class="news-ticker-separator">\u00b7</span>',
    ].join('');
  }).join('');
}

function renderTickerFallback() {
  var track = document.getElementById('newsTickerTrack');
  if (!track) return;
  var fallbackItems = [
    { title: 'The Hacker News \u2014 Latest Cybersecurity News',
      url: 'https://thehackernews.com', source: 'THN', source_color: '#00d4ff' },
    { title: 'BleepingComputer \u2014 Technology & Security News',
      url: 'https://bleepingcomputer.com', source: 'BC', source_color: '#00ff88' },
    { title: 'Krebs on Security \u2014 Security News & Investigation',
      url: 'https://krebsonsecurity.com', source: 'KOS', source_color: '#ffb800' },
    { title: 'CISA \u2014 Cybersecurity Advisories & Alerts',
      url: 'https://cisa.gov/news-events/cybersecurity-advisories',
      source: 'CISA', source_color: '#ff3b5c' },
  ];
  var html = buildTickerHTML(fallbackItems);
  track.innerHTML = html + html;
}

function escapeHtml(s) {
  return (s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Initialise news ticker on DOM ready
document.addEventListener('DOMContentLoaded', function() {
  initNewsTicker();
});
