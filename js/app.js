// CYBER CONSTELLATION — Master Application Controller v3.0
// SIH26106 — AI-Powered Email Threat Intelligence & Forensic Investigation Platform
// All demo data is synthetic — clearly labeled for SIH judging

'use strict';

document.addEventListener('DOMContentLoaded', () => {

  // ── STATE ────────────────────────────────────────────────────────────
  const state = {
    activeTab: 'landing',
    currentCase: null,
    activeInvTab: 'overview',
    sidebarCollapsed: false,
    maps: {},
    d3Graphs: {},
    pulseInterval: null,
    selectedReportCase: null,
    selectedCampaign: null,
  };

  // ── UTILITIES ────────────────────────────────────────────────────────
  function showToast(msg, type = 'info', dur = 3500) {
    const icons = { info: 'fa-circle-info', success: 'fa-check-circle', danger: 'fa-triangle-exclamation', warn: 'fa-bell' };
    const c = document.getElementById('toast-container');
    if (!c) return;
    const t = document.createElement('div');
    t.className = `toast toast-${type}`;
    t.setAttribute('role', 'alert');
    t.innerHTML = `<i class="fa-solid ${icons[type] || icons.info}" aria-hidden="true"></i><span>${msg}</span>`;
    c.appendChild(t);
    setTimeout(() => { t.style.animation = 'toast-out 0.3s ease forwards'; setTimeout(() => t.remove(), 300); }, dur);
  }

  function formatTime(dateStr) {
    return new Date(dateStr).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', hour12: false });
  }

  function getSevClass(score) {
    if (score >= 85) return 'critical';
    if (score >= 65) return 'high';
    if (score >= 45) return 'medium';
    if (score >= 20) return 'low';
    return 'safe';
  }

  function getThreatLabel(c) {
    if (c.riskScore >= 85) return 'CRITICAL THREAT';
    if (c.riskScore >= 65) return 'HIGH RISK';
    if (c.riskScore >= 45) return 'SUSPICIOUS';
    if (c.riskScore >= 20) return 'GUARDED';
    return 'LEGITIMATE';
  }

  function severityColor(sev) {
    const map = { critical: 'var(--sev-critical)', high: 'var(--sev-high)', medium: 'var(--sev-medium)', low: 'var(--sev-low)', safe: 'var(--sev-safe)' };
    return map[sev] || 'var(--text-muted)';
  }

  // ── LIVE CLOCK ───────────────────────────────────────────────────────
  function updateClock() {
    const el = document.getElementById('live-clock');
    if (el) {
      const t = new Date().toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour12: false });
      el.textContent = `IST ${t}`;
    }
  }
  updateClock();
  setInterval(updateClock, 1000);

  // ── NAVIGATION ───────────────────────────────────────────────────────
  function navigateTo(tabId) {
    if (state.activeTab === tabId) return;

    // Deactivate all
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

    // Activate target
    const navEl = document.getElementById(`nav-${tabId}`);
    if (navEl) navEl.classList.add('active');

    const pane = document.getElementById(`tab-${tabId}`);
    if (pane) pane.classList.add('active');

    state.activeTab = tabId;

    // Side effects per tab
    if (tabId === 'dashboard') _initDashboard();
    if (tabId === 'cases') _renderCases();
    if (tabId === 'campaigns') _renderCampaigns();
    if (tabId === 'evidence') _renderGlobalEvidence();
    if (tabId === 'reports') _renderReportCaseSelector();
    if (tabId === 'analyze' && state.currentCase) _renderResults(state.currentCase);

    // Scroll to top
    const mc = document.getElementById('main-content');
    if (mc) mc.scrollTop = 0;
  }

  // Wire nav items
  document.querySelectorAll('.nav-item[data-tab]').forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      navigateTo(item.getAttribute('data-tab'));
    });
    // Keyboard support
    item.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        navigateTo(item.getAttribute('data-tab'));
      }
    });
  });

  // Quick nav buttons
  document.getElementById('go-dashboard-btn')?.addEventListener('click', () => navigateTo('dashboard'));
  document.getElementById('dashboard-analyze-btn')?.addEventListener('click', () => navigateTo('analyze'));
  document.getElementById('cases-new-btn')?.addEventListener('click', () => navigateTo('analyze'));
  document.getElementById('view-all-cases-btn')?.addEventListener('click', () => navigateTo('cases'));
  document.getElementById('new-analysis-btn')?.addEventListener('click', _resetAnalyzer);

  // ── SIDEBAR COLLAPSE ─────────────────────────────────────────────────
  function _toggleSidebar() {
    state.sidebarCollapsed = !state.sidebarCollapsed;
    const sidebar = document.getElementById('sidebar');
    const container = document.getElementById('app-container');
    const icon = document.getElementById('collapse-icon');
    const label = document.getElementById('collapse-label');

    sidebar?.classList.toggle('collapsed', state.sidebarCollapsed);
    container?.classList.toggle('sidebar-collapsed', state.sidebarCollapsed);

    if (icon) icon.className = state.sidebarCollapsed ? 'fa-solid fa-chevron-right' : 'fa-solid fa-chevron-left';
    if (label) label.textContent = state.sidebarCollapsed ? 'Expand' : 'Collapse';

    // Invalidate maps after transition
    setTimeout(() => {
      Object.values(state.maps).forEach(m => m && m.invalidateSize?.());
    }, 300);
  }

  document.getElementById('sidebar-collapse-btn')?.addEventListener('click', _toggleSidebar);
  document.getElementById('collapse-btn-footer')?.addEventListener('click', _toggleSidebar);

  // ── MOBILE SIDEBAR ────────────────────────────────────────────────────
  const mobileBtn = document.getElementById('mobile-menu-btn');
  const overlay = document.getElementById('sidebar-overlay');
  const sidebar = document.getElementById('sidebar');

  function _openMobileSidebar() {
    sidebar?.classList.add('mobile-open');
    if (overlay) { overlay.style.display = 'block'; overlay.setAttribute('aria-hidden', 'false'); }
  }

  function _closeMobileSidebar() {
    sidebar?.classList.remove('mobile-open');
    if (overlay) { overlay.style.display = 'none'; overlay.setAttribute('aria-hidden', 'true'); }
  }

  mobileBtn?.addEventListener('click', _openMobileSidebar);
  overlay?.addEventListener('click', _closeMobileSidebar);

  // On mobile, close sidebar after nav
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => { if (window.innerWidth < 768) _closeMobileSidebar(); });
  });

  // Mobile detection
  function _checkMobile() {
    const isMobile = window.innerWidth < 768;
    if (mobileBtn) mobileBtn.style.display = isMobile ? 'flex' : 'none';
  }
  _checkMobile();
  window.addEventListener('resize', _checkMobile);

  // ── COMMAND PALETTE ───────────────────────────────────────────────────
  window.CommandPalette.init(navigateTo);
  document.getElementById('global-search-btn')?.addEventListener('click', () => window.CommandPalette.open());

  // ── STARS CANVAS (Landing) ────────────────────────────────────────────
  function _initStars() {
    const canvas = document.getElementById('stars-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    function resize() {
      canvas.width = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
    }

    resize();
    window.addEventListener('resize', resize);

    const stars = Array.from({ length: 120 }, () => ({
      x: Math.random(),
      y: Math.random(),
      size: Math.random() * 1.5 + 0.3,
      opacity: Math.random() * 0.5 + 0.1,
      speed: Math.random() * 0.003 + 0.001,
      phase: Math.random() * Math.PI * 2,
    }));

    function draw(t) {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      stars.forEach(s => {
        const o = s.opacity + Math.sin(t * s.speed + s.phase) * 0.15;
        ctx.beginPath();
        ctx.arc(s.x * canvas.width, s.y * canvas.height, s.size, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(79,156,249,${Math.max(0, o)})`;
        ctx.fill();
      });
      requestAnimationFrame(draw);
    }

    // Only animate if no reduced motion
    if (!window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      requestAnimationFrame(draw);
    }
  }

  // ── RELATIONSHIP DIAGRAM (Landing) ────────────────────────────────────
  function _initRelDiagram() {
    const nodes = document.querySelectorAll('.rel-sat-node');
    nodes.forEach((node, i) => {
      const label = node.dataset.label;
      const icon = node.dataset.icon;
      node.innerHTML = `
        <div style="width:64px; height:64px; background:rgba(79,156,249,0.08); border:1px solid rgba(79,156,249,0.25); border-radius:50%; display:flex; flex-direction:column; align-items:center; justify-content:center; cursor:default; transition:all 0.2s;">
          <i class="fa-solid ${icon}" style="font-size:1rem; color:var(--accent); margin-bottom:3px;"></i>
          <div style="font-size:0.5rem; letter-spacing:0.1em; color:var(--text-muted); font-weight:600;">${label}</div>
        </div>
      `;
    });
  }

  // ── LAUNCH DEMO ───────────────────────────────────────────────────────
  function _launchDemo() {
    const demoCase = DEMO_CASES[0]; // CX-1024 - Critical Phishing
    navigateTo('analyze');
    setTimeout(() => _runAnalysisPipeline(demoCase), 200);
    showToast('Investigation started — analyzing CX-1024 (Critical Phishing)', 'info', 4000);
  }

  document.getElementById('launch-demo-btn')?.addEventListener('click', _launchDemo);

  // Expose globally for command palette
  window.DemoMode = {
    launchDemo: _launchDemo,
    openCase: (id) => {
      const c = DEMO_CASES.find(x => x.id === id);
      if (c) {
        navigateTo('analyze');
        setTimeout(() => _runAnalysisPipeline(c), 200);
      }
    }
  };

  // ── DASHBOARD ─────────────────────────────────────────────────────────
  function _initDashboard() {
    // Sync time
    const syncEl = document.getElementById('dashboard-sync-time');
    if (syncEl) syncEl.textContent = `Last intelligence sync: ${new Date().toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour12: false })} IST`;

    // Metrics (with number animation)
    _animateMetric('m-active-cases', 37);
    _animateMetric('m-critical', 8, true);
    _animateMetric('m-phishing', 142);
    _animateMetric('m-campaigns', 12);
    _animateMetric('m-infra', 86);
    _animateMetric('m-today', 29);

    // Wire metric cards
    document.getElementById('metric-cases')?.addEventListener('click', () => navigateTo('cases'));
    document.getElementById('metric-critical')?.addEventListener('click', () => navigateTo('cases'));
    document.getElementById('metric-phishing')?.addEventListener('click', () => navigateTo('cases'));
    document.getElementById('metric-campaigns')?.addEventListener('click', () => navigateTo('campaigns'));
    document.getElementById('metric-infra')?.addEventListener('click', () => navigateTo('campaigns'));
    document.getElementById('metric-today')?.addEventListener('click', () => navigateTo('cases'));

    // Pulse Feed
    _renderPulseFeed();

    // Cases Table
    _renderDashboardCasesTable();

    // Map
    _initDashboardMap();

    // Dashboard Graph
    _initDashboardGraph();

    // DB Graph buttons
    document.getElementById('db-graph-2d')?.addEventListener('click', () => _setDashboardGraphMode('2d'));
    document.getElementById('db-graph-3d')?.addEventListener('click', () => _setDashboardGraphMode('3d'));
    document.getElementById('db-load-demo-constellation')?.addEventListener('click', () => {
      const c = DEMO_CASES[0];
      state.currentCase = c;
      _renderDashboardGraph(c);
      document.getElementById('db-graph-empty')?.classList.add('hidden');
    });
    document.getElementById('db-expand-graph')?.addEventListener('click', () => {
      navigateTo('analyze');
      if (state.currentCase) setTimeout(() => _showInvTab('graph'), 500);
    });
    document.getElementById('db-open-map')?.addEventListener('click', () => {
      navigateTo('analyze');
      if (state.currentCase) setTimeout(() => _showInvTab('geo'), 500);
    });
    document.getElementById('refresh-dashboard-btn')?.addEventListener('click', () => {
      _initDashboard();
      showToast('Dashboard refreshed', 'success', 2000);
    });

    // View all cases
    document.getElementById('view-all-cases-btn')?.addEventListener('click', () => navigateTo('cases'));
  }

  function _animateMetric(id, target, padded = false) {
    const el = document.getElementById(id);
    if (!el) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      el.textContent = padded && target < 10 ? `0${target}` : target;
      return;
    }
    let current = 0;
    const step = target / 30;
    const timer = setInterval(() => {
      current = Math.min(current + step, target);
      el.textContent = padded && Math.round(current) < 10 ? `0${Math.round(current)}` : Math.round(current);
      if (current >= target) clearInterval(timer);
    }, 40);
  }

  function _renderPulseFeed() {
    const feed = document.getElementById('pulse-feed');
    if (!feed) return;

    feed.innerHTML = DEMO_PULSE.map(item => `
      <div class="pulse-item animate-slide-up">
        <div class="pulse-time">${item.time}</div>
        <div class="pulse-dot-wrap"><div class="pulse-dot ${item.severity}" aria-hidden="true"></div></div>
        <div class="pulse-msg">${item.msg}</div>
      </div>
    `).join('');

    // Auto-add new events every 8 seconds (demo feel)
    if (state.pulseInterval) clearInterval(state.pulseInterval);
    const extra = [
      { severity: 'info',     msg: 'Campaign CAM-091 updated — 1 new correlated email' },
      { severity: 'critical', msg: 'High-risk domain observed: gov-nic-portal-secure.com' },
      { severity: 'medium',   msg: 'IP 185.220.101.5 seen across 3 active cases' },
      { severity: 'info',     msg: 'Evidence vault integrity check passed — all SHA-256 verified' },
    ];
    let extraIdx = 0;
    state.pulseInterval = setInterval(() => {
      if (document.getElementById('tab-dashboard')?.classList.contains('active')) {
        const now = new Date().toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour12: false });
        const item = extra[extraIdx % extra.length];
        const div = document.createElement('div');
        div.className = 'pulse-item animate-slide-up';
        div.innerHTML = `<div class="pulse-time">${now}</div><div class="pulse-dot-wrap"><div class="pulse-dot ${item.severity}" aria-hidden="true"></div></div><div class="pulse-msg">${item.msg}</div>`;
        feed.insertBefore(div, feed.firstChild);
        while (feed.children.length > 15) feed.removeChild(feed.lastChild);
        extraIdx++;
      }
    }, 8000);
  }

  function _renderDashboardCasesTable() {
    const tbody = document.getElementById('cases-table-body');
    if (!tbody) return;

    const displayCases = DEMO_CASES.slice(0, 6);
    tbody.innerHTML = displayCases.map(c => `
      <tr onclick="window.DemoMode.openCase('${c.id}')" style="cursor:pointer;" role="row" aria-label="Case ${c.id}: ${c.type}, risk ${c.riskScore}">
        <td><span class="monospace" style="color:var(--accent);">${c.id}</span></td>
        <td>${c.type}</td>
        <td>
          <div style="display:flex; align-items:center; gap:8px;">
            <div style="flex:1; height:5px; background:rgba(255,255,255,0.06); border-radius:3px; overflow:hidden; max-width:60px;">
              <div style="height:100%; width:${c.riskScore}%; background:${severityColor(c.severity)}; border-radius:3px;"></div>
            </div>
            <span class="sev-tag ${c.severity}">${c.riskScore}</span>
          </div>
        </td>
        <td><span class="sev-tag ${c.severity}">${c.status}</span></td>
        <td style="color:var(--text-muted); font-size:0.75rem;">${c.assignedTo}</td>
        <td style="color:var(--text-muted); font-size:0.72rem; font-family:var(--font-mono);">${new Date(c.lastActivity).toLocaleTimeString('en-IN', {hour12:false})}</td>
        <td>
          <button class="btn btn-ghost btn-sm" onclick="event.stopPropagation(); window.DemoMode.openCase('${c.id}')" aria-label="Investigate case ${c.id}">
            <i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i> Investigate
          </button>
        </td>
      </tr>
    `).join('');
  }

  // ── DASHBOARD MAP ────────────────────────────────────────────────────
  function _initDashboardMap() {
    if (state.maps.dashboard) return;

    const mapEl = document.getElementById('dashboard-map');
    if (!mapEl || !window.L) return;

    const map = L.map('dashboard-map', { zoomControl: true, scrollWheelZoom: false, attributionControl: false });
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { attribution: '' }).addTo(map);
    map.setView([25, 40], 2);
    state.maps.dashboard = map;

    // Plot all relay hops from demo cases
    const plotted = new Set();
    DEMO_CASES.forEach(c => {
      c.relayHops.forEach(hop => {
        if (plotted.has(hop.ip)) return;
        plotted.add(hop.ip);

        const color = hop.isTor ? '#ff4757' : hop.abuseScore > 70 ? '#ff6b35' : '#8b5cf6';
        const size = hop.isTor ? 12 : hop.abuseScore > 70 ? 10 : 8;

        const marker = L.circleMarker([hop.lat, hop.lng], {
          radius: size, color, fillColor: color, fillOpacity: 0.7, weight: 2
        }).addTo(map);

        marker.bindPopup(`
          <div style="font-family:Inter,sans-serif; font-size:12px; color:#1a202c;">
            <div style="font-weight:700; margin-bottom:4px;">${hop.ip}</div>
            <div>${hop.city}, ${hop.country}</div>
            <div style="color:#64748b;">${hop.isp}</div>
            <div style="margin-top:6px; font-weight:600; color:${hop.abuseScore > 70 ? '#dc2626' : '#059669'};">
              Abuse Score: ${hop.abuseScore}%${hop.isTor ? ' · TOR EXIT' : ''}
            </div>
          </div>
        `);
      });
    });

    // Draw lines between hops in first case
    const hops = DEMO_CASES[0].relayHops;
    for (let i = 0; i < hops.length - 1; i++) {
      L.polyline([[hops[i].lat, hops[i].lng], [hops[i+1].lat, hops[i+1].lng]], {
        color: '#8b5cf6', weight: 1.5, opacity: 0.5, dashArray: '4 4'
      }).addTo(map);
    }
  }

  // ── DASHBOARD GRAPH ──────────────────────────────────────────────────
  function _initDashboardGraph() {
    if (state.currentCase) {
      _renderDashboardGraph(state.currentCase);
      document.getElementById('db-graph-empty')?.classList.add('hidden');
    }
  }

  function _setDashboardGraphMode(mode) {
    const btn2d = document.getElementById('db-graph-2d');
    const btn3d = document.getElementById('db-graph-3d');
    const graph2d = document.getElementById('dashboard-graph-2d');
    const graph3d = document.getElementById('dashboard-graph-3d');

    if (mode === '3d') {
      btn2d?.setAttribute('aria-pressed', 'false');
      btn3d?.setAttribute('aria-pressed', 'true');
      btn2d?.classList.remove('active');
      btn3d?.classList.add('active');
      if (graph2d) graph2d.style.display = 'none';
      if (graph3d) graph3d.style.display = 'block';
      if (state.currentCase) _render3DGraph('dashboard-graph-3d', state.currentCase);
    } else {
      btn2d?.setAttribute('aria-pressed', 'true');
      btn3d?.setAttribute('aria-pressed', 'false');
      btn2d?.classList.add('active');
      btn3d?.classList.remove('active');
      if (graph2d) graph2d.style.display = 'block';
      if (graph3d) graph3d.style.display = 'none';
    }
  }

  function _renderDashboardGraph(caseData) {
    const container = document.getElementById('dashboard-graph-2d');
    if (!container || !window.d3) return;
    _buildD3Graph('dashboard-graph-2d', caseData, { height: 340 });
  }

  // ── D3 GRAPH ─────────────────────────────────────────────────────────
  function _buildD3Graph(containerId, caseData, opts = {}) {
    const container = document.getElementById(containerId);
    if (!container || !window.d3) return;

    container.innerHTML = '';

    const width = container.offsetWidth || 600;
    const height = opts.height || 460;

    const svg = d3.select(`#${containerId}`)
      .append('svg')
      .attr('width', '100%')
      .attr('height', height)
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('role', 'img')
      .attr('aria-label', `Threat graph for case ${caseData.id}`);

    // Defs for glow
    const defs = svg.append('defs');
    ['blue', 'red', 'orange', 'green'].forEach((name, i) => {
      const colors = ['#8b5cf6', '#ff4757', '#ff6b35', '#2dd4bf'];
      const filter = defs.append('filter').attr('id', `glow-${name}`);
      filter.append('feGaussianBlur').attr('stdDeviation', '3').attr('result', 'coloredBlur');
      const merge = filter.append('feMerge');
      merge.append('feMergeNode').attr('in', 'coloredBlur');
      merge.append('feMergeNode').attr('in', 'SourceGraphic');
    });

    const g = svg.append('g');

    // Zoom
    svg.call(d3.zoom().scaleExtent([0.3, 3]).on('zoom', e => g.attr('transform', e.transform)));

    // Build graph data
    const nodes = [];
    const links = [];
    const added = new Set();

    const addNode = (id, label, type, color, size, info) => {
      if (!added.has(id)) { nodes.push({ id, label, type, color, size, info }); added.add(id); }
    };

    const emailColor = caseData.riskScore >= 75 ? '#ff4757' : '#2dd4bf';
    addNode(caseData.from.email, caseData.from.email, 'EMAIL', emailColor, 18, `Score: ${caseData.riskScore}/100`);
    addNode(caseData.from.domain, caseData.from.domain, 'DOMAIN', '#ff6b35', 14, `Age: ${caseData.domainAge} days`);
    links.push({ source: caseData.from.email, target: caseData.from.domain, rel: 'SENT_FROM' });

    if (caseData.replyTo.domain !== caseData.from.domain) {
      addNode(caseData.replyTo.domain, caseData.replyTo.domain, 'DOMAIN', '#ff8c00', 12, 'Reply-To Hijack');
      links.push({ source: caseData.from.email, target: caseData.replyTo.domain, rel: 'REPLY_HIJACK' });
    }

    caseData.relayHops.forEach((hop, i) => {
      const hc = hop.isTor ? '#ff4757' : hop.abuseScore > 70 ? '#ff6b35' : '#8b5cf6';
      addNode(hop.ip, `${hop.ip}\n${hop.city}`, 'IP', hc, 11, `Abuse: ${hop.abuseScore}%`);
      if (i === 0) links.push({ source: caseData.from.domain, target: hop.ip, rel: 'HOSTED_ON' });
      else links.push({ source: caseData.relayHops[i-1].ip, target: hop.ip, rel: 'RELAY_HOP' });
    });

    caseData.suspiciousUrls.slice(0, 2).forEach((url, i) => {
      const shortUrl = url.replace(/https?:\/\//, '').substring(0, 30) + '…';
      addNode(`url-${i}`, shortUrl, 'URL', '#a78bfa', 11, url);
      links.push({ source: caseData.from.email, target: `url-${i}`, rel: 'CONTAINS' });
    });

    if (caseData.campaignId) {
      addNode(caseData.campaignId, caseData.campaignId, 'CAMPAIGN', '#f59e0b', 13, 'Campaign correlation');
      links.push({ source: caseData.from.email, target: caseData.campaignId, rel: 'PART_OF' });
    }

    // Simulation
    const sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(links).id(d => d.id).distance(80))
      .force('charge', d3.forceManyBody().strength(-220))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide(30));

    // Links
    const link = g.append('g').selectAll('line')
      .data(links).join('line')
      .attr('stroke', d => d.rel === 'RELAY_HOP' ? 'rgba(79,156,249,0.3)' : 'rgba(255,71,87,0.3)')
      .attr('stroke-width', 1.5)
      .attr('stroke-dasharray', d => d.rel === 'REPLY_HIJACK' ? '4 3' : null);

    // Nodes
    const nodeG = g.append('g').selectAll('g')
      .data(nodes).join('g')
      .style('cursor', 'pointer')
      .call(d3.drag()
        .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
        .on('end', (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; })
      );

    // Node circles
    nodeG.append('circle')
      .attr('r', d => d.size)
      .attr('fill', d => d.color + '22')
      .attr('stroke', d => d.color)
      .attr('stroke-width', 2)
      .attr('filter', d => {
        if (d.color === '#ff4757') return 'url(#glow-red)';
        if (d.color === '#8b5cf6') return 'url(#glow-blue)';
        return null;
      });

    // Node icons (using Unicode approximations)
    const typeIcon = { EMAIL: '✉', DOMAIN: '◈', IP: '◎', URL: '⊕', CAMPAIGN: '⬡' };
    nodeG.append('text')
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'central')
      .attr('font-size', d => d.size * 0.8)
      .attr('fill', d => d.color)
      .attr('pointer-events', 'none')
      .text(d => typeIcon[d.type] || '●');

    // Labels
    nodeG.append('text')
      .attr('y', d => d.size + 12)
      .attr('text-anchor', 'middle')
      .attr('font-size', '9')
      .attr('font-family', 'JetBrains Mono, monospace')
      .attr('fill', 'rgba(148,163,184,0.8)')
      .attr('pointer-events', 'none')
      .text(d => d.label.split('\n')[0].substring(0, 22) + (d.label.length > 22 ? '…' : ''));

    // Inspector
    const inspector = document.getElementById(containerId.includes('dashboard') ? 'dashboard-node-inspector' : 'inv-node-inspector');

    nodeG.on('click', (e, d) => {
      e.stopPropagation();
      if (inspector) {
        inspector.classList.remove('hidden');
        inspector.innerHTML = `
          <div class="node-inspector-type">${d.type}</div>
          <div class="node-inspector-title">${d.label}</div>
          <div class="node-inspector-row"><span class="label">Info</span><span class="value">${d.info || '—'}</span></div>
          <div class="node-inspector-row"><span class="label">Connections</span><span class="value">${links.filter(l => l.source.id === d.id || l.target.id === d.id).length}</span></div>
        `;
      }
    });

    svg.on('click', () => { inspector?.classList.add('hidden'); });

    sim.on('tick', () => {
      link
        .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      nodeG.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    // Reset button
    const resetBtn = document.getElementById(containerId.includes('dashboard') ? 'db-graph-reset' : 'inv-graph-reset-btn');
    resetBtn?.addEventListener('click', () => {
      svg.transition().duration(500).call(d3.zoom().transform, d3.zoomIdentity);
    });

    state.d3Graphs[containerId] = { sim, svg };
  }

  // ── 3D GRAPH (Three.js minimal) ───────────────────────────────────────
  function _render3DGraph(containerId, caseData) {
    const container = document.getElementById(containerId);
    if (!container) return;

    // Check reduced motion
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      container.innerHTML = `<div class="empty-state" style="padding:80px 20px;"><i class="fa-solid fa-diagram-project"></i><h3>3D Unavailable</h3><p>Reduced motion is enabled. Switch to 2D view.</p></div>`;
      return;
    }

    container.innerHTML = `
      <canvas id="${containerId}-canvas" style="width:100%; height:100%; display:block;"></canvas>
      <div style="position:absolute; top:12px; left:12px; font-size:0.65rem; color:var(--text-muted); background:rgba(8,12,20,0.8); padding:6px 10px; border-radius:6px; border:1px solid var(--border-subtle);">
        <i class="fa-solid fa-cube" style="color:var(--accent); margin-right:4px;"></i>3D Constellation — Drag to orbit
      </div>
    `;

    // Simple Three.js-like effect using Canvas 2D (no external dependency needed)
    const canvas = document.getElementById(`${containerId}-canvas`);
    if (!canvas) return;
    canvas.width = container.offsetWidth;
    canvas.height = container.offsetHeight;
    const ctx = canvas.getContext('2d');

    // Build 3D nodes
    const nodeTypes = [
      { label: 'EMAIL', x: 0, y: 0, z: 0, color: caseData.riskScore >= 75 ? '#ff4757' : '#2dd4bf', size: 20, fixed: true },
      { label: 'DOMAIN', x: 120, y: -60, z: 40, color: '#ff6b35', size: 14 },
      { label: 'REPLY-TO', x: -100, y: -40, z: 30, color: '#ff8c00', size: 11 },
      ...caseData.relayHops.map((h, i) => ({
        label: `IP ${i+1}`, x: (i-1)*100, y: 80, z: -30 + i*20,
        color: h.isTor ? '#ff4757' : '#8b5cf6', size: 12
      })),
      ...(caseData.suspiciousUrls.slice(0,2).map((u, i) => ({
        label: `URL ${i+1}`, x: 80 + i*60, y: -90, z: 20, color: '#a78bfa', size: 10
      }))),
      ...(caseData.campaignId ? [{ label: caseData.campaignId, x: 0, y: -140, z: -50, color: '#f59e0b', size: 13 }] : []),
    ];

    const edges = [
      [0,1],[0,2],
      ...nodeTypes.slice(3, 3+caseData.relayHops.length).map((_, i) => [i === 0 ? 1 : 3+i-1, 3+i]),
      ...caseData.suspiciousUrls.slice(0,2).map((_, i) => [0, 3+caseData.relayHops.length+i]),
      ...(caseData.campaignId ? [[0, nodeTypes.length-1]] : [])
    ].filter(e => e[0] < nodeTypes.length && e[1] < nodeTypes.length);

    let rotX = 0.2, rotY = 0;
    let isDragging = false, lastX = 0, lastY = 0;
    let animFrame;

    function project(x, y, z) {
      // Rotate around Y
      const cosY = Math.cos(rotY), sinY = Math.sin(rotY);
      const x1 = x * cosY - z * sinY;
      const z1 = x * sinY + z * cosY;
      // Rotate around X
      const cosX = Math.cos(rotX), sinX = Math.sin(rotX);
      const y1 = y * cosX - z1 * sinX;
      const z2 = y * sinX + z1 * cosX;
      // Perspective
      const fov = 400, d = fov / (fov + z2 + 200);
      return { sx: x1 * d + canvas.width/2, sy: y1 * d + canvas.height/2, scale: d };
    }

    function draw3D() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      // Background gradient
      const bg = ctx.createRadialGradient(canvas.width/2, canvas.height/2, 0, canvas.width/2, canvas.height/2, canvas.width/2);
      bg.addColorStop(0, 'rgba(15,23,42,1)');
      bg.addColorStop(1, 'rgba(8,12,20,1)');
      ctx.fillStyle = bg;
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      // Project nodes
      const projected = nodeTypes.map(n => ({ ...n, ...project(n.x, n.y, n.z) }));

      // Draw edges
      edges.forEach(([ai, bi]) => {
        if (!projected[ai] || !projected[bi]) return;
        const a = projected[ai], b = projected[bi];
        ctx.beginPath();
        ctx.moveTo(a.sx, a.sy);
        ctx.lineTo(b.sx, b.sy);
        ctx.strokeStyle = 'rgba(79,156,249,0.2)';
        ctx.lineWidth = 1;
        ctx.stroke();
      });

      // Sort by z for painter's algorithm
      const sorted = [...projected].sort((a,b) => b.z - a.z);

      // Draw nodes
      sorted.forEach(n => {
        const r = n.size * n.scale;

        // Glow
        const grd = ctx.createRadialGradient(n.sx, n.sy, 0, n.sx, n.sy, r * 3);
        grd.addColorStop(0, n.color + '33');
        grd.addColorStop(1, 'transparent');
        ctx.beginPath();
        ctx.arc(n.sx, n.sy, r * 3, 0, Math.PI * 2);
        ctx.fillStyle = grd;
        ctx.fill();

        // Node
        ctx.beginPath();
        ctx.arc(n.sx, n.sy, r, 0, Math.PI * 2);
        ctx.fillStyle = n.color + '22';
        ctx.fill();
        ctx.strokeStyle = n.color;
        ctx.lineWidth = 2 * n.scale;
        ctx.stroke();

        // Label
        if (n.scale > 0.6) {
          ctx.font = `${Math.max(8, 10 * n.scale)}px JetBrains Mono, monospace`;
          ctx.fillStyle = 'rgba(148,163,184,0.9)';
          ctx.textAlign = 'center';
          ctx.fillText(n.label, n.sx, n.sy + r + 12 * n.scale);
        }
      });

      // Auto-rotate slowly
      if (!isDragging) rotY += 0.004;

      animFrame = requestAnimationFrame(draw3D);
    }

    canvas.addEventListener('mousedown', e => { isDragging = true; lastX = e.clientX; lastY = e.clientY; });
    canvas.addEventListener('mousemove', e => {
      if (!isDragging) return;
      rotY += (e.clientX - lastX) * 0.008;
      rotX += (e.clientY - lastY) * 0.008;
      rotX = Math.max(-1.2, Math.min(1.2, rotX));
      lastX = e.clientX; lastY = e.clientY;
    });
    canvas.addEventListener('mouseup', () => { isDragging = false; });
    canvas.addEventListener('mouseleave', () => { isDragging = false; });

    // Touch support
    canvas.addEventListener('touchstart', e => { isDragging = true; lastX = e.touches[0].clientX; lastY = e.touches[0].clientY; });
    canvas.addEventListener('touchmove', e => {
      if (!isDragging) return;
      rotY += (e.touches[0].clientX - lastX) * 0.008;
      rotX += (e.touches[0].clientY - lastY) * 0.008;
      lastX = e.touches[0].clientX; lastY = e.touches[0].clientY;
    });
    canvas.addEventListener('touchend', () => { isDragging = false; });

    // Stop when tab hidden
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) cancelAnimationFrame(animFrame);
      else if (container.style.display !== 'none') animFrame = requestAnimationFrame(draw3D);
    });

    draw3D();
  }

  // ── ANALYSIS PIPELINE ─────────────────────────────────────────────────
  const PIPELINE_STEPS = [
    { id: 'acquire',    label: 'Evidence acquired',           duration: 600 },
    { id: 'parse',      label: 'Email structure parsed',       duration: 800 },
    { id: 'headers',    label: 'Header forensics',             duration: 900 },
    { id: 'auth',       label: 'Authentication validation',    duration: 700 },
    { id: 'urls',       label: 'URLs extracted & analyzed',    duration: 1000 },
    { id: 'domain',     label: 'Domain intelligence',          duration: 900 },
    { id: 'ip',         label: 'IP infrastructure analysis',   duration: 1100 },
    { id: 'ai',         label: 'AI threat classification',     duration: 1400 },
    { id: 'correlate',  label: 'Threat correlation engine',    duration: 800 },
    { id: 'risk',       label: 'Risk assessment computed',     duration: 600 },
    { id: 'report',     label: 'Forensic report generated',    duration: 500 },
  ];

  function _runAnalysisPipeline(caseData) {
    // Show pipeline section
    document.getElementById('analyze-upload-section')?.classList.add('hidden');
    document.getElementById('analyze-pipeline-section')?.classList.remove('hidden');
    document.getElementById('analyze-results-section')?.classList.add('hidden');

    const subjectEl = document.getElementById('pipeline-subject');
    if (subjectEl) subjectEl.textContent = caseData.subject;

    const stepsContainer = document.getElementById('pipeline-steps');
    if (!stepsContainer) return;

    // Render steps
    stepsContainer.innerHTML = PIPELINE_STEPS.map((s, i) => `
      <div class="pipeline-step pending" id="step-${s.id}" role="listitem" aria-label="Step ${i+1}: ${s.label}">
        <div class="pipeline-step-num" aria-hidden="true">${String(i+1).padStart(2,'0')}</div>
        <div class="pipeline-step-name">${s.label}</div>
        <div class="pipeline-step-icon">
          <i class="fa-solid fa-circle step-icon-pending" id="step-icon-${s.id}" aria-hidden="true"></i>
        </div>
      </div>
    `).join('');

    // Live preview updates
    const preview = document.getElementById('live-preview-area');
    const eta = document.getElementById('analysis-eta-display');

    // Execute steps sequentially
    let cumDelay = 0;
    PIPELINE_STEPS.forEach((step, idx) => {
      // Activate
      setTimeout(() => {
        const el = document.getElementById(`step-${step.id}`);
        const icon = document.getElementById(`step-icon-${step.id}`);
        if (el) { el.classList.remove('pending'); el.classList.add('active'); el.setAttribute('aria-label', `Step ${idx+1}: ${step.label} - in progress`); }
        if (icon) icon.className = 'fa-solid fa-circle-notch step-icon-active';

        // Update preview
        if (preview) {
          const updates = {
            acquire: `<div style="font-family:var(--font-mono); font-size:0.72rem; color:var(--text-muted);">SHA-256: ${caseData.evidence?.[0]?.sha256?.substring(0,32) || 'a3f9...'}...</div>`,
            auth: `<div style="font-size:0.78rem;">SPF: <span style="color:${caseData.auth.spf === 'PASS' ? 'var(--green)' : 'var(--sev-critical)'}">${caseData.auth.spf}</span> · DKIM: <span style="color:${caseData.auth.dkim === 'PASS' ? 'var(--green)' : 'var(--sev-critical)'}">${caseData.auth.dkim}</span> · DMARC: <span style="color:${caseData.auth.dmarc === 'PASS' ? 'var(--green)' : 'var(--sev-critical)'}">${caseData.auth.dmarc}</span></div>`,
            domain: `<div style="font-size:0.78rem;">Domain age: <span style="color:${caseData.domainAge < 30 ? 'var(--sev-critical)' : 'var(--green)'};">${caseData.domainAge} days</span> · Lookalike: ${caseData.isLookalike ? '<span style="color:var(--sev-critical);">DETECTED</span>' : '<span style="color:var(--green);">Clean</span>'}</div>`,
            ai: `<div style="font-size:0.78rem;">Classification: <span style="color:${caseData.riskScore >= 75 ? 'var(--sev-critical)' : 'var(--green)'};font-weight:700;">${caseData.type}</span> · Confidence: ${caseData.confidence}%</div>`,
          };
          if (updates[step.id]) preview.innerHTML = updates[step.id];
        }

        const remaining = PIPELINE_STEPS.slice(idx+1).reduce((a,s) => a + s.duration, 0);
        if (eta) eta.textContent = `Estimated completion: ${(remaining/1000).toFixed(1)}s`;

      }, cumDelay);

      // Complete
      setTimeout(() => {
        const el = document.getElementById(`step-${step.id}`);
        const icon = document.getElementById(`step-icon-${step.id}`);
        if (el) { el.classList.remove('active'); el.classList.add('done'); el.setAttribute('aria-label', `Step ${idx+1}: ${step.label} - complete`); }
        if (icon) icon.className = 'fa-solid fa-check-circle step-icon-done';
      }, cumDelay + step.duration);

      cumDelay += step.duration;
    });

    // After all steps complete
    setTimeout(() => {
      state.currentCase = caseData;
      document.getElementById('analyze-pipeline-section')?.classList.add('hidden');
      document.getElementById('analyze-results-section')?.classList.remove('hidden');
      _renderResults(caseData);
      showToast(`Analysis complete — ${caseData.type} detected (Score: ${caseData.riskScore}/100)`, caseData.riskScore >= 75 ? 'danger' : 'success', 5000);
    }, cumDelay + 400);
  }

  // ── INVESTIGATION RESULTS ─────────────────────────────────────────────
  function _renderResults(caseData) {
    _renderInvHeader(caseData);
    _showInvTab('overview');
    _renderOverviewTab(caseData);
  }

  function _renderInvHeader(c) {
    const area = document.getElementById('inv-header-area');
    if (!area) return;

    area.innerHTML = `
      <div>
        <div class="inv-case-id">${c.id} · ${formatTime(c.createdAt)} IST</div>
        <div class="inv-title">${c.subject}</div>
        <div class="inv-meta">
          <span class="threat-tier ${c.severity}">${getThreatLabel(c)} · ${c.riskScore}/100</span>
          <span class="inv-meta-item"><i class="fa-solid fa-percent" aria-hidden="true"></i>${c.confidence}% confidence</span>
          <span class="inv-meta-item"><i class="fa-solid fa-circle-half-stroke" aria-hidden="true"></i>${c.status}</span>
          <span class="inv-meta-item"><i class="fa-solid fa-user" aria-hidden="true"></i>${c.assignedTo}</span>
          ${c.campaignId ? `<span class="sev-tag medium">${c.campaignId}</span>` : ''}
        </div>
      </div>
      <div class="inv-actions">
        <button class="btn btn-danger btn-sm" onclick="showToast('Case escalated — senior analyst notified', 'warn')" aria-label="Escalate case">
          <i class="fa-solid fa-arrow-up" aria-hidden="true"></i> Escalate
        </button>
        <button class="btn btn-secondary btn-sm" onclick="showToast('Marked as false positive — analyst review required', 'info')" aria-label="Mark as false positive">
          <i class="fa-solid fa-thumbs-down" aria-hidden="true"></i> False Positive
        </button>
        <button class="btn btn-secondary btn-sm" onclick="window.showInvTabGlobal('report')" aria-label="Generate forensic report">
          <i class="fa-solid fa-file-lines" aria-hidden="true"></i> Report
        </button>
      </div>
    `;
  }

  window.showInvTabGlobal = _showInvTab;
  window.showToast = showToast;

  function _showInvTab(tabId) {
    document.querySelectorAll('.tab-btn[data-inv-tab]').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.invTab === tabId);
      btn.setAttribute('aria-selected', btn.dataset.invTab === tabId);
    });
    document.querySelectorAll('.inv-tab-pane').forEach(pane => {
      pane.style.display = pane.id === `inv-${tabId}` ? 'block' : 'none';
    });

    state.activeInvTab = tabId;

    // Lazy-initialize tab content
    const c = state.currentCase;
    if (!c) return;

    if (tabId === 'email') _renderEmailTab(c);
    if (tabId === 'ai') _renderAITab(c);
    if (tabId === 'headers') _renderHeadersTab(c);
    if (tabId === 'urls') _renderUrlsTab(c);
    if (tabId === 'relay') _renderRelayTab(c);
    if (tabId === 'geo') _renderGeoTab(c);
    if (tabId === 'graph') _renderGraphTab(c);
    if (tabId === 'timeline') _renderTimelineTab(c);
    if (tabId === 'evidence') _renderEvidenceTab(c);
    if (tabId === 'report') _renderReportTab(c);
  }

  // Wire investigation tabs
  document.querySelectorAll('.tab-btn[data-inv-tab]').forEach(btn => {
    btn.addEventListener('click', () => _showInvTab(btn.dataset.invTab));
  });

  // ── OVERVIEW TAB ──────────────────────────────────────────────────────
  function _renderOverviewTab(c) {
    // Risk gauge
    const circle = document.getElementById('risk-gauge-circle');
    const scoreEl = document.getElementById('risk-score-num');
    const tierEl = document.getElementById('risk-score-tier');
    const summaryEl = document.getElementById('risk-summary-text');
    const tierBadge = document.getElementById('threat-tier-badge');

    if (circle) {
      const pct = c.riskScore / 100;
      const circumference = 427;
      const offset = circumference - pct * circumference;
      const gaugeColor = c.severity === 'critical' ? 'var(--sev-critical)' : c.severity === 'high' ? 'var(--sev-high)' : c.severity === 'safe' ? 'var(--sev-safe)' : 'var(--sev-medium)';
      circle.style.strokeDashoffset = offset;
      circle.style.stroke = gaugeColor;
    }

    if (scoreEl) { scoreEl.textContent = c.riskScore; scoreEl.style.color = severityColor(c.severity); }
    if (tierEl) tierEl.textContent = c.type;
    if (summaryEl) summaryEl.textContent = c.story.split('\n\n')[0].substring(0, 160) + '…';
    if (tierBadge) {
      tierBadge.innerHTML = `<span class="threat-tier ${c.severity}">${getThreatLabel(c)}</span>`;
    }

    // Authentication
    const authPanel = document.getElementById('auth-panel');
    if (authPanel) {
      authPanel.innerHTML = `
        <div class="auth-row"><span class="auth-protocol">SPF</span><span class="auth-status ${c.auth.spf.toLowerCase()}">${c.auth.spf}</span></div>
        <div class="auth-row"><span class="auth-protocol">DKIM</span><span class="auth-status ${c.auth.dkim.toLowerCase()}">${c.auth.dkim}</span></div>
        <div class="auth-row"><span class="auth-protocol">DMARC</span><span class="auth-status ${c.auth.dmarc.toLowerCase()}">${c.auth.dmarc}</span></div>
        <div style="margin-top:14px; padding-top:14px; border-top:1px solid var(--border-subtle);">
          <div style="font-size:0.68rem; text-transform:uppercase; letter-spacing:0.1em; color:var(--text-muted); margin-bottom:8px;">Why This Matters</div>
          <p style="font-size:0.78rem; color:var(--text-secondary); line-height:1.6;">
            ${c.auth.spf === 'FAIL' && c.auth.dkim === 'FAIL' && c.auth.dmarc === 'FAIL'
              ? 'All three authentication checks failed. The email is NOT authorized by the claimed domain. This is a strong indicator of spoofing or phishing.'
              : c.auth.spf === 'PASS' && c.auth.dkim === 'PASS' && c.auth.dmarc === 'PASS'
              ? 'All authentication checks passed. The email is authorized by the claimed sending domain.'
              : 'Partial authentication failure detected. The email does not fully satisfy the domain owner\'s authentication policy.'}
          </p>
        </div>
      `;
    }

    // Danger Reasons
    const dangerList = document.getElementById('danger-reasons-list');
    if (dangerList) {
      if (c.dangerReasons.length === 0) {
        dangerList.innerHTML = `<div class="empty-state" style="padding:32px;"><i class="fa-solid fa-check-circle" style="color:var(--sev-safe);"></i><h3>No Threats Detected</h3><p>This email passed all security checks.</p></div>`;
        document.getElementById('why-dangerous-card').querySelector('.card-title span').textContent = 'WHY THIS EMAIL IS SAFE';
        document.getElementById('why-dangerous-card').querySelector('.card-title i').style.color = 'var(--sev-safe)';
        document.getElementById('why-dangerous-card').querySelector('.card-title i').className = 'fa-solid fa-check-circle';
      } else {
        dangerList.innerHTML = c.dangerReasons.map((r, i) => `
          <div class="danger-item animate-slide-up" style="animation-delay:${i*80}ms" role="listitem">
            <div class="danger-num">0${i+1}</div>
            <div class="danger-text"><strong>${r.title}</strong>${r.detail}</div>
            <i class="fa-solid fa-chevron-right" style="color:var(--sev-critical); opacity:0.6;" aria-hidden="true"></i>
          </div>
        `).join('');
      }
    }

    // Signal Breakdown
    const sigPanel = document.getElementById('signal-breakdown-panel');
    if (sigPanel) {
      const total = c.scoreBreakdown.reduce((a, b) => a + b.score, 0);
      sigPanel.innerHTML = c.scoreBreakdown.map((s, i) => `
        <div class="signal-row animate-slide-up" style="animation-delay:${i*60}ms">
          <div class="signal-label">${s.label}</div>
          <div class="signal-bar-wrap">
            <div class="signal-bar" style="width:${(s.score/30*100)}%; background:${s.score >= 20 ? 'var(--sev-critical)' : s.score >= 12 ? 'var(--sev-high)' : 'var(--accent)'};"></div>
          </div>
          <div class="signal-weight">+${s.score}</div>
        </div>
      `).join('') + `
        <div style="display:flex; justify-content:flex-end; padding-top:10px; border-top:1px solid var(--border-subtle); margin-top:8px; font-weight:700; font-size:0.85rem; color:${severityColor(c.severity)};">
          TOTAL: ${c.riskScore} / 100
        </div>
      `;
    }

    // Confidence
    const confPanel = document.getElementById('confidence-panel');
    if (confPanel) {
      const confidences = [
        { label: `${c.type} Classification`, pct: c.confidence },
        { label: 'Source Infrastructure', pct: Math.round(c.confidence * 0.85) },
        { label: 'Domain Correlation', pct: Math.round(c.confidence * 0.94) },
        { label: 'Campaign Relationship', pct: c.campaignId ? 72 : 0 },
        { label: 'Authentication Evidence', pct: c.auth.spf === 'FAIL' ? 98 : 45 },
      ];
      confPanel.innerHTML = confidences.map(conf => `
        <div class="confidence-row">
          <div class="confidence-label">${conf.label}</div>
          <div class="confidence-track"><div class="confidence-fill" style="width:${conf.pct}%;"></div></div>
          <div class="confidence-pct">${conf.pct}%</div>
        </div>
      `).join('');
    }

    // Story
    const storyEl = document.getElementById('story-text');
    const storySection = document.getElementById('inv-story-section');
    if (storyEl && storySection) {
      storySection.classList.remove('hidden');
      storyEl.innerHTML = c.story.split('\n\n').map(p => `<p>${p}</p>`).join('');
    }
  }

  // ── EMAIL TAB ─────────────────────────────────────────────────────────
  function _renderEmailTab(c) {
    const panel = document.getElementById('email-meta-panel');
    if (!panel) return;

    const metaRows = [
      { label: 'From',        val: `${c.from.name} &lt;${c.from.email}&gt;` },
      { label: 'To',          val: c.to },
      { label: 'Subject',     val: c.subject },
      { label: 'Date',        val: formatTime(c.createdAt) },
      { label: 'Message-ID',  val: `<span class="mono">${c.messageId}</span>` },
      { label: 'Reply-To',    val: `<span class="mono ${c.replyTo.domain !== c.from.domain ? 'text-critical' : ''}">${c.replyTo.email}</span>${c.replyTo.domain !== c.from.domain ? ' <span class="sev-tag critical" style="font-size:0.58rem;">MISMATCH</span>' : ''}` },
      { label: 'Return-Path', val: `<span class="mono">${c.returnPath.email}</span>` },
      { label: 'Domain Age',  val: `<span class="${c.domainAge < 30 ? 'text-critical' : 'text-safe'}">${c.domainAge} days ${c.domainAge < 30 ? '(Newly registered — HIGH RISK)' : '(Established)'}</span>` },
    ];

    panel.innerHTML = metaRows.map(r => `
      <div class="auth-row">
        <span class="auth-protocol" style="min-width:100px;">${r.label}</span>
        <span style="font-size:0.78rem; color:var(--text-secondary); word-break:break-all;">${r.val}</span>
      </div>
    `).join('');

    const rawEl = document.getElementById('raw-headers-display');
    if (rawEl) rawEl.textContent = c.rawEmail;
  }

  // ── AI TAB ────────────────────────────────────────────────────────────
  function _renderAITab(c) {
    const panel = document.getElementById('ai-analysis-panel');
    if (!panel) return;

    const sevStyle = c.severity === 'critical' ? 'background:var(--sev-critical-dim); color:var(--sev-critical); border:1px solid var(--sev-critical-border);' : c.severity === 'safe' ? 'background:var(--sev-safe-dim); color:var(--sev-safe); border:1px solid var(--sev-safe-border);' : 'background:var(--sev-high-dim); color:var(--sev-high); border:1px solid var(--sev-high-border);';

    panel.innerHTML = `
      <div style="margin-bottom:20px;">
        <div style="font-size:0.68rem; letter-spacing:0.12em; text-transform:uppercase; color:var(--purple); margin-bottom:10px;">CLASSIFICATION</div>
        <div class="ai-classification-badge" style="${sevStyle}">
          <i class="fa-solid fa-brain" aria-hidden="true"></i>
          ${c.type} — ${c.confidence}% confidence
        </div>
        <div style="font-size:0.72rem; color:var(--text-muted); margin-top:6px; font-style:italic;">
          Classification was influenced by the following factors — human analyst review required for final determination
        </div>
      </div>

      <div style="margin-bottom:20px;">
        <div style="font-size:0.68rem; letter-spacing:0.12em; text-transform:uppercase; color:var(--purple); margin-bottom:10px;">MAJOR CONTRIBUTING FACTORS</div>
        <div class="ai-features">
          ${c.aiFeatures.map(f => `
            <div class="ai-feature">
              <i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i>
              <span>${f}</span>
            </div>
          `).join('')}
        </div>
      </div>

      <div>
        <div style="font-size:0.68rem; letter-spacing:0.12em; text-transform:uppercase; color:var(--purple); margin-bottom:10px;">MODEL INFORMATION</div>
        <div class="ai-model-meta">
          <div>
            <div class="ai-model-field">Model</div>
            <div class="ai-model-value">${c.aiModel.name}</div>
          </div>
          <div>
            <div class="ai-model-field">Version</div>
            <div class="ai-model-value">${c.aiModel.version}</div>
          </div>
          <div>
            <div class="ai-model-field">Dataset</div>
            <div class="ai-model-value">${c.aiModel.dataset}</div>
          </div>
          <div>
            <div class="ai-model-field">Threshold</div>
            <div class="ai-model-value">${c.aiModel.threshold}</div>
          </div>
        </div>

        <div style="margin-top:16px; padding:12px 14px; background:var(--sev-unknown-dim); border:1px solid rgba(107,114,128,0.2); border-radius:8px; font-size:0.75rem; color:var(--text-muted); line-height:1.6;">
          <strong style="color:var(--text-secondary);">⚠ Limitations:</strong> This AI classification is based on pattern matching and probabilistic analysis. SPF/DKIM/DMARC results are cryptographic facts — the AI does not override them. All conclusions should be verified by a qualified analyst. Never use AI output alone for legal proceedings.
        </div>
      </div>
    `;
  }

  // ── HEADERS TAB ───────────────────────────────────────────────────────
  function _renderHeadersTab(c) {
    const panel = document.getElementById('headers-analysis-panel');
    if (!panel) return;
    panel.innerHTML = `
      <div class="card-header"><div class="card-title"><i class="fa-solid fa-code" aria-hidden="true"></i><span>Header Analysis</span></div></div>
      <div class="card-body">
        <div class="auth-row"><span class="auth-protocol">SPF</span><span class="auth-status ${c.auth.spf.toLowerCase()}">${c.auth.spf}</span><span style="font-size:0.72rem; color:var(--text-muted);">Sender Policy Framework — verifies sending IP is authorized</span></div>
        <div class="auth-row"><span class="auth-protocol">DKIM</span><span class="auth-status ${c.auth.dkim.toLowerCase()}">${c.auth.dkim}</span><span style="font-size:0.72rem; color:var(--text-muted);">DomainKeys Identified Mail — cryptographic signature</span></div>
        <div class="auth-row"><span class="auth-protocol">DMARC</span><span class="auth-status ${c.auth.dmarc.toLowerCase()}">${c.auth.dmarc}</span><span style="font-size:0.72rem; color:var(--text-muted);">Domain-based Message Authentication — policy enforcement</span></div>
        <div class="auth-row"><span class="auth-protocol" style="min-width:130px;">Return-Path Match</span><span class="auth-status ${c.returnPath.domain === c.from.domain ? 'pass' : 'fail'}">${c.returnPath.domain === c.from.domain ? 'ALIGNED' : 'MISMATCH'}</span><span style="font-size:0.72rem; color:var(--text-muted);">Return-Path domain vs From domain</span></div>
        <div class="auth-row"><span class="auth-protocol" style="min-width:130px;">Reply-To Match</span><span class="auth-status ${c.replyTo.domain === c.from.domain ? 'pass' : 'fail'}">${c.replyTo.domain === c.from.domain ? 'ALIGNED' : 'HIJACKED'}</span><span style="font-size:0.72rem; color:var(--text-muted);">Reply-To domain vs From domain — hijack indicator</span></div>
        <div class="auth-row"><span class="auth-protocol" style="min-width:130px;">Domain Age</span><span class="auth-status ${c.domainAge < 30 ? 'fail' : 'pass'}">${c.domainAge < 30 ? `${c.domainAge} DAYS` : 'ESTABLISHED'}</span><span style="font-size:0.72rem; color:var(--text-muted);">${c.domainAge} days since registration</span></div>
        <div class="auth-row"><span class="auth-protocol" style="min-width:130px;">Lookalike Domain</span><span class="auth-status ${c.isLookalike ? 'fail' : 'pass'}">${c.isLookalike ? 'DETECTED' : 'CLEAR'}</span><span style="font-size:0.72rem; color:var(--text-muted);">${c.isLookalike ? `${c.lookalikeMethod} — targeting ${c.lookalikeTarget}` : 'No lookalike pattern detected'}</span></div>
      </div>
    `;
  }

  // ── URLS TAB ──────────────────────────────────────────────────────────
  function _renderUrlsTab(c) {
    const content = document.getElementById('urls-content');
    if (!content) return;

    if (c.suspiciousUrls.length === 0) {
      content.innerHTML = `<div class="empty-state" style="padding:40px;"><i class="fa-solid fa-link-slash" aria-hidden="true"></i><h3>No Suspicious URLs</h3><p>No malicious or suspicious URLs detected in this email.</p></div>`;
      return;
    }

    content.innerHTML = c.suspiciousUrls.map((url, i) => `
      <div style="padding:14px 18px; border-bottom:1px solid var(--border-subtle);">
        <div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
          <span class="sev-tag critical">SUSPICIOUS</span>
          <span style="font-family:var(--font-mono); font-size:0.72rem; color:var(--text-secondary); word-break:break-all;">${url}</span>
        </div>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; font-size:0.75rem; color:var(--text-muted);">
          <div><strong>Assessment:</strong> Credential harvesting / malicious redirect</div>
          <div><strong>Domain:</strong> ${url.split('/')[2]}</div>
          <div><strong>Risk:</strong> <span style="color:var(--sev-critical);">HIGH — Do not visit</span></div>
          <div><strong>Defanged:</strong> <span class="mono">${url.replace('://', '[://]')}</span></div>
        </div>
      </div>
    `).join('');
  }

  // ── RELAY TAB ────────────────────────────────────────────────────────
  function _renderRelayTab(c) {
    const container = document.getElementById('relay-chain-container');
    if (!container) return;

    container.innerHTML = `
      <div class="relay-chain" role="list" aria-label="SMTP relay chain">
        <div class="relay-node" style="opacity:0.6;" role="listitem">
          <div class="relay-node-icon" style="background:var(--sev-unknown-dim); color:var(--text-muted);">
            <i class="fa-solid fa-laptop" aria-hidden="true"></i>
          </div>
          <div>
            <div class="relay-node-label">Mail Client / Attacker</div>
            <div class="relay-node-sub">Origin — masked</div>
          </div>
        </div>
        ${c.relayHops.map((hop, i) => `
          <div style="position:relative;">
            <div style="position:absolute; left:17px; top:-12px; width:2px; height:12px; background:linear-gradient(var(--border-default),transparent);"></div>
            <div class="relay-node" data-hop="${i}" role="listitem" tabindex="0" aria-label="Relay ${hop.hop}: ${hop.ip}, ${hop.city}, ${hop.country}">
              <div class="relay-node-icon" style="background:${hop.isTor ? 'var(--sev-critical-dim)' : hop.abuseScore > 70 ? 'var(--sev-high-dim)' : 'var(--accent-dim)'}; color:${hop.isTor ? 'var(--sev-critical)' : hop.abuseScore > 70 ? 'var(--sev-high)' : 'var(--accent)'};">
                <i class="fa-solid fa-server" aria-hidden="true"></i>
              </div>
              <div>
                <div class="relay-node-label">
                  Relay ${hop.hop} — ${hop.isTor ? '⚠ TOR EXIT' : hop.abuseScore > 70 ? '⚠ HIGH RISK' : 'Infrastructure'}
                </div>
                <div class="relay-node-sub">${hop.ip} · ${hop.city}, ${hop.country}</div>
                <div class="relay-node-sub">${hop.isp}</div>
              </div>
              <span class="sev-tag ${hop.isTor ? 'critical' : hop.abuseScore > 70 ? 'high' : 'low'}" style="margin-left:auto;">${hop.abuseScore}%</span>
            </div>
          </div>
        `).join('')}
        <div style="position:relative;">
          <div style="position:absolute; left:17px; top:-12px; width:2px; height:12px; background:linear-gradient(var(--border-default),transparent);"></div>
          <div class="relay-node" style="background:var(--sev-safe-dim); border:1px solid var(--sev-safe-border); border-radius:8px;">
            <div class="relay-node-icon" style="background:var(--sev-safe-dim); color:var(--sev-safe);">
              <i class="fa-solid fa-inbox" aria-hidden="true"></i>
            </div>
            <div>
              <div class="relay-node-label">Recipient Mailbox</div>
              <div class="relay-node-sub">Earliest Reliable Observed Node</div>
            </div>
          </div>
        </div>
      </div>
    `;

    // Relay node click handler
    container.querySelectorAll('.relay-node[data-hop]').forEach(el => {
      const onClick = () => {
        const hop = c.relayHops[parseInt(el.dataset.hop)];
        const detail = document.getElementById('relay-node-detail-content');
        if (!detail || !hop) return;
        detail.innerHTML = `
          <div class="node-inspector-type">RELAY HOP ${hop.hop}</div>
          <div class="node-inspector-title">${hop.ip}</div>
          <div class="node-inspector-row"><span class="label">City</span><span class="value">${hop.city}</span></div>
          <div class="node-inspector-row"><span class="label">Country</span><span class="value">${hop.country}</span></div>
          <div class="node-inspector-row"><span class="label">ISP</span><span class="value">${hop.isp}</span></div>
          <div class="node-inspector-row"><span class="label">Abuse Score</span><span class="value" style="color:${hop.abuseScore>70?'var(--sev-critical)':'var(--green)'};">${hop.abuseScore}%</span></div>
          <div class="node-inspector-row"><span class="label">Tor Exit</span><span class="value" style="color:${hop.isTor?'var(--sev-critical)':'var(--green)'};">${hop.isTor ? '⚠ YES' : 'No'}</span></div>
          <div class="node-inspector-row"><span class="label">VPN/Proxy</span><span class="value">${hop.isVpn ? 'YES' : 'No'}</span></div>
          <div class="node-inspector-row"><span class="label">Timestamp</span><span class="value">${hop.timestamp || '—'}</span></div>
          <div style="margin-top:10px; padding-top:10px; border-top:1px solid var(--border-subtle); font-size:0.68rem; color:var(--amber); font-style:italic;">
            ⚠ Probable infrastructure location — not attacker physical location
          </div>
        `;
      };
      el.addEventListener('click', onClick);
      el.addEventListener('keydown', e => { if (e.key === 'Enter') onClick(); });
    });
  }

  // ── GEO TAB ──────────────────────────────────────────────────────────
  function _renderGeoTab(c) {
    if (state.maps.geo) {
      state.maps.geo.remove();
      delete state.maps.geo;
    }

    const mapEl = document.getElementById('geo-trace-map');
    if (!mapEl || !window.L) return;

    setTimeout(() => {
      const map = L.map('geo-trace-map', { zoomControl: true, attributionControl: false });
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);
      state.maps.geo = map;

      const coords = c.relayHops.map(h => [h.lat, h.lng]);
      if (coords.length === 0) return;

      // Fit to hops
      map.fitBounds(coords, { padding: [40, 40] });

      // Animated path
      let pathCoords = [coords[0]];
      const polyline = L.polyline(pathCoords, { color: '#8b5cf6', weight: 2.5, opacity: 0.7, dashArray: '6 4' }).addTo(map);

      c.relayHops.forEach((hop, i) => {
        setTimeout(() => {
          pathCoords.push([hop.lat, hop.lng]);
          polyline.setLatLngs([...pathCoords]);

          const color = hop.isTor ? '#ff4757' : hop.abuseScore > 70 ? '#ff6b35' : '#8b5cf6';
          const marker = L.circleMarker([hop.lat, hop.lng], {
            radius: hop.isTor ? 12 : 9, color, fillColor: color, fillOpacity: 0.7, weight: 2
          }).addTo(map);

          marker.bindPopup(`
            <div style="font-family:Inter,sans-serif; font-size:12px;">
              <div style="font-weight:700; color:${color};">${hop.isTor ? '⚠ TOR EXIT NODE' : `Relay ${hop.hop}`}</div>
              <div style="margin:4px 0;"><strong>${hop.ip}</strong></div>
              <div>${hop.city}, ${hop.country}</div>
              <div style="color:#64748b; font-size:11px;">${hop.isp}</div>
              <div style="margin-top:6px; font-weight:600; color:${hop.abuseScore>70?'#dc2626':'#059669'};">Abuse: ${hop.abuseScore}%</div>
            </div>
          `);
        }, i * 400);
      });

      // Geo details
      const details = document.getElementById('geo-details-panel');
      if (details) {
        details.innerHTML = `
          <div style="font-size:0.68rem; letter-spacing:0.1em; text-transform:uppercase; color:var(--text-muted); margin-bottom:10px;">Relay Infrastructure</div>
          ${c.relayHops.map((hop, i) => `
            <div style="display:flex; align-items:center; gap:12px; padding:10px 0; border-bottom:1px solid var(--border-subtle);">
              <span class="sev-tag ${hop.isTor ? 'critical' : hop.abuseScore > 70 ? 'high' : 'info'}">HOP ${hop.hop}</span>
              <div style="flex:1;">
                <div class="mono" style="font-size:0.78rem; color:var(--text-primary);">${hop.ip}</div>
                <div style="font-size:0.72rem; color:var(--text-muted); margin-top:2px;">${hop.city}, ${hop.country} · ${hop.isp}</div>
              </div>
              <div style="text-align:right; font-size:0.72rem; color:${hop.abuseScore>70?'var(--sev-critical)':'var(--text-muted)'};">${hop.abuseScore}% abuse${hop.isTor ? ' · TOR' : ''}</div>
            </div>
          `).join('')}
          <div style="margin-top:12px; padding:10px; background:rgba(245,158,11,0.06); border:1px solid rgba(245,158,11,0.2); border-radius:6px; font-size:0.72rem; color:var(--amber);">
            ⚠ Geographic data indicates probable infrastructure location only — not attacker physical location. Infrastructure may be hosted in compromised systems, VPNs, or shared hosting.
          </div>
        `;
      }
    }, 100);
  }

  // ── GRAPH TAB ────────────────────────────────────────────────────────
  function _renderGraphTab(c) {
    setTimeout(() => {
      _buildD3Graph('inv-graph-2d', c, { height: 480 });
    }, 100);

    document.getElementById('inv-graph-2d-btn')?.addEventListener('click', () => {
      document.getElementById('inv-graph-2d').style.display = 'block';
      document.getElementById('inv-graph-3d').style.display = 'none';
      document.getElementById('inv-graph-2d-btn').classList.add('active');
      document.getElementById('inv-graph-3d-btn').classList.remove('active');
    });

    document.getElementById('inv-graph-3d-btn')?.addEventListener('click', () => {
      document.getElementById('inv-graph-2d').style.display = 'none';
      document.getElementById('inv-graph-3d').style.display = 'block';
      document.getElementById('inv-graph-2d-btn').classList.remove('active');
      document.getElementById('inv-graph-3d-btn').classList.add('active');
      _render3DGraph('inv-graph-3d', c);
    });
  }

  // ── TIMELINE TAB ─────────────────────────────────────────────────────
  function _renderTimelineTab(c) {
    const panel = document.getElementById('timeline-panel');
    if (!panel) return;

    const events = [
      ...c.custody.map(e => ({ time: e.time, action: e.action, actor: e.actor, type: 'system' })),
      { time: new Date(c.lastActivity).toLocaleTimeString('en-IN', {hour12:false}), action: `Analysis status: ${c.status}`, actor: c.assignedTo, type: 'analyst' },
    ].sort((a, b) => a.time.localeCompare(b.time));

    panel.innerHTML = events.map(e => `
      <div class="custody-event" role="listitem">
        <div class="custody-dot" style="border-color:${e.type==='analyst'?'var(--purple)':'var(--accent)'};" aria-hidden="true"></div>
        <div class="custody-content">
          <div class="custody-time">${e.time} IST</div>
          <div class="custody-action">${e.action}</div>
          <div class="custody-actor">${e.actor}</div>
        </div>
      </div>
    `).join('');
  }

  // ── EVIDENCE TAB ──────────────────────────────────────────────────────
  function _renderEvidenceTab(c) {
    const listEl = document.getElementById('evidence-list-panel');
    if (listEl) {
      listEl.innerHTML = c.evidence.map(e => `
        <div class="evidence-item" role="listitem" tabindex="0" aria-label="Evidence ${e.id}: ${e.type}">
          <div class="evidence-icon" style="background:var(--accent-dim); color:var(--accent);">
            <i class="fa-solid fa-file-shield" aria-hidden="true"></i>
          </div>
          <div class="evidence-meta">
            <div class="evidence-id">${e.id}</div>
            <div class="evidence-type">${e.type}</div>
            <div class="evidence-hash">${e.sha256}</div>
          </div>
          <div style="text-align:right;">
            <div class="evidence-status ${e.integrity}">${e.integrity.toUpperCase()}</div>
            <div style="font-size:0.65rem; color:var(--text-dim); margin-top:4px;">${e.collectedAt}</div>
            <div style="font-size:0.65rem; color:var(--text-dim);">${e.size}</div>
          </div>
        </div>
      `).join('');
    }

    const custodyEl = document.getElementById('custody-panel');
    if (custodyEl) {
      custodyEl.innerHTML = c.custody.map(e => `
        <div class="custody-event" role="listitem">
          <div class="custody-dot" aria-hidden="true"></div>
          <div class="custody-content">
            <div class="custody-time">${e.time} IST</div>
            <div class="custody-action">${e.action}</div>
            <div class="custody-actor">${e.actor}</div>
            <div class="custody-hash">SHA-256: ${e.hash}</div>
          </div>
        </div>
      `).join('');
    }
  }

  // ── REPORT TAB ────────────────────────────────────────────────────────
  function _renderReportTab(c) {
    const container = document.getElementById('report-preview-container');
    if (!container || !window.ReportBuilder) return;
    container.innerHTML = `<div class="report-preview">${window.ReportBuilder.buildReport(c)}</div>`;

    document.getElementById('export-json-btn')?.addEventListener('click', () => window.ReportBuilder.exportJSON(c));
    document.getElementById('export-pdf-btn')?.addEventListener('click', () => window.ReportBuilder.exportPDF());
  }

  // ── CASES PAGE ────────────────────────────────────────────────────────
  function _renderCases(filter = 'all') {
    const grid = document.getElementById('cases-grid');
    if (!grid) return;

    let cases = [...DEMO_CASES];
    if (filter === 'critical') cases = cases.filter(c => c.severity === 'critical');
    if (filter === 'active') cases = cases.filter(c => c.status !== 'CLOSED');

    grid.innerHTML = cases.map(c => `
      <div class="card" style="cursor:pointer; transition:all 0.15s;" onclick="window.DemoMode.openCase('${c.id}')" role="listitem" tabindex="0" aria-label="Case ${c.id}: ${c.type}">
        <div style="display:flex; align-items:center; gap:14px; padding:16px 18px;">
          <div style="flex-shrink:0; width:8px; height:100%; min-height:60px; border-radius:4px; background:${severityColor(c.severity)}; position:relative;">
            <div style="position:absolute; inset:0; background:${severityColor(c.severity)}; border-radius:4px; box-shadow:0 0 10px ${severityColor(c.severity)}44;"></div>
          </div>
          <div style="flex:1; min-width:0;">
            <div style="display:flex; align-items:center; gap:10px; margin-bottom:6px; flex-wrap:wrap;">
              <span class="monospace" style="color:var(--accent); font-size:0.82rem; font-weight:700;">${c.id}</span>
              <span class="sev-tag ${c.severity}">${c.type}</span>
              <span class="sev-tag ${c.severity}">${c.riskScore}/100</span>
              ${c.campaignId ? `<span class="sev-tag medium">${c.campaignId}</span>` : ''}
            </div>
            <div style="font-size:0.88rem; color:var(--text-primary); font-weight:500; margin-bottom:4px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${c.subject}</div>
            <div style="font-size:0.72rem; color:var(--text-muted); display:flex; gap:12px; flex-wrap:wrap;">
              <span><i class="fa-solid fa-envelope" aria-hidden="true"></i> ${c.from.email}</span>
              <span><i class="fa-solid fa-user" aria-hidden="true"></i> ${c.assignedTo}</span>
              <span><i class="fa-solid fa-clock" aria-hidden="true"></i> ${new Date(c.lastActivity).toLocaleTimeString('en-IN', {hour12:false})} IST</span>
            </div>
          </div>
          <div style="display:flex; flex-direction:column; align-items:flex-end; gap:8px; flex-shrink:0;">
            <span class="sev-tag ${c.status === 'ESCALATED' ? 'critical' : c.status === 'CLOSED' ? 'safe' : 'medium'}">${c.status}</span>
            <button class="btn btn-primary btn-sm" onclick="event.stopPropagation(); window.DemoMode.openCase('${c.id}')" aria-label="Investigate case ${c.id}">
              <i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i>
            </button>
          </div>
        </div>
      </div>
    `).join('');

    // Wire case detail view to also go to analyze tab
    grid.querySelectorAll('[role=listitem]').forEach(el => {
      el.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ' ') {
          const id = el.getAttribute('onclick').match(/'([^']+)'/)[1];
          window.DemoMode.openCase(id);
        }
      });
    });
  }

  // Case filter buttons
  document.getElementById('filter-all-cases')?.addEventListener('click', () => _renderCases('all'));
  document.getElementById('filter-critical-cases')?.addEventListener('click', () => _renderCases('critical'));
  document.getElementById('filter-active-cases')?.addEventListener('click', () => _renderCases('active'));

  // ── CAMPAIGNS PAGE ────────────────────────────────────────────────────
  function _renderCampaigns() {
    const grid = document.getElementById('campaigns-grid');
    if (!grid) return;

    grid.innerHTML = DEMO_CAMPAIGNS.map(camp => `
      <div class="campaign-card" role="listitem" tabindex="0" onclick="window.AppController.openCampaign('${camp.id}')" aria-label="Campaign ${camp.id}: ${camp.name}">
        <div class="campaign-id">${camp.id}</div>
        <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">
          <div class="campaign-name">${camp.name}</div>
          <span class="sev-tag ${camp.severity}">${camp.severity.toUpperCase()}</span>
        </div>
        <div style="font-size:0.75rem; color:var(--text-muted); margin-bottom:12px; line-height:1.5;">${camp.description.substring(0,100)}…</div>
        <div class="campaign-stats">
          <div class="campaign-stat"><div class="campaign-stat-num">${camp.emailCount}</div><div>Emails</div></div>
          <div class="campaign-stat"><div class="campaign-stat-num">${camp.domains.length}</div><div>Domains</div></div>
          <div class="campaign-stat"><div class="campaign-stat-num">${camp.ips.length}</div><div>IPs</div></div>
          <div class="campaign-stat"><div class="campaign-stat-num">${camp.infraClusters}</div><div>Clusters</div></div>
        </div>
        <div style="margin-top:12px; display:flex; gap:6px; flex-wrap:wrap;">
          ${camp.ttps.map(t => `<span style="font-size:0.6rem; padding:2px 6px; background:rgba(167,139,250,0.1); border:1px solid rgba(167,139,250,0.2); border-radius:3px; color:var(--purple); font-family:var(--font-mono);">${t.split(' — ')[0]}</span>`).join('')}
        </div>
      </div>
    `).join('');
  }

  window.AppController = {
    openCampaign(id) {
      const camp = DEMO_CAMPAIGNS.find(c => c.id === id);
      if (!camp) return;
      state.selectedCampaign = camp;
      const detail = document.getElementById('campaign-detail');
      const content = document.getElementById('campaign-detail-content');
      if (!detail || !content) return;

      content.innerHTML = `
        <div class="card-header">
          <div class="card-title"><i class="fa-solid fa-diagram-project" aria-hidden="true"></i><span>${camp.id} — ${camp.name}</span></div>
          <div class="card-actions">
            <span class="sev-tag ${camp.severity}">${camp.status}</span>
            <button class="btn btn-ghost btn-sm" onclick="document.getElementById('campaign-detail').classList.add('hidden')">
              <i class="fa-solid fa-times"></i>
            </button>
          </div>
        </div>
        <div class="card-body">
          <p style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:16px; line-height:1.7;">${camp.description}</p>
          <div class="grid-2" style="gap:12px; margin-bottom:16px;">
            <div>
              <div style="font-size:0.62rem; letter-spacing:0.1em; text-transform:uppercase; color:var(--text-muted); margin-bottom:6px;">Domains (${camp.domains.length})</div>
              ${camp.domains.map(d => `<div class="mono" style="font-size:0.72rem; color:var(--text-secondary); padding:2px 0;">${d}</div>`).join('')}
            </div>
            <div>
              <div style="font-size:0.62rem; letter-spacing:0.1em; text-transform:uppercase; color:var(--text-muted); margin-bottom:6px;">IPs (${camp.ips.length})</div>
              ${camp.ips.map(ip => `<div class="mono" style="font-size:0.72rem; color:var(--text-secondary); padding:2px 0;">${ip}</div>`).join('')}
            </div>
          </div>
          <div style="margin-bottom:12px;">
            <div style="font-size:0.62rem; letter-spacing:0.1em; text-transform:uppercase; color:var(--text-muted); margin-bottom:6px;">Related Cases</div>
            <div style="display:flex; gap:8px; flex-wrap:wrap;">
              ${camp.cases.map(id => `<button class="btn btn-secondary btn-sm" onclick="window.DemoMode.openCase('${id}')">${id}</button>`).join('')}
            </div>
          </div>
          <div>
            <div style="font-size:0.62rem; letter-spacing:0.1em; text-transform:uppercase; color:var(--text-muted); margin-bottom:6px;">MITRE ATT&CK TTPs</div>
            <div style="display:flex; gap:6px; flex-wrap:wrap;">
              ${camp.ttps.map(t => `<span style="font-size:0.7rem; padding:3px 8px; background:rgba(167,139,250,0.1); border:1px solid rgba(167,139,250,0.2); border-radius:4px; color:var(--purple); font-family:var(--font-mono);">${t}</span>`).join('')}
            </div>
          </div>
        </div>
      `;

      detail.classList.remove('hidden');
      detail.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  // ── EVIDENCE PAGE ─────────────────────────────────────────────────────
  function _renderGlobalEvidence() {
    const list = document.getElementById('global-evidence-list');
    if (!list) return;

    const allEvidence = DEMO_CASES.flatMap(c => c.evidence.map(e => ({ ...e, caseId: c.id })));

    list.innerHTML = allEvidence.map(e => `
      <div class="evidence-item" role="listitem" tabindex="0" aria-label="Evidence ${e.id}">
        <div class="evidence-icon" style="background:var(--accent-dim); color:var(--accent);">
          <i class="fa-solid fa-file-shield" aria-hidden="true"></i>
        </div>
        <div class="evidence-meta">
          <div class="evidence-id">${e.id} · Case: ${e.caseId}</div>
          <div class="evidence-type">${e.type}</div>
          <div class="evidence-hash">${e.sha256}</div>
        </div>
        <div style="text-align:right;">
          <div class="evidence-status ${e.integrity}">${e.integrity.toUpperCase()}</div>
          <div style="font-size:0.65rem; color:var(--text-dim); margin-top:4px;">${e.collectedAt}</div>
        </div>
      </div>
    `).join('');

    const custody = document.getElementById('global-custody');
    if (custody) {
      const allCustody = DEMO_CASES.flatMap(c => c.custody.map(ev => ({ ...ev, caseId: c.id })))
        .sort((a, b) => a.time.localeCompare(b.time));

      custody.innerHTML = allCustody.map(e => `
        <div class="custody-event" role="listitem">
          <div class="custody-dot" aria-hidden="true"></div>
          <div class="custody-content">
            <div class="custody-time">${e.time} IST · ${e.caseId}</div>
            <div class="custody-action">${e.action}</div>
            <div class="custody-actor">${e.actor}</div>
          </div>
        </div>
      `).join('');
    }
  }

  // ── REPORTS PAGE ──────────────────────────────────────────────────────
  function _renderReportCaseSelector() {
    const selector = document.getElementById('report-case-selector');
    if (!selector) return;

    selector.innerHTML = DEMO_CASES.map(c => `
      <div style="display:flex; align-items:center; gap:10px; padding:8px 10px; border-radius:7px; cursor:pointer; transition:background 0.12s;" onclick="window.AppController.selectReportCase('${c.id}')" role="button" tabindex="0" aria-label="Select case ${c.id} for report">
        <span class="sev-tag ${c.severity}" style="flex-shrink:0;">${c.riskScore}</span>
        <div>
          <div style="font-size:0.78rem; font-weight:600;">${c.id}</div>
          <div style="font-size:0.68rem; color:var(--text-muted);">${c.type}</div>
        </div>
      </div>
    `).join('');

    window.AppController.selectReportCase = (id) => {
      const c = DEMO_CASES.find(x => x.id === id);
      if (!c || !window.ReportBuilder) return;
      const preview = document.getElementById('report-page-preview');
      if (preview) preview.innerHTML = `<div class="report-preview">${window.ReportBuilder.buildReport(c)}</div>`;

      document.getElementById('report-page-json')?.onclick !== null;
      document.getElementById('report-page-json')?.removeEventListener('click', document.getElementById('report-page-json')._handler);
      const jsonH = () => window.ReportBuilder.exportJSON(c);
      document.getElementById('report-page-json')._handler = jsonH;
      document.getElementById('report-page-json')?.addEventListener('click', jsonH);
    };

    // PDF export
    document.getElementById('report-page-pdf')?.addEventListener('click', () => window.print());
  }

  // ── ADMIN ─────────────────────────────────────────────────────────────
  function _initAdmin() {
    // Toggle switches
    document.querySelectorAll('.toggle-switch[id^="flag-"]').forEach(sw => {
      sw.addEventListener('click', () => {
        sw.classList.toggle('on');
        const on = sw.classList.contains('on');
        sw.setAttribute('aria-checked', on);
        showToast(`Feature flag ${sw.id} ${on ? 'enabled' : 'disabled'}`, 'info', 2000);
      });
    });

    // Threshold sliders
    const crit = document.getElementById('threshold-critical');
    const critVal = document.getElementById('threshold-critical-val');
    const high = document.getElementById('threshold-high');
    const highVal = document.getElementById('threshold-high-val');

    crit?.addEventListener('input', () => { if (critVal) critVal.textContent = crit.value; });
    high?.addEventListener('input', () => { if (highVal) highVal.textContent = high.value; });
  }

  // ── NOTIFICATION BUTTON ───────────────────────────────────────────────
  document.getElementById('notif-btn')?.addEventListener('click', () => {
    showToast('Notifications: 3 unread — CX-1024 critical, CX-1023 escalated, CAM-091 updated', 'warn', 5000);
  });

  // ── RESET ANALYZER ────────────────────────────────────────────────────
  function _resetAnalyzer() {
    state.currentCase = null;
    document.getElementById('analyze-upload-section')?.classList.remove('hidden');
    document.getElementById('analyze-pipeline-section')?.classList.add('hidden');
    document.getElementById('analyze-results-section')?.classList.add('hidden');
    const textarea = document.getElementById('email-paste-area');
    if (textarea) textarea.value = '';
    navigateTo('analyze');
  }

  // ── DEMO SCENARIO LIST ────────────────────────────────────────────────
  function _renderDemoScenarios() {
    const list = document.getElementById('demo-scenario-list');
    if (!list) return;

    list.innerHTML = DEMO_CASES.map(c => `
      <div style="display:flex; align-items:center; gap:10px; padding:8px 10px; border-radius:7px; cursor:pointer; transition:background 0.12s; border-bottom:1px solid var(--border-subtle);"
           onclick="window.DemoMode.openCase('${c.id}')" role="button" tabindex="0" aria-label="Load demo case ${c.id}: ${c.type}">
        <div style="width:8px; height:8px; border-radius:50%; flex-shrink:0; background:${severityColor(c.severity)};"></div>
        <div style="flex:1; min-width:0;">
          <div style="font-size:0.78rem; font-weight:600; color:var(--text-primary);">${c.id} — ${c.type}</div>
          <div style="font-size:0.68rem; color:var(--text-muted); white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${c.subject.substring(0,45)}…</div>
        </div>
        <span class="sev-tag ${c.severity}">${c.riskScore}</span>
      </div>
    `).join('');

    // Keyboard support
    list.querySelectorAll('[role=button]').forEach(el => {
      el.addEventListener('keydown', e => {
        if (e.key === 'Enter' || e.key === ' ') el.click();
      });
    });
  }

  // ── UPLOAD ZONE ───────────────────────────────────────────────────────
  function _initUploadZone() {
    const zone = document.getElementById('upload-zone');
    const input = document.getElementById('email-file-input');

    zone?.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
    zone?.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
    zone?.addEventListener('drop', (e) => {
      e.preventDefault();
      zone.classList.remove('drag-over');
      const file = e.dataTransfer?.files[0];
      if (file) _handleFileUpload(file);
    });

    input?.addEventListener('change', () => {
      if (input.files?.[0]) _handleFileUpload(input.files[0]);
    });

    document.getElementById('analyze-paste-btn')?.addEventListener('click', async () => {
      const text = document.getElementById('email-paste-area')?.value?.trim();
      if (!text) { showToast('Please paste email content first', 'warn'); return; }
      
      showToast('Initiating Live Analysis Pipeline...', 'info', 3000);
      try {
        const parsed = window.EmailParser ? window.EmailParser.parseRawEmail(text) : { subject: 'Pasted Email', body: text, urls: [] };
        
        // Fetch Live AI and Intel from our new Backend API
        const response = await fetch('/api/v1/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            domain: parsed.domain || '',
            originIp: parsed.receivedHops && parsed.receivedHops.length ? parsed.receivedHops[0] : '',
            emailData: parsed
          })
        });
        
        const data = await response.json();
        let dynamicCase = JSON.parse(JSON.stringify(DEMO_CASES[0])); // Clone demo layout
        
        // Merge Live AI Results if enabled in backend
        if (data && data.success && data.liveVerification && data.liveVerification.aiAnalysis) {
            const ai = data.liveVerification.aiAnalysis;
            dynamicCase.score = ai.riskScore || dynamicCase.score;
            dynamicCase.threatVerdict = ai.verdict || dynamicCase.threatVerdict;
            dynamicCase.story = ai.summary || dynamicCase.story;
        }

        // Merge Live VirusTotal Results
        if (data && data.success && data.liveVerification && data.liveVerification.vtScan) {
           dynamicCase.story += `\\n\\n[VirusTotal Live]: ${data.liveVerification.vtScan.threatVerdict} (${data.liveVerification.vtScan.malicious} engines flagged).`;
        }

        _runAnalysisPipeline(dynamicCase);
      } catch (err) {
        console.error('API Error, falling back to offline demo data', err);
        showToast('Live API unavailable — falling back to synthetic offline engine', 'warn', 4000);
        _runAnalysisPipeline(DEMO_CASES[0]);
      }
    });

    document.getElementById('clear-paste-btn')?.addEventListener('click', () => {
      const ta = document.getElementById('email-paste-area');
      if (ta) ta.value = '';
    });
  }

  function _handleFileUpload(file) {
    const hashDisplay = document.getElementById('upload-hash-display');
    if (hashDisplay) hashDisplay.textContent = `Processing: ${file.name} (${(file.size/1024).toFixed(1)} KB)…`;

    showToast(`File uploaded: ${file.name} — starting analysis`, 'info', 3000);

    setTimeout(() => {
      if (hashDisplay) hashDisplay.textContent = `SHA-256: a3f9b2e1...d4e5 · ${file.name}`;
      // For uploads in demo mode, just run the default offline case since we don't extract raw text yet
      _runAnalysisPipeline(DEMO_CASES[0]);
    }, 500);
  }

  // ── ADMIN INIT ────────────────────────────────────────────────────────
  document.getElementById('nav-admin')?.addEventListener('click', _initAdmin);

  // ── INITIALIZATION ────────────────────────────────────────────────────
  function init() {
    _initStars();
    _initRelDiagram();
    _initUploadZone();
    _renderDemoScenarios();
    _initAdmin();

    // Set landing as active
    navigateTo('landing');

    // Sync time
    setInterval(() => {
      const syncEl = document.getElementById('dashboard-sync-time');
      if (syncEl && document.getElementById('tab-dashboard')?.classList.contains('active')) {
        syncEl.textContent = `Last intelligence sync: ${new Date().toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour12: false })} IST`;
      }
    }, 30000);

    console.log('%cCYBER CONSTELLATION v3.0', 'font-size:1.2rem; font-weight:bold; color:#8b5cf6;');
    console.log('%cSIH26106 — Email Threat Intelligence Platform', 'color:#94a3b8;');
    console.log('%cSYNTHETIC DEMO DATA — All case data is fictional', 'color:#f59e0b;');
  }

  init();

}); // DOMContentLoaded
