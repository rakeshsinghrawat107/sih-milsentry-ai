// MailSentry AI — Master SOC Application Controller v2.0
// Full wiring: drag-and-drop, audio, animated map, graph, panchnama, dispatch

document.addEventListener('DOMContentLoaded', () => {
  let activeMap = null;
  let mapMarkers = [];
  let mapPolylines = [];
  let currentAnalysis = null;
  let isAnalyzing = false;

  // ── LIVE CLOCK ─────────────────────────────────────────────────
  function updateClock() {
    const now = new Date();
    const ist = now.toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour12: false });
    const el = document.getElementById('live-clock');
    if (el) el.textContent = `IST ${ist}`;
  }
  updateClock();
  setInterval(updateClock, 1000);

  // ── TOAST SYSTEM ────────────────────────────────────────────────
  function showToast(message, type = 'info', duration = 3500) {
    const container = document.getElementById('toast-container');
    if (!container) return;
    const icons = { info: 'fa-circle-info', success: 'fa-check-circle', danger: 'fa-triangle-exclamation', warn: 'fa-bell' };
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `<i class="fa-solid ${icons[type] || icons.info}"></i><span>${message}</span>`;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.animation = 'toast-out 0.3s ease forwards';
      setTimeout(() => toast.remove(), 300);
    }, duration);
  }

  // ── AUDIO TOGGLE ─────────────────────────────────────────────────
  const audioBtn = document.getElementById('audio-toggle-btn');
  const audioIcon = document.getElementById('audio-icon');
  const audioLabel = document.getElementById('audio-label');
  let audioOn = true;

  if (audioBtn) {
    audioBtn.addEventListener('click', () => {
      audioOn = !audioOn;
      window.AudioEngine.setMuted(!audioOn);
      audioBtn.classList.toggle('active', audioOn);
      audioIcon.className = audioOn ? 'fa-solid fa-volume-high' : 'fa-solid fa-volume-xmark';
      audioLabel.textContent = audioOn ? 'AUDIO ON' : 'AUDIO OFF';
    });
  }

  // ── NAV TAB SWITCHING ───────────────────────────────────────────
  const navItems = document.querySelectorAll('.nav-item');
  const tabPanes = document.querySelectorAll('.tab-pane');

  navItems.forEach(item => {
    item.addEventListener('click', e => {
      e.preventDefault();
      const targetTab = item.getAttribute('data-tab');
      if (window.AudioEngine) window.AudioEngine.navClick();

      navItems.forEach(n => n.classList.remove('active'));
      tabPanes.forEach(t => t.classList.remove('active'));
      item.classList.add('active');

      const pane = document.getElementById(`tab-${targetTab}`);
      if (pane) pane.classList.add('active');

      if (targetTab === 'geomap' && activeMap) {
        setTimeout(() => { activeMap.invalidateSize(); }, 200);
      }
      if (targetTab === 'graph' && currentAnalysis) {
        setTimeout(() => {
          const gd = window.GraphEngine.buildGraphData(currentAnalysis.parsed, currentAnalysis.geo, currentAnalysis.domain, currentAnalysis.score);
          window.GraphEngine.renderD3Graph('identity-graph', gd);
        }, 150);
      }
    });
  });

  // ── LEAFLET MAP ─────────────────────────────────────────────────
  function initLeafletMap() {
    if (typeof L === 'undefined') return;
    const el = document.getElementById('geo-map');
    if (!el || activeMap) return;
    activeMap = L.map('geo-map', { zoomControl: true, attributionControl: false }).setView([25, 60], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', { maxZoom: 18 }).addTo(activeMap);
  }

  function updateMapHops(hops) {
    if (!activeMap || !hops || hops.length === 0) return;
    mapMarkers.forEach(m => activeMap.removeLayer(m));
    mapMarkers = [];
    mapPolylines.forEach(p => activeMap.removeLayer(p));
    mapPolylines = [];

    const latLngs = [];

    hops.forEach((hop, idx) => {
      const isOrigin = idx === hops.length - 1;
      const col = isOrigin ? '#ff0033' : (hop.isVpn ? '#ffaa00' : '#00d4ff');
      const r   = isOrigin ? 11 : 7;

      const m = L.circleMarker([hop.lat, hop.lng], {
        radius: r, fillColor: col, color: '#ffffff',
        weight: 2, opacity: 1, fillOpacity: 0.9
      }).addTo(activeMap);

      m.bindPopup(`
        <div style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#111;">
          <strong style="color:${isOrigin ? '#d90429' : '#0077b6'};">${isOrigin ? '🚨 THREAT ORIGIN NODE' : `HOP #${hop.hopIndex}`}</strong><br>
          <b>IP:</b> ${hop.ip}<br>
          <b>Location:</b> ${hop.city}, ${hop.country}<br>
          <b>ISP:</b> ${hop.isp}<br>
          <b>Tor:</b> ${hop.isTor ? '✅ YES' : 'No'} &nbsp; <b>VPN:</b> ${hop.isVpn ? '⚠ YES' : 'No'}<br>
          <b>Abuse Score:</b> <strong style="color:${hop.abuseScore > 60 ? 'red' : 'green'}">${hop.abuseScore}%</strong>
        </div>
      `);

      mapMarkers.push(m);
      latLngs.push([hop.lat, hop.lng]);
      if (window.AudioEngine) setTimeout(() => window.AudioEngine.radarPing(), idx * 250);
    });

    if (latLngs.length > 1) {
      // Animated dashed polyline
      const poly = L.polyline(latLngs, {
        color: '#ffaa00', weight: 2.5,
        dashArray: '10, 8', opacity: 0.8
      }).addTo(activeMap);
      mapPolylines.push(poly);
      activeMap.fitBounds(poly.getBounds(), { padding: [60, 60] });
    } else if (latLngs.length === 1) {
      activeMap.setView(latLngs[0], 5);
    }
  }

  // ── MAIN FORENSIC ANALYSIS ENGINE ──────────────────────────────
  window.runForensicAnalysis = async function(rawText) {
    if (isAnalyzing || !rawText || rawText.trim().length < 20) {
      showToast('Please paste a valid RFC 5322 email to analyze.', 'warn');
      return;
    }

    isAnalyzing = true;
    if (window.AudioEngine) window.AudioEngine.scanStart();
    showToast('Forensic analysis running…', 'info', 1800);

    const analyzeBtn = document.getElementById('btn-analyze-now');
    if (analyzeBtn) { analyzeBtn.innerHTML = '<i class="fa-solid fa-spinner spinner"></i> Analyzing…'; analyzeBtn.disabled = true; }

    const t0 = performance.now();
    try {
      const parsed  = window.EmailParser.parseRawEmail(rawText);
      if (!parsed) throw new Error('Email parse failed');

      const nlp     = window.NlpEngine.analyzeText(parsed.subject, parsed.body, parsed.from.name);
      const headers = window.HeaderEngine.analyzeHeaders(parsed);
      const geo     = window.GeoEngine.analyzeHops(parsed.receivedHops);
      const domain  = window.DomainEngine.analyzeDomain(parsed.from.domain);
      const score   = window.ScoringEngine.calculateScore(parsed, nlp, headers, geo, domain);
      const evidenceBlock = await window.BlockchainVault.sealEvidence(parsed, score, geo);

      currentAnalysis = { parsed, nlp, headers, geo, domain, score, evidenceBlock };
      const elapsed = ((performance.now() - t0) / 1000).toFixed(2);

      renderAnalysisResults(currentAnalysis);
      updateMapHops(geo.hops);

      // Switch to dashboard tab
      document.querySelector('.nav-item[data-tab="dashboard"]')?.click();

      if (window.AudioEngine) {
        if (score.finalScore >= 85) window.AudioEngine.criticalAlert();
        else if (score.finalScore >= 45) window.AudioEngine.warnAlert();
        else window.AudioEngine.safeAlert();
      }

      const toastType = score.finalScore >= 85 ? 'danger' : score.finalScore >= 45 ? 'warn' : 'success';
      showToast(`Analysis complete in ${elapsed}s — ${score.threatTier}`, toastType, 4000);
    } catch (err) {
      showToast('Analysis error: ' + err.message, 'danger');
      console.error(err);
    } finally {
      isAnalyzing = false;
      if (analyzeBtn) { analyzeBtn.innerHTML = '<i class="fa-solid fa-bolt"></i><span>Run Deep Analysis</span>'; analyzeBtn.disabled = false; }
    }
  };

  // ── RENDER RESULTS TO DOM ───────────────────────────────────────
  function renderAnalysisResults(a) {
    const { parsed, nlp, headers, geo, domain, score, evidenceBlock } = a;

    // Threat Dial
    const dial = document.getElementById('threat-score-dial');
    const scoreNum = document.getElementById('threat-score-num');
    const scoreLabel = document.getElementById('threat-score-label');
    const summaryText = document.getElementById('threat-summary-text');

    const colorMap = { safe: 'var(--green-safe)', suspicious: 'var(--amber-warn)', phishing: 'var(--orange-phish)', fraud: 'var(--red-fraud)', critical: 'var(--red-critical)' };
    if (dial) dial.className = `threat-score-dial ${score.colorClass}`;
    if (scoreNum) { scoreNum.style.color = colorMap[score.colorClass] || 'var(--cyan-glow)'; scoreNum.textContent = score.finalScore; }
    if (scoreLabel) scoreLabel.textContent = score.threatTier;
    if (summaryText) summaryText.textContent = score.summaryText;

    // Stat tile
    setText('stat-threat-score', `${score.finalScore} / 100`);
    setText('stat-hops', `${geo.totalHops} Hops`);

    // MITRE badge
    const mitreLink = document.getElementById('mitre-badge-link');
    const mitreText = document.getElementById('mitre-tag-text');
    if (mitreLink) mitreLink.href = score.mitreUrl || '#';
    if (mitreText) mitreText.textContent = score.mitreTag || 'MITRE ATT&CK';

    // Auth badges
    updateBadge('badge-spf',  'SPF',  headers.spfStatus);
    updateBadge('badge-dkim', 'DKIM', headers.dkimStatus);
    updateBadge('badge-dmarc','DMARC',headers.dmarcStatus);

    // Metadata
    setText('res-from', parsed.from.raw);
    setText('res-subject', parsed.subject);
    setText('res-origin-ip', `${geo.originatingNode.ip} (${geo.originatingNode.city}, ${geo.originatingNode.country})`);
    setText('res-threat-cat', nlp.threatCategory.replace(/_/g, ' '));
    setText('res-ai-flag', nlp.isSyntheticAI ? '⚠ WormGPT / GenAI Detected' : '✅ Human-authored');
    const el_ai = document.getElementById('res-ai-flag');
    if (el_ai) el_ai.style.color = nlp.isSyntheticAI ? 'var(--red-fraud)' : 'var(--green-safe)';

    setText('res-blockchain-hash', evidenceBlock.blockHash);
    setText('res-bsa-ref', evidenceBlock.bsaComplianceCode);
    setText('res-admissibility', 'FULLY ADMISSIBLE (BSA 2023 Sec 65B)');

    // URL count
    setText('res-urls', `${parsed.urls.length} found (${parsed.suspiciousUrls?.length || 0} suspicious)`);

    // Signal table
    const sigBody = document.getElementById('signals-table-body');
    if (sigBody) {
      sigBody.innerHTML = score.signalBreakdown.map(s => `
        <tr>
          <td><span class="tag ${s.type === 'CRITICAL' ? 'tag-red' : 'tag-amber'}">${s.type}</span></td>
          <td style="color:var(--text-secondary);">${s.signal}</td>
          <td><strong style="color:var(--cyan-glow); font-family:var(--font-mono);">+${s.weight}</strong></td>
        </tr>
      `).join('') || '<tr><td colspan="3" style="color:var(--green-safe); text-align:center;">✅ No threat signals triggered</td></tr>';
    }

    // Header anomalies
    const anomalyList = document.getElementById('header-anomaly-list');
    if (anomalyList) {
      anomalyList.innerHTML = headers.anomalies.length > 0
        ? headers.anomalies.map(a => `<div style="display:flex; gap:7px; margin-bottom:6px; font-size:0.76rem;"><i class="fa-solid fa-triangle-exclamation" style="color:var(--red-fraud); flex-shrink:0; margin-top:2px;"></i><span style="color:var(--text-secondary);">${a}</span></div>`).join('')
        : '<div style="color:var(--green-safe); font-size:0.78rem;">✅ No authentication anomalies detected.</div>';
    }

    // Domain Intelligence
    setText('di-domain', domain.domain);
    const diHomo = document.getElementById('di-homoglyph');
    if (diHomo) { diHomo.innerHTML = domain.isHomoglyph ? '<span class="tag tag-red">⚠ YES — Cyrillic/Unicode</span>' : '<span class="tag tag-green">No</span>'; }
    const diLike = document.getElementById('di-lookalike');
    if (diLike) {
      diLike.innerHTML = domain.lookalikeMatch
        ? `<span class="tag tag-red">${domain.lookalikeMatch.targetBrand} (d=${domain.lookalikeMatch.editDistance || '—'})</span>`
        : '<span class="tag tag-green">None</span>';
    }
    setText('di-age', `${domain.domainAgeDays} days`);

    // NLP Stylometry
    const nlpUrgency = document.getElementById('nlp-urgency');
    if (nlpUrgency) nlpUrgency.innerHTML = `<div style="display:flex; align-items:center; gap:6px;"><div style="width:${nlp.urgencyScore}px; max-width:80px; height:5px; background:var(--amber-warn); border-radius:3px;"></div><span>${nlp.urgencyScore}/100</span></div>`;
    const nlpBec = document.getElementById('nlp-bec');
    if (nlpBec) nlpBec.innerHTML = `<div style="display:flex; align-items:center; gap:6px;"><div style="width:${nlp.becScore}px; max-width:80px; height:5px; background:var(--red-fraud); border-radius:3px;"></div><span>${nlp.becScore}/100</span></div>`;
    setText('nlp-burst', `${nlp.burstinessScore} (TTR: ${nlp.typeTokenRatio})`);
    const nlpAi = document.getElementById('nlp-ai');
    if (nlpAi) { nlpAi.textContent = nlp.isSyntheticAI ? 'WormGPT/GenAI Detected' : 'Human-Authored'; nlpAi.style.color = nlp.isSyntheticAI ? 'var(--red-fraud)' : 'var(--green-safe)'; }

    // URL pills
    const urlContainer = document.getElementById('url-list-container');
    if (urlContainer) {
      if (parsed.urls.length === 0) {
        urlContainer.innerHTML = '<span style="color:var(--text-muted); font-size:0.78rem;">No URLs detected.</span>';
      } else {
        urlContainer.innerHTML = parsed.urls.map(u => {
          const isSus = (parsed.suspiciousUrls || []).includes(u);
          return `<span class="url-pill ${isSus ? 'danger' : 'safe'}" title="${u}">${isSus ? '⚠ ' : ''}${u.substring(0, 70)}${u.length > 70 ? '…' : ''}</span>`;
        }).join('');
      }
    }

    // STRAD table
    const stradBody = document.getElementById('strad-table-body');
    if (stradBody) {
      stradBody.innerHTML = geo.stradAnomalies.length === 0
        ? '<tr><td colspan="5" style="color:var(--green-safe); text-align:center; padding:14px;">✅ All relay transit latencies are physically consistent.</td></tr>'
        : geo.stradAnomalies.map(a => `
          <tr>
            <td>${a.from}</td><td>${a.to}</td>
            <td><strong style="color:var(--cyan-glow); font-family:var(--font-mono);">${a.distanceKm.toLocaleString()} km</strong></td>
            <td style="font-family:var(--font-mono);">${a.minPhysicalTransitMs || '—'} ms</td>
            <td><span class="tag tag-red">${a.flag}</span></td>
          </tr>
        `).join('');
    }

    // Evidence blockchain ledger
    renderBlockchainLedger();

    // Panchnama
    const panchnamaEl = document.getElementById('panchnama-report-content');
    if (panchnamaEl) panchnamaEl.textContent = window.BlockchainVault.generateBsaPanchnamaReport(evidenceBlock, parsed);

    // CERT-In JSON Dispatch
    const certinEl = document.getElementById('certin-dispatch-json');
    if (certinEl) certinEl.textContent = window.BlockchainVault.generateCertInDispatch(evidenceBlock, parsed, nlp, geo, domain);

    // I4C FIR Docket
    renderI4cFir(evidenceBlock, parsed, score, geo);

    // Mitigation Playbook
    renderPlaybook(geo, domain, score);
  }

  function renderBlockchainLedger() {
    const timeline = document.getElementById('blockchain-timeline');
    if (!timeline || window.BlockchainVault.ledger.length === 0) return;
    timeline.innerHTML = window.BlockchainVault.ledger.slice().reverse().map(b => {
      const isTampered = !b.isValid;
      return `
        <div class="block-entry ${isTampered ? 'tampered' : ''} fade-in">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:5px;">
            <strong style="color:var(--cyan-glow); font-family:var(--font-mono); font-size:0.75rem;">
              BLOCK #${b.blockIndex} • ${b.bsaComplianceCode}
            </strong>
            <span class="tag ${b.scoringResult.finalScore > 50 ? 'tag-red' : 'tag-green'}">${b.threatTier} (${b.scoringResult.finalScore}/100)</span>
          </div>
          <div class="block-hash ${isTampered ? 'tampered-hash' : ''}">MERKLE: ${b.blockHash}</div>
          <div style="font-size:0.7rem; color:var(--text-muted); margin-top:4px;">
            PREV: ${b.previousHash.substring(0, 32)}…
            &nbsp;|&nbsp; ${b.timestamp}
            &nbsp;|&nbsp; ORIGIN: ${b.originIp} [${b.originCountry}]
          </div>
        </div>
      `;
    }).join('');
  }

  function renderI4cFir(eb, parsed, score, geo) {
    const el = document.getElementById('i4c-fir-docket');
    if (!el) return;
    el.textContent = `
I4C NATIONAL CYBER CRIME HELPLINE 1930 — FIR DOCKET
=====================================================
Complaint Reference : ${eb.bsaComplianceCode}
Date / Time         : ${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })} IST
Cyber Crime Type    : ${score.threatTier}
MITRE ATT&CK        : ${score.mitreTag}

VICTIM DETAILS:
  Email Address     : ${parsed.to}
  Incident Subject  : ${parsed.subject}

ACCUSED / THREAT ACTOR:
  Fraudulent Sender : ${parsed.from.raw}
  Originating IP    : ${geo.originatingNode.ip} (${geo.originatingNode.country})
  ISP / Hosting     : ${geo.originatingNode.isp}
  Reply-To Hijack   : ${parsed.replyTo?.raw || 'N/A'}

EVIDENCE TRAIL:
  BSA Certificate   : ${eb.bsaComplianceCode}
  SHA-256 Hash      : ${eb.rawEmailHash}
  Blockchain Block  : #${eb.blockIndex}

RECOMMENDED FILING:
  Portal URL        : https://cybercrime.gov.in
  Helpline          : 1930 (National Cyber Crime Helpline)
  Section           : IT Act 2000 Sec 66 / 66C / 66D; IPC 420; BSA 2023 Sec 65B
    `.trim();
  }

  function renderPlaybook(geo, domain, score) {
    const list = document.getElementById('playbook-list');
    if (!list) return;
    const rules = [];
    if (geo.originatingNode?.ip) {
      rules.push({ icon: 'fa-ban', text: `BGP Blackhole / Null-Route: ${geo.originatingNode.ip} (AS${geo.originatingNode.isp})` });
      rules.push({ icon: 'fa-shield', text: `iptables: iptables -A INPUT -s ${geo.originatingNode.ip} -j DROP` });
      rules.push({ icon: 'fa-eye', text: `Snort/Suricata Rule: alert tcp ${geo.originatingNode.ip} any -> $HOME_NET 25 (msg:"MailSentry TI Block"; sid:20260901;)` });
    }
    if (domain.lookalikeMatch) {
      rules.push({ icon: 'fa-globe', text: `DNS Sinkhole / Registrar Abuse: ${domain.domain} → Report to Registrar via ICANN WDPRS` });
    }
    if (score.finalScore >= 65) {
      rules.push({ icon: 'fa-building-shield', text: `CERT-In Dispatch: Send incident report via CERT-In ISAC portal (https://cert-in.org.in)` });
    }
    if (score.finalScore >= 85) {
      rules.push({ icon: 'fa-gavel', text: `Freeze Beneficiary Account: Coordinate with NPCI / Cybercrime Wing for RTGS/NEFT fund hold` });
    }

    list.innerHTML = rules.length > 0
      ? rules.map(r => `<li class="playbook-item"><i class="fa-solid ${r.icon}"></i><div style="font-family:var(--font-mono); font-size:0.72rem; color:var(--text-secondary);">${r.text}</div></li>`).join('')
      : '<li class="playbook-item"><i class="fa-solid fa-check"></i><div>No immediate mitigation required for this email.</div></li>';
  }

  function updateBadge(id, protocol, status) {
    const badge = document.getElementById(id);
    if (!badge) return;
    const isPass = status === 'PASS';
    const cls = isPass ? 'pass' : (status === 'NEUTRAL' || status === 'NONE') ? 'neutral' : 'fail';
    badge.className = `auth-badge ${cls}`;
    badge.innerHTML = `<div class="protocol-name">${protocol}</div><div class="protocol-status">${status}</div>`;
  }

  function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text || 'N/A';
  }

  // ── SAMPLE BUTTONS ───────────────────────────────────────────────
  document.querySelectorAll('.sample-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.sample-btn').forEach(b => b.classList.remove('active-sample'));
      btn.classList.add('active-sample');
      const key = btn.getAttribute('data-sample');
      if (window.SAMPLE_EMAILS?.[key]) {
        const rawInput = document.getElementById('raw-email-input');
        if (rawInput) rawInput.value = window.SAMPLE_EMAILS[key].raw;
        window.runForensicAnalysis(window.SAMPLE_EMAILS[key].raw);
        if (window.AudioEngine) window.AudioEngine.blip();
      }
    });
  });

  // ── ANALYZE BUTTON ───────────────────────────────────────────────
  document.getElementById('btn-analyze-now')?.addEventListener('click', () => {
    const raw = document.getElementById('raw-email-input')?.value;
    if (window.AudioEngine) window.AudioEngine.buttonClick();
    window.runForensicAnalysis(raw);
  });

  // ── CLEAR BUTTON ─────────────────────────────────────────────────
  document.getElementById('btn-clear')?.addEventListener('click', () => {
    const ti = document.getElementById('raw-email-input');
    if (ti) ti.value = '';
    document.querySelectorAll('.sample-btn').forEach(b => b.classList.remove('active-sample'));
    if (window.AudioEngine) window.AudioEngine.buttonClick();
  });

  // ── DRAG & DROP .EML ─────────────────────────────────────────────
  const dropZone = document.getElementById('eml-drop-zone');
  const fileInput = document.getElementById('eml-file-input');

  if (dropZone) {
    dropZone.addEventListener('click', () => fileInput?.click());
    dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
    dropZone.addEventListener('drop', e => {
      e.preventDefault();
      dropZone.classList.remove('drag-over');
      const file = e.dataTransfer.files[0];
      if (file) readEmlFile(file);
    });
  }

  if (fileInput) {
    fileInput.addEventListener('change', () => {
      const file = fileInput.files[0];
      if (file) readEmlFile(file);
    });
  }

  function readEmlFile(file) {
    const reader = new FileReader();
    reader.onload = e => {
      const raw = e.target.result;
      const ti = document.getElementById('raw-email-input');
      if (ti) ti.value = raw;
      showToast(`Loaded: ${file.name}`, 'success');
      window.runForensicAnalysis(raw);
    };
    reader.readAsText(file);
  }

  // ── BLOCKCHAIN VAULT ACTIONS ─────────────────────────────────────
  document.getElementById('btn-verify-ledger')?.addEventListener('click', async () => {
    if (window.BlockchainVault.ledger.length === 0) { showToast('No blocks to verify. Run analysis first.', 'warn'); return; }
    if (window.AudioEngine) window.AudioEngine.scanStart();
    const results = await window.BlockchainVault.verifyLedgerIntegrity();
    const allValid = results.every(r => r.status === 'VERIFIED');
    const status = document.getElementById('ledger-status');
    if (status) {
      status.innerHTML = allValid
        ? '<i class="fa-solid fa-lock"></i> LEDGER SEALED & VERIFIED'
        : '<i class="fa-solid fa-triangle-exclamation"></i> TAMPER DETECTED';
      status.className = `tag ${allValid ? 'tag-green' : 'tag-red'}`;
    }
    showToast(allValid ? '✅ All blocks verified — ledger integrity confirmed' : '🚨 Tampering detected in blockchain ledger!', allValid ? 'success' : 'danger', 4000);
    if (window.AudioEngine) { if (allValid) window.AudioEngine.scanComplete(); else window.AudioEngine.criticalAlert(); }
  });

  document.getElementById('btn-tamper-demo')?.addEventListener('click', async () => {
    if (window.BlockchainVault.ledger.length === 0) { showToast('No blocks to tamper. Run analysis first.', 'warn'); return; }
    await window.BlockchainVault.simulateTampering();
    renderBlockchainLedger();
    const status = document.getElementById('ledger-status');
    if (status) { status.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i> TAMPER SIMULATED'; status.className = 'tag tag-red'; }
    showToast('🚨 Demo: Block #1 corrupted — verify ledger to detect breach', 'danger', 5000);
    if (window.AudioEngine) window.AudioEngine.criticalAlert();
  });

  document.getElementById('btn-print-panchnama')?.addEventListener('click', () => {
    if (!currentAnalysis) { showToast('Run analysis first.', 'warn'); return; }
    window.print();
    if (window.AudioEngine) window.AudioEngine.buttonClick();
  });

  document.getElementById('btn-download-panchnama')?.addEventListener('click', () => {
    if (!currentAnalysis) { showToast('Run analysis first.', 'warn'); return; }
    const reportText = window.BlockchainVault.generateBsaPanchnamaReport(currentAnalysis.evidenceBlock, currentAnalysis.parsed);
    const blob = new Blob([reportText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `${currentAnalysis.evidenceBlock.bsaComplianceCode}.txt`;
    a.click(); URL.revokeObjectURL(url);
    showToast('E-Panchnama downloaded', 'success');
    if (window.AudioEngine) window.AudioEngine.blockSealed();
  });

  // ── CERT-In COPY ─────────────────────────────────────────────────
  document.getElementById('btn-copy-certin')?.addEventListener('click', () => {
    const text = document.getElementById('certin-dispatch-json')?.textContent;
    if (text && text.includes('{')) {
      navigator.clipboard.writeText(text).then(() => showToast('CERT-In JSON copied to clipboard', 'success'));
      if (window.AudioEngine) window.AudioEngine.buttonClick();
    } else { showToast('Run analysis first.', 'warn'); }
  });

  document.getElementById('btn-copy-playbook')?.addEventListener('click', () => {
    const items = document.querySelectorAll('#playbook-list .playbook-item div');
    const text = Array.from(items).map(i => i.textContent).join('\n');
    navigator.clipboard.writeText(text).then(() => showToast('Mitigation playbook copied', 'success'));
    if (window.AudioEngine) window.AudioEngine.buttonClick();
  });

  // ── INIT ─────────────────────────────────────────────────────────
  initLeafletMap();

  // Auto-load SBI Phishing demo
  if (window.SAMPLE_EMAILS?.sbi_phish) {
    const rawInput = document.getElementById('raw-email-input');
    if (rawInput) rawInput.value = window.SAMPLE_EMAILS.sbi_phish.raw;
    document.querySelector('.sample-btn[data-sample="sbi_phish"]')?.classList.add('active-sample');
    // Small delay to allow DOM to settle
    setTimeout(() => window.runForensicAnalysis(window.SAMPLE_EMAILS.sbi_phish.raw), 400);
  }
});
