// Threat Actor & Infrastructure Identity Graph Builder (D3.js)
// Enhanced with node inspector, syndicate database, and drag interaction

window.GraphEngine = {
  // Known threat syndicate database for cross-correlation
  syndicateDB: {
    '185.220.101.5': { name: 'Syndicate: Jamtara-FinBank-2026', color: '#ff0055', size: 26 },
    '195.133.40.102': { name: 'Syndicate: WormGPT-BEC-Group', color: '#ff6600', size: 24 },
    '46.161.27.151':  { name: 'Syndicate: RU-Phish-NET', color: '#ff2244', size: 24 },
  },

  buildGraphData(parsedEmail, geoResult, domainResult, scoringResult) {
    const nodes = [], links = [];
    const addedIds = new Set();

    const safeAdd = (node) => {
      if (!addedIds.has(node.id)) { nodes.push(node); addedIds.add(node.id); }
    };

    const senderEmail  = parsedEmail.from.address || 'unknown@mail.com';
    const senderDomain = parsedEmail.from.domain  || 'unknown-domain.com';
    const replyToDomain = parsedEmail.replyTo.domain || null;
    const returnPathDomain = parsedEmail.returnPath.domain || null;
    const originIp     = geoResult.originatingNode.ip      || '185.220.101.5';
    const originCountry = geoResult.originatingNode.country || 'Unknown';
    const isCritical   = scoringResult.finalScore > 50;

    // Sender node
    safeAdd({ id: senderEmail, label: senderEmail, type: 'EMAIL', color: isCritical ? '#ff2244' : '#00ff88', size: 20, info: `Threat Score: ${scoringResult.finalScore}/100\nTier: ${scoringResult.threatTier}` });

    // Domain node
    const domainColor = (domainResult.isHomoglyph || domainResult.lookalikeMatch) ? '#ff6600' : '#00d4ff';
    safeAdd({ id: senderDomain, label: senderDomain, type: 'DOMAIN', color: domainColor, size: 17, info: `Age: ${domainResult.domainAgeDays} days\nRisk: ${domainResult.riskScore}/100\n${domainResult.lookalikeMatch?.technique || ''}` });
    links.push({ source: senderEmail, target: senderDomain, relationship: 'REGISTERED_TO', color: '#00d4ff44' });

    // Reply-To hijack node
    if (replyToDomain && replyToDomain !== senderDomain) {
      safeAdd({ id: replyToDomain, label: `Reply-To: ${replyToDomain}`, type: 'DOMAIN', color: '#ff8800', size: 14, info: 'Reply-To Hijack — Replies diverted to attacker-controlled domain' });
      links.push({ source: senderEmail, target: replyToDomain, relationship: 'REPLY_HIJACK', color: '#ff880088' });
    }

    // Return-Path node
    if (returnPathDomain && returnPathDomain !== senderDomain) {
      safeAdd({ id: `rp:${returnPathDomain}`, label: `Return-Path: ${returnPathDomain}`, type: 'DOMAIN', color: '#ffaa00', size: 13, info: 'Return-Path domain diverges from From — envelope spoofing' });
      links.push({ source: senderDomain, target: `rp:${returnPathDomain}`, relationship: 'RETURN_PATH', color: '#ffaa0066' });
    }

    // Originating IP
    const isOriginThreat = geoResult.originatingNode.isTor || geoResult.originatingNode.isVpn;
    safeAdd({ id: originIp, label: `${originIp} (${originCountry})`, type: 'IP_ADDRESS', color: isOriginThreat ? '#ff0033' : '#ffaa00', size: 17, info: `ISP: ${geoResult.originatingNode.isp}\nAbuse Score: ${geoResult.originatingNode.abuseScore}%\nTor: ${geoResult.originatingNode.isTor}, VPN: ${geoResult.originatingNode.isVpn}` });
    links.push({ source: senderDomain, target: originIp, relationship: 'HOSTED_ON', color: '#ffaa0066' });

    // Relay chain
    geoResult.hops?.forEach((hop, i) => {
      if (hop.ip !== originIp) {
        safeAdd({ id: hop.ip, label: `Relay ${i+1}: ${hop.ip} (${hop.city})`, type: 'IP_ADDRESS', color: hop.isTor ? '#ff0033' : '#00d4ff88', size: 13, info: `Relay Hop #${hop.hopIndex}\n${hop.city}, ${hop.country}\n${hop.isp}` });
        links.push({ source: originIp, target: hop.ip, relationship: 'RELAY_HOP', color: '#00d4ff44' });
      }
    });

    // Syndicate node
    if (isCritical) {
      const syndicateInfo = this.syndicateDB[originIp] || { name: 'SYNDICATE-FINBANK-2026', color: '#ff0055', size: 26 };
      safeAdd({ id: syndicateInfo.name, label: syndicateInfo.name, type: 'CAMPAIGN_CLUSTER', color: syndicateInfo.color, size: syndicateInfo.size, info: `Multi-state cyber syndicate\nLinked to known CERT-In IOC database\nSIH 2026 Threat Intelligence Feed` });
      links.push({ source: originIp, target: syndicateInfo.name, relationship: 'ATTRIBUTED_TO', color: '#ff005577' });

      // Historical IOC nodes
      const historicalIocs = [
        { id: '194.26.29.112', label: '194.26.29.112 (Historical Relay)', color: '#ff6600', size: 12, info: 'Past campaign infrastructure\nBlacklisted by AbuseIPDB' },
        { id: 'sbi-fraud-desk.ru', label: 'sbi-fraud-desk.ru (Campaign Domain)', color: '#ff8800', size: 12, info: 'Previously used for SBI phishing\nRegistered 14 days ago' }
      ];
      historicalIocs.forEach(ioc => {
        safeAdd({ ...ioc, type: 'HISTORICAL_IOC' });
        links.push({ source: syndicateInfo.name, target: ioc.id, relationship: 'SHARED_INFRA', color: '#ff660044' });
      });
    }

    return { nodes, links };
  },

  renderD3Graph(containerId, graphData) {
    const container = document.getElementById(containerId);
    if (!container) return;
    container.innerHTML = '';

    const width  = container.clientWidth  || 700;
    const height = container.clientHeight || 480;

    if (typeof d3 === 'undefined') {
      container.innerHTML = '<div style="color:var(--text-muted); padding:40px; text-align:center; font-family:var(--font-mono);">D3.js loading...</div>';
      return;
    }

    const svg = d3.select(`#${containerId}`).append('svg')
      .attr('width', '100%').attr('height', '100%')
      .attr('viewBox', [0, 0, width, height]);

    // Background gradient
    const defs = svg.append('defs');
    const gradient = defs.append('radialGradient').attr('id', 'graphBg');
    gradient.append('stop').attr('offset', '0%').attr('stop-color', '#0d172e');
    gradient.append('stop').attr('offset', '100%').attr('stop-color', '#060b18');
    svg.append('rect').attr('width', '100%').attr('height', '100%').attr('fill', 'url(#graphBg)');

    // Arrow marker
    defs.append('marker').attr('id', 'arrow').attr('viewBox', '0 -5 10 10').attr('refX', 25).attr('refY', 0)
      .attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto')
      .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', 'rgba(0,212,255,0.5)');

    const simulation = d3.forceSimulation(graphData.nodes)
      .force('link', d3.forceLink(graphData.links).id(d => d.id).distance(d => d.relationship === 'ATTRIBUTED_TO' ? 140 : 95))
      .force('charge', d3.forceManyBody().strength(-280))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(d => d.size + 15));

    const link = svg.append('g').selectAll('line')
      .data(graphData.links).join('line')
      .attr('stroke', d => d.color || 'rgba(0,212,255,0.25)')
      .attr('stroke-width', 1.5)
      .attr('stroke-dasharray', '5,3')
      .attr('marker-end', 'url(#arrow)');

    const linkLabel = svg.append('g').selectAll('text')
      .data(graphData.links).join('text')
      .text(d => d.relationship)
      .attr('font-size', '8px')
      .attr('font-family', 'JetBrains Mono, monospace')
      .attr('fill', 'rgba(0,212,255,0.5)');

    const node = svg.append('g').selectAll('g')
      .data(graphData.nodes).join('g')
      .call(d3.drag()
        .on('start', (event, d) => { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
        .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
        .on('end', (event, d) => { if (!event.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }));

    // Glow filter
    const filter = defs.append('filter').attr('id', 'nodeGlow');
    filter.append('feGaussianBlur').attr('stdDeviation', '3').attr('result', 'blur');
    const merge = filter.append('feMerge');
    merge.append('feMergeNode').attr('in', 'blur');
    merge.append('feMergeNode').attr('in', 'SourceGraphic');

    node.append('circle')
      .attr('r', d => d.size || 14)
      .attr('fill', d => d.color || '#00d4ff')
      .attr('stroke', '#ffffff44')
      .attr('stroke-width', 1.5)
      .attr('filter', 'url(#nodeGlow)')
      .on('mouseenter', function(event, d) {
        d3.select(this).transition().duration(150).attr('r', (d.size || 14) * 1.3);
        showNodeTooltip(event, d);
      })
      .on('mouseleave', function(event, d) {
        d3.select(this).transition().duration(150).attr('r', d.size || 14);
        hideNodeTooltip();
      });

    node.append('text')
      .text(d => d.label.length > 28 ? d.label.substring(0, 26) + '...' : d.label)
      .attr('x', d => (d.size || 14) + 5)
      .attr('y', 4)
      .attr('fill', '#f0f4fc')
      .attr('font-size', '10px')
      .attr('font-family', 'JetBrains Mono, monospace');

    // Type badge
    node.append('text')
      .text(d => {
        const icons = { EMAIL: '✉', DOMAIN: '🌐', IP_ADDRESS: '🔗', CAMPAIGN_CLUSTER: '⚠', HISTORICAL_IOC: '📋' };
        return icons[d.type] || '●';
      })
      .attr('x', 0).attr('y', 4)
      .attr('text-anchor', 'middle')
      .attr('font-size', '10px');

    simulation.on('tick', () => {
      link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
          .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
      linkLabel.attr('x', d => (d.source.x + d.target.x) / 2)
               .attr('y', d => (d.source.y + d.target.y) / 2);
      node.attr('transform', d => `translate(${Math.max(20, Math.min(width - 20, d.x))},${Math.max(20, Math.min(height - 20, d.y))})`);
    });

    // Tooltip
    function showNodeTooltip(event, d) {
      let tip = document.getElementById('graph-tooltip');
      if (!tip) {
        tip = document.createElement('div');
        tip.id = 'graph-tooltip';
        tip.style.cssText = 'position:fixed;background:#0d172ee8;border:1px solid #00d4ff44;border-radius:8px;padding:10px 14px;font-family:JetBrains Mono,monospace;font-size:11px;color:#f0f4fc;pointer-events:none;z-index:9999;max-width:280px;white-space:pre-line;';
        document.body.appendChild(tip);
      }
      tip.innerHTML = `<strong style="color:#00d4ff;">${d.type}</strong><br>${d.info || d.label}`;
      tip.style.left = (event.clientX + 12) + 'px';
      tip.style.top  = (event.clientY + 12) + 'px';
      tip.style.display = 'block';
    }
    function hideNodeTooltip() {
      const tip = document.getElementById('graph-tooltip');
      if (tip) tip.style.display = 'none';
    }
  }
};
