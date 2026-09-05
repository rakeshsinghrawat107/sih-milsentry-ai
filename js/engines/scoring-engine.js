// 14-Signal Weighted Threat Scoring & Decision Aggregator
// Enhanced with MITRE ATT&CK mapping, display spoofing detection, and suspicious URL signals

window.ScoringEngine = {
  calculateScore(parsedEmail, nlpResult, headerResult, geoResult, domainResult) {
    let totalScore = 0;
    const signalBreakdown = [];

    const addSignal = (condition, signal, weight, type) => {
      if (condition) {
        totalScore += weight;
        signalBreakdown.push({ signal, weight, type });
      }
    };

    // ── AUTHENTICATION SIGNALS ──────────────────────────────────────────────────
    addSignal(headerResult.spfStatus === 'FAIL',
      'SPF Authentication Failed — Sender IP not permitted in DNS TXT record', 20, 'CRITICAL');
    addSignal(headerResult.spfStatus === 'SOFTFAIL',
      'SPF Softfail — Sender IP outside authorized range', 10, 'WARN');
    addSignal(headerResult.dkimStatus === 'FAIL',
      'DKIM Signature Forged / Invalid — Cryptographic hash mismatch', 18, 'CRITICAL');
    addSignal(headerResult.dmarcStatus === 'FAIL',
      'DMARC Enforcement Policy Violation', 15, 'CRITICAL');
    addSignal(!headerResult.isReturnPathAligned || !headerResult.isReplyToAligned,
      'Reply-To / Return-Path Domain Hijack — Replies redirected to attacker', 15, 'CRITICAL');
    addSignal(headerResult.isDisplaySpoofed,
      'Display Name Spoofing — Bank name impersonated in "From" field', 12, 'CRITICAL');

    // ── DOMAIN INTELLIGENCE SIGNALS ────────────────────────────────────────────
    addSignal(domainResult.isHomoglyph,
      `Cyrillic / Unicode Homoglyph Character Injection in domain "${domainResult.domain}"`, 20, 'CRITICAL');
    addSignal(!!(domainResult.lookalikeMatch),
      `Lookalike Domain Attack targeting: ${domainResult.lookalikeMatch?.targetBrand || 'Protected Brand'} (${domainResult.lookalikeMatch?.technique || ''})`, 18, 'CRITICAL');
    addSignal(domainResult.domainAgeDays < 30,
      `Newly Registered Disposable Domain — Age: ${domainResult.domainAgeDays} days`, 12, 'WARN');
    addSignal(domainResult.hasSuspiciousTld,
      `High-Abuse Top-Level Domain: ${domainResult.domain}`, 10, 'WARN');

    // ── GEOSPATIAL & NETWORK SIGNALS ────────────────────────────────────────────
    addSignal(geoResult.originatingNode?.isTor,
      `Tor Network Exit Node — IP: ${geoResult.originatingNode?.ip} (${geoResult.originatingNode?.country})`, 18, 'CRITICAL');
    addSignal(!geoResult.originatingNode?.isTor && geoResult.originatingNode?.isVpn,
      `Anonymizing Commercial VPN Gateway — ${geoResult.originatingNode?.isp}`, 10, 'WARN');
    addSignal(geoResult.stradAnomalies?.length > 0,
      `STRAD Physics Violation — ${geoResult.stradAnomalies?.[0]?.flag || 'Intercontinental relay anomaly'}`, 15, 'CRITICAL');

    // ── NLP / AI CONTENT SIGNALS ─────────────────────────────────────────────
    addSignal(nlpResult.urgencyScore >= 30,
      `High-Urgency Social Engineering Language — ${nlpResult.detectedUrgencyTerms?.slice(0,3).join(', ')}`, 12, 'WARN');
    addSignal(nlpResult.becScore >= 40,
      `BEC Wire Coercion — C-Suite Impersonation Escrow/RTGS Payment Demand`, 18, 'CRITICAL');
    addSignal(nlpResult.phishScore >= 40,
      `Credential Harvesting Verbs Detected — ${nlpResult.detectedPhishTerms?.slice(0,3).join(', ')}`, 14, 'WARN');
    addSignal(nlpResult.quishScore >= 30,
      `Quishing (QR-Code) Social Engineering Vector — ${nlpResult.detectedQuishTerms?.slice(0,2).join(', ')}`, 18, 'CRITICAL');
    addSignal(nlpResult.isSyntheticAI,
      `GenAI / WormGPT Linguistic Fingerprint — Low burstiness (${nlpResult.burstinessScore}), Uniform phrasing`, 12, 'WARN');

    // ── ATTACHMENT & PAYLOAD SIGNALS ─────────────────────────────────────────
    addSignal(parsedEmail.hasQuishing,
      `QR Code Payload URL Detected in email body`, 18, 'CRITICAL');
    addSignal(parsedEmail.hasAttachment,
      `Suspicious Attachment Detected: ${parsedEmail.attachmentNames?.join(', ') || 'Unknown file'}`, 10, 'WARN');
    addSignal(parsedEmail.suspiciousUrls?.length > 0,
      `Malicious / Suspicious Redirect URL — ${parsedEmail.suspiciousUrls?.[0] || ''}`, 15, 'CRITICAL');

    // Cap at 100
    const finalScore = Math.min(100, totalScore);

    // Tier classification
    let threatTier = 'SAFE', colorClass = 'safe';
    let summaryText = 'Email demonstrates legitimate authentication, routing, and content.';

    if (finalScore >= 85) {
      threatTier = 'CRITICAL FRAUD';
      colorClass = 'critical';
      summaryText = 'Active weaponized cyberattack confirmed. Immediate containment, CERT-In dispatch, and I4C 1930 FIR recommended.';
    } else if (finalScore >= 65) {
      threatTier = 'HIGH RISK FRAUD';
      colorClass = 'fraud';
      summaryText = 'High-confidence malicious email attempting financial diversion or large-scale credential theft.';
    } else if (finalScore >= 45) {
      threatTier = 'PHISHING ATTEMPT';
      colorClass = 'phishing';
      summaryText = 'Credential harvesting or lookalike domain impersonation detected. Quarantine and investigate immediately.';
    } else if (finalScore >= 25) {
      threatTier = 'SUSPICIOUS';
      colorClass = 'suspicious';
      summaryText = 'Anomalies detected in header routing, domain age, or content. Exercise caution and manual review recommended.';
    }

    const mitreTag = nlpResult.mitreTag || 'T1566 — Phishing';
    const mitreUrl = nlpResult.mitreUrl || 'https://attack.mitre.org/techniques/T1566/';

    return { finalScore, threatTier, colorClass, summaryText, signalBreakdown, mitreTag, mitreUrl };
  }
};
