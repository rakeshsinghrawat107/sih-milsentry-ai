// AI NLP & Stylometry Forensic Classifier
// Enhanced with expanded Indian banking vocabulary, WormGPT/GenAI detection, and MITRE ATT&CK tagging

window.NlpEngine = {
  analyzeText(subject, body, senderName) {
    const fullText = `${subject} ${senderName} ${body}`.toLowerCase();

    // 1. Urgency & Social Engineering Trigger Lexicon (Indian-specific)
    const urgencyKeywords = [
      'urgent', 'immediately', 'within 24 hours', 'within 48 hours', 'action required',
      'suspended', 'terminated', 'permanently blocked', 'critical notice', 'overdue',
      'legal action', 'statutory penalty', 'wire transfer', 'rtgs', 'neft', 'imps',
      'escrow', 'aadhaar', 'pan card', 'kyc update', 'income tax refund', 'itc mismatch',
      'tds refund', 'penalty notice', 'court summons', 'final notice', 'last warning',
      'account will be locked', 'click here now', 'verify now', 'deadline today',
      'itr refund', 'cbdt', 'rbi directive', 'sebi circular', 'narcotics', 'ed investigation'
    ];

    let urgencyMatches = urgencyKeywords.filter(kw => fullText.includes(kw));

    // 2. Business Email Compromise (BEC) Patterns
    const becKeywords = [
      'confidential', 'closed-door', 'do not call', 'cannot take phone', 'cannot speak',
      'wire the funds', 'bank transfer', 'beneficiary', 'ifsc', 'escrow payment',
      'acquisition', 'strictly private', 'settlement tranche', 'acquisition settlement',
      'strategic vendor', 'ministry review', 'utr number', 'transfer today',
      'strictly confidential', 'do not involve', 'bypass', 'direct transfer',
      'authorized signatory', 'board approval', 'emergency wire', 'account details below'
    ];
    let becMatches = becKeywords.filter(kw => fullText.includes(kw));

    // 3. Credential Harvesting & Phishing Verbs
    const phishKeywords = [
      'verify account', 'update kyc', 'click here', 'login now', 'confirm password',
      'netbanking', 'unlock card', 'claim refund', 'scan qr', 'otp', 'pin number',
      'password expired', 'reactivate', 'secure portal', 'validate identity',
      'linked aadhaar', 'upload documents', 'account suspended', 'blocked debit card',
      'upi blocked', 'cvv', 'credit card number', 'mobile banking'
    ];
    let phishMatches = phishKeywords.filter(kw => fullText.includes(kw));

    // 4. Quishing / QR-Code Social Engineering
    const quishingKeywords = ['scan qr', 'qr code', 'scan the code', 'payment qr', 'gst invoice qr'];
    const quishMatches = quishingKeywords.filter(kw => fullText.includes(kw));

    // 5. Stylometry: Perplexity & Burstiness Calculation
    const words = fullText.split(/\s+/).filter(w => w.length > 0);
    const totalWords = words.length || 1;
    const avgWordLength = words.reduce((acc, w) => acc + w.length, 0) / totalWords;

    const sentences = fullText.split(/[.!?]+/).filter(s => s.trim().length > 5);
    const sentenceLengths = sentences.map(s => s.trim().split(/\s+/).length);
    const avgSentenceLength = sentenceLengths.reduce((a, b) => a + b, 0) / (sentences.length || 1);
    const variance = sentenceLengths.reduce((acc, len) => acc + Math.pow(len - avgSentenceLength, 2), 0) / (sentences.length || 1);
    const burstiness = Math.sqrt(variance);

    // AI/WormGPT: Low burstiness + highly formal cohesion + financial trigger
    const isSyntheticAI = burstiness < 2.5 && totalWords > 40 && (becMatches.length > 0 || urgencyMatches.length > 0);

    // Vocabulary richness (Type-Token Ratio)
    const uniqueWords = new Set(words);
    const ttr = uniqueWords.size / totalWords;

    // 6. Compute sub-scores
    const urgencyScore  = Math.min(100, urgencyMatches.length * 15);
    const becScore      = Math.min(100, becMatches.length * 20);
    const phishScore    = Math.min(100, phishMatches.length * 20);
    const quishScore    = Math.min(100, quishMatches.length * 30);

    // 7. Threat category & MITRE ATT&CK technique
    let threatCategory = 'BENIGN';
    let mitreTag = 'None';
    let mitreUrl = '';

    if (becScore >= 40) {
      threatCategory = 'BEC_EXECUTIVE_FRAUD';
      mitreTag = 'T1566.001 — Spearphishing Attachment / BEC Wire Fraud';
      mitreUrl = 'https://attack.mitre.org/techniques/T1566/001/';
    } else if (quishScore >= 30) {
      threatCategory = 'QUISHING_QR_CODE';
      mitreTag = 'T1566.002 — Spearphishing Link via QR Steganography';
      mitreUrl = 'https://attack.mitre.org/techniques/T1566/002/';
    } else if (phishScore >= 40) {
      threatCategory = 'CREDENTIAL_HARVESTING';
      mitreTag = 'T1566 — Phishing / Credential Access (T1078)';
      mitreUrl = 'https://attack.mitre.org/techniques/T1566/';
    } else if (urgencyScore >= 30) {
      threatCategory = 'SOCIAL_ENGINEERING';
      mitreTag = 'T1598 — Phishing for Information / Social Engineering';
      mitreUrl = 'https://attack.mitre.org/techniques/T1598/';
    }

    return {
      threatCategory,
      urgencyScore,
      becScore,
      phishScore,
      quishScore,
      isSyntheticAI,
      burstinessScore: burstiness.toFixed(2),
      avgSentenceLength: avgSentenceLength.toFixed(1),
      avgWordLength: avgWordLength.toFixed(1),
      typeTokenRatio: ttr.toFixed(3),
      totalWords,
      mitreTag,
      mitreUrl,
      detectedUrgencyTerms: urgencyMatches,
      detectedBecTerms: becMatches,
      detectedPhishTerms: phishMatches,
      detectedQuishTerms: quishMatches
    };
  }
};
