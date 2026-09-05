// Domain Intelligence, Homoglyph De-obfuscator & Brand Squatting Engine
// Expanded to 25+ critical Indian banking, fintech, and government domains

window.DomainEngine = {
  // 25+ Protected Indian Banking, Fintech, Government & National Infrastructure Domains
  protectedDomains: [
    'sbi.co.in', 'hdfcbank.com', 'icicibank.com', 'pnbindia.in', 'axisbank.com',
    'kotak.com', 'yesbank.in', 'canarabank.in', 'bankofbaroda.in', 'unionbankofindia.co.in',
    'incometax.gov.in', 'gst.gov.in', 'nic.in', 'cert-in.org.in', 'npci.org.in',
    'rbi.org.in', 'sebi.gov.in', 'uidai.gov.in', 'bharatpe.com', 'phonepe.com',
    'paytm.com', 'razorpay.com', 'policybazaar.com', 'liciindia.in', 'irctc.co.in',
    'google.com', 'microsoft.com', 'amazon.in', 'flipkart.com', 'myntra.com'
  ],

  // Unicode homoglyph mapping (Cyrillic, Greek, Latin lookalikes)
  homoglyphMap: {
    '\u0430': 'a', // Cyrillic а
    '\u0435': 'e', // Cyrillic е
    '\u043E': 'o', // Cyrillic о
    '\u0440': 'r', // Cyrillic р
    '\u0441': 'c', // Cyrillic с
    '\u0443': 'u', // Cyrillic у
    '\u0445': 'x', // Cyrillic х
    '\u0456': 'i', // Cyrillic і
    '\u0397': 'H', // Greek Η
    '\u039F': 'O', // Greek Ο
    '\u03A1': 'P', // Greek Ρ
    '\u03B1': 'a', // Greek α
    '\u03BF': 'o', // Greek ο
    '\u03C1': 'p', // Greek ρ
    '\u2113': 'l', // Script l
    '\u0131': 'i', // Dotless i
    '\u017F': 's', // Long s
  },

  analyzeDomain(domain) {
    if (!domain) {
      return { domain: 'N/A', isHomoglyph: false, lookalikeMatch: null, domainAgeDays: 0, riskScore: 50, homoglyphChars: [] };
    }

    const cleanDomain = domain.toLowerCase();

    // 1. Cyrillic / Greek / Unicode Homoglyph Detection
    const homoglyphRegex = /[\u0400-\u04FF\u0370-\u03FF\u2100-\u214F\u0131\u017F]/;
    const isHomoglyph = homoglyphRegex.test(domain);
    const homoglyphChars = [];
    for (const ch of domain) {
      if (this.homoglyphMap[ch]) {
        homoglyphChars.push({ char: ch, lookalike: this.homoglyphMap[ch], codePoint: ch.codePointAt(0).toString(16) });
      }
    }

    // Normalize by replacing homoglyphs for lookalike search
    let normalizedDomain = cleanDomain;
    for (const [char, replacement] of Object.entries(this.homoglyphMap)) {
      normalizedDomain = normalizedDomain.replaceAll(char, replacement);
    }

    // 2. Levenshtein Lookalike Search
    let lookalikeMatch = null;
    let minDistance = 999;
    this.protectedDomains.forEach(legitDomain => {
      const dist = this.levenshteinDistance(normalizedDomain, legitDomain);
      if (dist > 0 && dist <= 3 && dist < minDistance) {
        minDistance = dist;
        const technique = isHomoglyph ? 'Cyrillic/Unicode Homoglyph Substitution' : dist === 1 ? 'Typosquatting (1-char deviation)' : 'Combosquatting / Lookalike Brand Hijack';
        lookalikeMatch = {
          targetBrand: legitDomain,
          editDistance: dist,
          technique
        };
      }
    });

    // 3. Subdomain Impersonation Check (e.g., sbi.frauddomain.ru)
    let subdomainImpersonation = null;
    this.protectedDomains.forEach(brand => {
      const brandName = brand.split('.')[0];
      if (cleanDomain.includes(brandName) && cleanDomain !== brand) {
        subdomainImpersonation = { targetBrand: brand, technique: 'Subdomain / Prefix Impersonation' };
      }
    });

    // 4. TLD Risk Assessment
    const highRiskTlds = ['.ru', '.tk', '.xyz', '.online', '.top', '.click', '.live', '.pw', '.cc', '.to', '.biz'];
    const medRiskTlds = ['.info', '.net', '.org'];
    const hasSuspiciousTld = highRiskTlds.some(tld => cleanDomain.endsWith(tld));
    const hasMedRiskTld = medRiskTlds.some(tld => cleanDomain.endsWith(tld));

    // 5. Domain Age Simulation
    const isKnownGovOrBank = cleanDomain.endsWith('.gov.in') || cleanDomain.endsWith('.nic.in') || this.protectedDomains.includes(cleanDomain);
    const domainAgeDays = isKnownGovOrBank ? 4500 : (hasSuspiciousTld ? 12 : hasMedRiskTld ? 120 : 180);

    // 6. Score Computation
    let riskScore = 0;
    if (isHomoglyph) riskScore += 45;
    if (lookalikeMatch) riskScore += 30;
    if (subdomainImpersonation && !lookalikeMatch) riskScore += 20;
    if (hasSuspiciousTld) riskScore += 20;
    if (domainAgeDays < 30) riskScore += 20;
    if (domainAgeDays < 10) riskScore += 10;

    return {
      domain: cleanDomain,
      isHomoglyph,
      homoglyphChars,
      normalizedDomain,
      lookalikeMatch: lookalikeMatch || subdomainImpersonation,
      hasSuspiciousTld,
      hasMedRiskTld,
      domainAgeDays,
      riskScore: Math.min(100, riskScore)
    };
  },

  levenshteinDistance(a, b) {
    const matrix = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(matrix[i - 1][j - 1] + 1, matrix[i][j - 1] + 1, matrix[i - 1][j] + 1);
        }
      }
    }
    return matrix[b.length][a.length];
  }
};
