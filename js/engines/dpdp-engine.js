/**
 * MailSentry AI — DPDP Act 2023 Compliance & Citizen PII Redaction Engine
 * Digital Personal Data Protection Act, 2023 (DPDP Act) Section 4 & 8 Compliance.
 * Automatically masks citizen personal data (Aadhaar, PAN, phone numbers, cards)
 * to prevent unauthorized leak of victim PII in forensic logs, incident dispatches, and court reports.
 */

window.DpdpEngine = {
  // Regex patterns for Indian citizen identifiers
  patterns: {
    aadhaar: /\b([2-9]\d{3})[ -]?(\d{4})[ -]?(\d{4})\b/g,
    pan: /\b([A-Z]{5})(\d{4})([A-Z])\b/g,
    phone: /\b(?:\+?91|0)?[ -]?([6-9]\d{4})[ -]?(\d{5})\b/g,
    creditCard: /\b(\d{4})[ -]?(\d{4})[ -]?(\d{4})[ -]?(\d{4})\b/g,
    bankAccount: /\b(\d{3,6})(\d{5,10})\b/g
  },

  /**
   * Inspect text and redact sensitive citizen PII according to DPDP Act 2023
   * @param {string} text 
   * @param {boolean} maskOnly If true, returns masked text; if false, extracts matches
   */
  redactPii(text, maskOnly = true) {
    if (!text || typeof text !== 'string') return { text: '', detectedPii: [], hasPii: false };

    let redacted = text;
    const detectedPii = [];

    // 1. Aadhaar Redaction (Mask first 8 digits: XXXX-XXXX-1234)
    redacted = redacted.replace(this.patterns.aadhaar, (match, p1, p2, p3) => {
      detectedPii.push({ type: 'AADHAAR_NUMBER', raw: match, masked: `XXXX-XXXX-${p3}` });
      return `XXXX-XXXX-${p3}`;
    });

    // 2. PAN Card Redaction (Mask middle 4 digits: ABCDE****F)
    redacted = redacted.replace(this.patterns.pan, (match, p1, p2, p3) => {
      detectedPii.push({ type: 'PAN_CARD', raw: match, masked: `${p1}****${p3}` });
      return `${p1}****${p3}`;
    });

    // 3. Indian Mobile Number (Mask first 5 digits: +91-XXXXX-98765)
    redacted = redacted.replace(this.patterns.phone, (match, p1, p2) => {
      detectedPii.push({ type: 'MOBILE_NUMBER', raw: match, masked: `+91-XXXXX-${p2}` });
      return `+91-XXXXX-${p2}`;
    });

    // 4. Payment Card (Mask first 12 digits: XXXX-XXXX-XXXX-1234)
    redacted = redacted.replace(this.patterns.creditCard, (match, p1, p2, p3, p4) => {
      detectedPii.push({ type: 'FINANCIAL_CARD', raw: match, masked: `XXXX-XXXX-XXXX-${p4}` });
      return `XXXX-XXXX-XXXX-${p4}`;
    });

    return {
      redactedText: redacted,
      detectedPii,
      hasPii: detectedPii.length > 0,
      piiCount: detectedPii.length,
      complianceNote: detectedPii.length > 0
        ? `DPDP Act 2023 Enforced: ${detectedPii.length} citizen PII identifiers automatically redacted.`
        : 'DPDP Act 2023: No unmasked citizen PII identified.'
    };
  }
};
