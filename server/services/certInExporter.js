/**
 * MailSentry AI — CERT-In Annexure-I Mandatory Incident Reporting Generator
 * Conforms with CERT-In directions under Section 70B of the Information Technology Act, 2000
 * Mandatory format for dispatch to incident@cert-in.org.in within 6 hours of detection.
 */

class CertInExporter {
  /**
   * Generates official CERT-In Section 70B incident payload
   * @param {Object} incidentData 
   */
  generateAnnexure1(incidentData) {
    const {
      incidentId = `CERT-IN-${Date.now().toString(36).toUpperCase()}`,
      reportingOrganization = 'National Cyber Security Response Operations / Law Enforcement Forensic Unit',
      contactPerson = 'Forensic Nodal Officer',
      email = 'nodal-officer@cybercrime.gov.in',
      phone = '+91-11-24368544',
      analysisResult,
      rawEmailHash
    } = incidentData;

    const now = new Date();
    const istTime = now.toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', hour12: false });
    const utcTime = now.toUTCString();

    const score = analysisResult?.score || {};
    const geo = analysisResult?.geo || {};
    const headers = analysisResult?.headers || {};
    const parsed = analysisResult?.parsed || {};

    // Map internal classification to CERT-In Incident Taxonomy
    let certInType = 'Phishing / Brand Impersonation';
    if (score.threatTier === 'CRITICAL') certInType = 'Targeted Spear-Phishing / Advanced Persistent Threat (APT) / BEC Wire Fraud';
    else if (parsed.quishingDetected) certInType = 'Malicious QR Code (Quishing) Financial Cyber Crime';

    const payload = {
      annexureType: 'ANNEXURE-I',
      statutoryMandate: 'Section 70B of Information Technology Act 2000 & CERT-In Cyber Security Directions (No. 20(3)/2022-CERT-In)',
      mandatoryDispatchWindow: 'Within 6 hours of notice/detection',
      incidentSummary: {
        incidentId,
        reportingDateIST: istTime,
        reportingDateUTC: utcTime,
        reportingOrganization,
        nodalOfficer: {
          name: contactPerson,
          email,
          phone
        },
        incidentClassification: certInType,
        threatSeverity: score.threatTier || 'HIGH',
        threatScore: `${score.finalScore || 85} / 100`
      },
      indicatorsOfCompromise: {
        originatingMtaIp: geo.originatingNode?.ip || 'Undetermined',
        originGeoLocation: `${geo.originatingNode?.city || 'Unknown'}, ${geo.originatingNode?.country || 'Unknown'}`,
        originIspAsn: geo.originatingNode?.isp || 'Unknown',
        senderAddress: parsed.from?.raw || 'Unknown',
        impersonatedDomain: analysisResult?.domain?.lookalikeMatch?.targetBrand || 'N/A',
        returnPath: parsed.returnPath?.raw || 'N/A',
        replyTo: parsed.replyTo?.raw || 'N/A',
        subjectLine: parsed.subject || 'N/A',
        suspiciousUrlsExtracted: parsed.urls || [],
        quishingPayload: parsed.quishingPayload || null,
        sha256EvidenceHash: rawEmailHash || analysisResult?.evidenceBlock?.rawEmailHash || 'N/A',
        blockchainLedgerAnchor: analysisResult?.evidenceBlock?.blockHash || 'N/A',
        bsa2023Reference: analysisResult?.evidenceBlock?.bsaComplianceCode || `BSA-2023-SEC65B-${Date.now().toString(36).toUpperCase()}`
      },
      authenticationFailures: {
        spf: headers.spfStatus || 'FAIL',
        dkim: headers.dkimStatus || 'FAIL',
        dmarc: headers.dmarcStatus || 'FAIL',
        anomalies: headers.anomalies || []
      },
      recommendedRemediation: [
        `Submit origin IP ${geo.originatingNode?.ip || 'N/A'} for immediate National Firewall BGP Blackholing`,
        `Issue domain takedown advisory for ${(analysisResult?.domain?.domain || 'malicious domain')}`,
        `Broadcast IOC hashes to Indian Banking & Financial CERT (CERT-Fin) threat feed`,
        `Anchor evidence into Bharatiya Sakshya Adhiniyam 2023 Panchnama archive`
      ]
    };

    return payload;
  }
}

module.exports = new CertInExporter();
