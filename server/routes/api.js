/**
 * MailSentry AI — REST API Endpoints Router
 * Exposes live DNS, IP intelligence, RDAP WHOIS, and CERT-In dispatch endpoints.
 */

const express = require('express');
const router = express.Router();

const dnsVerifier = require('../services/dnsVerifier');
const geoResolver = require('../services/geoResolver');
const whoisResolver = require('../services/whoisResolver');
const certInExporter = require('../services/certInExporter');
const geminiAnalyzer = require('../services/geminiAnalyzer');
const virusTotalScanner = require('../services/virusTotalScanner');

/**
 * Health check & platform capability discovery
 */
router.get('/status', (req, res) => {
  res.json({
    status: 'ONLINE',
    platform: 'MailSentry AI Enterprise Backend',
    version: '2.0.0',
    capabilities: [
      'LIVE_DNS_SPF_DKIM_DMARC',
      'LIVE_IP_GEOLOCATION_ASN',
      'ICANN_RDAP_DOMAIN_INTELLIGENCE',
      'CERT_IN_70B_ANNEXURE1_DISPATCH',
      'BSA_2023_EVIDENCE_ANCHORING',
      'LIVE_GEMINI_AI_ANALYSIS',
      'LIVE_VIRUSTOTAL_SCANNING'
    ],
    timestamp: new Date().toISOString()
  });
});

/**
 * Live DNS verification endpoint for SPF/DMARC/MX
 * Body: { domain: "sbi.co.in", originIp: "185.220.101.5" }
 */
router.post('/dns/verify', async (req, res) => {
  try {
    const { domain, originIp } = req.body;
    if (!domain) {
      return res.status(400).json({ error: 'domain field is required' });
    }

    const audit = await dnsVerifier.runFullDomainDnsAudit(domain, originIp);
    res.json({ success: true, audit });
  } catch (err) {
    res.status(500).json({ error: 'DNS verification failed', details: err.message });
  }
});

/**
 * Live Geolocation and Threat IP Lookup
 * Body: { ip: "185.220.101.5" }
 */
router.post('/ip/lookup', async (req, res) => {
  try {
    const { ip } = req.body;
    if (!ip) {
      return res.status(400).json({ error: 'ip field is required' });
    }

    const geo = await geoResolver.lookupIp(ip);
    res.json({ success: true, geo });
  } catch (err) {
    res.status(500).json({ error: 'IP lookup failed', details: err.message });
  }
});

/**
 * Live RDAP/WHOIS Domain Age Resolution
 * Body: { domain: "sbi-kyc-update.com" }
 */
router.post('/whois/lookup', async (req, res) => {
  try {
    const { domain } = req.body;
    if (!domain) {
      return res.status(400).json({ error: 'domain field is required' });
    }

    const whois = await whoisResolver.lookupDomain(domain);
    res.json({ success: true, whois });
  } catch (err) {
    res.status(500).json({ error: 'Domain WHOIS lookup failed', details: err.message });
  }
});

/**
 * Generate official CERT-In Section 70B Incident Dispatch Docket
 * Body: { incidentData: { ... } }
 */
router.post('/certin/dispatch', (req, res) => {
  try {
    const { incidentData } = req.body;
    if (!incidentData) {
      return res.status(400).json({ error: 'incidentData field is required' });
    }

    const dispatchDocket = certInExporter.generateAnnexure1(incidentData);
    res.json({ success: true, dispatchDocket });
  } catch (err) {
    res.status(500).json({ error: 'CERT-In dispatch generation failed', details: err.message });
  }
});

/**
 * Full Server-Side Forensic Pipeline Triage
 * Body: { domain, originIp, emailData }
 */
router.post('/analyze', async (req, res) => {
  try {
    const { domain, originIp, emailData } = req.body;
    const isLiveApiEnabled = process.env.ENABLE_LIVE_API_SCANS === 'true';

    const tasks = [
      domain ? dnsVerifier.runFullDomainDnsAudit(domain, originIp) : Promise.resolve(null),
      originIp ? geoResolver.lookupIp(originIp) : Promise.resolve(null),
      domain ? whoisResolver.lookupDomain(domain) : Promise.resolve(null),
    ];

    // Live Gemini NLP AI Scan
    if (isLiveApiEnabled && emailData && geminiAnalyzer.isConfigured()) {
      tasks.push(geminiAnalyzer.analyzeEmailText(emailData.subject, emailData.body));
    } else {
      tasks.push(Promise.resolve(null));
    }

    // Live VirusTotal Scan (for URLs if provided)
    if (isLiveApiEnabled && emailData && emailData.urls && emailData.urls.length > 0 && virusTotalScanner.isConfigured()) {
       tasks.push(virusTotalScanner.scanUrl(emailData.urls[0]));
    } else {
       tasks.push(Promise.resolve(null));
    }

    const [dnsAudit, geoOrigin, whoisData, aiAnalysis, vtScan] = await Promise.all(tasks);

    res.json({
      success: true,
      timestamp: new Date().toISOString(),
      liveVerification: {
        dnsAudit,
        geoOrigin,
        whoisData,
        aiAnalysis,
        vtScan
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Server-side analysis failed', details: err.message });
  }
});

module.exports = router;
