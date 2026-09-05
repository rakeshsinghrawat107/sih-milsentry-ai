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
      'BSA_2023_EVIDENCE_ANCHORING'
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
    const { domain, originIp, hops = [] } = req.body;

    const [dnsAudit, geoOrigin, whoisData] = await Promise.all([
      domain ? dnsVerifier.runFullDomainDnsAudit(domain, originIp) : null,
      originIp ? geoResolver.lookupIp(originIp) : null,
      domain ? whoisResolver.lookupDomain(domain) : null
    ]);

    res.json({
      success: true,
      timestamp: new Date().toISOString(),
      liveVerification: {
        dnsAudit,
        geoOrigin,
        whoisData
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Server-side analysis failed', details: err.message });
  }
});

module.exports = router;
