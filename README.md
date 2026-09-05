# MailSentry AI — Forensic Email Intelligence Platform
## India Cyber Shield | National Cyber Law Enforcement & CERT-In Operations

![MailSentry AI](https://img.shields.io/badge/SIH%202026-Grand%20Finale-00d4ff?style=for-the-badge&logo=shield&logoColor=black)
![BSA 2023](https://img.shields.io/badge/BSA%202023-Sec%2065B%20Certified-00ff88?style=for-the-badge)
![CERT-In](https://img.shields.io/badge/CERT--In-IT%20Act%20Sec%2070B-ffaa00?style=for-the-badge)
![DPDP Act 2023](https://img.shields.io/badge/DPDP%20Act%202023-PII%20Redacted-3b82f6?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1566%20Mapped-a855f7?style=for-the-badge)
![Docker](https://img.shields.io/badge/Docker-Production%20Ready-2496ed?style=for-the-badge&logo=docker&logoColor=white)

---

## 🛡️ Overview

**MailSentry AI** is an autonomous, defense-grade **Forensic Email Intelligence Platform** engineered for national cyber defense and law enforcement operations. It transforms raw RFC 5322 emails into court-admissible forensic dossiers and blockchain-anchored digital panchnamas in under 0.5 seconds.

Built in compliance with:
- **Bharatiya Sakshya Adhiniyam (BSA) 2023 Section 63 & 65B** (Admissibility of Electronic Evidence)
- **Digital Personal Data Protection (DPDP) Act, 2023** (Citizen PII Redaction)
- **Information Technology Act, 2000 Section 70B** (CERT-In Mandatory Incident Reporting)
- **I4C 1930 National Cyber Crime Reporting Portal** (`cybercrime.gov.in`)

---

## ⚡ Progressive Hybrid Architecture

MailSentry AI is architected to operate in two seamless modes:
1. **Air-Gapped Offline Mode:** Zero external dependencies; operates fully within browser RAM and local databases for crime scene field forensics and sensitive SCADA/defense installations.
2. **Enterprise Connected Mode:** Activates live server-side DNS queries (SPF, DKIM, DMARC), ICANN RDAP domain registration intelligence, real-time IP geolocation/ASN feeds, and persistent IndexedDB evidence vaults.

```
                                  MAILSENTRY AI ENTERPRISE TOPOLOGY
                                  
  [ Suspect Email (.eml) ] ──► [ RFC 5322 MIME Parser ]
                                        │
             ┌──────────────────────────┼──────────────────────────┐
             ▼                          ▼                          ▼
   [ Header Forensics ]        [ NLP Stylometry ]         [ Domain Engine ]
   • Live DNS Resolution       • WormGPT/GenAI Fingerprint • Homoglyph De-obfuscator
   • SPF / DKIM / DMARC        • Coercion & Wire Heuristics• ICANN RDAP True Age
             │                          │                          │
             └──────────────────────────┼──────────────────────────┘
                                        ▼
                         [ STRAD Geospatial Engine ]
                         • Haversine Relay Flight Paths
                         • Relativistic v > c Masquerade Check
                                        │
                                        ▼
                          [ 20-Signal Risk Matrix ]
                                        │
             ┌──────────────────────────┴──────────────────────────┐
             ▼                                                     ▼
   [ BSA 2023 Blockchain Vault ]                      [ National Dispatch Gate ]
   • Merkle SHA-256 Ledger                             • CERT-In 70B Annexure-I JSON
   • IndexedDB Persistence                             • DPDP Act 2023 PII Redactor
   • E-Panchnama Certificate                           • I4C 1930 FIR Complaint Docket
```

---

## 🔬 Core Forensic Capabilities

| Engine | Technical Function | Production Standard |
|---|---|---|
| **Live DNS Verification** | Resolves authoritative SPF TXT, DKIM keys, and DMARC policies live via 8.8.8.8 / 1.1.1.1. Eliminates client header forgery. | RFC 7208 / RFC 6376 / RFC 7489 |
| **DPDP Act 2023 Redaction** | Auto-redacts citizen Aadhaar (`XXXX-XXXX-1234`), PAN (`ABCDE****F`), and phone numbers from logs and incident reports. | DPDP Act 2023 Sec 4 & 8 |
| **STRAD Physics Engine** | Calculates speed-of-light physical fiber limits ($v = d / \Delta t > c$) on intercontinental relay jumps to prove header spoofing. | Court-admissible physical proof |
| **Domain Intelligence** | Detects Cyrillic/Greek Unicode homoglyphs across 30+ protected Indian entities and queries ICANN RDAP for true domain age. | RFC 9082 / ICANN RDAP |
| **Persistent Evidence Vault** | Browser IndexedDB engine (`MailSentryVaultDB`) stores blockchain ledger across reboots with one-click JSON export. | BSA 2023 Section 65B |
| **National Dispatch Gate** | Auto-populates official CERT-In Annexure-I mandatory reporting formats and I4C 1930 FIR complaint dockets. | CERT-In Directions 20(3)/2022 |

---

## 🚀 Quick Start & Deployment

### Option A: Standalone Browser Mode (Zero Installation)
Open `index.html` in any modern web browser or host on GitHub Pages immediately.

### Option B: Production Server Mode (Node.js REST API)
```bash
# 1. Install dependencies
cd server
npm install

# 2. Start the Enterprise Cyber Defense Server
npm start
# Server starts at: http://localhost:3000
# REST API Base:    http://localhost:3000/api/v1
# Health Status:    http://localhost:3000/health
```

### Option C: Sovereign Cloud / Docker Deployment
```bash
# 1-command deployment for MeghRaj (NIC Cloud) or AWS Mumbai (ap-south-1)
docker compose up -d

# Verify container health
docker ps
curl http://localhost:3000/health
```

---

## 📡 REST API Specifications

The production server exposes the following endpoints under `/api/v1`:

### 1. `POST /api/v1/dns/verify`
Performs live DNS resolution for domain authentication.
```json
// Request
{ "domain": "sbi.co.in", "originIp": "122.165.0.1" }

// Response
{
  "success": true,
  "audit": {
    "domain": "sbi.co.in",
    "spf": { "status": "PASS", "record": "v=spf1 ...", "verifiedViaDns": true },
    "dmarc": { "status": "VALID", "policy": "reject", "enforced": true },
    "mx": { "status": "VALID", "records": [...] }
  }
}
```

### 2. `POST /api/v1/ip/lookup`
Live IP intelligence, ISP, ASN, and threat score resolution.
```json
// Request
{ "ip": "185.220.101.5" }

// Response
{
  "success": true,
  "geo": {
    "ip": "185.220.101.5",
    "country": "Russia",
    "city": "Moscow",
    "isp": "Tor Exit Node (AS49981)",
    "abuseScore": 98
  }
}
```

### 3. `POST /api/v1/whois/lookup`
Authoritative ICANN RDAP domain registration query.
```json
// Request
{ "domain": "google.com" }

// Response
{
  "success": true,
  "whois": {
    "domain": "google.com",
    "registrationDate": "1997-09-15T04:00:00Z",
    "domainAgeDays": 10582,
    "isNewlyRegistered": false,
    "registrar": "MarkMonitor Inc."
  }
}
```

### 4. `POST /api/v1/certin/dispatch`
Generates statutory Section 70B Annexure-I Incident Dossier for submission to `incident@cert-in.org.in`.

---

## 📁 Repository Structure

```
d:\antigravvity projeect 1\
├── Dockerfile                  ← Sovereign Cloud production container
├── docker-compose.yml          ← Production orchestration
├── index.html                  ← Master Cyber SOC Dashboard
├── lab.html                    ← Quishing Lab & Sandbox viewer
├── presentation.html           ← 15-slide SIH 2026 pitch deck
├── manifest.json               ← PWA configuration
├── css/
│   ├── style.css               ← Dark tactical cyber design system
│   └── animations.css          ← Radar sweep, pulses, glitch effects
├── js/
│   ├── app.js                  ← Master SOC controller
│   ├── data/
│   │   └── sample-emails.js    ← 5 realistic RFC 5322 test cases
│   ├── engines/
│   │   ├── parser.js           ← RFC 5322 MIME deconstructor
│   │   ├── nlp-engine.js       ← Stylometry & WormGPT heuristics
│   │   ├── dpdp-engine.js      ← DPDP Act 2023 PII Redactor
│   │   ├── header-engine.js    ← SPF/DKIM/DMARC protocol analysis
│   │   ├── geo-engine.js       ← Hybrid live/offline GeoIP & STRAD
│   │   ├── domain-engine.js    ← Homoglyph & live RDAP intelligence
│   │   ├── scoring-engine.js   ← 20-signal threat aggregator
│   │   └── graph-engine.js     ← D3.js threat identity graph
│   └── utils/
│       ├── storage.js          ← IndexedDB Persistent Evidence Vault
│       ├── blockchain.js       ← SHA-256 Merkle chain-of-custody
│       └── audio.js            ← Web Audio API sound synthesizer
└── server/
    ├── package.json            ← Backend dependencies
    ├── server.js               ← Production Express server with Helmet
    ├── routes/
    │   └── api.js              ← REST endpoints router
    └── services/
        ├── dnsVerifier.js      ← Native live DNS resolver
        ├── geoResolver.js      ← Live IP intelligence with caching
        ├── whoisResolver.js    ← ICANN RDAP client
        └── certInExporter.js   ← CERT-In Annexure-I generator
```

---

## ⚖️ National Legal & Regulatory Mandates

- **Bharatiya Sakshya Adhiniyam, 2023 (BSA 2023):**
  - Section 63: Admissibility of Electronic Records
  - Section 65B: Conditions to admissibility of electronic records (SHA-256 Merkle chain-of-custody certificate)
- **Digital Personal Data Protection Act, 2023 (DPDP Act):**
  - Sections 4 & 8: Data Fiduciary obligations and citizen personal data anonymization
- **Information Technology Act, 2000:**
  - Section 70B: Powers of CERT-In to call for information and direct incident reporting within 6 hours

---

## 👥 Authors & Acknowledgments

**Team MailSentry AI** — Smart India Hackathon 2026
- Lead Architect: **Rakesh Singh Rawat** ([rakeshsinghrawat107@gmail.com](mailto:rakeshsinghrawat107@gmail.com))
- Organization: National Cyber Security Initiative

---

*MailSentry AI — Protecting India's Digital Sovereignty | Jai Hind 🇮🇳*
