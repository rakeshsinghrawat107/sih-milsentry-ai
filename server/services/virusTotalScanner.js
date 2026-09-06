const axios = require('axios');

class VirusTotalScanner {
  constructor() {
    this.apiKey = process.env.VIRUSTOTAL_API_KEY;
    this.apiUrl = `https://www.virustotal.com/api/v3`;
  }

  isConfigured() {
    return !!this.apiKey;
  }

  async scanUrl(url) {
    if (!this.isConfigured()) return null;
    
    try {
      const urlEncoded = Buffer.from(url).toString('base64').replace(/=/g, '');
      const response = await axios.get(`${this.apiUrl}/urls/${urlEncoded}`, {
        headers: { 'x-apikey': this.apiKey }
      });
      
      const stats = response.data.data.attributes.last_analysis_stats;
      return {
        malicious: stats.malicious,
        suspicious: stats.suspicious,
        harmless: stats.harmless,
        undetected: stats.undetected,
        totalVotes: stats.malicious + stats.suspicious,
        threatVerdict: (stats.malicious > 0 || stats.suspicious > 0) ? 'MALICIOUS' : 'CLEAN'
      };
    } catch (err) {
      if (err.response && err.response.status === 404) {
         // Not found in VT database yet
         return { threatVerdict: 'UNKNOWN', totalVotes: 0 };
      }
      console.error('VirusTotal API Error:', err.response?.data || err.message);
      return null;
    }
  }
}

module.exports = new VirusTotalScanner();
