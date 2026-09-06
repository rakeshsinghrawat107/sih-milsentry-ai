const axios = require('axios');

class GeminiAnalyzer {
  constructor() {
    this.apiKey = process.env.GEMINI_API_KEY;
    this.apiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent`;
  }

  isConfigured() {
    return !!this.apiKey;
  }

  async analyzeEmailText(subject, body) {
    if (!this.isConfigured()) return null;

    try {
      const prompt = `
        You are a highly advanced cybersecurity SOC analyst AI. 
        Analyze the following email subject and body for phishing threats.
        Respond ONLY with a JSON object in this exact format:
        {
          "riskScore": (0-100 integer),
          "verdict": "SAFE" or "SUSPICIOUS" or "PHISHING",
          "threatVectors": ["vector 1", "vector 2"],
          "urgencyLevel": "LOW" or "MEDIUM" or "HIGH",
          "socialEngineeringDetected": true or false,
          "summary": "1 sentence explanation"
        }

        Subject: ${subject || 'No Subject'}
        Body: ${body || 'No Body'}
      `;

      const response = await axios.post(`${this.apiUrl}?key=${this.apiKey}`, {
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.2,
          responseMimeType: "application/json"
        }
      }, {
        headers: { 'Content-Type': 'application/json' }
      });

      const rawText = response.data.candidates[0].content.parts[0].text;
      const parsed = JSON.parse(rawText);
      return parsed;

    } catch (err) {
      console.error('Gemini API Error:', err.response?.data || err.message);
      return null;
    }
  }
}

module.exports = new GeminiAnalyzer();
