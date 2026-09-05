/**
 * MailSentry AI — National Cyber Intelligence Backend Server
 * Production Express server with Helmet security, CORS, Rate-limiting, and Live Verification APIs.
 * Dual function: Serves REST APIs and statically hosts the Forensic SOC Dashboard.
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');

const apiRouter = require('./routes/api');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

// ── SECURITY & MIDDLEWARE ──────────────────────────────────────────
// Content Security Policy adjusted to allow Leaflet and D3 CDNs
app.use(
  helmet({
    contentSecurityPolicy: false, // Allow CDNs used by the dashboard
    crossOriginEmbedderPolicy: false
  })
);

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Simple in-memory rate limiter (120 requests per minute per IP)
const requestCounts = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000;
const MAX_REQUESTS = 120;

app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  const clientData = requestCounts.get(ip) || { count: 0, resetTime: now + RATE_LIMIT_WINDOW };

  if (now > clientData.resetTime) {
    clientData.count = 1;
    clientData.resetTime = now + RATE_LIMIT_WINDOW;
  } else {
    clientData.count += 1;
  }

  requestCounts.set(ip, clientData);

  if (clientData.count > MAX_REQUESTS) {
    return res.status(429).json({
      error: 'Too Many Requests',
      message: 'Rate limit exceeded. MailSentry AI protects against automated scraping.'
    });
  }

  next();
});

// Periodic rate limiter memory cleanup
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of requestCounts.entries()) {
    if (now > data.resetTime) requestCounts.delete(ip);
  }
}, 5 * 60 * 1000);

// ── HEALTH & DIAGNOSTICS ──────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status: 'HEALTHY',
    service: 'MailSentry AI Backend Engine',
    uptimeSeconds: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'production'
  });
});

// ── API ROUTES ────────────────────────────────────────────────────
app.use('/api/v1', apiRouter);

// ── STATIC FRONTEND HOSTING ────────────────────────────────────────
// Serve root frontend directory
const frontendRoot = path.join(__dirname, '..');
app.use(express.static(frontendRoot));

// Fallback to index.html for single-page routing
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(frontendRoot, 'index.html'));
});

// ── START SERVER ──────────────────────────────────────────────────
app.listen(PORT, HOST, () => {
  console.log(`================================================================`);
  console.log(` 🛡️  MailSentry AI — National Production Cyber Defense Server`);
  console.log(`================================================================`);
  console.log(` 🚀 Server listening on: http://${HOST}:${PORT}`);
  console.log(` 📡 REST API Base:        http://localhost:${PORT}/api/v1`);
  console.log(` 🩺 Health Check:         http://localhost:${PORT}/health`);
  console.log(` 🌐 Forensic Dashboard:   http://localhost:${PORT}/`);
  console.log(` ⚖️  BSA 2023 & CERT-In:  Fully Enforced`);
  console.log(`================================================================`);
});
