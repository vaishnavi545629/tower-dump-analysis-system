const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');
const routes = require('./routes');
const { getMonitorSnapshot } = require('./utils/monitorStore');
const { getCounts } = require('./utils/localStore');

const app = express();

// ── Security headers ──────────────────────────────────────────────────────────
const defaultHelmet = helmet({
  contentSecurityPolicy: false,
});

const monitorHelmet = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      baseUri: ["'self'"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", 'https:', 'data:'],
      imgSrc: ["'self'", 'data:'],
      objectSrc: ["'none'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      upgradeInsecureRequests: null,
    },
  },
});

app.use('/monitor', monitorHelmet);
app.use(defaultHelmet);

// ── CORS ──────────────────────────────────────────────────────────────────────
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:1235',
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-dev-role', 'x-dev-email', 'x-dev-uid'],
  credentials: true,
}));

// ── Rate limiting ─────────────────────────────────────────────────────────────
const isDev = process.env.NODE_ENV === 'development';
const rateLimitMax = parseInt(process.env.RATE_LIMIT_MAX) || 100;

const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  // In development, allow more burst so the UI doesn't get blocked.
  max: isDev ? Math.max(rateLimitMax, 5000) : rateLimitMax,
  standardHeaders: true,
  legacyHeaders: false,
  // Monitor UI polls frequently; exclude it from the global limiter so it
  // doesn't block user-triggered actions (login/upload/analysis).
  skip: (req) => req.path.startsWith("/api/monitor/"),
  message: { error: 'Too many requests, please try again later.' },
});
app.use(limiter);

// ── Stricter rate limit on auth-sensitive routes ──────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many auth-related requests.' },
});
app.use('/api/admin', authLimiter);
app.use('/api/analysis/reveal', authLimiter);

// ── Logging ───────────────────────────────────────────────────────────────────
if (process.env.NODE_ENV !== 'test') {
  app.use(morgan('combined'));
}

// ── Body parsing ──────────────────────────────────────────────────────────────
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// ── Routes ────────────────────────────────────────────────────────────────────
app.get('/monitor', (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  const monitorPath = path.join(__dirname, 'monitor.html');
  const html = fs.readFileSync(monitorPath, 'utf8');
  const snapshot = {
    status: 'ok',
    startedAt: getMonitorSnapshot().startedAt,
    counts: getCounts(),
    recentEvents: getMonitorSnapshot().events.slice(0, 40),
  };
  res.send(html.replace('"__INITIAL_MONITOR_DATA__"', JSON.stringify(snapshot)));
});

app.use('/api', routes);

// ── 404 handler ───────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// ── Global error handler ──────────────────────────────────────────────────────
// Note: Never expose internal error details in production
app.use((err, req, res, next) => {
  console.error('[GlobalError]', err);

  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ error: 'File too large. Maximum size is 50MB.' });
  }
  if (err.message?.includes('Invalid file type')) {
    return res.status(400).json({ error: err.message });
  }

  const isDev = process.env.NODE_ENV === 'development';
  res.status(500).json({
    error: 'Internal server error',
    ...(isDev && { detail: err.message }),
  });
});

module.exports = app;
