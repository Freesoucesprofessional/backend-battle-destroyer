const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { ipKeyGenerator } = require('express-rate-limit');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const axios = require('axios');
require('dotenv').config();

// Import BGMI service
const bgmiService = require('./services/bgmiService');

const app = express();

// ===== TRUST PROXY (for production behind load balancer) =====
app.set('trust proxy', 1);

// ===== ENFORCE HTTPS IN PRODUCTION =====
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && !req.secure && req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect('https://' + req.headers.host + req.url);
  }
  next();
});

// ===== SECURITY HEADERS (Helmet) =====
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      styleSrcElem: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: [
        "'self'",
        "https://api.battle-destroyer.shop",
        // ✅ SAFE: only spread if env var is defined
        ...(process.env.BGMI_API_URLS ? process.env.BGMI_API_URLS.split(',').map(u => u.trim()) : [])
      ],
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  frameguard: { action: 'deny' },
  xssFilter: true,
  noSniff: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// ===== CORS PROTECTION =====
const allowedOrigins = [
  'https://battle-destroyer.shop',
  'https://www.battle-destroyer.shop',
  'http://localhost:3000',
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, curl, server-to-server)
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS blocked for origin: ${origin}`));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Admin-Token'],
  maxAge: 86400
}));

// ===== BODY PARSERS WITH SIZE LIMITS =====
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ limit: '10kb', extended: true }));

// ===== COOKIE PARSER (for CSRF) =====
app.use(cookieParser(process.env.COOKIE_SECRET || 'your-cookie-secret'));

// ===== CSRF PROTECTION =====
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax'
  }
});

// ===== REQUEST LOGGING MIDDLEWARE =====
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    if (process.env.DEBUG_LOGS === 'true') {
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - ${res.statusCode} - ${duration}ms`);
      if (req.path.includes('attack') || req.path.includes('bgmi')) {
        console.log(`[BGMI] ${req.method} ${req.path} - ${res.statusCode}`);
      }
    }
  });
  next();
});

// ===== BGMI SERVICE MIDDLEWARE =====
app.use((req, res, next) => {
  req.bgmiService = bgmiService;
  next();
});

// ===== RATE LIMITERS CONFIGURATION =====

// Global rate limiter (for most API endpoints)
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { message: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip rate limit in dev
    if (process.env.NODE_ENV !== 'production') return true;
    // Skip for non-critical endpoints (health checks, CSRF token, stats)
    if (req.path === '/' || req.path === '/api/bgmi/health' || req.path === '/api/csrf-token') return true;
    if (req.path === '/panel/stats') return true;
    return false;
  },
});

// Attack rate limiter (STRICT - most sensitive endpoint)
const attackLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5,
  message: { message: 'Too many attack requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: ipKeyGenerator,
  skip: (req) => !req.path.includes('attack')
});

// Admin rate limiter (for admin panel operations)
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,
  message: { message: 'Too many admin requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Only count failed requests (brute force protection)
  keyGenerator: (req) => {
    return `${ipKeyGenerator(req)}:${req.headers['x-admin-token'] || 'anonymous'}`;
  },
  validate: { trustProxy: false, xForwardedForHeader: false }
});

// Reseller rate limiter
const resellerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 60,
  message: { message: 'Too many reseller requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => {
    return `${ipKeyGenerator(req)}:${req.resellerId || 'anonymous'}`;
  },
  validate: { trustProxy: false, xForwardedForHeader: false }
});

// Apply global limiter to all /api routes (but with skip conditions above)
app.use('/api/', globalLimiter);

// Apply attack limiter
app.use('/api/panel/attack', attackLimiter);

// Apply admin and reseller limiters
app.use('/api/admin', adminLimiter);
app.use('/api/reseller', resellerLimiter);

// ===== HEALTH CHECK - NO RATE LIMIT =====
app.get('/', async (req, res) => {
  try {
    const bgmiHealth = await bgmiService.checkHealth();
    res.json({
      message: '✅ Battle Destroyer API is running',
      version: '1.0.0',
      bgmiHealth: {
        healthy: bgmiHealth.healthy,
        total: bgmiHealth.total,
        successRate: bgmiHealth.successRate
      },
      environment: process.env.NODE_ENV || 'development'
    });
  } catch (error) {
    res.json({
      message: '✅ Battle Destroyer API is running (BGMI health check failed)',
      version: '1.0.0',
      bgmiHealth: { healthy: 0, total: 0, successRate: '0%' },
      environment: process.env.NODE_ENV || 'development'
    });
  }
});

// ===== BGMI HEALTH CHECK ENDPOINT - NO RATE LIMIT =====
app.get('/api/bgmi/health', async (req, res) => {
  try {
    const health = await bgmiService.checkHealth();
    res.json({ success: true, data: health });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to check BGMI health',
      error: error.message
    });
  }
});

// ===== CSRF TOKEN ENDPOINT - NO RATE LIMIT =====
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// ===== ROUTES (with CSRF protection on admin & reseller) =====
app.use('/api/auth', require('./routes/auth'));
app.use('/api/panel', require('./routes/panel'));
app.use('/api/admin', csrfProtection, require('./routes/admin'));
app.use('/api/reseller', csrfProtection, require('./routes/reseller'));

// ===== SECURITY HEADERS FOR API RESPONSES =====
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// ===== 404 HANDLER =====
app.use((req, res) => {
  res.status(404).json({ message: '❌ Route not found', path: req.path });
});

// ===== CSRF ERROR HANDLER =====
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ message: 'Invalid CSRF token' });
  }
  next(err);
});

// ===== GLOBAL ERROR HANDLER =====
app.use((err, req, res, next) => {
  console.error('❌ Error:', {
    message: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    path: req.path,
    method: req.method,
    ip: req.ip,
    timestamp: new Date().toISOString(),
    bgmiError: err.bgmiError || undefined
  });

  const statusCode = err.status || 500;
  const message = process.env.NODE_ENV === 'production'
    ? 'Internal server error'
    : err.message;

  res.status(statusCode).json({
    message,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// ===== MONGODB CONNECTION & SERVER START =====
mongoose.connect(process.env.MONGO_URI, {
  serverSelectionTimeoutMS: 5000,
})
  .then(async () => {
    console.log('✅ MongoDB connected successfully');

    await bgmiService.initialize();

    const PORT = process.env.PORT || 5000;
    const server = app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`🔒 HTTPS: ${process.env.NODE_ENV === 'production' ? 'Enforced' : 'Disabled (dev)'}`);
      console.log(`🛡️  CSRF Protection: Enabled`);
      console.log(`📦 Max Request Size: 10KB`);
      console.log(`🔗 BGMI APIs: ${bgmiService.getApiCount()} endpoints configured`);
      console.log(`\n📊 Rate Limiting Configuration:`);
      console.log(`   ├─ Global API: 100 req/15min (production)`);
      console.log(`   ├─ Attack Endpoint: 5 req/1min (STRICT)`);
      console.log(`   ├─ Admin Endpoints: 200 req/15min`);
      console.log(`   ├─ Reseller Endpoints: 60 req/15min`);
      console.log(`   └─ Health Checks: ✅ Unlimited (no rate limit)`);
    });

    process.on('SIGTERM', async () => {
      console.log('SIGTERM received, shutting down gracefully...');
      try {
        await bgmiService.cleanup();
        console.log('✅ BGMI cleanup completed');
      } catch (error) {
        console.error('❌ BGMI cleanup failed:', error);
      }

      server.close(() => {
        console.log('Server closed');
        mongoose.connection.close(false, () => {
          console.log('MongoDB connection closed');
          process.exit(0);
        });
      });
    });
  })
  .catch(err => {
    console.error('❌ MongoDB Connection Error:', err.message);
    process.exit(1);
  });

// ===== HANDLE UNHANDLED PROMISE REJECTIONS =====
process.on('unhandledRejection', (err) => {
  console.error('❌ Unhandled Promise Rejection:', err);
  process.exit(1);
});

// ===== HANDLE UNCAUGHT EXCEPTIONS =====
process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err);
  process.exit(1);
});

module.exports = app;