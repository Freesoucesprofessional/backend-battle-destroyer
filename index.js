const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { ipKeyGenerator } = require('express-rate-limit');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const axios = require('axios');
const crypto = require('crypto');
require('dotenv').config();
const apiAdminRoutes = require('./routes/apiAdmin');
const apiExternalRoutes = require('./routes/apiExternal');
const apiAuthRoutes = require('./routes/apiAuth');
// Import services
const bgmiService = require('./services/bgmiService');
const dailyResetService = require('./services/dailyResetService');
const ApiUser = require('./models/ApiUser');
const app = express();

// Optional: If you want a captcha endpoint, uncomment this
// const captchaRoutes = require('./routes/captchaRoutes');

// ===== TRUST PROXY (for production behind load balancer) =====
app.set('trust proxy', 2);

// ===== ENFORCE HTTPS IN PRODUCTION =====
app.use((req, res, next) => {
  if (process.env.NODE_ENV === 'production' && !req.secure && req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect('https://' + req.headers.host + req.url);
  }
  next();
});

function getRealIP(req) {
  return req.headers['cf-connecting-ip']    // Real IP from Cloudflare
    || req.headers['x-forwarded-for']?.split(',')[0].trim()
    || req.ip;
}

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
      frameSrc: ["https://challenges.cloudflare.com"],
      connectSrc: [
        "'self'",
        "https://api.battle-destroyer.shop",
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
  'https://backend-battle-destroyer-production.up.railway.app',
  'https://api.battle-destroyer.shop',
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error(`CORS blocked for origin: ${origin}`));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Admin-Token', 'X-API-Key', 'X-Timestamp', 'X-Signature'],
  maxAge: 86400
}));

// ===== BODY PARSERS WITH SIZE LIMITS =====
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ limit: '10kb', extended: true }));

// ===== COOKIE PARSER (for CSRF) =====
app.use(cookieParser(process.env.COOKIE_SECRET || 'your-cookie-secret'));

// ===== CSRF PROTECTION (Exclude API routes) =====
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

// Reseller search rate limiter (stricter for search operations)
const resellerSearchLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { message: 'Too many search requests, please wait before trying again.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return `${getRealIP(req)}:${req.resellerId || 'anonymous'}`;
  },
});

// Global rate limiter (for most API endpoints)
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { message: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    if (process.env.NODE_ENV !== 'production') return true;
    if (req.path === '/' || req.path === '/api/bgmi/health' || req.path === '/api/csrf-token') return true;
    if (req.path === '/panel/stats') return true;
    if (req.path.includes('/me')) return true;
    if (req.path.includes('/attack-status')) return true;
    if (req.path.includes('/daily-reset-status')) return true;
    if (req.path === '/api/captcha/challenge') return true;
    if (req.path.startsWith('/api/v1/health')) return true;
    return false;
  },
});

// Attack rate limiter (STRICT - most sensitive endpoint)
const attackLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { message: 'Too many attack requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: ipKeyGenerator,
  skip: (req) => !req.path.includes('attack')
});

// Admin rate limiter
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { message: 'Too many admin requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => {
    return `${ipKeyGenerator(req)}:${req.headers['x-admin-token'] || 'anonymous'}`;
  },
});

// Reseller rate limiter
const resellerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  message: { message: 'Too many reseller requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => {
    return `${getRealIP(req)}:${req.resellerId || 'anonymous'}`;
  },
});

// API rate limiter
const apiRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: 'Rate limit exceeded', message: 'Please slow down your requests' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.headers['x-api-key'] || req.headers['authorization'] || ipKeyGenerator(req);
  },
  skip: (req) => !req.path.startsWith('/api/v1')
});

// Apply rate limiters
app.use('/api/', globalLimiter);
app.use('/api/panel/attack', attackLimiter);
app.use('/api/admin', adminLimiter);
app.use('/api/reseller', resellerLimiter);
app.use('/api/v1', apiExternalRoutes);
app.use('/api/api-auth', apiAuthRoutes);
// If you want to use the captcha route, uncomment this line:
// app.use('/api/captcha', captchaRoutes);

// ===== ROUTES MOUNTING =====

// Public routes
app.get('/', (req, res) => {
  res.json({
    message: 'Server is running',
    status: 'active'
  });
});

// BGMI health check endpoint
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

// CSRF token endpoint
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// ===== AUTH ROUTES =====
app.use('/api/auth', require('./routes/auth'));

// ===== PANEL ROUTES =====
app.use('/api/panel', require('./routes/panel'));

// ===== EXTERNAL API =====
app.use('/api/v1', apiExternalRoutes);

// ===== ADMIN AND RESELLER ROUTES =====
app.use('/api/admin', csrfProtection, require('./routes/admin'));
app.use('/api/reseller', csrfProtection, require('./routes/reseller'));

// ===== SECURITY HEADERS =====
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// ===== 404 HANDLER =====
app.use((req, res) => {
  res.status(404).json({
    error: 'Route not found',
    message: `❌ ${req.method} ${req.path} does not exist`,
    path: req.path,
    method: req.method
  });
});

// ===== CSRF ERROR HANDLER =====
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({
      error: 'Invalid CSRF token',
      message: 'CSRF token validation failed'
    });
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
    error: 'Server error',
    message,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// ===== CLEANUP JOBS (FIXED - removed duplicate) =====
setInterval(async () => {
  try {
    await ApiUser.cleanExpiredAttacks();
  } catch (error) {
    console.error('Cleanup job error:', error);
  }
}, 60000); // Only ONE interval, not two

// ===== MONGODB CONNECTION & SERVER START =====
mongoose.connect(process.env.MONGO_URI, {
  serverSelectionTimeoutMS: 5000,
})
  .then(async () => {
    console.log('✅ MongoDB connected successfully');

    await bgmiService.initialize();

    console.log('\n🔄 Initializing Daily Reset Service...');
    dailyResetService.start();

    setTimeout(() => {
      const status = dailyResetService.getStatus();
      console.log('✅ Daily reset service initialized');
      console.log(`\n🔄 Daily Reset Service Configuration:`);
      console.log(`   ├─ Schedule: ${status.schedule}`);
      console.log(`   ├─ Timezone: ${status.timezone}`);
      console.log(`   ├─ Status: ${status.isRunning ? '🟢 Running' : '🔴 Stopped'}`);
      console.log(`   └─ Next Run: ${status.nextRun}`);
    }, 100);

    const PORT = process.env.PORT || 5000;
    const server = app.listen(PORT, () => {
      console.log(`\n🚀 Server running on port ${PORT}`);
      console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`🔒 HTTPS: ${process.env.NODE_ENV === 'production' ? 'Enforced' : 'Disabled (dev)'}`);
      console.log(`🛡️  CSRF Protection: Enabled (except API routes)`);
      console.log(`📦 Max Request Size: 10KB`);
      console.log(`🔗 BGMI APIs: ${bgmiService.getApiCount()} endpoints configured`);
      console.log(`\n📊 Rate Limiting Configuration:`);
      console.log(`   ├─ Global API: 100 req/15min (production)`);
      console.log(`   ├─ Attack Endpoint: 5 req/1min (STRICT)`);
      console.log(`   ├─ Admin Endpoints: 200 req/15min`);
      console.log(`   ├─ Reseller Endpoints: 60 req/15min`);
      console.log(`   ├─ External API: 100 req/min (per user)`);
      console.log(`   └─ Health Checks: ✅ Unlimited (no rate limit)`);
      console.log(`\n🔑 API Endpoints Available:`);
      console.log(`   ├─ External API: /api/v1/attack, /api/v1/stats, /api/v1/health`);
      console.log(`   ├─ Admin API: /api/admin/api-users (CRUD operations)`);
      console.log(`   ├─ Auth: /api/auth/login, /api/auth/register`);
      console.log(`   └─ Panel: /api/panel/*`);
      console.log(`\n✨ Server ready!`);
    });

    // Graceful shutdown
    process.on('SIGTERM', async () => {
      console.log('\n🛑 SIGTERM received, shutting down gracefully...');

      dailyResetService.stop();
      console.log('✅ Daily reset service stopped');

      try {
        await bgmiService.cleanup();
        console.log('✅ BGMI cleanup completed');
      } catch (error) {
        console.error('❌ BGMI cleanup failed:', error);
      }

      server.close(() => {
        console.log('✅ Server closed');
        mongoose.connection.close(false, () => {
          console.log('✅ MongoDB connection closed');
          process.exit(0);
        });
      });
    });
  })
  .catch(err => {
    console.error('❌ MongoDB Connection Error:', err.message);
    process.exit(1);
  });

module.exports = app;