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

// ===== SECURITY HEADERS (Helmet) - Updated for BGMI =====
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
        ...(process.env.BGMI_API_URLS ? process.env.BGMI_API_URLS.split(',') : [])// Add BGMI API URLs
      ],
    }
  },
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  },
  frameguard: { action: 'deny' },
  xssFilter: true,
  noSniff: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// ===== CORS PROTECTION - Updated for BGMI =====
app.use(cors({
  origin: function (origin, callback) {
    const allowedOrigins = [
      'https://battle-destroyer.shop',
      'https://www.battle-destroyer.shop',
      'http://localhost:3000',
      ...process.env.BGMI_API_URLS.split(',') // Allow BGMI APIs for testing
    ];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
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

// ===== REQUEST LOGGING MIDDLEWARE - Enhanced for BGMI =====
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    if (process.env.DEBUG_LOGS === 'true') {
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - ${res.statusCode} - ${duration}ms`);

      // Log BGMI-related requests
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

// ===== GLOBAL RATE LIMITER =====
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { message: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => process.env.NODE_ENV !== 'production',
});
app.use('/api/', globalLimiter);

// ===== ATTACK RATE LIMITER (STRICT) =====
const attackLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // limit each IP to 5 attack requests per minute
  message: { message: 'Too many attack requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: ipKeyGenerator,
  skip: (req) => !req.path.includes('attack') // Only apply to attack routes
});
app.use('/api/panel/attack', attackLimiter);

// ===== ADMIN RATE LIMITER (STRICT) =====
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { message: 'Too many admin requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  keyGenerator: (req) => {
    return `${ipKeyGenerator(req)}:${req.headers['x-admin-token'] || 'anonymous'}`;
  },
  validate: { trustProxy: false, xForwardedForHeader: false }
});
app.use('/api/admin', adminLimiter);

// ===== RESELLER RATE LIMITER =====
const resellerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
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
app.use('/api/reseller', resellerLimiter);

// ===== HEALTH CHECK - Enhanced with BGMI =====
app.get('/', async (req, res) => {
  try {
    // Check BGMI API health
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
      bgmiHealth: {
        healthy: 0,
        total: 0,
        successRate: '0%'
      },
      environment: process.env.NODE_ENV || 'development'
    });
  }
});

// ===== BGMI HEALTH CHECK ENDPOINT =====
app.get('/api/bgmi/health', async (req, res) => {
  try {
    const health = await bgmiService.checkHealth();
    res.json({
      success: true,
      data: health
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to check BGMI health',
      error: error.message
    });
  }
});

// ===== CSRF TOKEN ENDPOINT =====
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// ===== ROUTES (with CSRF for state-changing operations) =====
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
  res.status(404).json({
    message: '❌ Route not found',
    path: req.path
  });
});

// ===== CSRF ERROR HANDLER =====
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ message: 'Invalid CSRF token' });
  }
  next(err);
});

// ===== GLOBAL ERROR HANDLER - Enhanced for BGMI =====
app.use((err, req, res, next) => {
  console.error('❌ Error:', {
    message: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    path: req.path,
    method: req.method,
    ip: req.ip,
    timestamp: new Date().toISOString(),
    // Add BGMI-specific error details if available
    bgmiError: err.bgmiError || undefined
  });

  // Don't leak internal error details to client
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

    // Initialize BGMI service
    await bgmiService.initialize();

    const PORT = process.env.PORT || 5000;
    const server = app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`🔒 HTTPS: ${process.env.NODE_ENV === 'production' ? 'Enforced' : 'Disabled (dev)'}`);
      console.log(`🛡️  CSRF Protection: Enabled`);
      console.log(`📦 Max Request Size: 10KB`);
      console.log(`🔗 BGMI APIs: ${bgmiService.getApiCount()} endpoints configured`);
    });

    // Graceful shutdown with BGMI cleanup
    process.on('SIGTERM', async () => {
      console.log('SIGTERM received, shutting down gracefully...');

      // Stop all running BGMI servers
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