const express   = require('express');
const mongoose  = require('mongoose');
const cors      = require('cors');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const csrf      = require('csurf');
const cookieParser = require('cookie-parser');
require('dotenv').config();

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
      connectSrc: ["'self'"],
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

// ===== CORS PROTECTION =====
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:3000',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Admin-Token'],
  maxAge: 86400 // 24 hours
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
    sameSite: 'strict'
  }
});

// ===== REQUEST LOGGING MIDDLEWARE =====
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    if (process.env.DEBUG_LOGS === 'true') {
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - ${res.statusCode} - ${duration}ms`);
    }
  });
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

// ===== ADMIN RATE LIMITER (STRICT) =====
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { message: 'Too many admin requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  keyGenerator: (req) => {
    return `${req.ip.replace(/^.*:/, '')}:${req.headers['x-admin-token'] || 'anonymous'}`;
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
    return `${req.ip.replace(/^.*:/, '')}:${req.resellerId || 'anonymous'}`;
  },
  validate: { trustProxy: false, xForwardedForHeader: false }
});
app.use('/api/reseller', resellerLimiter);

// ===== HEALTH CHECK =====
app.get('/', (req, res) => {
  res.json({ message: '✅ Battle Destroyer API is running', version: '1.0.0' });
});

// ===== CSRF TOKEN ENDPOINT =====
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// ===== ROUTES (with CSRF for state-changing operations) =====
app.use('/api/auth',     require('./routes/auth'));
app.use('/api/panel',    require('./routes/panel'));
app.use('/api/admin',    csrfProtection, require('./routes/admin'));
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

// ===== GLOBAL ERROR HANDLER =====
app.use((err, req, res, next) => {
  console.error('❌ Error:', {
    message: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    path: req.path,
    method: req.method,
    ip: req.ip,
    timestamp: new Date().toISOString()
  });

  // Don't leak internal error details to client
  const statusCode = err.status || 500;
  const message = process.env.NODE_ENV === 'production' 
    ? 'Internal server error' 
    : err.message;

  res.status(statusCode).json({ message });
});

// ===== MONGODB CONNECTION & SERVER START =====
mongoose.connect(process.env.MONGO_URI, {
  serverSelectionTimeoutMS: 5000,
})
  .then(() => {
    console.log('✅ MongoDB connected successfully');
    
    const PORT = process.env.PORT || 5000;
    const server = app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`🔒 HTTPS: ${process.env.NODE_ENV === 'production' ? 'Enforced' : 'Disabled (dev)'}`);
      console.log(`🛡️  CSRF Protection: Enabled`);
      console.log(`📦 Max Request Size: 10KB`);
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
      console.log('SIGTERM received, shutting down gracefully...');
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