const express  = require('express');
const router   = express.Router();
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { ipKeyGenerator } = require('express-rate-limit'); // ✅ FIXED: import helper
const Reseller = require('../models/Reseller');
const User     = require('../models/User');
const AuditLog = require('../models/AuditLog');
const validation = require('../utils/validation');
const { createAuditLog } = require('../utils/audit');

// ===== RATE LIMITERS =====
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  skipSuccessfulRequests: true,
  message: { message: 'Too many login attempts. Try again in 15 minutes.' },
  keyGenerator: (req) => ipKeyGenerator(req), // ✅ FIXED: use ipKeyGenerator
  validate: { trustProxy: false, xForwardedForHeader: false }
});

const actionLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 30,
  message: { message: 'Too many requests. Slow down.' },
  keyGenerator: (req) => `${ipKeyGenerator(req)}:${req.resellerId || 'anonymous'}`, // ✅ FIXED
  validate: { trustProxy: false, xForwardedForHeader: false }
});

// ===== BRUTE FORCE MAP FOR LOGIN =====
const loginAttempts = new Map();
const MAX_LOGIN = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

setInterval(() => {
  const now = Date.now();
  for (const [ip, r] of loginAttempts.entries()) {
    if (r.lockedUntil < now && r.count === 0) loginAttempts.delete(ip);
  }
}, 30 * 60 * 1000);

// ===== JWT AUTH MIDDLEWARE =====
function resellerAuth(req, res, next) {
  const auth = req.headers['authorization'];

  if (!auth || typeof auth !== 'string' || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    const token = auth.slice(7);

    if (!token || token.length < 20) {
      return res.status(401).json({ message: 'Invalid token format' });
    }

    const decoded = jwt.verify(
      token,
      process.env.RESELLER_JWT_SECRET || process.env.JWT_SECRET
    );

    if (decoded.role !== 'reseller' || !validation.validateObjectId(decoded.id)) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    req.resellerId = decoded.id;
    req.resellerToken = token;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' });
    }
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
}

// ===== POST /api/reseller/login =====
router.post('/login', loginLimiter, async (req, res) => {
  const ip = req.ip;
  const now = Date.now();
  const record = loginAttempts.get(ip) || { count: 0, lockedUntil: 0 };

  if (record.lockedUntil > now) {
    const seconds = Math.ceil((record.lockedUntil - now) / 1000);

    await createAuditLog({
      actorType: 'reseller',
      action: 'BRUTE_FORCE_LOCKOUT',
      ip,
      userAgent: req.headers['user-agent'],
      success: false,
      error: `IP locked for ${seconds}s`
    });

    return res.status(429).json({
      message: `Account locked. Try again in ${seconds}s.`
    });
  }

  const { username, password } = req.body;

  if (!username || typeof username !== 'string') {
    return res.status(400).json({ message: 'Username is required' });
  }

  if (!password || typeof password !== 'string') {
    return res.status(400).json({ message: 'Password is required' });
  }

  const sanitizedUsername = validation.sanitizeString(username.trim(), 100);

  if (sanitizedUsername.length < 3) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  try {
    const reseller = await Reseller.findOne({
      $or: [
        { username: sanitizedUsername },
        { email: sanitizedUsername.toLowerCase() }
      ]
    });

    if (!reseller) {
      record.count += 1;
      if (record.count >= MAX_LOGIN) {
        record.lockedUntil = now + LOCKOUT_MS;
        record.count = 0;
        loginAttempts.set(ip, record);

        await createAuditLog({
          actorType: 'reseller',
          action: 'BRUTE_FORCE_LOCKOUT',
          ip,
          userAgent: req.headers['user-agent'],
          success: false,
          error: 'Max login attempts exceeded'
        });

        return res.status(429).json({
          message: 'Too many failed attempts. IP locked for 15 minutes.'
        });
      }

      loginAttempts.set(ip, record);
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const isPasswordValid = await bcrypt.compare(password, reseller.password);

    if (!isPasswordValid) {
      record.count += 1;
      if (record.count >= MAX_LOGIN) {
        record.lockedUntil = now + LOCKOUT_MS;
        record.count = 0;
        loginAttempts.set(ip, record);

        await createAuditLog({
          actorType: 'reseller',
          action: 'BRUTE_FORCE_LOCKOUT',
          ip,
          userAgent: req.headers['user-agent'],
          success: false,
          error: `Max attempts exceeded for reseller ${reseller._id}`
        });

        return res.status(429).json({
          message: 'Too many failed attempts. IP locked for 15 minutes.'
        });
      }

      loginAttempts.set(ip, record);
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    if (reseller.isBlocked) {
      await createAuditLog({
        actorType: 'reseller',
        action: 'UNAUTHORIZED_ACCESS',
        targetId: reseller._id,
        targetType: 'reseller',
        ip,
        userAgent: req.headers['user-agent'],
        success: false,
        error: 'Account is blocked'
      });

      return res.status(403).json({
        message: 'Your reseller account has been blocked. Contact admin.'
      });
    }

    loginAttempts.delete(ip);

    reseller.lastLogin = new Date();
    await reseller.save();

    const token = jwt.sign(
      { id: reseller._id, role: 'reseller' },
      process.env.RESELLER_JWT_SECRET || process.env.JWT_SECRET,
      { expiresIn: '12h' }
    );

    await createAuditLog({
      actorType: 'reseller',
      actorId: reseller._id,
      action: 'LOGIN',
      ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({
      token,
      expiresIn: 12 * 60 * 60 * 1000,
      reseller: {
        id: reseller._id,
        username: reseller.username,
        email: reseller.email,
        credits: reseller.credits,
        totalGiven: reseller.totalGiven,
      }
    });
  } catch (err) {
    console.error('❌ Login error:', err);

    await createAuditLog({
      actorType: 'reseller',
      action: 'LOGIN',
      ip,
      userAgent: req.headers['user-agent'],
      success: false,
      error: err.message
    });

    res.status(500).json({ message: 'Server error' });
  }
});

// ===== GET /api/reseller/me =====
router.get('/me', resellerAuth, async (req, res) => {
  try {
    const reseller = await Reseller.findById(req.resellerId)
      .select('-password')
      .lean();

    if (!reseller) {
      return res.status(404).json({ message: 'Reseller not found' });
    }

    if (reseller.isBlocked) {
      return res.status(403).json({ message: 'Account has been blocked' });
    }

    res.json(reseller);
  } catch (err) {
    console.error('❌ Get me error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ===== GET /api/reseller/search-user =====
router.get('/search-user', resellerAuth, actionLimiter, async (req, res) => {
  try {
    const reseller = await Reseller.findById(req.resellerId);

    if (!reseller || reseller.isBlocked) {
      return res.status(403).json({ message: 'Account is not active' });
    }

    const { query } = req.query;
    const searchQuery = validation.sanitizeSearch(query, 100);

    if (!searchQuery) {
      return res.status(400).json({
        message: 'Search query must be at least 3 characters'
      });
    }

    let searchFilter;
    if (validation.validateEmail(query)) {
      searchFilter = { email: query.trim().toLowerCase() };
    } else {
      searchFilter = { userId: query.trim() };
    }

    const user = await User.findOne(searchFilter).select(
      '_id userId username email credits isPro createdAt'
    ).lean();

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    await createAuditLog({
      actorType: 'reseller',
      actorId: reseller._id,
      action: 'SEARCH_USER',
      targetId: user._id,
      targetType: 'user',
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json(user);
  } catch (err) {
    console.error('❌ Search user error:', err);

    await createAuditLog({
      actorType: 'reseller',
      actorId: req.resellerId,
      action: 'SEARCH_USER',
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: false,
      error: err.message
    });

    res.status(500).json({ message: 'Server error' });
  }
});

// ===== POST /api/reseller/give-credits =====
router.post('/give-credits', resellerAuth, actionLimiter, async (req, res) => {
  try {
    const reseller = await Reseller.findById(req.resellerId);

    if (!reseller || reseller.isBlocked) {
      return res.status(403).json({ message: 'Account is not active' });
    }

    const { userId, amount } = req.body;

    if (!userId || typeof userId !== 'string') {
      return res.status(400).json({ message: 'userId is required' });
    }

    if (amount === undefined || amount === null) {
      return res.status(400).json({ message: 'amount is required' });
    }

    const sanitizedUserId = validation.sanitizeString(userId.trim(), 100);

    if (sanitizedUserId.length < 1) {
      return res.status(400).json({ message: 'Invalid userId' });
    }

    if (!validation.validateCredits(amount, 100000)) {
      return res.status(400).json({
        message: 'Amount must be an integer between 1 and 100,000'
      });
    }

    const credits = parseInt(amount, 10);

    if (reseller.credits < credits) {
      await createAuditLog({
        actorType: 'reseller',
        actorId: reseller._id,
        action: 'GIVE_CREDITS',
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        success: false,
        error: `Insufficient credits. Has ${reseller.credits}, requested ${credits}`
      });

      return res.status(400).json({
        message: `Insufficient credits. You have ${reseller.credits}.`
      });
    }

    const user = await User.findOne({
      $or: [
        { userId: sanitizedUserId },
        { email: sanitizedUserId.toLowerCase() }
      ]
    });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const userOldCredits = user.credits;
    const resellerOldCredits = reseller.credits;
    const userNewCredits = user.credits + credits;
    const resellerNewCredits = reseller.credits - credits;

    try {
      await Promise.all([
        User.findByIdAndUpdate(user._id, {
          $inc: { credits: credits },
          isPro: true,
          creditGiven: true,
        }),
        Reseller.findByIdAndUpdate(reseller._id, {
          $inc: { credits: -credits, totalGiven: credits },
        }),
      ]);

      await createAuditLog({
        actorType: 'reseller',
        actorId: reseller._id,
        action: 'GIVE_CREDITS',
        targetId: user._id,
        targetType: 'user',
        changes: {
          user: {
            credits: { old: userOldCredits, new: userNewCredits },
            isPro: true
          },
          reseller: {
            credits: { old: resellerOldCredits, new: resellerNewCredits }
          }
        },
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        success: true
      });

      res.json({
        message: `✅ ${credits} credits given to ${user.username}. They are now Pro.`,
        resellerCreditsLeft: resellerNewCredits,
        userNewCredits: userNewCredits,
      });
    } catch (updateErr) {
      console.error('❌ Credit update error:', updateErr);

      await createAuditLog({
        actorType: 'reseller',
        actorId: reseller._id,
        action: 'GIVE_CREDITS',
        targetId: user._id,
        targetType: 'user',
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        success: false,
        error: updateErr.message
      });

      throw updateErr;
    }
  } catch (err) {
    console.error('❌ Give credits error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ===== GET /api/reseller/audit-logs =====
router.get('/audit-logs', resellerAuth, async (req, res) => {
  try {
    const { page, limit } = validation.validatePaginationQuery(req.query);

    const logs = await AuditLog.find({
      actorId: req.resellerId,
      actorType: 'reseller'
    })
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean();

    const total = await AuditLog.countDocuments({
      actorId: req.resellerId,
      actorType: 'reseller'
    });

    res.json({
      logs,
      total,
      page,
      pages: Math.ceil(total / limit)
    });
  } catch (err) {
    console.error('❌ Audit logs error:', err);
    res.status(500).json({ message: 'Failed to fetch audit logs' });
  }
});

module.exports = router;
module.exports.resellerAuth = resellerAuth;