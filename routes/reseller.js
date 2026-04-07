// routes/reseller.js (Updated with encryption and CAPTCHA)
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { ipKeyGenerator } = require('express-rate-limit');
const CryptoJS = require('crypto-js');
const Reseller = require('../models/Reseller');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const validation = require('../utils/validation');
const { createAuditLog } = require('../utils/audit');
const { verifyCaptcha } = require('./captcha'); // Import CAPTCHA verification

// Encryption configuration
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'your-secret-key-2024-battle-destroyer';

/* ─── Encryption Helpers ──────────────────────────────────────── */
function decryptData(encryptedData) {
  try {
    const bytes = CryptoJS.AES.decrypt(encryptedData, ENCRYPTION_KEY);
    const decrypted = bytes.toString(CryptoJS.enc.Utf8);
    if (!decrypted) throw new Error('Decryption failed');
    return JSON.parse(decrypted);
  } catch (error) {
    console.error('Decryption error:', error);
    throw new Error('Invalid encrypted data');
  }
}

function encryptResponse(data) {
  const jsonString = JSON.stringify(data);
  return CryptoJS.AES.encrypt(jsonString, ENCRYPTION_KEY).toString();
}

function verifyHash(data, receivedHash) {
  const jsonString = JSON.stringify(data);
  const calculatedHash = CryptoJS.SHA256(jsonString + ENCRYPTION_KEY).toString();
  return calculatedHash === receivedHash;
}

function createHash(data) {
  const jsonString = JSON.stringify(data);
  return CryptoJS.SHA256(jsonString + ENCRYPTION_KEY).toString();
}

function sendEncryptedError(res, statusCode, message) {
  const errorResponse = { success: false, message };
  const encryptedError = encryptResponse(errorResponse);
  const errorHash = createHash(errorResponse);
  return res.status(statusCode).json({ encrypted: encryptedError, hash: errorHash });
}

// Helper to get IP
function getIp(req) {
  const raw = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '';
  let ip = raw.startsWith('::ffff:') ? raw.slice(7) : raw;
  if (ip === '::1') ip = '127.0.0.1';
  return ip;
}

// ── PLAN DEFINITIONS ──
const PLANS = [
  {
    label: 'Week',
    days: 7,
    credits: 200,
    customerPrice: 850,
    displayName: 'Weekly Pro (7 days)',
    profit: 650,
    multiplier: 4.25
  },
  {
    label: 'Month',
    days: 30,
    credits: 400,
    customerPrice: 1800,
    displayName: 'Monthly Pro (30 days)',
    profit: 1400,
    multiplier: 4.5
  },
  {
    label: 'Season',
    days: 90,
    credits: 800,
    customerPrice: 2500,
    displayName: 'Season Pro (90 days)',
    profit: 1700,
    multiplier: 3.125
  },
];

// ===== RATE LIMITERS =====
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  skipSuccessfulRequests: true,
  message: { message: 'Too many login attempts. Try again in 15 minutes.' },
  keyGenerator: (req) => ipKeyGenerator(req),
  validate: { trustProxy: false, xForwardedForHeader: false }
});

const actionLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 30,
  message: { message: 'Too many requests. Slow down.' },
  keyGenerator: (req) => `${ipKeyGenerator(req)}:${req.resellerId || 'anonymous'}`,
  validate: { trustProxy: false, xForwardedForHeader: false }
});

const resellerSearchLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 20,
  message: { message: 'Too many search attempts. Please wait 1 minute before trying again.' },
  keyGenerator: (req) => `${ipKeyGenerator(req)}:${req.resellerId || 'anonymous'}`,
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
    return sendEncryptedError(res, 401, 'Unauthorized');
  }

  try {
    const token = auth.slice(7);

    if (!token || token.length < 20) {
      return sendEncryptedError(res, 401, 'Invalid token format');
    }

    const decoded = jwt.verify(
      token,
      process.env.RESELLER_JWT_SECRET || process.env.JWT_SECRET
    );

    if (decoded.role !== 'reseller' || !validation.validateObjectId(decoded.id)) {
      return sendEncryptedError(res, 403, 'Forbidden');
    }

    req.resellerId = decoded.id;
    req.resellerToken = token;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return sendEncryptedError(res, 401, 'Token expired');
    }
    return sendEncryptedError(res, 401, 'Invalid or expired token');
  }
}
// ===== POST /api/reseller/login (Updated with encryption and CAPTCHA) =====
router.post('/login', loginLimiter, async (req, res) => {
  const ip = getIp(req);
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

    return sendEncryptedError(res, 429, `Account locked. Try again in ${seconds}s.`);
  }

  try {
    // Check if request is encrypted
    const { encrypted, hash } = req.body;

    if (!encrypted || !hash) {
      return sendEncryptedError(res, 400, 'Encrypted data required');
    }

    let decryptedData;
    try {
      decryptedData = decryptData(encrypted);
    } catch (err) {
      return sendEncryptedError(res, 400, 'Invalid encrypted payload');
    }

    if (!verifyHash(decryptedData, hash)) {
      return sendEncryptedError(res, 400, 'Data integrity check failed');
    }

    const currentTime = Date.now();
    const timeDiff = Math.abs(currentTime - decryptedData.timestamp);
    if (timeDiff > 5 * 60 * 1000) {
      return sendEncryptedError(res, 400, 'Request expired. Please try again.');
    }

    const { username, password, captchaData, hp } = decryptedData;

    // Honeypot check
    if (hp) {
      return sendEncryptedError(res, 400, 'Invalid request');
    }

    if (!username || typeof username !== 'string') {
      return sendEncryptedError(res, 400, 'Username is required');
    }

    if (!password || typeof password !== 'string') {
      return sendEncryptedError(res, 400, 'Password is required');
    }

    if (!captchaData) {
      return sendEncryptedError(res, 400, 'Captcha verification required');
    }

    // Verify CAPTCHA
    const captchaToken = captchaData.token || captchaData;
    const captcha = await verifyCaptcha(captchaToken, null, ip);

    if (!captcha.ok) {
      console.log(`[Reseller Login] Captcha failed for ${username}: ${captcha.reason}`);
      return sendEncryptedError(res, 400, captcha.reason || 'Captcha verification failed');
    }

    console.log(`[Reseller Login] Captcha passed for ${username}`);

    const sanitizedUsername = validation.sanitizeString(username.trim(), 100);

    if (sanitizedUsername.length < 3) {
      return sendEncryptedError(res, 400, 'Invalid credentials');
    }

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

        return sendEncryptedError(res, 429, 'Too many failed attempts. IP locked for 15 minutes.');
      }

      loginAttempts.set(ip, record);
      return sendEncryptedError(res, 401, 'Invalid credentials');
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

        return sendEncryptedError(res, 429, 'Too many failed attempts. IP locked for 15 minutes.');
      }

      loginAttempts.set(ip, record);
      return sendEncryptedError(res, 401, 'Invalid credentials');
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

      return sendEncryptedError(res, 403, 'Your reseller account has been blocked. Contact admin.');
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

    const responseData = {
      success: true,
      token,
      expiresIn: 12 * 60 * 60 * 1000,
      reseller: {
        id: reseller._id,
        username: reseller.username,
        email: reseller.email,
        credits: reseller.credits,
        totalGiven: reseller.totalGiven,
      },
      timestamp: Date.now()
    };

    const encryptedResponse = encryptResponse(responseData);
    const responseHash = createHash(responseData);

    return res.json({
      encrypted: encryptedResponse,
      hash: responseHash,
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

    return sendEncryptedError(res, 500, 'Server error');
  }
});

// ===== GET /api/reseller/me (Updated with encryption) =====
router.get('/me', resellerAuth, async (req, res) => {
  try {
    const reseller = await Reseller.findById(req.resellerId)
      .select('-password')
      .lean();

    if (!reseller) {
      return sendEncryptedError(res, 404, 'Reseller not found');
    }

    if (reseller.isBlocked) {
      return sendEncryptedError(res, 403, 'Account has been blocked');
    }

    const responseData = {
      ...reseller,
      timestamp: Date.now()
    };

    const encryptedResponse = encryptResponse(responseData);
    const responseHash = createHash(responseData);

    return res.json({
      encrypted: encryptedResponse,
      hash: responseHash,
    });
  } catch (err) {
    console.error('❌ Get me error:', err);
    return sendEncryptedError(res, 500, 'Server error');
  }
});

// ===== GET /api/reseller/search-user (Updated with encryption) =====
router.get('/search-user', resellerAuth, resellerSearchLimiter, async (req, res) => {
  try {
    const reseller = await Reseller.findById(req.resellerId);

    if (!reseller || reseller.isBlocked) {
      return sendEncryptedError(res, 403, 'Account is not active');
    }

    const { query } = req.query;
    const searchQuery = validation.sanitizeSearch(query, 100);

    if (!searchQuery) {
      return sendEncryptedError(res, 400, 'Search query must be at least 3 characters');
    }

    let searchFilter;
    if (validation.validateEmail(query)) {
      searchFilter = { email: query.trim().toLowerCase() };
    } else {
      searchFilter = { userId: query.trim() };
    }

    const user = await User.findOne(searchFilter).select(
      '_id userId username email credits isPro subscription createdAt'
    ).lean();

    if (!user) {
      return sendEncryptedError(res, 404, 'User not found');
    }

    const isProActive = user.subscription?.type === 'pro' && user.subscription?.expiresAt > new Date();
    let subscriptionStatus = null;

    if (isProActive && user.subscription) {
      subscriptionStatus = {
        plan: user.subscription.plan,
        daysLeft: Math.ceil((new Date(user.subscription.expiresAt) - new Date()) / (1000 * 60 * 60 * 24)),
        expiresAt: user.subscription.expiresAt
      };
    }

    await createAuditLog({
      actorType: 'reseller',
      actorId: reseller._id,
      action: 'RESELLER_SEARCH_USER',
      targetId: user._id,
      targetType: 'user',
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    const responseData = {
      ...user,
      isPro: isProActive,
      subscriptionStatus,
      timestamp: Date.now()
    };

    const encryptedResponse = encryptResponse(responseData);
    const responseHash = createHash(responseData);

    return res.json({
      encrypted: encryptedResponse,
      hash: responseHash,
    });
  } catch (err) {
    console.error('❌ Search user error:', err);

    await createAuditLog({
      actorType: 'reseller',
      actorId: req.resellerId,
      action: 'RESELLER_SEARCH_USER',
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: false,
      error: err.message
    });

    return sendEncryptedError(res, 500, 'Server error');
  }
});

// ===== POST /api/reseller/give-pro =====
// Gives Pro subscription to user, deducts credits from reseller
// ===== POST /api/reseller/give-pro =====
// Gives Pro subscription to user, deducts credits from reseller
router.post('/give-pro', resellerAuth, actionLimiter, async (req, res) => {
  try {
    // Check if request is encrypted
    let requestData = req.body;

    // Handle encrypted request
    if (req.body.encrypted && req.body.hash) {
      try {
        const decryptedData = decryptData(req.body.encrypted);

        if (!verifyHash(decryptedData, req.body.hash)) {
          return sendEncryptedError(res, 400, 'Data integrity check failed');
        }

        const currentTime = Date.now();
        const timeDiff = Math.abs(currentTime - decryptedData.timestamp);
        if (timeDiff > 5 * 60 * 1000) {
          return sendEncryptedError(res, 400, 'Request expired. Please try again.');
        }

        requestData = decryptedData;
      } catch (err) {
        return sendEncryptedError(res, 400, 'Invalid encrypted payload');
      }
    }

    const reseller = await Reseller.findById(req.resellerId);
    if (!reseller || reseller.isBlocked) {
      return sendEncryptedError(res, 403, 'Account is not active');
    }

    const { userId, planLabel } = requestData;

    console.log('Give Pro Request Data:', { userId, planLabel });

    if (!userId || typeof userId !== 'string') {
      return sendEncryptedError(res, 400, 'userId is required');
    }

    if (!planLabel || typeof planLabel !== 'string') {
      return sendEncryptedError(res, 400, 'Plan label is required');
    }

    // Validate plan
    const plan = PLANS.find(p => p.label.toLowerCase() === planLabel.toLowerCase());
    if (!plan) {
      return sendEncryptedError(res, 400, `Invalid plan. Choose from: ${PLANS.map(p => p.label).join(', ')}`);
    }

    // Check if reseller has enough credits
    if (reseller.credits < plan.credits) {
      return sendEncryptedError(res, 400, `Insufficient credits. You have ${reseller.credits}, plan requires ${plan.credits} credits.`);
    }

    const sanitizedUserId = validation.sanitizeString(userId.trim(), 100);
    const user = await User.findOne({
      $or: [{ userId: sanitizedUserId }, { email: sanitizedUserId.toLowerCase() }]
    });

    if (!user) {
      return sendEncryptedError(res, 404, 'User not found');
    }

    // Get old subscription info for audit
    const oldSubscription = user.subscription ? {
      type: user.subscription.type,
      plan: user.subscription.plan,
      expiresAt: user.subscription.expiresAt,
      dailyCredits: user.subscription.dailyCredits
    } : null;

    // Calculate new expiry date
    const now = new Date();
    let newExpiry = new Date(now.getTime() + plan.days * 24 * 60 * 60 * 1000);

    // Check if user already has active pro subscription
    if (user.subscription?.type === 'pro' && user.subscription?.expiresAt > now) {
      // EXTEND existing subscription
      const currentExpiry = new Date(user.subscription.expiresAt);
      newExpiry = new Date(currentExpiry.getTime() + plan.days * 24 * 60 * 60 * 1000);

      user.subscription.expiresAt = newExpiry;
      user.subscription.plan = plan.label.toLowerCase();
      // Keep existing daily credits (don't reset, just extend)
    } else {
      // CREATE new subscription
      user.subscription = {
        type: 'pro',
        plan: plan.label.toLowerCase(),
        expiresAt: newExpiry,
        dailyCredits: 30, // ✅ Set daily credits to 30 for Pro users
        lastCreditReset: now
      };
    }

    user.isPro = true;

    // ✅ Reset daily credits to 30 when upgrading to Pro (or extending)
    user.subscription.dailyCredits = 30;
    user.subscription.lastCreditReset = now;

    // ✅ Reset today's attack count so user can use their new Pro benefits immediately
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    user.dailyAttacks = {
      count: 0,
      date: today
    };

    await user.save();

    // Deduct credits from reseller
    const newResellerCredits = reseller.credits - plan.credits;
    reseller.credits = newResellerCredits;
    reseller.totalGiven = (reseller.totalGiven || 0) + plan.credits;
    await reseller.save();

    // Get updated subscription status
    const isProActive = user.subscription?.type === 'pro' && user.subscription?.expiresAt > new Date();
    const daysLeft = Math.ceil((new Date(user.subscription.expiresAt) - new Date()) / (1000 * 60 * 60 * 24));

    const subscriptionStatus = isProActive && user.subscription ? {
      plan: user.subscription.plan,
      daysLeft: daysLeft,
      expiresAt: user.subscription.expiresAt,
      dailyCreditsRemaining: user.subscription.dailyCredits
    } : null;

    // Audit log
    await createAuditLog({
      actorType: 'reseller',
      actorId: reseller._id,
      action: 'RESELLER_GIVE_PRO',
      targetId: user._id,
      targetType: 'user',
      changes: {
        plan: plan.label,
        days: plan.days,
        creditsUsed: plan.credits,
        customerPrice: plan.customerPrice,
        profit: plan.profit,
        oldSubscription,
        newSubscription: user.subscription,
        resellerCreditsLeft: newResellerCredits,
        dailyCreditsSet: 30
      },
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    const responseData = {
      message: `✅ ${plan.displayName} (${plan.days} days) successfully given to ${user.username}! They now have Pro access with 30 daily attacks!`,
      plan: plan.label,
      daysGiven: plan.days,
      creditsUsed: plan.credits,
      profit: plan.profit,
      resellerCreditsLeft: newResellerCredits,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isPro: isProActive,
        subscription: subscriptionStatus
      },
      timestamp: Date.now()
    };

    const encryptedResponse = encryptResponse(responseData);
    const responseHash = createHash(responseData);

    return res.json({
      encrypted: encryptedResponse,
      hash: responseHash,
    });
  } catch (err) {
    console.error('❌ Give pro error:', err);

    await createAuditLog({
      actorType: 'reseller',
      actorId: req.resellerId,
      action: 'RESELLER_GIVE_PRO',
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: false,
      error: err.message
    });

    return sendEncryptedError(res, 500, 'Server error: ' + err.message);
  }
});

// Helper function
async function giveProSubscriptionDirect(user, planLabel, days) {
  const now = new Date();
  const newExpiry = new Date(now.getTime() + days * 24 * 60 * 60 * 1000);

  // In routes/reseller.js - Update the give-pro route

  // When creating/updating the subscription, ensure the plan is lowercase
  if (user.subscription?.type === 'pro' && user.subscription?.expiresAt > now) {
    // Extend existing subscription
    const currentExpiry = new Date(user.subscription.expiresAt);
    const extendedExpiry = new Date(currentExpiry.getTime() + plan.days * 24 * 60 * 60 * 1000);
    user.subscription.expiresAt = extendedExpiry;
    user.subscription.plan = plan.label.toLowerCase(); // ✅ Convert to lowercase
  } else {
    // Create new subscription
    user.subscription = {
      type: 'pro',
      plan: plan.label.toLowerCase(), // ✅ Convert to lowercase
      expiresAt: newExpiry,
      attacksPerDay: 30,
      startedAt: now
    };
  }

  user.isPro = true;
  return days;
}

// ===== GET /api/reseller/plans (Updated with encryption) =====
router.get('/plans', resellerAuth, async (req, res) => {
  try {
    const reseller = await Reseller.findById(req.resellerId);
    if (!reseller || reseller.isBlocked) {
      return sendEncryptedError(res, 403, 'Account is not active');
    }

    const responseData = {
      plans: PLANS.map(plan => ({
        label: plan.label,
        displayName: plan.displayName,
        days: plan.days,
        credits: plan.credits,
        customerPrice: plan.customerPrice,
        profit: plan.profit,
        multiplier: plan.multiplier,
        description: `${plan.days} days of Pro access with 30 attacks per day`
      })),
      myCredits: reseller.credits,
      timestamp: Date.now()
    };

    const encryptedResponse = encryptResponse(responseData);
    const responseHash = createHash(responseData);

    return res.json({
      encrypted: encryptedResponse,
      hash: responseHash,
    });
  } catch (err) {
    console.error('❌ Get plans error:', err);
    return sendEncryptedError(res, 500, 'Failed to fetch plans');
  }
});

// ===== GET /api/reseller/stats (Updated with encryption) =====
router.get('/stats', resellerAuth, async (req, res) => {
  try {
    const reseller = await Reseller.findById(req.resellerId);
    if (!reseller || reseller.isBlocked) {
      return sendEncryptedError(res, 403, 'Account is not active');
    }

    const usersServed = await User.countDocuments({
      'subscription.type': 'pro',
      'subscription.expiresAt': { $gt: new Date() }
    });

    const responseData = {
      credits: reseller.credits,
      totalGiven: reseller.totalGiven,
      usersServed: usersServed,
      lastLogin: reseller.lastLogin,
      createdAt: reseller.createdAt,
      timestamp: Date.now()
    };

    const encryptedResponse = encryptResponse(responseData);
    const responseHash = createHash(responseData);

    return res.json({
      encrypted: encryptedResponse,
      hash: responseHash,
    });
  } catch (err) {
    console.error('❌ Get stats error:', err);
    return sendEncryptedError(res, 500, 'Failed to fetch stats');
  }
});

module.exports = router;
module.exports.resellerAuth = resellerAuth;