// routes/admin.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const mongoose = require('mongoose'); // ✅ ADD THIS — needed for ObjectId casting
const User = require('../models/User');
const Reseller = require('../models/Reseller');
const AuditLog = require('../models/AuditLog');
const validation = require('../utils/validation');
const { createAuditLog } = require('../utils/audit');
const dailyResetService = require('../services/dailyResetService');
const ApiUser = require('../models/ApiUser');
const { verifyCaptcha } = require('./captcha');
const attackTracker = require('../services/attackTracker');

const CryptoJS = require('crypto-js');
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'your-secret-key-2024-battle-destroyer';


// ===== ENCRYPTION HELPERS (ONLY FOR LOGIN) =====
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

function createHash(data) {
  const jsonString = JSON.stringify(data);
  return CryptoJS.SHA256(jsonString + ENCRYPTION_KEY).toString();
}

function sendEncryptedError(res, statusCode, message) {
  const errorResponse = { success: false, message };
  const encryptedError = encryptResponse(errorResponse);
  const errorHash = createHash(errorResponse);
  res.status(statusCode).json({ encrypted: encryptedError, hash: errorHash });
}
// ===== REDIS SESSION STORE =====
const redis = require('redis');
const redisClient = redis.createClient({
  url: process.env.REDIS_URL,
  socket: {
    reconnectStrategy: (retries) => Math.min(retries * 100, 3000)
  }
});

redisClient.on('error', (err) => {
  console.error('❌ Redis Error:', err);
});

redisClient.on('connect', () => {
  console.log('✅ Redis connected for session management');
});

(async () => {
  await redisClient.connect();
})().catch(err => console.error('❌ Failed to connect to Redis:', err));

const SESSION_TTL = 8 * 60 * 60; // 8 hours in seconds
const SESSION_PREFIX = 'admin:session:';

// ===== BRUTE FORCE PROTECTION =====
const failedAttempts = new Map();
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

setInterval(() => {
  const now = Date.now();
  for (const [ip, record] of failedAttempts.entries()) {
    if (record.lockedUntil < now && record.count === 0) failedAttempts.delete(ip);
  }
}, 30 * 60 * 1000);

// ===== AUTH MIDDLEWARE (session token validation) =====
async function adminAuth(req, res, next) {
  const token = req.headers['x-admin-token'];
  const ip = req.ip;

  if (!token) {
    await createAuditLog({
      actorType: 'admin',
      action: 'UNAUTHORIZED_ACCESS',
      ip,
      userAgent: req.headers['user-agent'],
      success: false,
      error: 'No token provided'
    });
    return res.status(401).json({ message: 'SESSION_INVALIDATED' });
  }

  try {
    const sessionData = await redisClient.get(SESSION_PREFIX + token);

    if (!sessionData) {
      await createAuditLog({
        actorType: 'admin',
        action: 'INVALID_TOKEN',
        ip,
        userAgent: req.headers['user-agent'],
        success: false,
        error: 'Invalid or expired token'
      });
      return res.status(401).json({ message: 'SESSION_EXPIRED' });
    }

    req.adminSession = JSON.parse(sessionData);
    next();
  } catch (err) {
    console.error('❌ Auth middleware error:', err);
    res.status(500).json({ message: 'Authentication failed' });
  }
}


/**
 * GET /api/admin/attacks/running
 * Get all currently running attacks from both API and Panel endpoints
 */
router.get('/attacks/running', adminAuth, async (req, res) => {
  try {
    const stats = attackTracker.getStats();

    // Add additional admin-specific info
    const response = {
      success: true,
      timestamp: new Date().toISOString(),
      data: {
        totalActive: stats.totalActive,
        bySource: stats.bySource,
        attacks: stats.attacks.map(attack => ({
          attackId: attack.attackId,
          target: attack.target,
          port: attack.port,
          duration: attack.duration,
          startedAt: attack.startedAt,
          expiresAt: attack.expiresAt,
          timeRemaining: attack.timeRemaining,
          username: attack.username,
          userId: attack.userId,
          source: attack.source,
          status: attack.status
        })),
        totalAttacksLaunched: stats.totalAttacksLaunched,
        lastUpdated: new Date().toISOString()
      }
    };

    // Encrypt response for consistency with other admin endpoints
    const encryptedResponse = encryptResponse(response);
    const responseHash = createHash(response);
    res.json({ encrypted: encryptedResponse, hash: responseHash });

  } catch (error) {
    console.error('[Admin] Error fetching running attacks:', error);
    sendEncryptedError(res, 500, 'Failed to fetch running attacks');
  }
});

/**
 * GET /api/admin/attacks/running/summary
 * Get lightweight summary of running attacks (good for dashboard widgets)
 */
router.get('/attacks/running/summary', adminAuth, async (req, res) => {
  try {
    const attacks = attackTracker.getActiveAttacks();
    const now = Date.now();

    const summary = {
      success: true,
      timestamp: new Date().toISOString(),
      totalActive: attacks.length,
      attacksBySource: {
        api: attacks.filter(a => a.source === 'api').length,
        panel: attacks.filter(a => a.source === 'panel').length
      },
      topTargets: attacks.slice(0, 5).map(a => ({
        target: a.target,
        port: a.port,
        username: a.username,
        timeRemaining: Math.max(0, Math.floor((a.expiresAt - now) / 1000))
      })),
      recentActivity: attacks.slice(-10).map(a => ({
        target: a.target,
        username: a.username,
        source: a.source,
        startedAt: a.startedAt,
        expiresIn: Math.max(0, Math.floor((a.expiresAt - now) / 1000))
      }))
    };

    const encryptedResponse = encryptResponse(summary);
    const responseHash = createHash(summary);
    res.json({ encrypted: encryptedResponse, hash: responseHash });

  } catch (error) {
    console.error('[Admin] Error fetching attacks summary:', error);
    sendEncryptedError(res, 500, 'Failed to fetch attacks summary');
  }
});


/**
 * GET /api/admin/attacks/user/:userId
 * Get running attacks for a specific user
 */
router.get('/attacks/user/:userId', adminAuth, async (req, res) => {
  try {
    const { userId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    const attacks = attackTracker.getUserAttacks(userId);
    const user = await User.findById(userId).select('username email').lean();

    const response = {
      success: true,
      user: user || { id: userId, username: 'Unknown', email: 'Unknown' },
      activeAttacks: attacks.length,
      attacks: attacks.map(a => ({
        attackId: a.attackId,
        target: a.target,
        port: a.port,
        duration: a.duration,
        startedAt: a.startedAt,
        expiresAt: a.expiresAt,
        timeRemaining: Math.max(0, Math.floor((a.expiresAt - Date.now()) / 1000)),
        source: a.source
      }))
    };

    const encryptedResponse = encryptResponse(response);
    const responseHash = createHash(response);
    res.json({ encrypted: encryptedResponse, hash: responseHash });

  } catch (error) {
    console.error('[Admin] Error fetching user attacks:', error);
    sendEncryptedError(res, 500, 'Failed to fetch user attacks');
  }
});

/**
 * DELETE /api/admin/attacks/:attackId
 * Stop a specific running attack
 */
router.delete('/attacks/:attackId', adminAuth, async (req, res) => {
  try {
    const { attackId } = req.params;
    const stopped = attackTracker.stopAttack(attackId);

    if (stopped) {
      await createAuditLog({
        actorType: 'admin',
        actorId: req.adminSession?.token,
        action: 'STOP_ATTACK',
        targetId: attackId,
        targetType: 'attack',
        changes: { attackId, stoppedBy: 'admin' },
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        success: true
      });

      const response = {
        success: true,
        message: `Attack ${attackId} stopped successfully`
      };

      const encryptedResponse = encryptResponse(response);
      const responseHash = createHash(response);
      res.json({ encrypted: encryptedResponse, hash: responseHash });

    } else {
      res.status(404).json({
        success: false,
        message: 'Attack not found or already completed'
      });
    }

  } catch (error) {
    console.error('[Admin] Error stopping attack:', error);
    sendEncryptedError(res, 500, 'Failed to stop attack');
  }
});

/**
 * DELETE /api/admin/attacks/user/:userId/stop-all
 * Stop all running attacks for a user
 */
router.delete('/attacks/user/:userId/stop-all', adminAuth, async (req, res) => {
  try {
    const { userId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    const stopped = attackTracker.stopUserAttacks(userId);

    await createAuditLog({
      actorType: 'admin',
      actorId: req.adminSession?.token,
      action: 'STOP_ALL_USER_ATTACKS',
      targetId: userId,
      targetType: 'user',
      changes: { userId, attacksStopped: stopped },
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    const response = {
      success: true,
      message: `Stopped ${stopped} attacks for user`,
      attacksStopped: stopped
    };

    const encryptedResponse = encryptResponse(response);
    const responseHash = createHash(response);
    res.json({ encrypted: encryptedResponse, hash: responseHash });

  } catch (error) {
    console.error('[Admin] Error stopping user attacks:', error);
    sendEncryptedError(res, 500, 'Failed to stop user attacks');
  }
});

/**
 * GET /api/admin/attacks/stats
 * Get attack statistics (historical)
 */
router.get('/attacks/stats', adminAuth, async (req, res) => {
  try {
    const stats = attackTracker.getStats();
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());

    // Get historical stats from database
    const [totalAttacksAllTime, attacksToday] = await Promise.all([
      AuditLog.countDocuments({ action: { $in: ['ATTACK_LAUNCHED', 'API_ATTACK_LAUNCHED'] }, success: true }),
      AuditLog.countDocuments({
        action: { $in: ['ATTACK_LAUNCHED', 'API_ATTACK_LAUNCHED'] },
        success: true,
        createdAt: { $gte: today }
      })
    ]);

    const response = {
      success: true,
      timestamp: new Date().toISOString(),
      currentActive: stats.totalActive,
      bySource: stats.bySource,
      historical: {
        totalAttacksAllTime,
        attacksToday,
        peakConcurrent: stats.totalAttacksLaunched // You can track peak separately if needed
      },
      totalLaunched: stats.totalAttacksLaunched
    };

    const encryptedResponse = encryptResponse(response);
    const responseHash = createHash(response);
    res.json({ encrypted: encryptedResponse, hash: responseHash });

  } catch (error) {
    console.error('[Admin] Error fetching attack stats:', error);
    sendEncryptedError(res, 500, 'Failed to fetch attack statistics');
  }
});

router.post('/api-users/:id/extend', adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id))
      return res.status(400).json({ message: 'Invalid user ID format' });

    const { days } = req.body;

    if (days === undefined || days === null)
      return res.status(400).json({ message: 'Days parameter is required' });

    const daysNum = parseInt(days);
    if (isNaN(daysNum) || daysNum < 1 || daysNum > 365)
      return res.status(400).json({ message: `Days must be between 1 and 365. Received: ${days}` });

    const apiUser = await ApiUser.findById(req.params.id);
    if (!apiUser)
      return res.status(404).json({ message: 'API user not found' });

    const oldExpiry = apiUser.expiresAt;

    // Extend: from current expiry if still valid, else from now
    const base = apiUser.expiresAt && apiUser.expiresAt > new Date()
      ? apiUser.expiresAt
      : new Date();
    apiUser.expiresAt = new Date(base.getTime() + daysNum * 24 * 60 * 60 * 1000);

    if (apiUser.status === 'expired') apiUser.status = 'active';

    await apiUser.save();   // ← explicit save; don't rely solely on the model method

    const newExpiry = apiUser.expiresAt;

    await createAuditLog({
      actorType: 'admin', actorId: req.userId,
      action: 'EXTEND_API_USER', targetId: apiUser._id, targetType: 'api_user',
      changes: { days: daysNum, oldExpiry, newExpiry },
      ip: req.ip, userAgent: req.headers['user-agent'], success: true
    });

    res.json({
      success: true,
      message: `API user expiration extended by ${daysNum} days`,
      expiresAt: newExpiry,
      daysRemaining: apiUser.getDaysRemaining()
    });
  } catch (err) {
    console.error('❌ Extend API user error:', err);
    res.status(500).json({ message: 'Failed to extend expiration: ' + err.message });
  }
});

// SET API user expiration (replace)
router.post('/api-users/:id/set-expiration', adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    const { days } = req.body;

    if (!days || days < 1 || days > 365) {
      return res.status(400).json({ message: 'Days must be between 1 and 365' });
    }

    const apiUser = await ApiUser.findById(req.params.id);
    if (!apiUser) {
      return res.status(404).json({ message: 'API user not found' });
    }

    const oldExpiry = apiUser.expiresAt;
    apiUser.expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
    if (apiUser.status === 'expired') {
      apiUser.status = 'active';
    }
    await apiUser.save();

    await createAuditLog({
      actorType: 'admin',
      actorId: req.userId,
      action: 'SET_API_USER_EXPIRATION',
      targetId: apiUser._id,
      targetType: 'api_user',
      changes: { days, oldExpiry, newExpiry: apiUser.expiresAt },
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({
      success: true,
      message: `API user expiration set to ${days} days`,
      expiresAt: apiUser.expiresAt,
      daysRemaining: apiUser.getDaysRemaining()
    });
  } catch (err) {
    console.error('❌ Set API user expiration error:', err);
    res.status(500).json({ message: 'Failed to set expiration: ' + err.message });
  }
});

// GET all API users
router.get('/api-users', adminAuth, async (req, res) => {
  try {
    let page = parseInt(req.query.page) || 1;
    let limit = parseInt(req.query.limit) || 50;
    const search = req.query.search ? String(req.query.search).trim() : '';
    const status = req.query.status;

    if (page < 1) page = 1;
    if (limit < 1 || limit > 100) limit = 50;

    const query = {};
    if (search.length > 0) {
      query.$or = [
        { username: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }
    if (status && status !== 'all' && status !== '') {
      query.status = status;
    }

    const total = await ApiUser.countDocuments(query);
    const totalPages = Math.ceil(total / limit);
    if (page > totalPages && totalPages > 0) page = totalPages;

    const apiUsers = await ApiUser.find(query)
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean();

    const usersWithInfo = apiUsers.map(user => ({
      ...user,
      currentActive: user.activeAttacks?.filter(a => new Date(a.expiresAt) > new Date()).length || 0,
      isExpired: user.expiresAt ? new Date(user.expiresAt) < new Date() : false,
      daysRemaining: user.expiresAt ? Math.max(0, Math.ceil((new Date(user.expiresAt) - new Date()) / (1000 * 60 * 60 * 24))) : null
    }));

    res.json({ users: usersWithInfo, total, totalPages, currentPage: page });
  } catch (err) {
    console.error('❌ Get API users error:', err);
    res.status(500).json({ message: 'Failed to fetch API users' });
  }
});

// CREATE API user (PLAIN JSON)
router.post('/api-users', adminAuth, async (req, res) => {
  try {
    let { username, email, maxConcurrent, maxDuration, expirationDays = 30 } = req.body;

    // Validate and sanitize username
    if (!username) {
      return res.status(400).json({ message: 'Username is required' });
    }

    username = username.trim().toLowerCase();

    if (username.length < 3 || username.length > 30) {
      return res.status(400).json({ message: 'Username must be between 3 and 30 characters' });
    }

    const validUsernameRegex = /^[a-zA-Z0-9_.-]+$/;
    if (!validUsernameRegex.test(username)) {
      return res.status(400).json({
        message: 'Username can only contain letters, numbers, underscores, dots, and hyphens'
      });
    }

    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }

    email = email.trim().toLowerCase();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }

    const existingUser = await ApiUser.findOne({ $or: [{ username }, { email }] });
    if (existingUser) {
      const field = existingUser.username === username ? 'Username' : 'Email';
      return res.status(400).json({ message: `${field} already exists` });
    }

    let apiKey, apiSecret, apiSecretHash;

    try {
      apiKey = await ApiUser.generateUniqueApiKey();
      const secretData = await ApiUser.generateUniqueApiSecret();
      apiSecret = secretData.raw;
      apiSecretHash = secretData.hashed;
    } catch (err) {
      console.error('Credential generation error:', err);
      return res.status(500).json({ message: 'Failed to generate unique credentials. Please try again.' });
    }

    const expiresAt = expirationDays > 0
      ? new Date(Date.now() + expirationDays * 24 * 60 * 60 * 1000)
      : null;

    const apiUser = new ApiUser({
      username,
      email,
      apiKey,
      apiSecretHash,
      limits: {
        maxConcurrent: maxConcurrent || 2,
        maxDuration: maxDuration || 300
      },
      status: 'active',
      expiresAt: expiresAt,
      createdBy: req.userId
    });

    await apiUser.save();

    await createAuditLog({
      actorType: 'admin',
      actorId: req.userId,
      action: 'CREATE_API_USER',
      targetId: apiUser._id,
      targetType: 'api_user',
      changes: { username, email, maxConcurrent, maxDuration, expirationDays },
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.status(201).json({
      success: true,
      message: 'API user created successfully',
      user: {
        id: apiUser._id,
        username: apiUser.username,
        email: apiUser.email,
        apiKey: apiUser.apiKey,
        apiSecret: apiSecret,
        limits: apiUser.limits,
        status: apiUser.status,
        expiresAt: apiUser.expiresAt,
        daysRemaining: apiUser.getDaysRemaining(),
        createdAt: apiUser.createdAt
      },
      warning: 'Save the apiSecret now! It will not be shown again.'
    });
  } catch (err) {
    console.error('❌ Create API user error:', err);
    if (err.code === 11000) {
      const field = Object.keys(err.keyPattern || {})[0];
      return res.status(400).json({ message: `${field} already exists` });
    }
    if (err.name === 'ValidationError') {
      const messages = Object.values(err.errors).map(e => e.message);
      return res.status(400).json({ message: messages.join(', ') });
    }
    res.status(500).json({ message: 'Failed to create API user: ' + err.message });
  }
});

// GET single API user
router.get('/api-users/:id', adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    const apiUser = await ApiUser.findById(req.params.id).lean();
    if (!apiUser) {
      return res.status(404).json({ message: 'API user not found' });
    }

    // Add real-time active count
    apiUser.currentActive = apiUser.activeAttacks?.filter(a => new Date(a.expiresAt) > new Date()).length || 0;

    res.json(apiUser);
  } catch (err) {
    console.error('❌ Get API user error:', err);
    res.status(500).json({ message: 'Failed to fetch API user' });
  }
});

// UPDATE API user limits
router.patch('/api-users/:id/limits', adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    const { maxConcurrent, maxDuration, status } = req.body;
    const apiUser = await ApiUser.findById(req.params.id);

    if (!apiUser) {
      return res.status(404).json({ message: 'API user not found' });
    }

    const oldLimits = { ...apiUser.limits };
    const oldStatus = apiUser.status;

    if (maxConcurrent !== undefined) apiUser.limits.maxConcurrent = maxConcurrent;
    if (maxDuration !== undefined) apiUser.limits.maxDuration = maxDuration;
    if (status !== undefined) apiUser.status = status;

    await apiUser.save();

    await createAuditLog({
      actorType: 'admin',
      actorId: req.userId,
      action: 'UPDATE_API_USER',
      targetId: apiUser._id,
      targetType: 'api_user',
      changes: { oldLimits, newLimits: apiUser.limits, oldStatus, newStatus: apiUser.status },
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({
      success: true,
      message: 'API user updated',
      user: {
        id: apiUser._id,
        username: apiUser.username,
        limits: apiUser.limits,
        status: apiUser.status,
        expiresAt: apiUser.expiresAt,
        daysRemaining: apiUser.getDaysRemaining()
      }
    });
  } catch (err) {
    console.error('❌ Update API user error:', err);
    res.status(500).json({ message: 'Failed to update API user: ' + err.message });
  }
});
// REGENERATE API secret
router.post('/api-users/:id/regenerate-secret', adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    const apiUser = await ApiUser.findById(req.params.id);
    if (!apiUser) {
      return res.status(404).json({ message: 'API user not found' });
    }

    let newSecretRaw, newSecretHash;
    let attempts = 0;
    const maxAttempts = 5;
    let isUnique = false;

    while (!isUnique && attempts < maxAttempts) {
      newSecretRaw = 'as_' + crypto.randomBytes(32).toString('hex');
      newSecretHash = crypto.createHash('sha256').update(newSecretRaw).digest('hex');

      const existing = await ApiUser.findOne({ apiSecretHash: newSecretHash });
      if (!existing) {
        isUnique = true;
      }
      attempts++;
    }

    if (!isUnique) {
      return res.status(500).json({ message: 'Failed to generate unique secret. Please try again.' });
    }

    apiUser.apiSecretHash = newSecretHash;
    await apiUser.save();

    await createAuditLog({
      actorType: 'admin',
      actorId: req.userId,
      action: 'REGENERATE_API_SECRET',
      targetId: apiUser._id,
      targetType: 'api_user',
      changes: { username: apiUser.username, regenerated: true },
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({
      success: true,
      message: 'API secret regenerated successfully',
      apiSecret: newSecretRaw,
      warning: 'Save this secret now! It will not be shown again.'
    });
  } catch (err) {
    console.error('❌ Regenerate secret error:', err);
    res.status(500).json({ message: 'Failed to regenerate secret: ' + err.message });
  }
});
// DELETE API user
router.delete('/api-users/:id', adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    const apiUser = await ApiUser.findByIdAndDelete(req.params.id);
    if (!apiUser) {
      return res.status(404).json({ message: 'API user not found' });
    }

    await createAuditLog({
      actorType: 'admin',
      actorId: req.userId,
      action: 'DELETE_API_USER',
      targetId: req.params.id,
      targetType: 'api_user',
      changes: { username: apiUser.username, email: apiUser.email },
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({ success: true, message: 'API user deleted successfully' });
  } catch (err) {
    console.error('❌ Delete API user error:', err);
    res.status(500).json({ message: 'Failed to delete API user: ' + err.message });
  }
});

// GET API user stats
router.get('/api-users/:id/stats', adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    const apiUser = await ApiUser.findById(req.params.id);
    if (!apiUser) {
      return res.status(404).json({ message: 'API user not found' });
    }

    const now = new Date();
    const activeCount = apiUser.activeAttacks?.filter(a => new Date(a.expiresAt) > now).length || 0;

    // Only include rate limit data if requestHistory exists in schema
    const statsResponse = {
      username: apiUser.username,
      email: apiUser.email,
      status: apiUser.status,
      limits: apiUser.limits,
      totalRequests: apiUser.totalRequests || 0,
      totalAttacks: apiUser.totalAttacks || 0,
      currentActiveAttacks: activeCount,
      expiresAt: apiUser.expiresAt,
      daysRemaining: apiUser.getDaysRemaining(),
      isExpired: apiUser.isExpired(),
      createdAt: apiUser.createdAt,
      lastLoginAt: apiUser.lastLoginAt,
      activeAttacks: apiUser.activeAttacks
        .filter(a => new Date(a.expiresAt) > now)
        .map(a => ({
          attackId: a.attackId,
          target: a.target,
          port: a.port,
          startedAt: a.startedAt,
          expiresIn: Math.floor((new Date(a.expiresAt) - now) / 1000)
        }))
    };

    // Only add rate limits if requestHistory exists
    if (apiUser.requestHistory) {
      const lastMinute = apiUser.requestHistory?.filter(r => now - new Date(r.timestamp) < 60 * 1000).length || 0;
      const lastHour = apiUser.requestHistory?.filter(r => now - new Date(r.timestamp) < 60 * 60 * 1000).length || 0;
      const lastDay = apiUser.requestHistory?.filter(r => now - new Date(r.timestamp) < 24 * 60 * 60 * 1000).length || 0;

      statsResponse.currentRateLimits = {
        lastMinute,
        lastHour,
        lastDay
      };
    }

    res.json(statsResponse);
  } catch (err) {
    console.error('❌ Get API user stats error:', err);
    res.status(500).json({ message: 'Failed to fetch stats: ' + err.message });
  }
});


// ===== POST /api/admin/session — exchange secret for session token =====
router.post('/session', async (req, res) => {
  if (!redisClient.isReady) {
    console.error('❌ Redis not connected');
    return res.status(503).json({ message: 'Service temporarily unavailable' });
  }

  const ip = req.ip;
  const now = Date.now();
  const record = failedAttempts.get(ip) || { count: 0, lockedUntil: 0 };

  if (record.lockedUntil > now) {
    const seconds = Math.ceil((record.lockedUntil - now) / 1000);
    await createAuditLog({
      actorType: 'admin',
      action: 'BRUTE_FORCE_LOCKOUT',
      ip,
      userAgent: req.headers['user-agent'],
      success: false,
      error: `IP locked for ${seconds}s`
    });
    return res.status(429).json({ message: `Too many failed attempts. Try again in ${seconds}s.` });
  }

  let secret, captchaData;

  // Handle encrypted request (ONLY FOR LOGIN)
  if (req.body.encrypted && req.body.hash) {
    try {
      const decrypted = decryptData(req.body.encrypted);
      const calculatedHash = createHash(decrypted);

      if (calculatedHash !== req.body.hash) {
        return res.status(400).json({ message: 'Data integrity check failed' });
      }

      const currentTime = Date.now();
      const timeDiff = Math.abs(currentTime - (decrypted.timestamp || currentTime));
      if (timeDiff > 5 * 60 * 1000) {
        return res.status(400).json({ message: 'Request expired. Please try again.' });
      }

      secret = decrypted.secret;
      captchaData = decrypted.captchaData;
    } catch (err) {
      return res.status(400).json({ message: 'Invalid encrypted payload' });
    }
  } else {
    secret = req.body.secret;
    captchaData = req.body.captchaData;
  }

  // Verify captcha
  if (!captchaData) {
    return res.status(400).json({ message: 'Captcha verification required' });
  }

  const captchaToken = captchaData.token || captchaData;
  const captcha = await verifyCaptcha(captchaToken, null, ip);

  if (!captcha.ok) {
    console.log(`[Admin Login] Captcha failed: ${captcha.reason}`);
    return res.status(400).json({ message: captcha.reason || 'Captcha verification failed' });
  }

  if (!secret || typeof secret !== 'string' || secret !== process.env.ADMIN_SECRET) {
    record.count += 1;
    failedAttempts.set(ip, record);

    if (record.count >= MAX_ATTEMPTS) {
      record.lockedUntil = now + LOCKOUT_MS;
      record.count = 0;
      failedAttempts.set(ip, record);
      await createAuditLog({
        actorType: 'admin',
        action: 'BRUTE_FORCE_LOCKOUT',
        ip,
        userAgent: req.headers['user-agent'],
        success: false,
        error: 'Max attempts exceeded, IP locked for 15 minutes'
      });
      return res.status(429).json({ message: 'Too many failed attempts. IP locked for 15 minutes.' });
    }

    return res.status(401).json({ message: `Invalid secret. ${MAX_ATTEMPTS - record.count} attempts remaining.` });
  }

  failedAttempts.delete(ip);

  const token = crypto.randomBytes(48).toString('hex');
  const sessionData = {
    token,
    createdAt: now,
    ip,
    userAgent: req.headers['user-agent'] || 'unknown',
    expiresAt: new Date(now + SESSION_TTL * 1000).toISOString()
  };

  try {
    await redisClient.setEx(SESSION_PREFIX + token, SESSION_TTL, JSON.stringify(sessionData));
    await createAuditLog({
      actorType: 'admin',
      action: 'SESSION_CREATED',
      ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    // Send encrypted response (ONLY FOR LOGIN)
    const responseData = { token, expiresIn: SESSION_TTL * 1000 };
    const encryptedResponse = encryptResponse(responseData);
    const responseHash = createHash(responseData);
    res.json({ encrypted: encryptedResponse, hash: responseHash });
  } catch (err) {
    console.error('❌ Redis error:', err);
    res.status(500).json({ message: 'Session storage failed' });
  }
});

// ===== DELETE /api/admin/session — explicit logout =====
router.delete('/session', async (req, res) => {
  const token = req.headers['x-admin-token'];
  if (!token) return res.status(400).json({ message: 'No token provided' });

  try {
    await redisClient.del(SESSION_PREFIX + token);
    await createAuditLog({
      actorType: 'admin',
      action: 'LOGOUT',
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    console.error('❌ Redis error:', err);
    res.status(500).json({ message: 'Logout failed' });
  }
});

// ===== GET /api/admin/session/check — frontend heartbeat =====
router.get('/session/check', async (req, res) => {
  const token = req.headers['x-admin-token'];
  if (!token) return res.status(401).json({ message: 'SESSION_INVALIDATED' });

  try {
    const sessionData = await redisClient.get(SESSION_PREFIX + token);
    if (!sessionData) return res.status(401).json({ message: 'SESSION_INVALIDATED' });
    res.json({ ok: true });
  } catch (err) {
    console.error('❌ Redis error:', err);
    res.status(500).json({ message: 'Session check failed' });
  }
});


// ===== POST /api/admin/trigger-daily-reset =====
router.post('/trigger-daily-reset', adminAuth, async (req, res) => {
  try {
    const { secret } = req.body;
    if (process.env.NODE_ENV === 'production' && secret !== process.env.ADMIN_RESET_SECRET) {
      return res.status(403).json({ message: 'Unauthorized: Invalid reset secret' });
    }

    const result = await dailyResetService.manualReset();

    if (result.success) {
      await createAuditLog({
        actorType: 'admin',
        actorId: req.adminSession?.token,
        action: 'DAILY_RESET',
        targetType: 'system',
        changes: result,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        success: true
      });
      res.json({ message: 'Daily reset triggered successfully', result });
    } else {
      res.status(500).json({ message: 'Daily reset failed', error: result.error });
    }
  } catch (err) {
    console.error('❌ Manual reset error:', err);
    await createAuditLog({
      actorType: 'admin',
      action: 'DAILY_RESET_FAILED',
      success: false,
      error: err.message,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });
    res.status(500).json({ message: 'Failed to trigger reset' });
  }
});

// ===== GET /api/admin/daily-reset-status =====
router.get('/stats', adminAuth, async (req, res) => {
  try {
    const [total, proUsers, freeUsers, withCredits, today, totalResellers, activeResellers] =
      await Promise.all([
        User.countDocuments(),
        User.countDocuments({
          'subscription.type': 'pro',
          'subscription.expiresAt': { $gt: new Date() }
        }),
        User.countDocuments({ 'subscription.type': 'free' }),
        User.countDocuments({ credits: { $gt: 0 } }),
        User.countDocuments({ createdAt: { $gte: new Date(Date.now() - 86400000) } }),
        Reseller.countDocuments(),
        Reseller.countDocuments({ isBlocked: false })
      ]);

    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    const attacksToday = await User.aggregate([
      { $match: { 'dailyAttacks.date': { $gte: todayStart } } },
      { $group: { _id: null, total: { $sum: '$dailyAttacks.count' } } }
    ]);

    const apiUsersRes = await ApiUser.find().limit(100);
    const activeApiUsers = apiUsersRes.filter(u => u.status === 'active').length;

    res.json({
      total, pro: proUsers, free: freeUsers,
      withCredits, today, totalResellers, activeResellers,
      attacksToday: attacksToday[0]?.total || 0,
      totalApiUsers: apiUsersRes.length,
      activeApiUsers
    });
  } catch (err) {
    console.error('❌ Stats error:', err);
    res.status(500).json({ message: 'Failed to fetch stats' });
  }
});


// ═══════════════════════════════════════════════════════════════════════════════
//  STATS
// ═══════════════════════════════════════════════════════════════════════════════

router.get('/stats', adminAuth, async (req, res) => {
  try {
    const [total, proUsers, freeUsers, withCredits, today, totalResellers, activeResellers] =
      await Promise.all([
        User.countDocuments(),
        User.countDocuments({
          'subscription.type': 'pro',
          'subscription.expiresAt': { $gt: new Date() }
        }),
        User.countDocuments({ 'subscription.type': 'free' }),
        User.countDocuments({ credits: { $gt: 0 } }),
        User.countDocuments({ createdAt: { $gte: new Date(Date.now() - 86400000) } }),
        Reseller.countDocuments(),
        Reseller.countDocuments({ isBlocked: false })
      ]);

    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    const attacksToday = await User.aggregate([
      { $match: { 'dailyAttacks.date': { $gte: todayStart } } },
      { $group: { _id: null, total: { $sum: '$dailyAttacks.count' } } }
    ]);

    const statsData = {
      total, pro: proUsers, free: freeUsers,
      withCredits, today, totalResellers, activeResellers,
      attacksToday: attacksToday[0]?.total || 0
    };

    const encryptedResponse = encryptResponse(statsData);
    const responseHash = createHash(statsData);
    res.json({ encrypted: encryptedResponse, hash: responseHash });
  } catch (err) {
    console.error('❌ Stats error:', err);
    sendEncryptedError(res, 500, 'Failed to fetch stats');
  }
});
// ═══════════════════════════════════════════════════════════════════════════════
//  USER ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

router.get('/users', adminAuth, async (req, res) => {
  try {
    let page = parseInt(req.query.page) || 1;
    let limit = parseInt(req.query.limit) || 50;
    const search = req.query.search ? String(req.query.search).trim() : '';
    const subscriptionType = req.query.subscriptionType;

    if (page < 1) page = 1;
    if (limit < 1 || limit > 100) limit = 50;

    const conditions = [];

    if (search.length > 0) {
      conditions.push({
        $or: [
          { username: { $regex: search, $options: 'i' } },
          { email: { $regex: search, $options: 'i' } },
          { userId: { $regex: search, $options: 'i' } },
        ]
      });
    }

    if (subscriptionType === 'pro') {
      conditions.push({
        $and: [
          { 'subscription.type': 'pro' },
          { 'subscription.expiresAt': { $gt: new Date() } }
        ]
      });
    } else if (subscriptionType === 'free') {
      conditions.push({
        $or: [
          { 'subscription.type': 'free' },
          { 'subscription.type': { $exists: false } },
          { 'subscription.expiresAt': null },
          { 'subscription.expiresAt': { $exists: false } },
          { 'subscription.expiresAt': { $lte: new Date() } }
        ]
      });
    }

    const query = conditions.length > 0 ? { $and: conditions } : {};

    const total = await User.countDocuments(query);
    const totalPages = Math.ceil(total / limit) || 1;
    if (page > totalPages) page = totalPages;

    const users = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean();

    const usersWithStatus = users.map(user => {
      const isProActive =
        user.subscription?.type === 'pro' &&
        user.subscription?.expiresAt &&
        new Date(user.subscription.expiresAt) > new Date();

      return {
        ...user,
        isPro: isProActive,
        subscriptionStatus: {
          active: isProActive,
          daysLeft: user.subscription?.expiresAt
            ? Math.ceil((new Date(user.subscription.expiresAt) - new Date()) / 86400000)
            : 0,
          plan: user.subscription?.plan || 'none',
          expiresAt: user.subscription?.expiresAt
        },
        remainingAttacks: isProActive
          ? user.subscription?.dailyCredits
          : user.credits
      };
    });

    res.json({ users: usersWithStatus, total, totalPages, currentPage: page });
  } catch (err) {
    console.error('❌ Get users error:', err);
    res.status(500).json({ message: 'Failed to fetch users' });
  }
});

router.get('/users/:id', adminAuth, async (req, res) => {
  try {
    if (!validation.validateObjectId(req.params.id)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    const user = await User.findById(req.params.id).select('-password').lean();
    if (!user) return res.status(404).json({ message: 'User not found' });

    user.isPro = user.subscription?.type === 'pro' && user.subscription?.expiresAt > new Date();
    user.subscriptionStatus = {
      active: user.isPro,
      daysLeft: user.subscription?.expiresAt
        ? Math.ceil((new Date(user.subscription.expiresAt) - new Date()) / (1000 * 60 * 60 * 24))
        : 0,
      plan: user.subscription?.plan || 'none',
      expiresAt: user.subscription?.expiresAt
    };
    user.remainingAttacks = user.isPro ? user.subscription?.dailyCredits : user.credits;

    res.json(user);
  } catch (err) {
    console.error('❌ Get user error:', err);
    res.status(500).json({ message: 'Failed to fetch user' });
  }
});

router.get('/users/:id/status', adminAuth, async (req, res) => {
  try {
    if (!validation.validateObjectId(req.params.id)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    const user = await User.findById(req.params.id).select('-password');
    if (!user) return res.status(404).json({ message: 'User not found' });

    const isPro = user.subscription?.type === 'pro' && user.subscription?.expiresAt > new Date();

    res.json({
      id: user._id,
      username: user.username,
      email: user.email,
      isPro,
      subscription: user.subscription,
      credits: user.credits,
      totalAttacks: user.totalAttacks || 0,
      createdAt: user.createdAt,
      subscriptionStatus: isPro ? {
        active: true,
        plan: user.subscription.plan,
        daysLeft: Math.ceil((new Date(user.subscription.expiresAt) - new Date()) / (1000 * 60 * 60 * 24)),
        expiresAt: user.subscription.expiresAt,
        dailyCredits: user.subscription.dailyCredits
      } : {
        active: false,
        plan: 'free',
        daysLeft: 0,
        expiresAt: null,
        dailyCredits: 10
      }
    });
  } catch (err) {
    console.error('❌ Get user status error:', err);
    res.status(500).json({ message: 'Failed to get user status' });
  }
});

router.patch('/users/:id', adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    const allowed = ['credits', 'username', 'email'];
    const sanitized = {};

    for (const key of allowed) {
      if (req.body[key] !== undefined) sanitized[key] = req.body[key];
    }

    if (req.body.password) {
      sanitized.password = await bcrypt.hash(req.body.password, 12);
    }

    const user = await User.findByIdAndUpdate(req.params.id, sanitized, { new: true })
      .select('-password').lean();

    if (!user) return res.status(404).json({ message: 'User not found' });

    await createAuditLog({
      actorType: 'admin',
      action: 'UPDATE_USER',
      targetId: req.params.id,
      targetType: 'user',
      changes: sanitized,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json(user);
  } catch (err) {
    console.error('❌ Update user error:', err);
    res.status(500).json({ message: 'Failed to update user' });
  }
});

router.delete('/users/:id', adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    await createAuditLog({
      actorType: 'admin',
      action: 'DELETE_USER',
      targetId: req.params.id,
      targetType: 'user',
      changes: { username: user.username },
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    console.error('❌ Delete user error:', err);
    res.status(500).json({ message: 'Failed to delete user' });
  }
});

// ── Subscription management ────────────────────────────────────────────────────

router.post('/users/:id/give-pro', adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    const { planType, customDays } = req.body;

    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    let days = 0;
    let plan = planType;

    if (planType === 'custom' && customDays) {
      days = parseInt(customDays);
      plan = 'custom';
    } else {
      const planDays = { week: 7, month: 30, season: 60 };
      days = planDays[planType];
      if (!days) {
        return res.status(400).json({
          message: 'Invalid plan type',
          validPlans: ['week', 'month', 'season', 'custom']
        });
      }
    }

    if (isNaN(days) || days < 1 || days > 365) {
      return res.status(400).json({ message: 'Days must be between 1 and 365' });
    }

    // Get old subscription info for audit
    const oldSubscription = user.subscription ? {
      type: user.subscription.type,
      plan: user.subscription.plan,
      expiresAt: user.subscription.expiresAt
    } : null;

    user.addProSubscription(plan, days);

    // Add 30 credits to the user
    user.credits = (user.credits || 0) + 30;

    await user.save();

    await createAuditLog({
      actorType: 'admin',
      action: 'GIVE_PRO_SUBSCRIPTION',
      targetId: user._id,
      targetType: 'user',
      changes: {
        plan,
        days,
        bonusCreditsGiven: 30,
        userCreditsAfter: user.credits,
        oldSubscription,
        newSubscription: user.subscription
      },
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({
      message: `✅ Pro subscription added successfully for ${days} days with 30 bonus credits!`,
      user: {
        id: user._id,
        username: user.username,
        isPro: user.isProUser(),
        expiresAt: user.subscription.expiresAt,
        daysLeft: user.getSubscriptionStatus().daysLeft,
        credits: user.credits
      }
    });
  } catch (err) {
    console.error('❌ Give pro error:', err);
    res.status(500).json({ message: 'Failed to give pro subscription' });
  }
});

router.delete('/users/:id/remove-pro', adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    user.subscription.type = 'free';
    user.subscription.plan = 'none';
    user.subscription.expiresAt = null;
    user.subscription.dailyCredits = 10;
    user.subscription.lastCreditReset = new Date();
    await user.save();

    await createAuditLog({
      actorType: 'admin',
      action: 'REMOVE_PRO_SUBSCRIPTION',
      targetId: user._id,
      targetType: 'user',
      changes: {},
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({ message: 'Pro subscription removed' });
  } catch (err) {
    console.error('❌ Remove pro error:', err);
    res.status(500).json({ message: 'Failed to remove pro subscription' });
  }
});

router.post('/users/:id/extend-pro', adminAuth, async (req, res) => {
  try {
    if (!validation.validateObjectId(req.params.id)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    // 🔐 DECRYPT THE REQUEST BODY FIRST
    let requestData = req.body;

    if (req.body.encrypted && req.body.hash) {
      try {
        const decryptedBytes = CryptoJS.AES.decrypt(req.body.encrypted, ENCRYPTION_KEY);
        const decryptedString = decryptedBytes.toString(CryptoJS.enc.Utf8);

        if (!decryptedString) {
          throw new Error('Decryption failed');
        }

        requestData = JSON.parse(decryptedString);

        const calculatedHash = createHash(requestData);
        if (calculatedHash !== req.body.hash) {
          return res.status(400).json({ message: 'Request integrity check failed' });
        }

        if (requestData.timestamp) {
          delete requestData.timestamp;
        }
      } catch (decryptError) {
        console.error('Decryption error:', decryptError);
        return res.status(400).json({ message: 'Invalid encrypted data' });
      }
    }

    const { planType, customDays } = requestData;
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    let days = 0;
    let plan = planType;

    if (planType === 'custom' && customDays) {
      days = parseInt(customDays);
      plan = 'custom';
    } else {
      // ✅ FIXED: Changed season from 90 to 60
      const planDays = { week: 7, month: 30, season: 60 };
      days = planDays[planType];
      if (!days) {
        return res.status(400).json({
          message: 'Invalid plan type',
          validPlans: ['week', 'month', 'season', 'custom'],
          received: planType
        });
      }
    }

    if (isNaN(days) || days < 1 || days > 365) {
      return res.status(400).json({ message: 'Days must be between 1 and 365', provided: days });
    }

    // Extend existing subscription
    if (user.subscription.expiresAt && user.subscription.expiresAt > new Date()) {
      user.subscription.expiresAt = new Date(user.subscription.expiresAt.getTime() + days * 24 * 60 * 60 * 1000);
    } else {
      user.subscription.expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
    }

    user.subscription.type = 'pro';
    user.subscription.plan = plan;
    await user.save();

    await createAuditLog({
      actorType: 'admin',
      action: 'EXTEND_PRO_SUBSCRIPTION',
      targetId: user._id,
      targetType: 'user',
      changes: { extendedBy: days, newExpiry: user.subscription.expiresAt, plan },
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({
      message: `Pro subscription extended by ${days} days`,
      user: {
        id: user._id,
        username: user.username,
        expiresAt: user.subscription.expiresAt,
        daysLeft: user.getSubscriptionStatus().daysLeft
      }
    });
  } catch (err) {
    console.error('❌ Extend pro error:', err);
    res.status(500).json({ message: 'Failed to extend pro subscription', error: err.message });
  }
});

router.post('/users/:id/replace-pro', adminAuth, async (req, res) => {
  try {
    if (!validation.validateObjectId(req.params.id)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    // 🔐 DECRYPT THE REQUEST BODY FIRST
    let requestData = req.body;

    // Check if the request is encrypted
    if (req.body.encrypted && req.body.hash) {
      try {
        const decryptedBytes = CryptoJS.AES.decrypt(req.body.encrypted, ENCRYPTION_KEY);
        const decryptedString = decryptedBytes.toString(CryptoJS.enc.Utf8);

        if (!decryptedString) {
          throw new Error('Decryption failed');
        }

        requestData = JSON.parse(decryptedString);

        // Verify hash
        const calculatedHash = createHash(requestData);
        if (calculatedHash !== req.body.hash) {
          return res.status(400).json({ message: 'Request integrity check failed' });
        }

        // Remove timestamp if present
        if (requestData.timestamp) {
          delete requestData.timestamp;
        }
      } catch (decryptError) {
        console.error('Decryption error:', decryptError);
        return res.status(400).json({ message: 'Invalid encrypted data' });
      }
    }

    // Now use requestData instead of req.body
    const { planType, customDays } = requestData;

    // Debug logging
    console.log('📥 Replace Pro - Received planType:', planType);
    console.log('📥 Replace Pro - Received customDays:', customDays);

    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    let days = 0;
    let plan = planType;

    if (planType === 'custom' && customDays) {
      days = parseInt(customDays);
      plan = 'custom';
    } else {
      // ✅ FIXED: Changed season from 90 to 60 to match frontend
      const planDays = { week: 7, month: 30, season: 60 };
      days = planDays[planType];
      if (!days) {
        return res.status(400).json({
          message: 'Invalid plan type',
          validPlans: ['week', 'month', 'season', 'custom'],
          received: planType
        });
      }
    }

    if (isNaN(days) || days < 1 || days > 365) {
      return res.status(400).json({ message: 'Days must be between 1 and 365', provided: days });
    }

    const oldSubscription = user.subscription ? {
      type: user.subscription.type,
      plan: user.subscription.plan,
      expiresAt: user.subscription.expiresAt,
      dailyCredits: user.subscription.dailyCredits
    } : null;
    const oldExpiry = user.subscription?.expiresAt;

    // Remove old subscription first
    user.subscription.type = 'free';
    user.subscription.plan = 'none';
    user.subscription.expiresAt = null;
    user.subscription.dailyCredits = 10;
    user.subscription.lastCreditReset = new Date();

    // Add new pro subscription
    user.addProSubscription(plan, days);
    await user.save();

    await createAuditLog({
      actorType: 'admin',
      action: 'REPLACE_PRO_SUBSCRIPTION',
      targetId: user._id,
      targetType: 'user',
      changes: {
        oldSubscription,
        newSubscription: {
          type: user.subscription.type,
          plan: user.subscription.plan,
          expiresAt: user.subscription.expiresAt,
          dailyCredits: user.subscription.dailyCredits
        },
        days,
        plan,
        oldExpiry,
        newExpiry: user.subscription.expiresAt
      },
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({
      message: `Pro subscription replaced with ${days} days plan`,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        isPro: user.isProUser(),
        subscription: {
          type: user.subscription.type,
          plan: user.subscription.plan,
          expiresAt: user.subscription.expiresAt,
          dailyCredits: user.subscription.dailyCredits
        },
        expiresAt: user.subscription.expiresAt,
        daysLeft: user.getSubscriptionStatus().daysLeft
      }
    });
  } catch (err) {
    console.error('❌ Replace pro error:', err);
    res.status(500).json({ message: 'Failed to replace pro subscription', error: err.message });
  }
});

router.post('/users/:id/add-credits', adminAuth, async (req, res) => {
  try {
    if (!validation.validateObjectId(req.params.id)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    const { amount } = req.body;
    if (!amount || amount < 1 || amount > 10000) {
      return res.status(400).json({ message: 'Amount must be between 1 and 10000' });
    }

    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const oldCredits = user.credits;
    user.credits += amount;
    await user.save();

    await createAuditLog({
      actorType: 'admin',
      action: 'ADD_CREDITS',
      targetId: user._id,
      targetType: 'user',
      changes: { old: oldCredits, new: user.credits, added: amount },
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({ message: `Added ${amount} credits to ${user.username}`, credits: user.credits });
  } catch (err) {
    console.error('❌ Add credits error:', err);
    res.status(500).json({ message: 'Failed to add credits' });
  }
});

router.post('/users/:id/remove-credits', adminAuth, async (req, res) => {
  try {
    if (!validation.validateObjectId(req.params.id)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    const { amount } = req.body;
    if (!amount || amount < 1 || amount > 10000) {
      return res.status(400).json({ message: 'Amount must be between 1 and 10000' });
    }

    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const oldCredits = user.credits;
    user.credits = Math.max(0, user.credits - amount);
    await user.save();

    await createAuditLog({
      actorType: 'admin',
      action: 'REMOVE_CREDITS',
      targetId: user._id,
      targetType: 'user',
      changes: { old: oldCredits, new: user.credits, removed: amount },
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({ message: `Removed ${amount} credits from ${user.username}`, credits: user.credits });
  } catch (err) {
    console.error('❌ Remove credits error:', err);
    res.status(500).json({ message: 'Failed to remove credits' });
  }
});

router.post('/users/:id/reset-daily', adminAuth, async (req, res) => {
  try {
    if (!validation.validateObjectId(req.params.id)) {
      return res.status(400).json({ message: 'Invalid user ID format' });
    }

    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    user.subscription.dailyCredits = user.isProUser() ? 30 : 10;
    user.subscription.lastCreditReset = new Date();
    user.dailyAttacks.count = 0;
    user.dailyAttacks.date = new Date();
    await user.save();

    await createAuditLog({
      actorType: 'admin',
      action: 'RESET_DAILY_LIMIT',
      targetId: user._id,
      targetType: 'user',
      changes: { dailyCredits: user.subscription.dailyCredits },
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({ message: `Daily limit reset for ${user.username}`, dailyCredits: user.subscription.dailyCredits });
  } catch (err) {
    console.error('❌ Reset daily error:', err);
    res.status(500).json({ message: 'Failed to reset daily limit' });
  }
});

// ===== GET /api/admin/plans =====
router.get('/plans', adminAuth, async (req, res) => {
  res.json({
    plans: [
      { id: 'week', name: 'Weekly Plan', displayName: '7 Days Pro', days: 7, price: 850, priceINR: '₹850', dailyAttacks: 30, maxDuration: 300, description: 'Perfect for testing', features: ['30 attacks per day', '300s max duration', 'Priority support'] },
      { id: 'month', name: 'Monthly Plan', displayName: '30 Days Pro', days: 30, price: 1800, priceINR: '₹1800', dailyAttacks: 30, maxDuration: 300, description: 'Most popular', features: ['30 attacks per day', '300s max duration', 'Priority support', 'Best value'] },
      { id: 'season', name: 'Season Plan', displayName: '60 Days Pro', days: 60, price: 2500, priceINR: '₹2500', dailyAttacks: 30, maxDuration: 300, description: 'Best value', features: ['30 attacks per day', '300s max duration', 'Priority support', 'Save 35%'] }
    ]
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
//  RESELLER ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

router.get('/resellers', adminAuth, async (req, res) => {
  try {
    let page = parseInt(req.query.page) || 1;
    let limit = parseInt(req.query.limit) || 50;
    const search = req.query.search ? String(req.query.search).trim() : '';

    if (page < 1) page = 1;
    if (limit < 1 || limit > 100) limit = 50;

    const query = {};
    if (search.length > 0) {
      query.$or = [
        { username: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }

    const total = await Reseller.countDocuments(query);
    const totalPages = Math.ceil(total / limit);
    if (page > totalPages && totalPages > 0) page = totalPages;

    const resellers = await Reseller.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean();

    res.json({ resellers, total, totalPages, currentPage: page });
  } catch (err) {
    console.error('❌ Get resellers error:', err);
    res.status(500).json({ message: 'Failed to fetch resellers' });
  }
});

router.post('/resellers', adminAuth, async (req, res) => {
  try {
    const { username, email, password, credits = 0 } = req.body;

    if (!username || username.length < 3) {
      return res.status(400).json({ message: 'Username must be at least 3 characters' });
    }
    if (!email || !email.includes('@')) {
      return res.status(400).json({ message: 'Invalid email format' });
    }
    if (!password || password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }

    const hashed = await bcrypt.hash(password, 12);
    const reseller = await Reseller.create({ username, email: email.toLowerCase(), password: hashed, credits });

    await createAuditLog({
      actorType: 'admin',
      action: 'CREATE_RESELLER',
      targetId: reseller._id,
      targetType: 'reseller',
      changes: { username, email, credits },
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.status(201).json({
      id: reseller._id,
      username: reseller.username,
      email: reseller.email,
      credits: reseller.credits,
      isBlocked: reseller.isBlocked
    });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({ message: 'Username or email already exists' });
    }
    console.error('❌ Create reseller error:', err);
    res.status(500).json({ message: 'Failed to create reseller' });
  }
});

router.patch('/resellers/:id', adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: 'Invalid reseller ID format' });
    }

    const { credits, isBlocked, username, email, password } = req.body;
    const updateData = {};

    if (credits !== undefined) updateData.credits = credits;
    if (isBlocked !== undefined) updateData.isBlocked = isBlocked;
    if (username) updateData.username = username;
    if (email) updateData.email = email;
    if (password) updateData.password = await bcrypt.hash(password, 12);

    const reseller = await Reseller.findByIdAndUpdate(req.params.id, updateData, { new: true })
      .select('-password').lean();

    if (!reseller) return res.status(404).json({ message: 'Reseller not found' });

    await createAuditLog({
      actorType: 'admin',
      action: 'UPDATE_RESELLER',
      targetId: req.params.id,
      targetType: 'reseller',
      changes: updateData,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json(reseller);
  } catch (err) {
    console.error('❌ Update reseller error:', err);
    res.status(500).json({ message: 'Failed to update reseller' });
  }
});

router.delete('/resellers/:id', adminAuth, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      return res.status(400).json({ message: 'Invalid reseller ID format' });
    }

    const reseller = await Reseller.findByIdAndDelete(req.params.id);
    if (!reseller) return res.status(404).json({ message: 'Reseller not found' });

    await createAuditLog({
      actorType: 'admin',
      action: 'DELETE_RESELLER',
      targetId: req.params.id,
      targetType: 'reseller',
      changes: { username: reseller.username },
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      success: true
    });

    res.json({ message: 'Reseller deleted successfully' });
  } catch (err) {
    console.error('❌ Delete reseller error:', err);
    res.status(500).json({ message: 'Failed to delete reseller' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  RESELLER STATS  ✅ FIXED: ObjectId casting for all MongoDB queries
// ═══════════════════════════════════════════════════════════════════════════════

router.get('/resellers/:id/stats', adminAuth, async (req, res) => {
  try {
    if (!validation.validateObjectId(req.params.id)) {
      return res.status(400).json({ message: 'Invalid reseller ID format' });
    }

    // ✅ FIX 1: Cast the string param to ObjectId once, reuse everywhere
    const resellerId = new mongoose.Types.ObjectId(req.params.id);

    const reseller = await Reseller.findById(resellerId).select('-password').lean();
    if (!reseller) return res.status(404).json({ message: 'Reseller not found' });

    // ✅ FIX 1 applied: actorId is now an ObjectId — matches what was stored by reseller.js
    const giveEvents = await AuditLog.find({
      actorId: resellerId,   // <-- was req.params.id (string). Now ObjectId. This was the main bug.
      actorType: 'reseller',
      action: 'RESELLER_GIVE_PRO',
      success: true
    }).sort({ createdAt: -1 }).lean();

    // ── Aggregate totals ───────────────────────────────────────────────────
    let totalRevenue = 0;
    let totalProfit = 0;
    let totalCreditsSpent = 0;

    const planBreakdown = {
      week: { sales: 0, revenue: 0, profit: 0, cost: 0 },
      month: { sales: 0, revenue: 0, profit: 0, cost: 0 },
      season: { sales: 0, revenue: 0, profit: 0, cost: 0 }
    };
    const uniqueCustomers = new Set();
    const dailySalesMap = new Map();
    const monthlySalesMap = new Map();

    giveEvents.forEach(event => {
      const c = event.changes || {};
      const plan = (c.plan || '').toLowerCase();
      const creditsUsed = c.creditsUsed || 0;
      const customerPrice = c.customerPrice || 0;
      const profit = c.profit || 0;

      totalRevenue += customerPrice;
      totalProfit += profit;
      totalCreditsSpent += creditsUsed;

      if (planBreakdown[plan]) {
        planBreakdown[plan].sales++;
        planBreakdown[plan].revenue += customerPrice;
        planBreakdown[plan].profit += profit;
        planBreakdown[plan].cost += creditsUsed;
      }

      if (event.targetId) uniqueCustomers.add(event.targetId.toString());

      const date = new Date(event.createdAt).toISOString().split('T')[0];
      const month = date.slice(0, 7);
      dailySalesMap.set(date, (dailySalesMap.get(date) || 0) + customerPrice);
      monthlySalesMap.set(month, (monthlySalesMap.get(month) || 0) + customerPrice);
    });

    // ── Top customers — ✅ FIX 2: cast string ids back to ObjectId for the query
    const customerObjectIds = Array.from(uniqueCustomers).map(
      id => new mongoose.Types.ObjectId(id)  // <-- was plain strings, never matched _id
    );
    const customerUsers = await User.find({ _id: { $in: customerObjectIds } })
      .select('username email userId').lean();
    const userMap = Object.fromEntries(customerUsers.map(u => [u._id.toString(), u]));

    const topCustomers = Array.from(uniqueCustomers).map(customerId => {
      const user = userMap[customerId];
      if (!user) return null;

      const customerEvents = giveEvents.filter(e => e.targetId?.toString() === customerId);
      return {
        id: user._id,
        username: user.username,
        email: user.email,
        userId: user.userId,
        totalPurchases: customerEvents.length,
        totalSpent: customerEvents.reduce((s, e) => s + (e.changes?.customerPrice || 0), 0),
        totalProfit: customerEvents.reduce((s, e) => s + (e.changes?.profit || 0), 0),
        lastPurchase: customerEvents[0]?.createdAt || null
      };
    }).filter(Boolean).sort((a, b) => b.totalSpent - a.totalSpent);

    // ── Recent activity — ✅ FIX 3: same cast for recent activity user lookup
    const recentSlice = giveEvents.slice(0, 20);
    const recentTargetIds = [...new Set(
      recentSlice.map(e => e.targetId?.toString()).filter(Boolean)
    )].map(id => new mongoose.Types.ObjectId(id));  // <-- was plain strings

    const recentUsers = await User.find({ _id: { $in: recentTargetIds } })
      .select('username email').lean();
    const recentUserMap = Object.fromEntries(recentUsers.map(u => [u._id.toString(), u]));

    const recentActivity = recentSlice.map(event => ({
      id: event._id,
      plan: event.changes?.plan,
      days: event.changes?.days,
      creditsUsed: event.changes?.creditsUsed,
      customerPrice: event.changes?.customerPrice,
      profit: event.changes?.profit,
      user: event.targetId ? (recentUserMap[event.targetId.toString()] || null) : null,
      timestamp: event.createdAt
    }));

    // ── Charts ─────────────────────────────────────────────────────────────
    const dailySalesArray = Array.from(dailySalesMap.entries())
      .map(([date, amount]) => ({ date, amount }))
      .sort((a, b) => a.date.localeCompare(b.date))
      .slice(-30);

    const monthlySalesArray = Array.from(monthlySalesMap.entries())
      .map(([month, amount]) => ({ month, amount }))
      .sort((a, b) => a.month.localeCompare(b.month));

    // ── ROI & averages ─────────────────────────────────────────────────────
    const totalInvestment = reseller.totalGiven || totalCreditsSpent;
    const roi = totalInvestment > 0
      ? Number(((totalProfit / totalInvestment) * 100).toFixed(1)) : 0;
    const avgProfitPerSale = giveEvents.length > 0
      ? Number((totalProfit / giveEvents.length).toFixed(2)) : 0;
    const accountAgeDays = Math.floor(
      (Date.now() - new Date(reseller.createdAt)) / (1000 * 60 * 60 * 24)
    );

    res.json({
      reseller: {
        id: reseller._id,
        username: reseller.username,
        email: reseller.email,
        credits: reseller.credits,
        totalGiven: reseller.totalGiven,
        isBlocked: reseller.isBlocked,
        createdAt: reseller.createdAt,
        lastLogin: reseller.lastLogin
      },
      statistics: {
        totalSales: giveEvents.length,
        totalCustomers: uniqueCustomers.size,
        totalRevenue,
        totalProfit,
        totalCreditsSpent,
        averageProfitPerSale: avgProfitPerSale,
        roi,
        accountAge: accountAgeDays
      },
      planBreakdown,
      charts: {
        dailySales: dailySalesArray,
        monthlySales: monthlySalesArray
      },
      topCustomers,
      recentActivity
    });
  } catch (err) {
    console.error('❌ Get reseller stats error:', err);
    res.status(500).json({ message: 'Failed to fetch reseller statistics' });
  }
});

// ── All-resellers aggregated stats ────────────────────────────────────────────

router.get('/resellers/all-stats', adminAuth, async (req, res) => {
  try {
    const resellers = await Reseller.find().select('-password').lean();

    const totalResellers = resellers.length;
    const activeResellers = resellers.filter(r => !r.isBlocked).length;
    const totalCreditsAcrossResellers = resellers.reduce((s, r) => s + (r.credits || 0), 0);
    const totalGivenAcrossResellers = resellers.reduce((s, r) => s + (r.totalGiven || 0), 0);

    const allGiveEvents = await AuditLog.find({
      actorType: 'reseller',
      action: 'RESELLER_GIVE_PRO',
      success: true
    }).lean();

    let totalSales = allGiveEvents.length;
    let totalRevenue = 0;
    let totalProfit = 0;
    allGiveEvents.forEach(event => {
      if (event.changes) {
        totalRevenue += event.changes.customerPrice || 0;
        totalProfit += event.changes.profit || 0;
      }
    });

    const resellerSalesCount = new Map();
    allGiveEvents.forEach(event => {
      const id = event.actorId?.toString();
      if (id) resellerSalesCount.set(id, (resellerSalesCount.get(id) || 0) + 1);
    });

    let topResellerId = null;
    let topResellerSales = 0;
    for (const [id, sales] of resellerSalesCount.entries()) {
      if (sales > topResellerSales) { topResellerSales = sales; topResellerId = id; }
    }

    let topReseller = null;
    if (topResellerId) {
      topReseller = await Reseller.findById(topResellerId).select('username email').lean();
    }

    res.json({
      summary: {
        totalResellers,
        activeResellers,
        blockedResellers: totalResellers - activeResellers,
        totalCreditsInSystem: totalCreditsAcrossResellers,
        totalCreditsGiven: totalGivenAcrossResellers,
        totalSales,
        totalRevenue,
        totalProfit,
        averageProfitPerReseller: totalResellers > 0 ? totalProfit / totalResellers : 0,
        averageSalesPerReseller: totalResellers > 0 ? totalSales / totalResellers : 0
      },
      topReseller: topReseller ? {
        username: topReseller.username,
        email: topReseller.email,
        totalSales: topResellerSales
      } : null,
      resellers: resellers.map(r => ({
        id: r._id, username: r.username, email: r.email,
        credits: r.credits, totalGiven: r.totalGiven,
        isBlocked: r.isBlocked, createdAt: r.createdAt, lastLogin: r.lastLogin
      }))
    });
  } catch (err) {
    console.error('❌ Get all resellers stats error:', err);
    res.status(500).json({ message: 'Failed to fetch reseller statistics' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
//  AUDIT LOG ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

router.get('/audit-logs', adminAuth, async (req, res) => {
  try {
    let page = parseInt(req.query.page) || 1;
    let limit = parseInt(req.query.limit) || 50;
    if (page < 1) page = 1;
    if (limit < 1 || limit > 100) limit = 50;

    const total = await AuditLog.countDocuments();
    const totalPages = Math.ceil(total / limit);
    if (page > totalPages && totalPages > 0) page = totalPages;

    const logs = await AuditLog.find()
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean();

    res.json({ logs, total, totalPages, currentPage: page });
  } catch (err) {
    console.error('❌ Audit logs error:', err);
    res.status(500).json({ message: 'Failed to fetch audit logs' });
  }
});

module.exports = router;
module.exports.adminAuth = adminAuth;