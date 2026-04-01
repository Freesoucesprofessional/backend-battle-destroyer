const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const User = require('../models/User');
const Reseller = require('../models/Reseller');
const AuditLog = require('../models/AuditLog');
const validation = require('../utils/validation');
const { createAuditLog } = require('../utils/audit');

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

// ===== POST /api/admin/session — exchange secret for session token =====
router.post('/session', async (req, res) => {
    if (!redisClient.isReady) {
        console.error('❌ Redis not connected');
        return res.status(503).json({ message: 'Service temporarily unavailable. Please try again.' });
    }
    const ip = req.ip;
    const now = Date.now();
    const record = failedAttempts.get(ip) || { count: 0, lockedUntil: 0 };

    // Check if IP is locked
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

        return res.status(429).json({
            message: `Too many failed attempts. Try again in ${seconds}s.`
        });
    }

    const { secret } = req.body;

    // Validate secret
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
                error: `Max attempts exceeded, IP locked for 15 minutes`
            });

            return res.status(429).json({
                message: 'Too many failed attempts. IP locked for 15 minutes.'
            });
        }

        return res.status(401).json({
            message: `Invalid secret. ${MAX_ATTEMPTS - record.count} attempts remaining.`
        });
    }

    // Clear failed attempts for this IP
    failedAttempts.delete(ip);

    // Generate session token
    const token = crypto.randomBytes(48).toString('hex');
    const sessionData = {
        token,
        createdAt: now,
        ip,
        userAgent: req.headers['user-agent'] || 'unknown',
        expiresAt: new Date(now + SESSION_TTL * 1000).toISOString()
    };

    // Store session in Redis
    try {
        await redisClient.setEx(
            SESSION_PREFIX + token,
            SESSION_TTL,
            JSON.stringify(sessionData)
        );

        await createAuditLog({
            actorType: 'admin',
            action: 'SESSION_CREATED',
            ip,
            userAgent: req.headers['user-agent'],
            success: true
        });

        res.json({
            token,
            expiresIn: SESSION_TTL * 1000
        });
    } catch (err) {
        console.error('❌ Redis error:', err);
        return res.status(500).json({ message: 'Session storage failed' });
    }
});

// ===== DELETE /api/admin/session — explicit logout =====
router.delete('/session', async (req, res) => {
    const token = req.headers['x-admin-token'];
    const ip = req.ip;

    if (!token) {
        return res.status(400).json({ message: 'No token provided' });
    }

    try {
        await redisClient.del(SESSION_PREFIX + token);

        await createAuditLog({
            actorType: 'admin',
            action: 'LOGOUT',
            ip,
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

    if (!token) {
        return res.status(401).json({ message: 'SESSION_INVALIDATED' });
    }

    try {
        const sessionData = await redisClient.get(SESSION_PREFIX + token);

        if (!sessionData) {
            return res.status(401).json({ message: 'SESSION_INVALIDATED' });
        }

        res.json({ ok: true });
    } catch (err) {
        console.error('❌ Redis error:', err);
        res.status(500).json({ message: 'Session check failed' });
    }
});

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

// ═══════════════════════════════════════════════
//  STATS ROUTE
// ═══════════════════════════════════════════════

router.get('/stats', adminAuth, async (req, res) => {
    try {
        const [total, pro, withCredits, today, totalResellers, activeResellers] = await Promise.all([
            User.countDocuments(),
            User.countDocuments({ isPro: true }),
            User.countDocuments({ credits: { $gt: 0 } }),
            User.countDocuments({ createdAt: { $gte: new Date(Date.now() - 86400000) } }),
            Reseller.countDocuments(),
            Reseller.countDocuments({ isBlocked: false }),
        ]);

        res.json({
            total,
            pro,
            withCredits,
            today,
            totalResellers,
            activeResellers
        });
    } catch (err) {
        console.error('❌ Stats error:', err);
        res.status(500).json({ message: 'Failed to fetch stats' });
    }
});

// ═══════════════════════════════════════════════
//  USER ROUTES - FIXED WITH FILTERS & PAGINATION
// ═══════════════════════════════════════════════

/**
 * GET /api/admin/users
 * Query Parameters:
 * - page (number): Page number, default 1
 * - limit (number): Items per page, default 50 (max 100)
 * - search (string): Search in username, email, userId
 * - isPro (string): Filter by "true" or "false"
 * 
 * Response:
 * {
 *   "users": [...],
 *   "total": 250,
 *   "totalPages": 5,
 *   "currentPage": 1
 * }
 */
router.get('/users', adminAuth, async (req, res) => {
    try {
        // Parse and validate query parameters
        let page = parseInt(req.query.page) || 1;
        let limit = parseInt(req.query.limit) || 50;
        const search = req.query.search ? String(req.query.search).trim() : '';
        const isPro = req.query.isPro; // Can be "true", "false", or undefined

        // Validate pagination
        if (page < 1) page = 1;
        if (limit < 1 || limit > 100) limit = 50;

        // Build filter query
        const query = {};

        // Add search filter
        if (search && search.length > 0) {
            query.$or = [
                { username: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { userId: { $regex: search, $options: 'i' } },
            ];
        }

        // Add isPro filter
        if (isPro !== undefined) {
            query.isPro = isPro === 'true'; // Convert string to boolean
        }

        // Count total matching documents
        const total = await User.countDocuments(query);
        const totalPages = Math.ceil(total / limit);

        // Ensure page is within valid range
        if (page > totalPages && totalPages > 0) {
            page = totalPages;
        }

        // Fetch users with pagination
        const users = await User.find(query)
            .select('-password') // Exclude password field
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(limit)
            .lean(); // Return plain objects (faster)

        res.json({
            users,
            total,
            totalPages,
            currentPage: page
        });
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

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.json(user);
    } catch (err) {
        console.error('❌ Get user error:', err);
        res.status(500).json({ message: 'Failed to fetch user' });
    }
});

router.patch('/users/:id', adminAuth, async (req, res) => {
    try {
        if (!validation.validateObjectId(req.params.id)) {
            return res.status(400).json({ message: 'Invalid user ID format' });
        }

        const allowed = ['credits', 'isPro', 'username', 'email', 'referralCount', 'creditGiven'];
        const sanitized = validation.validateUserInput(req.body, allowed);

        // Validate specific fields
        if (sanitized.username && !validation.validateUsername(sanitized.username)) {
            return res.status(400).json({ message: 'Invalid username format' });
        }

        if (sanitized.email && !validation.validateEmail(sanitized.email)) {
            return res.status(400).json({ message: 'Invalid email format' });
        }

        if (sanitized.credits !== undefined && !validation.validateCredits(sanitized.credits)) {
            return res.status(400).json({ message: 'Invalid credit amount' });
        }

        // Handle password change (requires strong password)
        if (req.body.password) {
            const feedback = validation.getPasswordFeedback(req.body.password);
            if (feedback.length > 0) {
                return res.status(400).json({
                    message: 'Password requirements not met',
                    requirements: feedback
                });
            }
            sanitized.password = await bcrypt.hash(req.body.password, 12);
        }

        // Get old values for audit
        const oldUser = await User.findById(req.params.id);
        const changes = {};
        for (const key in sanitized) {
            if (oldUser[key] !== sanitized[key]) {
                changes[key] = { old: oldUser[key], new: sanitized[key] };
            }
        }

        const user = await User.findByIdAndUpdate(req.params.id, sanitized, { new: true })
            .select('-password')
            .lean();

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Log the action
        await createAuditLog({
            actorType: 'admin',
            action: 'UPDATE_USER',
            targetId: req.params.id,
            targetType: 'user',
            changes,
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            success: true
        });

        res.json(user);
    } catch (err) {
        if (err.code === 11000) {
            const field = Object.keys(err.keyPattern || {})[0] || 'field';
            return res.status(400).json({ message: `${field} already in use` });
        }

        console.error('❌ Update user error:', err);
        res.status(500).json({ message: 'Failed to update user' });
    }
});

router.delete('/users/:id', adminAuth, async (req, res) => {
    try {
        if (!validation.validateObjectId(req.params.id)) {
            return res.status(400).json({ message: 'Invalid user ID format' });
        }

        const user = await User.findByIdAndDelete(req.params.id);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Log the action
        await createAuditLog({
            actorType: 'admin',
            action: 'DELETE_USER',
            targetId: req.params.id,
            targetType: 'user',
            changes: { username: user.username, email: user.email },
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

// ═══════════════════════════════════════════════
//  RESELLER ROUTES - FIXED WITH FILTERS & PAGINATION
// ═══════════════════════════════════════════════

/**
 * GET /api/admin/resellers
 * Query Parameters:
 * - page (number): Page number, default 1
 * - limit (number): Items per page, default 50 (max 100)
 * - search (string): Search in username, email
 * - isBlocked (string): Filter by "true" (blocked) or "false" (active)
 * 
 * Response:
 * {
 *   "resellers": [...],
 *   "total": 150,
 *   "totalPages": 3,
 *   "currentPage": 1
 * }
 */
router.get('/resellers', adminAuth, async (req, res) => {
    try {
        // Parse and validate query parameters
        let page = parseInt(req.query.page) || 1;
        let limit = parseInt(req.query.limit) || 50;
        const search = req.query.search ? String(req.query.search).trim() : '';
        const isBlocked = req.query.isBlocked; // Can be "true", "false", or undefined

        // Validate pagination
        if (page < 1) page = 1;
        if (limit < 1 || limit > 100) limit = 50;

        // Build filter query
        const query = {};

        // Add search filter
        if (search && search.length > 0) {
            query.$or = [
                { username: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
            ];
        }

        // Add isBlocked filter
        if (isBlocked !== undefined) {
            query.isBlocked = isBlocked === 'true'; // Convert string to boolean
        }

        // Count total matching documents
        const total = await Reseller.countDocuments(query);
        const totalPages = Math.ceil(total / limit);

        // Ensure page is within valid range
        if (page > totalPages && totalPages > 0) {
            page = totalPages;
        }

        // Fetch resellers with pagination
        const resellers = await Reseller.find(query)
            .select('-password') // Exclude password field
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(limit)
            .lean(); // Return plain objects (faster)

        res.json({
            resellers,
            total,
            totalPages,
            currentPage: page
        });
    } catch (err) {
        console.error('❌ Get resellers error:', err);
        res.status(500).json({ message: 'Failed to fetch resellers' });
    }
});

router.post('/resellers', adminAuth, async (req, res) => {
    try {
        const { username, email, password, credits = 0 } = req.body;

        // Validate inputs
        if (!username || !validation.validateUsername(username)) {
            return res.status(400).json({ message: 'Invalid username format' });
        }

        if (!email || !validation.validateEmail(email)) {
            return res.status(400).json({ message: 'Invalid email format' });
        }

        const passwordFeedback = validation.getPasswordFeedback(password);
        if (passwordFeedback.length > 0) {
            return res.status(400).json({
                message: 'Password requirements not met',
                requirements: passwordFeedback
            });
        }

        if (!validation.validateCredits(credits, 1000000)) {
            return res.status(400).json({ message: 'Invalid credit amount' });
        }

        const hashed = await bcrypt.hash(password, 12);
        const reseller = await Reseller.create({
            username,
            email: email.toLowerCase(),
            password: hashed,
            credits
        });

        // Log the action
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
            isBlocked: reseller.isBlocked,
        });
    } catch (err) {
        if (err.code === 11000) {
            const field = Object.keys(err.keyPattern || {})[0] || 'field';
            return res.status(400).json({ message: `${field} already in use` });
        }

        console.error('❌ Create reseller error:', err);
        res.status(500).json({ message: 'Failed to create reseller' });
    }
});

router.patch('/resellers/:id', adminAuth, async (req, res) => {
    try {
        if (!validation.validateObjectId(req.params.id)) {
            return res.status(400).json({ message: 'Invalid reseller ID format' });
        }

        const allowed = ['credits', 'isBlocked', 'username', 'email'];
        const sanitized = validation.validateUserInput(req.body, allowed);

        if (sanitized.username && !validation.validateUsername(sanitized.username)) {
            return res.status(400).json({ message: 'Invalid username format' });
        }

        if (sanitized.email && !validation.validateEmail(sanitized.email)) {
            return res.status(400).json({ message: 'Invalid email format' });
        }

        if (sanitized.credits !== undefined && !validation.validateCredits(sanitized.credits, 1000000)) {
            return res.status(400).json({ message: 'Invalid credit amount' });
        }

        if (req.body.password) {
            const feedback = validation.getPasswordFeedback(req.body.password);
            if (feedback.length > 0) {
                return res.status(400).json({
                    message: 'Password requirements not met',
                    requirements: feedback
                });
            }
            sanitized.password = await bcrypt.hash(req.body.password, 12);
        }

        // Get old values for audit
        const oldReseller = await Reseller.findById(req.params.id);
        const changes = {};
        for (const key in sanitized) {
            if (oldReseller[key] !== sanitized[key]) {
                changes[key] = { old: oldReseller[key], new: sanitized[key] };
            }
        }

        const reseller = await Reseller.findByIdAndUpdate(req.params.id, sanitized, { new: true })
            .select('-password')
            .lean();

        if (!reseller) {
            return res.status(404).json({ message: 'Reseller not found' });
        }

        // Log the action
        await createAuditLog({
            actorType: 'admin',
            action: 'UPDATE_RESELLER',
            targetId: req.params.id,
            targetType: 'reseller',
            changes,
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            success: true
        });

        res.json(reseller);
    } catch (err) {
        if (err.code === 11000) {
            const field = Object.keys(err.keyPattern || {})[0] || 'field';
            return res.status(400).json({ message: `${field} already in use` });
        }

        console.error('❌ Update reseller error:', err);
        res.status(500).json({ message: 'Failed to update reseller' });
    }
});

router.delete('/resellers/:id', adminAuth, async (req, res) => {
    try {
        if (!validation.validateObjectId(req.params.id)) {
            return res.status(400).json({ message: 'Invalid reseller ID format' });
        }

        const reseller = await Reseller.findByIdAndDelete(req.params.id);

        if (!reseller) {
            return res.status(404).json({ message: 'Reseller not found' });
        }

        // Log the action
        await createAuditLog({
            actorType: 'admin',
            action: 'DELETE_RESELLER',
            targetId: req.params.id,
            targetType: 'reseller',
            changes: { username: reseller.username, email: reseller.email },
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

// ===== AUDIT LOG ROUTES (Admin only) =====

router.get('/audit-logs', adminAuth, async (req, res) => {
    try {
        // Parse and validate query parameters
        let page = parseInt(req.query.page) || 1;
        let limit = parseInt(req.query.limit) || 50;

        // Validate pagination
        if (page < 1) page = 1;
        if (limit < 1 || limit > 100) limit = 50;

        // Count total documents
        const total = await AuditLog.countDocuments();
        const totalPages = Math.ceil(total / limit);

        // Ensure page is within valid range
        if (page > totalPages && totalPages > 0) {
            page = totalPages;
        }

        const logs = await AuditLog.find()
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
            .limit(limit)
            .lean();

        res.json({
            logs,
            total,
            totalPages,
            currentPage: page
        });
    } catch (err) {
        console.error('❌ Audit logs error:', err);
        res.status(500).json({ message: 'Failed to fetch audit logs' });
    }
});

module.exports = router;
module.exports.adminAuth = adminAuth;