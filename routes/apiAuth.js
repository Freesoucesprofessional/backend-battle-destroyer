// routes/apiAuth.js - with encryption, CAPTCHA, and CSRF protection
const express = require('express');
const router  = express.Router();
const jwt     = require('jsonwebtoken');
const crypto  = require('crypto');
const CryptoJS = require('crypto-js');
const ApiUser = require('../models/ApiUser');
const { verifyCaptcha } = require('./captcha');

const JWT_SECRET = process.env.API_USER_JWT_SECRET;
if (!JWT_SECRET) throw new Error('API_USER_JWT_SECRET is not set in environment');

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
  const errorResponse = { success: false, error: message };
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

// ── Login with encryption and CAPTCHA ─────────────────────────────────────────

router.post('/login', async (req, res) => {
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

        const { username, apiSecret, captchaData, hp } = decryptedData;

        // Honeypot check
        if (hp) {
            return sendEncryptedError(res, 400, 'Invalid request');
        }

        if (!username || !apiSecret) {
            return sendEncryptedError(res, 400, 'Username and API Secret required');
        }

        if (!captchaData) {
            return sendEncryptedError(res, 400, 'Captcha verification required');
        }

        const ip = getIp(req);
        const captchaToken = captchaData.token || captchaData;
        const captcha = await verifyCaptcha(captchaToken, null, ip);

        if (!captcha.ok) {
            console.log(`[API Auth] Captcha failed for ${username}: ${captcha.reason}`);
            return sendEncryptedError(res, 400, captcha.reason || 'Captcha verification failed');
        }

        console.log(`[API Auth] Captcha passed for ${username}`);

        const apiUser = await ApiUser.findOne({ username });

        // Return the same error for "user not found" and "wrong secret"
        // to prevent username enumeration.
        if (!apiUser) {
            // Still run a dummy comparison to prevent timing side-channels
            crypto.timingSafeEqual(Buffer.alloc(32), Buffer.alloc(32));
            return sendEncryptedError(res, 401, 'Invalid credentials');
        }

        // Check expiration before anything else
        if (apiUser.isExpired()) {
            return sendEncryptedError(res, 403, 'Account has expired');
        }

        if (apiUser.status !== 'active') {
            return sendEncryptedError(res, 403, apiUser.status === 'suspended' ? 'Account is suspended' : 'Account is not active');
        }

        // Timing-safe secret comparison
        const providedHash = crypto.createHash('sha256').update(apiSecret).digest('hex');
        let secretMatch = false;
        try {
            secretMatch = crypto.timingSafeEqual(
                Buffer.from(providedHash, 'hex'),
                Buffer.from(apiUser.apiSecretHash, 'hex')
            );
        } catch {
            // Buffer length mismatch → wrong
        }

        if (!secretMatch) {
            return sendEncryptedError(res, 401, 'Invalid credentials');
        }

        // Update last login
        apiUser.lastLoginAt = new Date();
        await apiUser.save();

        // Issue JWT (short-lived — dashboard access only, NOT for API request signing)
        const token = jwt.sign(
            { id: apiUser._id, username: apiUser.username },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        const responseData = {
            success: true,
            token,
            user: {
                id:            apiUser._id,
                username:      apiUser.username,
                email:         apiUser.email,
                status:        apiUser.status,
                limits:        apiUser.limits,
                totalAttacks:  apiUser.totalAttacks,
                expiresAt:     apiUser.expiresAt,
                daysRemaining: apiUser.getDaysRemaining(),
                createdAt:     apiUser.createdAt
            },
            timestamp: Date.now()
        };

        const encryptedResponse = encryptResponse(responseData);
        const responseHash = createHash(responseData);

        res.json({
            encrypted: encryptedResponse,
            hash: responseHash,
        });

    } catch (error) {
        console.error('[apiAuth] Login error:', error);
        sendEncryptedError(res, 500, 'Login failed');
    }
});

// ── Dashboard stats with encryption ───────────────────────────────────────────

router.get('/dashboard/stats', verifyApiUserToken, async (req, res) => {
    try {
        const apiUser = await ApiUser.findById(req.apiUserId);

        if (!apiUser) {
            return sendEncryptedError(res, 404, 'User not found');
        }

        const isExpired      = apiUser.isExpired();
        const daysRemaining  = apiUser.getDaysRemaining();
        const now            = new Date();

        // Clean expired attacks
        const beforeCount = apiUser.activeAttacks.length;
        apiUser.activeAttacks = apiUser.activeAttacks.filter(a => a.expiresAt > now);
        if (beforeCount !== apiUser.activeAttacks.length) await apiUser.save();

        const activeCount = apiUser.activeAttacks.length;

        const responseData = {
            success: true,
            user: {
                id:            apiUser._id,
                username:      apiUser.username,
                email:         apiUser.email,
                status:        isExpired ? 'expired' : apiUser.status,
                limits: {
                    maxConcurrent: apiUser.limits.maxConcurrent,
                    maxDuration:   apiUser.limits.maxDuration
                },
                createdAt:     apiUser.createdAt,
                expiresAt:     apiUser.expiresAt,
                daysRemaining,
                isExpired
            },
            stats: {
                totalAttacks:        apiUser.totalAttacks  || 0,
                totalRequests:       apiUser.totalRequests || 0,
                currentActiveAttacks: activeCount,
                remainingSlots:      Math.max(0, apiUser.limits.maxConcurrent - activeCount)
            },
            activeAttacks: apiUser.activeAttacks.map(a => ({
                attackId:  a.attackId,
                target:    a.target,
                port:      a.port,
                expiresIn: Math.max(0, Math.floor((a.expiresAt - now) / 1000))
            })),
            apiKey: apiUser.apiKey, // public key — safe to return
            timestamp: Date.now()
        };

        const encryptedResponse = encryptResponse(responseData);
        const responseHash = createHash(responseData);

        res.json({
            encrypted: encryptedResponse,
            hash: responseHash,
        });

    } catch (error) {
        console.error('[apiAuth] Dashboard error:', error);
        sendEncryptedError(res, 500, 'Failed to fetch dashboard data');
    }
});

// ── JWT middleware with encrypted errors ─────────────────────────────────────

function verifyApiUserToken(req, res, next) {
    const authHeader = req.headers.authorization;
    const token      = authHeader && authHeader.startsWith('Bearer ')
        ? authHeader.slice(7)
        : null;

    if (!token) {
        return sendEncryptedError(res, 401, 'Access token required');
    }

    try {
        const decoded   = jwt.verify(token, JWT_SECRET);
        req.apiUserId   = decoded.id;
        req.apiUsername = decoded.username;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return sendEncryptedError(res, 401, 'Token expired');
        }
        return sendEncryptedError(res, 401, 'Invalid token');
    }
}

module.exports = router;
module.exports.verifyApiUserToken = verifyApiUserToken;