const express = require('express');
const router = express.Router();
const auth = require('../middleware/authMiddleware');
const User = require('../models/User');
const axios = require('axios');
const usedCaptchaTokens = new Map();

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

// ─── POST /api/panel/attack ───────────────────────────────────────────────────
//
//  Rules:
//    • Must be authenticated
//    • Must have at least 1 credit
//    • ip, port, duration are required and validated
//    • Free users  → duration capped at 60 seconds
//    • Pro  users  → duration up to 300 seconds (no cap)
//    • 1 credit is deducted per successful launch
// ─────────────────────────────────────────────────────────────────────────────
router.post('/attack', auth, async (req, res) => {
    try {
        // ── Load fresh user from DB (never trust client-side credit count) ────────
        const user = await User.findById(req.user.id).select('-password');
        if (!user) return res.status(404).json({ message: 'User not found' });

        const { ip, port, duration } = req.body;

        // ── Field presence ────────────────────────────────────────────────────────
        if (!ip || !port || !duration) {
            return res.status(400).json({ message: 'IP, port, and duration are required' });
        }

        // ── IP validation ─────────────────────────────────────────────────────────
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(ip)) {
            return res.status(400).json({ message: 'Invalid IP address format' });
        }

        const { captchaToken } = req.body;
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

        // Validate each octet is 0-255
        const parts = ip.split('.').map(Number);
        if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
            return res.status(400).json({ message: 'Invalid IP address format' });
        }
        const isPrivate =
            parts[0] === 10 ||
            parts[0] === 127 ||
            (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
            (parts[0] === 192 && parts[1] === 168);
        if (isPrivate) {
            return res.status(400).json({ message: 'Private/loopback IP addresses are not allowed' });
        }

        // ── Port validation ───────────────────────────────────────────────────────
        const portNum = parseInt(port);
        if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
            return res.status(400).json({ message: 'Port must be between 1 and 65535' });
        }

        // ── Duration validation ───────────────────────────────────────────────────
        const durNum = parseInt(duration);
        if (isNaN(durNum) || durNum < 1) {
            return res.status(400).json({ message: 'Duration must be at least 1 second' });
        }

        const MAX_DURATION = user.isPro ? 300 : 60; // Pro = 300s, Free = 60s

        if (durNum > MAX_DURATION) {
            return res.status(403).json({
                message: user.isPro
                    ? 'Duration cannot exceed 300 seconds'
                    : `Free accounts are limited to 60 seconds. Upgrade to Pro for up to 300 seconds.`,
                maxDuration: MAX_DURATION,
                isPro: user.isPro,
            });
        }

        // ── Credit check ──────────────────────────────────────────────────────────
        if (user.credits < 1) {
            return res.status(403).json({
                message: 'Insufficient credits. Share your referral link to earn more.',
                credits: user.credits,
            });
        }

        // ── Deduct 1 credit atomically ────────────────────────────────────────────
        // findByIdAndUpdate with $inc is atomic — safe against race conditions
        const updated = await User.findByIdAndUpdate(
            user._id,
            { $inc: { credits: -1 } },
            { new: true }           // return the updated document
        );

        // ── TODO: trigger your actual attack logic here ───────────────────────────
        // e.g. await sendAttackToWorker({ ip, port: portNum, duration: durNum, userId: user._id });

        console.log(`🚀 Attack launched by ${user.username} → ${ip}:${portNum} for ${durNum}s (isPro: ${user.isPro})`);

        return res.json({
            message: 'Attack launched successfully',
            attack: {
                ip,
                port: portNum,
                duration: durNum,
            },
            credits: updated.credits, // send back updated credit count
            isPro: user.isPro,
        });

    } catch (err) {
        console.error('Attack error:', err);
        res.status(500).json({ message: 'Server error. Please try again.' });
    }
});

module.exports = router;