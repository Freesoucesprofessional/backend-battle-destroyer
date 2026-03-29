const express = require('express');
const router  = express.Router();
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const axios   = require('axios');
const User    = require('../models/User');

// ─────────────────────────────────────────────────────────────────────────────
// TOKEN BLACKLIST — prevents single-use tokens from being replayed
//
// In production, replace this Map with Redis so it persists across
// restarts and scales across multiple server instances:
//
//   const redis = require('redis');
//   const client = redis.createClient({ url: process.env.REDIS_URL });
//   await client.set(`captcha:${token}`, '1', { EX: 310 });
//   const used = await client.get(`captcha:${token}`);
// ─────────────────────────────────────────────────────────────────────────────
const usedCaptchaTokens = new Map(); // token → expiry timestamp

/** Mark a token as used. Auto-purge it after 310s (just past Cloudflare's window). */
function blacklistToken(token) {
    usedCaptchaTokens.set(token, Date.now() + 310_000);
    // Lazy GC — remove expired entries to avoid memory leak
    for (const [t, exp] of usedCaptchaTokens) {
        if (Date.now() > exp) usedCaptchaTokens.delete(t);
    }
}

/** Returns true if the token has already been used. */
function isTokenBlacklisted(token) {
    const exp = usedCaptchaTokens.get(token);
    if (!exp) return false;
    if (Date.now() > exp) { usedCaptchaTokens.delete(token); return false; }
    return true;
}


// ─────────────────────────────────────────────────────────────────────────────
// TURNSTILE VERIFICATION
// ─────────────────────────────────────────────────────────────────────────────
async function verifyTurnstile(token, ip) {
    // Fast-fail on obviously invalid tokens
    if (!token || token.length < 10) {
        return { success: false, 'error-codes': ['missing-input-response'] };
    }

    // Reject already-used tokens before hitting Cloudflare's API
    if (isTokenBlacklisted(token)) {
        console.warn('⚠️  Replay attempt — token already used:', token.slice(0, 20) + '…');
        return { success: false, 'error-codes': ['duplicate-use'] };
    }

    try {
        const params = new URLSearchParams({
            secret:   process.env.TURNSTILE_SECRET,
            response: token,
        });

        // Only include remoteip when it's a real routable IP.
        // With `trust proxy` set, req.ip is forwarded correctly.
        // Passing '::1' (localhost) or '127.0.0.1' to Cloudflare causes errors.
        if (ip && ip !== '::1' && ip !== '127.0.0.1' && !ip.startsWith('::ffff:127')) {
            params.append('remoteip', ip);
        }

        const { data } = await axios.post(
            'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            params,
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        );

        if (data.success) {
            // Immediately blacklist token so it cannot be replayed
            blacklistToken(token);
        } else {
            console.warn('❌ Turnstile rejected:', data['error-codes']);
        }

        return data;

    } catch (err) {
        console.error('❌ Turnstile request failed:', err.message);
        return { success: false, 'error-codes': ['internal-error'] };
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// PASSWORD VALIDATION
// ─────────────────────────────────────────────────────────────────────────────
function validatePassword(password) {
    const errors = [];
    if (!password || password.length < 8)   errors.push('Min 8 characters');
    if (!/[A-Z]/.test(password))             errors.push('At least 1 uppercase letter');
    if (!/[0-9]/.test(password))             errors.push('At least 1 number');
    if (!/[^A-Za-z0-9]/.test(password))      errors.push('At least 1 special character');
    return errors;
}


// ─────────────────────────────────────────────────────────────────────────────
// SIGNUP  POST /api/auth/signup
// ─────────────────────────────────────────────────────────────────────────────
router.post('/signup', async (req, res) => {
    try {
        const { username, email, password, captchaToken, fingerprint, referralCode } = req.body;

        // req.ip is correct when app.set('trust proxy', 1) is configured in server.js
        const ip = req.ip;

        // ── Basic field presence ───────────────────────────────────────────────
        if (!username || !email || !password || !captchaToken || !fingerprint) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        // ── CAPTCHA verification (always first — stops bots before DB queries) ─
        const captcha = await verifyTurnstile(captchaToken, ip);
        if (!captcha.success) {
            return res.status(400).json({
                message: captcha['error-codes']?.includes('duplicate-use')
                    ? 'CAPTCHA already used. Please solve it again.'
                    : 'CAPTCHA verification failed. Please try again.',
                codes: captcha['error-codes'],
            });
        }

        // ── Password & username validation ────────────────────────────────────
        const pwErrors = validatePassword(password);
        if (pwErrors.length) return res.status(400).json({ message: pwErrors[0] });

        if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
            return res.status(400).json({ message: 'Username must be 3–20 alphanumeric characters' });
        }

        // ── Uniqueness check ──────────────────────────────────────────────────
        const exists = await User.findOne({ $or: [{ email }, { username }] });
        if (exists) return res.status(400).json({ message: 'Email or username already taken' });

        // ── Referral validation ───────────────────────────────────────────────
        let referrer = null;
        if (referralCode) {
            referrer = await User.findOne({ referralCode: referralCode.trim() });
            if (!referrer) return res.status(400).json({ message: 'Invalid referral code' });
        }

        // ── Abuse detection (same IP or fingerprint = no bonus) ───────────────
        const abuseCheck = await User.findOne({ $or: [{ ipAddress: ip }, { fingerprint }] });

        if (referrer && abuseCheck && abuseCheck._id.toString() === referrer._id.toString()) {
            return res.status(400).json({ message: 'Cannot use your own referral code' });
        }

        // ── Create user ───────────────────────────────────────────────────────
        const hashed = await bcrypt.hash(password, 12);
        const user = new User({
            username,
            email,
            password:    hashed,
            credits:     !abuseCheck ? 3 : 0,
            ipAddress:   ip,
            fingerprint,
            creditGiven: !abuseCheck,
            referredBy:  referrer ? referrer.referralCode : null,
        });
        user.referralCode = user.userId;
        await user.save();

        // ── Credit referrer ───────────────────────────────────────────────────
        if (referrer && !abuseCheck) {
            await User.findByIdAndUpdate(referrer._id, {
                $inc: { credits: 2, referralCount: 1 }
            });
        }

        // ── Issue JWT ─────────────────────────────────────────────────────────
        const token = jwt.sign(
            { id: user._id, userId: user.userId },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        return res.status(201).json({
            message: 'Account created successfully!',
            token,
            user: {
                userId:        user.userId,
                username:      user.username,
                email:         user.email,
                credits:       user.credits,
                referralCode:  user.referralCode,
                referralCount: user.referralCount,
            },
        });

    } catch (err) {
        console.error('Signup error:', err);
        return res.status(500).json({ message: 'Server error. Please try again.' });
    }
});


// ─────────────────────────────────────────────────────────────────────────────
// LOGIN  POST /api/auth/login
// ─────────────────────────────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
    try {
        const { email, password, captchaToken } = req.body;
        const ip = req.ip;

        // ── Field presence ────────────────────────────────────────────────────
        if (!email || !password || !captchaToken) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        // ── CAPTCHA (verify before any DB lookup) ─────────────────────────────
        const captcha = await verifyTurnstile(captchaToken, ip);
        if (!captcha.success) {
            return res.status(400).json({
                message: captcha['error-codes']?.includes('duplicate-use')
                    ? 'CAPTCHA already used. Please solve it again.'
                    : 'CAPTCHA verification failed. Please try again.',
                codes: captcha['error-codes'],
            });
        }

        // ── Credential check ──────────────────────────────────────────────────
        const user = await User.findOne({ email });
        // Use same message for missing user & wrong password — prevents user enumeration
        const credError = { message: 'Invalid email or password' };

        if (!user) return res.status(400).json(credError);

        const match = await bcrypt.compare(password, user.password);
        if (!match)  return res.status(400).json(credError);

        // ── Issue JWT ─────────────────────────────────────────────────────────
        const token = jwt.sign(
            { id: user._id, userId: user.userId },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        return res.json({
            token,
            user: {
                userId:        user.userId,
                username:      user.username,
                email:         user.email,
                credits:       user.credits,
                referralCode:  user.referralCode,
                referralCount: user.referralCount,
            },
        });

    } catch (err) {
        console.error('Login error:', err);
        return res.status(500).json({ message: 'Server error. Please try again.' });
    }
});

module.exports = router;