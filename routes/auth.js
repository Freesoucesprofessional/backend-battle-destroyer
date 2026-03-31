const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const User = require('../models/User');
const Stats = require('../models/Stats');

// ─── TOKEN BLACKLIST ──────────────────────────────────────────────────────────
// In production replace with Redis for persistence across restarts/instances.
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

// ─── TURNSTILE VERIFICATION ───────────────────────────────────────────────────
async function verifyTurnstile(token, ip) {
  if (!token || token.length < 10) {
    return { success: false, 'error-codes': ['missing-input-response'] };
  }
  if (isTokenBlacklisted(token)) {
    console.warn('⚠️  Replay attempt — token already used:', token.slice(0, 20) + '…');
    return { success: false, 'error-codes': ['duplicate-use'] };
  }
  try {
    const params = new URLSearchParams({
      secret: process.env.TURNSTILE_SECRET,
      response: token,
    });
    if (ip && ip !== '::1' && ip !== '127.0.0.1' && !ip.startsWith('::ffff:127')) {
      params.append('remoteip', ip);
    }
    const { data } = await axios.post(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      params,
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    if (data.success) blacklistToken(token);
    else console.warn('❌ Turnstile rejected:', data['error-codes']);
    return data;
  } catch (err) {
    console.error('❌ Turnstile request failed:', err.message);
    return { success: false, 'error-codes': ['internal-error'] };
  }
}

// ─── PASSWORD VALIDATION ──────────────────────────────────────────────────────
function validatePassword(password) {
  const errors = [];
  if (!password || password.length < 8) errors.push('Min 8 characters');
  if (!/[A-Z]/.test(password)) errors.push('At least 1 uppercase letter');
  if (!/[0-9]/.test(password)) errors.push('At least 1 number');
  if (!/[^A-Za-z0-9]/.test(password)) errors.push('At least 1 special character');
  return errors;
}

// ─── SIGNUP  POST /api/auth/signup ────────────────────────────────────────────
router.post('/signup', async (req, res) => {
  try {
    const { username, email, password, captchaToken, fingerprint, referralCode } = req.body;
    const ip = req.ip;

    if (!username || !email || !password || !captchaToken || !fingerprint) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const captcha = await verifyTurnstile(captchaToken, ip);
    if (!captcha.success) {
      return res.status(400).json({
        message: captcha['error-codes']?.includes('duplicate-use')
          ? 'CAPTCHA already used. Please solve it again.'
          : 'CAPTCHA verification failed. Please try again.',
        codes: captcha['error-codes'],
      });
    }

    const pwErrors = validatePassword(password);
    if (pwErrors.length) return res.status(400).json({ message: pwErrors[0] });

    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({ message: 'Username must be 3–20 alphanumeric characters' });
    }

    const exists = await User.findOne({ $or: [{ email }, { username }] });
    if (exists) return res.status(400).json({ message: 'Email or username already taken' });

    let referrer = null;
    if (referralCode) {
      referrer = await User.findOne({ referralCode: referralCode.trim() });
      if (!referrer) return res.status(400).json({ message: 'Invalid referral code' });
    }

    const abuseCheck = await User.findOne({ $or: [{ ipAddress: ip }, { fingerprint }] });

    if (referrer && abuseCheck && abuseCheck._id.toString() === referrer._id.toString()) {
      return res.status(400).json({ message: 'Cannot use your own referral code' });
    }

    const hashed = await bcrypt.hash(password, 12);

    const user = new User({
      username,
      email,
      password: hashed,
      credits: !abuseCheck ? 3 : 0,
      ipAddress: ip,
      fingerprint,
      creditGiven: !abuseCheck,
      referredBy: referrer ? referrer.referralCode : null,
      // FIX: Do NOT set referralCode here — pre('save') hook handles it.
      // Setting it here meant userId was still undefined at this point,
      // so referralCode would be saved as undefined → duplicate key crash.
    });

    // pre('save') sets both user.userId and user.referralCode atomically
    await user.save();

    if (referrer && !abuseCheck) {
      await User.findByIdAndUpdate(referrer._id, {
        $inc: { credits: 2, referralCount: 1 }
      });
    }

    const token = jwt.sign(
      { id: user._id, userId: user.userId },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    await Stats.findByIdAndUpdate(
      'global',
      { $inc: { totalUsers: 1 } },
      { upsert: true }
    );

    return res.status(201).json({
      message: 'Account created successfully!',
      token,
      user: {
        userId: user.userId,
        username: user.username,
        email: user.email,
        credits: user.credits,
        referralCode: user.referralCode,
        referralCount: user.referralCount,
        isPro: user.isPro,
      },
    });



  } catch (err) {
    console.error('Signup error:', err);

    // FIX: Surface MongoDB duplicate-key errors clearly during development.
    // Code 11000 = unique index violation (e.g. duplicate email/username/referralCode).
    if (err.code === 11000) {
      const field = Object.keys(err.keyPattern || {})[0] || 'field';
      return res.status(400).json({ message: `Duplicate value for ${field}. Please try again.` });
    }

    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

// ─── LOGIN  POST /api/auth/login ──────────────────────────────────────────────
router.post('/login', async (req, res) => {
  try {
    const { email, password, captchaToken } = req.body;
    const ip = req.ip;

    if (!email || !password || !captchaToken) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const captcha = await verifyTurnstile(captchaToken, ip);
    if (!captcha.success) {
      return res.status(400).json({
        message: captcha['error-codes']?.includes('duplicate-use')
          ? 'CAPTCHA already used. Please solve it again.'
          : 'CAPTCHA verification failed. Please try again.',
        codes: captcha['error-codes'],
      });
    }

    const user = await User.findOne({ email });
    const credError = { message: 'Invalid email or password' };
    if (!user) return res.status(400).json(credError);

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json(credError);

    const token = jwt.sign(
      { id: user._id, userId: user.userId },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    return res.json({
      token,
      user: {
        userId: user.userId,
        username: user.username,
        email: user.email,
        credits: user.credits,
        referralCode: user.referralCode,
        referralCount: user.referralCount,
        isPro: user.isPro,
      },
    });

  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ message: 'Server error. Please try again.' });
  }
});

module.exports = router;