const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const User = require('../models/User');


// ✅ IMPROVED TURNSTILE VERIFY
async function verifyTurnstile(token, ip) {
  try {
    if (!token || token.length < 10) {
      return { success: false, 'error-codes': ['invalid-input'] };
    }

    const res = await axios.post(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      new URLSearchParams({
        secret: process.env.TURNSTILE_SECRET,
        response: token,
        remoteip: ip,
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    // 🔥 LOG FULL RESPONSE (VERY IMPORTANT)
    if (!res.data.success) {
      console.log('❌ Turnstile failed:', res.data);
    }

    return res.data;

  } catch (err) {
    console.error('❌ Turnstile request error:', err.message);
    return { success: false, 'error-codes': ['internal-error'] };
  }
}


// ✅ PASSWORD VALIDATION
function validatePassword(password) {
  const errors = [];
  if (password.length < 8) errors.push('Min 8 characters');
  if (!/[A-Z]/.test(password)) errors.push('At least 1 uppercase letter');
  if (!/[0-9]/.test(password)) errors.push('At least 1 number');
  if (!/[^A-Za-z0-9]/.test(password)) errors.push('At least 1 special character');
  return errors;
}


// ── SIGNUP ───────────────────────────────────────────────────
router.post('/signup', async (req, res) => {
  try {
    const { username, email, password, captchaToken, fingerprint, referralCode } = req.body;
    const ip = req.ip; // ✅ FIX (trust proxy required)

    if (!username || !email || !password || !captchaToken || !fingerprint)
      return res.status(400).json({ message: 'All fields are required' });

    // ✅ CAPTCHA VERIFY
    const captcha = await verifyTurnstile(captchaToken, ip);
    if (!captcha.success) {
      return res.status(400).json({
        message: 'CAPTCHA failed',
        error: captcha['error-codes']
      });
    }

    // Password check
    const pwErrors = validatePassword(password);
    if (pwErrors.length > 0)
      return res.status(400).json({ message: pwErrors[0] });

    // Username validation
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username))
      return res.status(400).json({ message: 'Username must be valid' });

    const exists = await User.findOne({ $or: [{ email }, { username }] });
    if (exists)
      return res.status(400).json({ message: 'Email or username already taken' });

    // Referral
    let referrer = null;
    if (referralCode) {
      referrer = await User.findOne({ referralCode: referralCode.trim() });
      if (!referrer)
        return res.status(400).json({ message: 'Invalid referral code' });
    }

    const abuseCheck = await User.findOne({
      $or: [{ ipAddress: ip }, { fingerprint }]
    });

    if (referrer && abuseCheck && abuseCheck._id.toString() === referrer._id.toString()) {
      return res.status(400).json({ message: 'Cannot use own referral code' });
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
    });

    user.referralCode = user.userId;
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

    res.status(201).json({
      token,
      user: {
        userId: user.userId,
        username: user.username,
        email: user.email,
        credits: user.credits,
        referralCode: user.referralCode,
        referralCount: user.referralCount,
      },
    });

  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});


// ── LOGIN ────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  try {
    const { email, password, captchaToken } = req.body;
    const ip = req.ip; // ✅ FIX

    if (!email || !password || !captchaToken)
      return res.status(400).json({ message: 'All fields are required' });

    // ✅ CAPTCHA VERIFY (IMPORTANT FIX)
    const captcha = await verifyTurnstile(captchaToken, ip);

    if (!captcha.success) {
      return res.status(400).json({
        message: 'CAPTCHA failed',
        error: captcha['error-codes']
      });
    }

    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ message: 'Invalid email or password' });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(400).json({ message: 'Invalid email or password' });

    const token = jwt.sign(
      { id: user._id, userId: user.userId },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: {
        userId: user.userId,
        username: user.username,
        email: user.email,
        credits: user.credits,
        referralCode: user.referralCode,
        referralCount: user.referralCount,
      },
    });

  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

module.exports = router;