const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const User = require('../models/User');

async function verifyTurnstile(token, ip) {
  const res = await axios.post(
    'https://challenges.cloudflare.com/turnstile/v0/siteverify',
    new URLSearchParams({
      secret: process.env.TURNSTILE_SECRET,
      response: token,
      remoteip: ip,
    }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );
  return res.data.success;
}

function validatePassword(password) {
  const errors = [];
  if (password.length < 8)          errors.push('Min 8 characters');
  if (!/[A-Z]/.test(password))      errors.push('At least 1 uppercase letter');
  if (!/[0-9]/.test(password))      errors.push('At least 1 number');
  if (!/[^A-Za-z0-9]/.test(password)) errors.push('At least 1 special character');
  return errors;
}

// ── SIGNUP ───────────────────────────────────────────────────
router.post('/signup', async (req, res) => {
  try {
    const { username, email, password, captchaToken, fingerprint, referralCode } = req.body;
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;

    // 1. Validate fields
    if (!username || !email || !password || !captchaToken || !fingerprint)
      return res.status(400).json({ message: 'All fields are required' });

    // 2. Validate password strength
    const pwErrors = validatePassword(password);
    if (pwErrors.length > 0)
      return res.status(400).json({ message: pwErrors[0] });

    // 3. Validate username (alphanumeric only)
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username))
      return res.status(400).json({ message: 'Username must be 3-20 chars, letters/numbers/underscore only' });

    // 4. Verify CAPTCHA
    const captchaOk = await verifyTurnstile(captchaToken, ip);
    if (!captchaOk)
      return res.status(400).json({ message: 'CAPTCHA verification failed' });

    // 5. Check email/username exists
    const exists = await User.findOne({ $or: [{ email }, { username }] });
    if (exists)
      return res.status(400).json({ message: 'Email or username already taken' });

    // 6. Handle referral code
    let referrer = null;
    if (referralCode && referralCode.trim() !== '') {
      referrer = await User.findOne({ referralCode: referralCode.trim() });
      if (!referrer)
        return res.status(400).json({ message: 'Invalid referral code' });
    }

    // 7. Check abuse (IP + fingerprint)
    const abuseCheck = await User.findOne({
      $or: [{ ipAddress: ip }, { fingerprint }]
    });

    // 8. Prevent self-referral (check if referrer's IP/fingerprint matches current user)
    if (referrer && abuseCheck && abuseCheck._id.toString() === referrer._id.toString()) {
      return res.status(400).json({ message: 'You cannot use your own referral code' });
    }

    // 9. Hash password
    const hashed = await bcrypt.hash(password, 12);

    // 10. Determine credits
    const creditGiven = !abuseCheck;
    const baseCredits = creditGiven ? 3 : 0;

    // 11. Create user
    const { nanoid } = require('nanoid');
    const newUserId = nanoid(10);

    const user = new User({
      userId: newUserId,
      referralCode: newUserId, // userId = referralCode
      username,
      email,
      password: hashed,
      credits: baseCredits,
      ipAddress: ip,
      fingerprint,
      creditGiven,
      referredBy: referrer ? referrer.referralCode : null,
    });

    await user.save();

    // 12. Give referrer +2 credits (only if new device)
    if (referrer && creditGiven) {
      await User.findByIdAndUpdate(referrer._id, {
        $inc: { credits: 2, referralCount: 1 }
      });
    }

    // 13. Sign JWT
    const token = jwt.sign(
      { id: user._id, userId: user.userId },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      token,
      message: creditGiven
        ? referrer
          ? '🎉 Account created with referral! You received 3 credits.'
          : '🎉 Account created! You received 3 credits.'
        : '⚠️ Account created, but no credits (device already used).',
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
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.ip;

    if (!email || !password || !captchaToken)
      return res.status(400).json({ message: 'All fields are required' });

    const captchaOk = await verifyTurnstile(captchaToken, ip);
    if (!captchaOk)
      return res.status(400).json({ message: 'CAPTCHA verification failed' });

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