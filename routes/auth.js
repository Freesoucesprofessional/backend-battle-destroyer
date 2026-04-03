const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const CryptoJS = require('crypto-js');
const User = require('../models/User');
const Stats = require('../models/Stats');
const { verifyCaptcha } = require('./captcha'); // Your hCaptcha module

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
  const errorResponse = { success: false, message };
  const encryptedError = encryptResponse(errorResponse);
  const errorHash = createHash(errorResponse);
  return res.status(statusCode).json({ encrypted: encryptedError, hash: errorHash });
}

/* ─── Shared IP extractor ─────────────────────────────────────── */

function getIp(req) {
  const raw = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || '';
  let ip = raw.startsWith('::ffff:') ? raw.slice(7) : raw;
  if (ip === '::1') ip = '127.0.0.1';
  return ip;
}

/* ─── Password validation ─────────────────────────────────────── */

function validatePassword(password) {
  const errors = [];
  if (!password || password.length < 8) errors.push('Min 8 characters');
  if (!/[A-Z]/.test(password)) errors.push('At least 1 uppercase letter');
  if (!/[0-9]/.test(password)) errors.push('At least 1 number');
  if (!/[^A-Za-z0-9]/.test(password)) errors.push('At least 1 special character');
  return errors;
}

/* ─── SIGNUP with hCaptcha ───────────────────────────────── */

router.post('/signup', async (req, res) => {
  try {
    const { encrypted, hash, clientVersion } = req.body;

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

    const { username, email, password, fingerprint, referralCode, captchaData, hp } = decryptedData;

    if (hp) {
      // For honeypot, still return encrypted response
      const responseData = { success: true, message: 'Account created successfully!' };
      const encryptedResponse = encryptResponse(responseData);
      const responseHash = createHash(responseData);
      return res.status(201).json({ encrypted: encryptedResponse, hash: responseHash });
    }

    if (!username || !email || !password || !captchaData) {
      return sendEncryptedError(res, 400, 'All fields are required');
    }

    const ip = getIp(req);
    const captchaToken = captchaData.token || captchaData;
    const captcha = await verifyCaptcha(captchaToken, null, ip);

    if (!captcha.ok) {
      console.log(`[Signup] Captcha failed for ${email}: ${captcha.reason}`);
      return sendEncryptedError(res, 400, captcha.reason || 'Captcha verification failed');
    }

    const pwErrors = validatePassword(password);
    if (pwErrors.length) {
      return sendEncryptedError(res, 400, pwErrors[0]);
    }

    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return sendEncryptedError(res, 400, 'Username must be 3–20 alphanumeric characters');
    }

    const isInternalIp = /^(10\.|172\.16\.|192\.168\.|127\.)/.test(ip);
    
    // Better duplicate error messages
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      if (existingUser.email === email) {
        return sendEncryptedError(res, 400, 'Email already registered. Please use a different email or login.');
      }
      if (existingUser.username === username) {
        return sendEncryptedError(res, 400, 'Username already taken. Please choose a different username.');
      }
    }

    let referrer = null;
    if (referralCode) {
      referrer = await User.findOne({ referralCode: referralCode.trim() });
      if (!referrer) {
        return sendEncryptedError(res, 400, 'Invalid referral code. Please check and try again.');
      }
    }

    const abuseOrClauses = [];
    if (!isInternalIp && ip) abuseOrClauses.push({ ipAddress: ip });
    if (fingerprint) abuseOrClauses.push({ fingerprint });

    const abuseCheck = abuseOrClauses.length
      ? await User.findOne({ $or: abuseOrClauses })
      : null;

    if (referrer && abuseCheck && abuseCheck._id.toString() === referrer._id.toString()) {
      return sendEncryptedError(res, 400, 'Cannot use your own referral code');
    }

    const isNewUniqueUser = !abuseCheck;
    const startingCredits = isNewUniqueUser ? 1 : 0;

    console.log(`[Signup] ${username} | IP: ${ip} | credits: ${startingCredits}`);

    const hashed = await bcrypt.hash(password, 12);
    const user = new User({
      username,
      email,
      password: hashed,
      credits: startingCredits,
      ipAddress: isInternalIp ? null : ip,
      fingerprint: fingerprint || null,
      creditGiven: isNewUniqueUser,
      referredBy: referrer ? referrer.referralCode : null,
      subscription: {
        type: 'free',
        plan: 'none',
        dailyCredits: 1,
        lastCreditReset: new Date(),
      },
    });

    await user.save();

    if (referrer && isNewUniqueUser) {
      await User.findByIdAndUpdate(referrer._id, { $inc: { credits: 2, referralCount: 1 } });
      await User.findByIdAndUpdate(user._id, { $inc: { credits: 2 } });
      user.credits += 2;
      console.log(`[Referral] ${referrer.username} +2 | ${username} +2`);
    }

    const token = jwt.sign(
      { id: user._id, userId: user.userId },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    await Stats.findByIdAndUpdate('global', { $inc: { totalUsers: 1 } }, { upsert: true });

    const responseData = {
      success: true,
      message: 'Account created successfully! You received 10 free credits!',
      token,
      user: {
        userId: user.userId,
        username: user.username,
        email: user.email,
        credits: user.credits,
        referralCode: user.referralCode,
        referralCount: user.referralCount,
        isPro: user.isProUser(),
        subscription: user.subscription,
        remainingAttacks: await user.getRemainingAttacks(),
        maxDuration: user.getMaxDuration(),
      },
      timestamp: Date.now(),
    };

    const encryptedResponse = encryptResponse(responseData);
    const responseHash = createHash(responseData);

    return res.status(201).json({
      encrypted: encryptedResponse,
      hash: responseHash,
    });

  } catch (err) {
    console.error('Signup error:', err);
    if (err.code === 11000) {
      const field = Object.keys(err.keyPattern || {})[0] || 'field';
      const message = field === 'email' 
        ? 'Email already registered. Please use a different email.'
        : 'Username already taken. Please choose a different username.';
      return sendEncryptedError(res, 400, message);
    }
    return sendEncryptedError(res, 500, 'Server error. Please try again later.');
  }
});
/* ─── LOGIN with hCaptcha ────────────────────────────────── */

router.post('/login', async (req, res) => {
  try {
    const { encrypted, hash, clientVersion } = req.body;

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

    const { email, password, captchaData, hp } = decryptedData;

    if (hp) {
      return sendEncryptedError(res, 400, 'Invalid request');
    }

    if (!email || !password || !captchaData) {
      return sendEncryptedError(res, 400, 'All fields are required');
    }

    const ip = getIp(req);
    const captchaToken = captchaData.token || captchaData;
    const captcha = await verifyCaptcha(captchaToken, null, ip);

    if (!captcha.ok) {
      console.log(`[Login] Captcha failed for ${email}: ${captcha.reason}`);
      return sendEncryptedError(res, 400, captcha.reason || 'Captcha verification failed');
    }

    console.log(`[Login] Captcha passed for ${email}`);

    const user = await User.findOne({ email });
    if (!user) {
      return sendEncryptedError(res, 400, 'Invalid email or password');
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return sendEncryptedError(res, 400, 'Invalid email or password');
    }

    await user.checkAndResetDailyCredits();

    const token = jwt.sign(
      { id: user._id, userId: user.userId },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    const responseData = {
      success: true,
      token,
      user: {
        userId: user.userId,
        username: user.username,
        email: user.email,
        credits: user.credits,
        referralCode: user.referralCode,
        referralCount: user.referralCount,
        isPro: user.isProUser(),
        subscription: user.subscription,
        remainingAttacks: await user.getRemainingAttacks(),
        maxDuration: user.getMaxDuration(),
        totalAttacks: user.totalAttacks,
      },
      timestamp: Date.now(),
    };

    const encryptedResponse = encryptResponse(responseData);
    const responseHash = createHash(responseData);

    return res.json({
      encrypted: encryptedResponse,
      hash: responseHash,
    });

  } catch (err) {
    console.error('Login error:', err);
    return sendEncryptedError(res, 500, 'Server error. Please try again later.');
  }
});

module.exports = router;