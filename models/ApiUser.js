// models/ApiUser.js - Complete working model with duplicate prevention
const mongoose = require('mongoose');
const crypto = require('crypto');

const apiUserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
        validate: {
            validator: function (v) {
                return /^[a-zA-Z0-9_.-]{3,30}$/.test(v);
            },
            message: 'Username must be 3-30 characters and can only contain letters, numbers, underscores, dots, and hyphens'
        }
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        validate: {
            validator: function (v) {
                return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
            },
            message: 'Invalid email format'
        }
    },
    apiKey: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    apiSecretHash: {
        type: String,
        required: true,
        unique: true,
        index: true
    },
    status: {
        type: String,
        enum: ['active', 'suspended', 'expired'],
        default: 'active'
    },
    expiresAt: {
        type: Date,
        default: null
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    limits: {
        maxConcurrent: {
            type: Number,
            default: 2,
            min: 1,
            max: 100
        },
        maxDuration: {
            type: Number,
            default: 300,
            min: 30,
            max: 3600
        }
    },
    activeAttacks: [{
        attackId: { type: String, required: true },
        target: String,
        port: Number,
        startedAt: { type: Date, default: Date.now },
        expiresAt: Date
    }],
    totalAttacks: { type: Number, default: 0 },
    totalRequests: { type: Number, default: 0 },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    lastLoginAt: { type: Date }
});

// ── Static generators with collision prevention ──────────────────────────────

apiUserSchema.statics.generateUniqueApiKey = async function (retryCount = 0) {
    const maxRetries = 5;
    const apiKey = 'ak_' + crypto.randomBytes(24).toString('hex');

    // Check if this key already exists
    const existing = await this.findOne({ apiKey });

    if (existing && retryCount < maxRetries) {
        console.log(`API key collision detected, retrying... (${retryCount + 1}/${maxRetries})`);
        return this.generateUniqueApiKey(retryCount + 1);
    }

    if (existing) {
        throw new Error('Failed to generate unique API key after multiple attempts');
    }

    return apiKey;
};

apiUserSchema.statics.generateUniqueApiSecret = async function (retryCount = 0) {
    const maxRetries = 5;
    const raw = 'as_' + crypto.randomBytes(32).toString('hex');
    const hashed = crypto.createHash('sha256').update(raw).digest('hex');

    // Check if this hash already exists
    const existing = await this.findOne({ apiSecretHash: hashed });

    if (existing && retryCount < maxRetries) {
        console.log(`Secret hash collision detected, retrying... (${retryCount + 1}/${maxRetries})`);
        return this.generateUniqueApiSecret(retryCount + 1);
    }

    if (existing) {
        throw new Error('Failed to generate unique API secret after multiple attempts');
    }

    return { raw, hashed };
};

// Legacy methods (for backward compatibility)
apiUserSchema.statics.generateApiKey = function () {
    return 'ak_' + crypto.randomBytes(24).toString('hex');
};

apiUserSchema.statics.generateApiSecret = function () {
    const raw = 'as_' + crypto.randomBytes(32).toString('hex');
    const hashed = crypto.createHash('sha256').update(raw).digest('hex');
    return { raw, hashed };
};

// ── Expiration helpers ────────────────────────────────────────────────────────

apiUserSchema.methods.isExpired = function () {
    if (!this.expiresAt) return false;
    return new Date() > new Date(this.expiresAt);
};

apiUserSchema.methods.getDaysRemaining = function () {
    if (!this.expiresAt) return null;
    const days = Math.ceil((new Date(this.expiresAt) - new Date()) / (1000 * 60 * 60 * 24));
    return days > 0 ? days : 0;
};

apiUserSchema.methods.extendExpiration = async function (days) {
    const newExpiry = new Date();
    newExpiry.setDate(newExpiry.getDate() + days);

    // If current expiry is in the future, add to it instead of resetting
    if (this.expiresAt && this.expiresAt > new Date()) {
        this.expiresAt.setDate(this.expiresAt.getDate() + days);
    } else {
        this.expiresAt = newExpiry;
    }

    await this.save();
    return this.expiresAt;
};

apiUserSchema.methods.setDefaultExpiration = async function () {
    this.expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await this.save();
    return this.expiresAt;
};

// ── Attack tracking ───────────────────────────────────────────────────────────

apiUserSchema.statics.cleanExpiredAttacks = async function () {
    const now = new Date();
    const attackResult = await this.updateMany(
        { 'activeAttacks.expiresAt': { $lt: now } },
        { $pull: { activeAttacks: { expiresAt: { $lt: now } } } }
    );
    const expireResult = await this.updateMany(
        { expiresAt: { $lt: now }, status: 'active' },
        { status: 'expired' }
    );
    if (attackResult.modifiedCount > 0 || expireResult.modifiedCount > 0) {
        console.log(`Cleaned ${attackResult.modifiedCount} attacks, ${expireResult.modifiedCount} accounts expired`);
    }
    return { attackResult, expireResult };
};

apiUserSchema.methods.getActiveCount = async function () {
    const now = new Date();
    const beforeCount = this.activeAttacks.length;
    this.activeAttacks = this.activeAttacks.filter(a => a.expiresAt > now);
    if (beforeCount !== this.activeAttacks.length) await this.save();
    return this.activeAttacks.length;
};

apiUserSchema.methods.addActiveAttack = async function (attackId, target, port, duration) {
    if (this.isExpired()) throw new Error('Account has expired');
    this.activeAttacks.push({
        attackId,
        target,
        port,
        startedAt: new Date(),
        expiresAt: new Date(Date.now() + duration * 1000)
    });
    this.totalAttacks++;
    await this.save();
};

apiUserSchema.methods.removeActiveAttack = async function (attackId) {
    this.activeAttacks = this.activeAttacks.filter(a => a.attackId !== attackId);
    await this.save();
};

apiUserSchema.methods.cleanExpired = async function () {
    const now = new Date();
    const beforeCount = this.activeAttacks.length;
    this.activeAttacks = this.activeAttacks.filter(a => a.expiresAt > now);
    if (beforeCount !== this.activeAttacks.length) await this.save();
    return this.activeAttacks.length;
};
// In models/ApiUser.js - add this method if missing
apiUserSchema.methods.getRemainingAttacks = async function () {
    // Reset daily credits if needed
    const now = new Date();
    const lastReset = this.subscription?.lastCreditReset || this.createdAt;
    const daysSinceReset = Math.floor((now - lastReset) / (1000 * 60 * 60 * 24));

    if (daysSinceReset > 0) {
        this.subscription.lastCreditReset = now;
        this.subscription.creditsUsedToday = 0;
        await this.save();
    }

    const dailyLimit = this.isProUser() ? 30 : 10;
    const used = this.subscription?.creditsUsedToday || 0;
    return Math.max(0, dailyLimit - used);
};

apiUserSchema.methods.isProUser = function () {
    return this.subscription?.type === 'pro' && this.subscription?.expiresAt > new Date();
};
// Ensure indexes are created
apiUserSchema.index({ apiKey: 1 }, { unique: true });
apiUserSchema.index({ apiSecretHash: 1 }, { unique: true });
apiUserSchema.index({ username: 1 }, { unique: true });
apiUserSchema.index({ email: 1 }, { unique: true });

// Don't return sensitive data by default
apiUserSchema.set('toJSON', {
    transform: (doc, ret) => {
        delete ret.apiSecretHash;
        delete ret.__v;
        return ret;
    }
});

module.exports = mongoose.model('ApiUser', apiUserSchema);