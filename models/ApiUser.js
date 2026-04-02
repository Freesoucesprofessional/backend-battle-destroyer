// models/ApiUser.js - ADDED expiration fields
const mongoose = require('mongoose');
const crypto = require('crypto');

const apiUserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true },
    apiKey: { type: String, required: true, unique: true },
    apiSecret: { type: String, required: true, unique: true },
    status: { type: String, enum: ['active', 'suspended', 'expired'], default: 'active' },
    
    // EXPIRATION FIELDS - ADD THESE
    expiresAt: { type: Date, default: null },  // When account expires
    createdAt: { type: Date, default: Date.now },
    
    // ONLY TWO LIMITS
    limits: {
        maxConcurrent: { type: Number, default: 2 },
        maxDuration: { type: Number, default: 300 }
    },
    
    // Track active attacks only
    activeAttacks: [{
        attackId: { type: String, required: true },
        target: String,
        port: Number,
        startedAt: { type: Date, default: Date.now },
        expiresAt: Date
    }],
    
    // Simple stats
    totalAttacks: { type: Number, default: 0 },
    totalRequests: { type: Number, default: 0 },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    lastLoginAt: { type: Date }
});

// Generate API credentials
apiUserSchema.statics.generateApiKey = function() {
    return 'ak_' + crypto.randomBytes(24).toString('hex');
};

apiUserSchema.statics.generateApiSecret = function() {
    return 'as_' + crypto.randomBytes(32).toString('hex');
};

// Check if account is expired
apiUserSchema.methods.isExpired = function() {
    if (!this.expiresAt) return false;
    return new Date() > new Date(this.expiresAt);
};

// Get days remaining
apiUserSchema.methods.getDaysRemaining = function() {
    if (!this.expiresAt) return null;
    const days = Math.ceil((new Date(this.expiresAt) - new Date()) / (1000 * 60 * 60 * 24));
    return days > 0 ? days : 0;
};

// Extend expiration by days
apiUserSchema.methods.extendExpiration = async function(days) {
    if (!this.expiresAt) {
        this.expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
    } else {
        this.expiresAt = new Date(new Date(this.expiresAt).getTime() + days * 24 * 60 * 60 * 1000);
    }
    if (this.status === 'expired') {
        this.status = 'active';
    }
    await this.save();
    return this.expiresAt;
};

// Set expiration (30 days from now)
apiUserSchema.methods.setDefaultExpiration = async function() {
    this.expiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await this.save();
    return this.expiresAt;
};

// Clean expired attacks (static method for cleanup job)
apiUserSchema.statics.cleanExpiredAttacks = async function() {
    const now = new Date();
    const result = await this.updateMany(
        { 'activeAttacks.expiresAt': { $lt: now } },
        { $pull: { activeAttacks: { expiresAt: { $lt: now } } } }
    );
    
    // Also update expired accounts
    const expiredResult = await this.updateMany(
        { expiresAt: { $lt: now }, status: 'active' },
        { status: 'expired' }
    );
    
    if (result.modifiedCount > 0 || expiredResult.modifiedCount > 0) {
        console.log(`Cleaned ${result.modifiedCount} attacks, ${expiredResult.modifiedCount} accounts expired`);
    }
    return result;
};

// Get current active attack count (real-time)
apiUserSchema.methods.getActiveCount = async function() {
    const now = new Date();
    const beforeCount = this.activeAttacks.length;
    this.activeAttacks = this.activeAttacks.filter(a => a.expiresAt > now);
    
    if (beforeCount !== this.activeAttacks.length) {
        await this.save();
    }
    return this.activeAttacks.length;
};

// Add active attack
apiUserSchema.methods.addActiveAttack = async function(attackId, target, port, duration) {
    // Check if expired
    if (this.isExpired()) {
        throw new Error('Account has expired');
    }
    
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

// Remove active attack
apiUserSchema.methods.removeActiveAttack = async function(attackId) {
    this.activeAttacks = this.activeAttacks.filter(a => a.attackId !== attackId);
    await this.save();
};

// Clean expired attacks for this user
apiUserSchema.methods.cleanExpired = async function() {
    const now = new Date();
    const beforeCount = this.activeAttacks.length;
    this.activeAttacks = this.activeAttacks.filter(a => a.expiresAt > now);
    if (beforeCount !== this.activeAttacks.length) {
        await this.save();
    }
    return this.activeAttacks.length;
};

module.exports = mongoose.model('ApiUser', apiUserSchema);