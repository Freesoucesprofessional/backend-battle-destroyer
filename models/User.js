// models/User.js
const mongoose = require('mongoose');
const crypto = require('crypto');

const UserSchema = new mongoose.Schema({
  userId: { type: String, unique: true },
  username: { type: String, required: true, unique: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  
  // NEW: Subscription system instead of simple credits
  credits: { type: Number, default: 1 }, // Free users: 10 free credits on signup
  
  // Subscription details
  subscription: {
    type: {
      type: String,
      enum: ['free', 'pro'],
      default: 'free'
    },
    plan: {
      type: String,
      enum: ['none', 'week', 'month', 'season','custom'],
      default: 'none'
    },
    expiresAt: {
      type: Date,
      default: null
    },
    dailyCredits: {
      type: Number,
      default: 1 // Free users get 10 daily credits (but they use credits balance)
    },
    lastCreditReset: {
      type: Date,
      default: Date.now
    }
  },
  
  // Daily attack tracking
  dailyAttacks: {
    count: { type: Number, default: 0 },
    date: { type: Date, default: Date.now }
  },
  totalAttacks: { type: Number, default: 0 },
  
  // Referral system
  referralCode: { type: String, unique: true, sparse: true },
  referredBy: { type: String, default: null },
  referralCount: { type: Number, default: 0 },
  
  // Anti-abuse
  ipAddress: { type: String, default: '' },
  fingerprint: { type: String, default: '' },
  creditGiven: { type: Boolean, default: false },
  
  isPro: { type: Boolean, default: false }, // Legacy field, will be replaced by subscription.type
  createdAt: { type: Date, default: Date.now },
});

// Generate userId AND referralCode
UserSchema.pre('save', async function () {
  if (this.isNew && !this.userId) {
    const hex = crypto.randomBytes(4).toString('hex');
    this.userId = hex;
    this.referralCode = hex;
  }
});

// Check if user has active pro subscription
UserSchema.methods.isProUser = function() {
  if (this.subscription.type !== 'pro') return false;
  if (!this.subscription.expiresAt) return false;
  return this.subscription.expiresAt > new Date();
};

// Check and reset daily credits for pro users
UserSchema.methods.checkAndResetDailyCredits = async function() {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  
  const lastReset = new Date(this.subscription.lastCreditReset);
  lastReset.setHours(0, 0, 0, 0);
  
  // Reset if new day
  if (lastReset < today) {
    if (this.isProUser()) {
      // Pro users get 30 daily credits (free attacks)
      this.subscription.dailyCredits = 30;
    } else {
      // Free users get daily limit of 10 attacks (but they still use credits)
      this.subscription.dailyCredits = 1;
    }
    this.subscription.lastCreditReset = new Date();
    
    // Reset daily attack count
    this.dailyAttacks.count = 0;
    this.dailyAttacks.date = new Date();
    
    await this.save();
  }
  
  return this.subscription.dailyCredits;
};

// Check if user can attack
UserSchema.methods.canAttack = async function() {
  await this.checkAndResetDailyCredits();
  
  if (this.isProUser()) {
    // Pro users: check daily credits
    return this.subscription.dailyCredits > 0;
  } else {
    // Free users: check credit balance
    return this.credits > 0;
  }
};

// Use one attack
UserSchema.methods.useAttack = async function() {
  await this.checkAndResetDailyCredits();
  
  if (this.isProUser()) {
    // Pro users: deduct from daily credits
    if (this.subscription.dailyCredits <= 0) {
      throw new Error('Daily attack limit reached. Please try again tomorrow.');
    }
    this.subscription.dailyCredits -= 1;
  } else {
    // Free users: deduct from credits
    if (this.credits <= 0) {
      throw new Error('Insufficient credits. Please purchase credits or upgrade to pro.');
    }
    this.credits -= 1;
  }
  
  // Update daily attack count
  this.dailyAttacks.count += 1;
  this.totalAttacks += 1;
  
  await this.save();
  return true;
};

// Get remaining attacks for today
UserSchema.methods.getRemainingAttacks = async function() {
  await this.checkAndResetDailyCredits();
  
  if (this.isProUser()) {
    return this.subscription.dailyCredits;
  } else {
    return this.credits;
  }
};

// Get max attack duration
UserSchema.methods.getMaxDuration = function() {
  return this.isProUser() ? 300 : 60;
};

UserSchema.methods.addProSubscription = function(planType, customDays = null) {
  const planDays = {
    week: 7,
    month: 30,
    season: 60,
    custom: customDays || 30 // Default to 30 days for custom if not specified
  };
  
  let days;
  let plan = planType;
  
  if (planType === 'custom' && customDays) {
    days = parseInt(customDays);
    plan = 'custom';
  } else {
    days = planDays[planType];
    if (!days) throw new Error('Invalid plan type');
  }
  
  if (isNaN(days) || days < 1 || days > 365) {
    throw new Error('Days must be between 1 and 365');
  }
  
  this.subscription.type = 'pro';
  this.subscription.plan = plan;
  
  const currentExpiry = this.subscription.expiresAt;
  let newExpiry = new Date();
  
  if (currentExpiry && currentExpiry > newExpiry) {
    // Extend existing subscription
    newExpiry = new Date(currentExpiry);
    newExpiry.setDate(newExpiry.getDate() + days);
  } else {
    // New subscription
    newExpiry.setDate(newExpiry.getDate() + days);
  }
  
  this.subscription.expiresAt = newExpiry;
  this.subscription.dailyCredits = 30;
  this.subscription.lastCreditReset = new Date();
  this.isPro = true;
  
  return days;
};

// Get subscription expiry text
UserSchema.methods.getSubscriptionStatus = function() {
  if (!this.isProUser()) {
    return { active: false, daysLeft: 0 };
  }
  
  const daysLeft = Math.ceil((this.subscription.expiresAt - new Date()) / (1000 * 60 * 60 * 24));
  return {
    active: true,
    daysLeft: daysLeft,
    plan: this.subscription.plan,
    expiresAt: this.subscription.expiresAt
  };
};

module.exports = mongoose.model('User', UserSchema);