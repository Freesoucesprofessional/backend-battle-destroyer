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
// models/User.js
userSchema.methods.isProUser = function() {
    // Check if user has Pro flag AND subscription is not expired
    if (!this.isPro) return false;
    
    // If no subscription object, not a Pro user
    if (!this.subscription) return false;
    
    // Check if subscription is expired
    if (this.subscription.expiresAt && this.subscription.expiresAt < new Date()) {
        // Auto-downgrade expired Pro users
        this.isPro = false;
        this.save(); // Don't await to avoid blocking
        return false;
    }
    
    return this.subscription.type === 'pro';
};

// Check and reset daily credits for pro users
// User.js - Updated checkAndResetDailyCredits method
UserSchema.methods.checkAndResetDailyCredits = async function() {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  
  const lastReset = this.subscription.lastCreditReset ? new Date(this.subscription.lastCreditReset) : new Date();
  lastReset.setHours(0, 0, 0, 0);
  
  // Reset if new day
  if (lastReset < today) {
    if (this.isProUser()) {
      // Pro users get 30 daily attacks
      this.subscription.dailyCredits = 30;
    } else {
      // Free users get 1 daily credit (or whatever you want)
      this.subscription.dailyCredits = 1;
    }
    this.subscription.lastCreditReset = new Date();
    
    // Reset daily attack count
    this.dailyAttacks = {
      count: 0,
      date: new Date()
    };
    
    await this.save();
    console.log(`[Daily Reset] Reset daily credits for user ${this.username} to ${this.subscription.dailyCredits}`);
  }
  
  return this.subscription.dailyCredits;
};

// Also add a method to manually refresh Pro benefits
UserSchema.methods.refreshProBenefits = async function() {
  if (this.isProUser()) {
    // Reset daily credits to 30
    this.subscription.dailyCredits = 30;
    this.subscription.lastCreditReset = new Date();
    
    // Reset today's attack count
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    this.dailyAttacks = {
      count: 0,
      date: today
    };
    
    await this.save();
    return true;
  }
  return false;
};

// Check if user can attack
userSchema.methods.canAttack = async function() {
    // ✅ PRO USERS HAVE NO DAILY LIMIT - Check this FIRST!
    if (this.isProUser()) {
        // Only check if subscription is active
        if (this.subscription && this.subscription.expiresAt > new Date()) {
            return true;  // Unlimited attacks for Pro users
        }
        // If subscription expired, fall through to free user logic
    }
    
    // ==========================================
    // FREE USERS ONLY FROM HERE
    // ==========================================
    
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    // Initialize dailyAttacks if needed
    if (!this.dailyAttacks) {
        this.dailyAttacks = { count: 0, date: today };
        await this.save();
    }
    
    // Reset daily attacks if new day
    if (this.dailyAttacks.date < today) {
        this.dailyAttacks = { count: 0, date: today };
        await this.save();
    }
    
    // Free users: Check if they've reached 30 daily attacks
    if (this.dailyAttacks.count >= 30) {
        return false;  // Free user reached daily limit
    }
    
    // Free users also need credits
    return this.credits > 0;
};
// Use one attack
userSchema.methods.useAttack = async function() {
    // ✅ Pro users: Track for stats but no deduction
    if (this.isProUser()) {
        // Check if subscription is active
        if (this.subscription && this.subscription.expiresAt > new Date()) {
            // Only track for statistics, not for limiting
            this.totalAttacks = (this.totalAttacks || 0) + 1;
            
            // Optional: Track daily stats for Pro users (but don't limit)
            const today = new Date();
            today.setHours(0, 0, 0, 0);
            
            if (!this.dailyAttacks || this.dailyAttacks.date < today) {
                this.dailyAttacks = { count: 1, date: today };
            } else {
                this.dailyAttacks.count += 1;
            }
            
            await this.save();
            return true;
        }
        // If expired, fall through to free user logic
    }
    
    // FREE USERS: Deduct one credit/attack
    if (this.credits > 0) {
        this.credits -= 1;
        this.totalAttacks = (this.totalAttacks || 0) + 1;
        
        // Also track daily attacks for free users
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        if (!this.dailyAttacks || this.dailyAttacks.date < today) {
            this.dailyAttacks = { count: 1, date: today };
        } else {
            this.dailyAttacks.count += 1;
        }
        
        await this.save();
        return true;
    }
    
    return false;
};
// Get remaining attacks for today
userSchema.methods.getRemainingAttacks = async function() {
    // ✅ Pro users have unlimited attacks
    if (this.isProUser()) {
        // Check if subscription is active
        if (this.subscription && this.subscription.expiresAt > new Date()) {
            return Infinity;  // Unlimited!
        }
        // If expired, treat as free user
    }
    
    // FREE USERS: remaining daily attacks or credits
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    if (!this.dailyAttacks || this.dailyAttacks.date < today) {
        return Math.min(30, this.credits);
    }
    
    const remainingDaily = Math.max(0, 30 - this.dailyAttacks.count);
    const remainingCredits = this.credits;
    
    return Math.min(remainingDaily, remainingCredits);
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