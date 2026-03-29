const mongoose = require('mongoose');
const { nanoid } = require('nanoid');

const UserSchema = new mongoose.Schema({
  userId: {
    type: String,
    unique: true,
  },
  username: { type: String, required: true, unique: true, trim: true },
  email:    { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  credits:  { type: Number, default: 3 },

  // Referral system
  referralCode:  { type: String, unique: true },
  referredBy:    { type: String, default: null },
  referralCount: { type: Number, default: 0 },

  // Anti-abuse
  ipAddress:   { type: String, default: '' },
  fingerprint: { type: String, default: '' },
  creditGiven: { type: Boolean, default: false },

  createdAt: { type: Date, default: Date.now },
});

// Auto-generate userId + referralCode before save
UserSchema.pre('save', function(next) {
  if (!this.userId) {
    this.userId = nanoid(10);
  }
  if (!this.referralCode) {
    this.referralCode = this.userId;
  }
  next();
});

module.exports = mongoose.model('User', UserSchema);