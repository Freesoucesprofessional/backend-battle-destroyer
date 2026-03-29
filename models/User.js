const mongoose = require('mongoose');
const crypto   = require('crypto'); // built-in Node module — no install needed

const UserSchema = new mongoose.Schema({
  // Auto-generated 8-char hex ID, e.g. "a3f9c21b"
  // Generated in pre('save') below — never null.
  userId:        { type: String, unique: true },

  username:      { type: String, required: true, unique: true, trim: true },
  email:         { type: String, required: true, unique: true, lowercase: true },
  password:      { type: String, required: true },
  credits:       { type: Number, default: 3 },
  referralCode:  { type: String, unique: true, sparse: true },
  referredBy:    { type: String, default: null },
  referralCount: { type: Number, default: 0 },
  ipAddress:     { type: String, default: '' },
  fingerprint:   { type: String, default: '' },
  creditGiven:   { type: Boolean, default: false },
  isPro:         { type: Boolean, default: false }, // upgraded when user purchases credits
  createdAt:     { type: Date, default: Date.now },
});

// ─── Auto-generate userId before every insert ─────────────────────────────
// This runs only on new documents (isNew guard), so existing users are safe.
UserSchema.pre('save', async function () {
  if (this.isNew && !this.userId) {
    this.userId       = crypto.randomBytes(4).toString('hex'); // 8-char unique hex
    this.referralCode = this.userId; // set both here — no need for double save in auth.js
  }
});

module.exports = mongoose.model('User', UserSchema);