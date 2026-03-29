const mongoose = require('mongoose');
const crypto   = require('crypto');

const UserSchema = new mongoose.Schema({
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
  isPro:         { type: Boolean, default: false },
  createdAt:     { type: Date, default: Date.now },
});

// FIX: Generate userId AND referralCode together in pre('save').
// Previously auth.js set user.referralCode = user.userId BEFORE pre('save') ran,
// meaning userId was still undefined at that point — causing referralCode to be
// saved as undefined, which broke the unique index and threw a duplicate-key error.
UserSchema.pre('save', async function () {
  if (this.isNew && !this.userId) {
    const hex = crypto.randomBytes(4).toString('hex'); // e.g. "a3f9c21b"
    this.userId      = hex;
    this.referralCode = hex; // set both here — auth.js must NOT touch referralCode
  }
});

module.exports = mongoose.model('User', UserSchema);