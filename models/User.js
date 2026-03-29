const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
  userId:        { type: String, unique: true },
  username:      { type: String, required: true, unique: true, trim: true },
  email:         { type: String, required: true, unique: true, lowercase: true },
  password:      { type: String, required: true },
  credits:       { type: Number, default: 3 },
  referralCode:  { type: String, unique: true },
  referredBy:    { type: String, default: null },
  referralCount: { type: Number, default: 0 },
  ipAddress:     { type: String, default: '' },
  fingerprint:   { type: String, default: '' },
  creditGiven:   { type: Boolean, default: false },
  createdAt:     { type: Date, default: Date.now },
});

module.exports = mongoose.model('User', UserSchema);