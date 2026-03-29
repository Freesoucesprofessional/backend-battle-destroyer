const mongoose = require('mongoose');

const AuditLogSchema = new mongoose.Schema({
  actorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    sparse: true
  },
  actorType: {
    type: String,
    enum: ['admin', 'reseller'],
    required: true
  },
  action: {
    type: String,
    enum: [
      'LOGIN', 'LOGOUT', 'CREATE_USER', 'UPDATE_USER', 'DELETE_USER',
      'UPDATE_USER_CREDITS', 'UPDATE_USER_PASSWORD', 'CREATE_RESELLER',
      'UPDATE_RESELLER', 'DELETE_RESELLER', 'BLOCK_RESELLER', 'GIVE_CREDITS',
      'SEARCH_USER', 'SESSION_CREATED', 'SESSION_EXPIRED', 'BRUTE_FORCE_LOCKOUT',
      'UNAUTHORIZED_ACCESS', 'INVALID_TOKEN'
    ],
    required: true
  },
  targetId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    sparse: true
  },
  targetType: {
    type: String,
    enum: ['user', 'reseller'],
    sparse: true
  },
  changes: {
    type: mongoose.Schema.Types.Mixed,
    default: null
  },
  ip: String,
  userAgent: String,
  success: {
    type: Boolean,
    default: true
  },
  error: String,
  createdAt: {
    type: Date,
    default: Date.now,
    index: true
  }
});

AuditLogSchema.index({ actorId: 1, createdAt: -1 });
AuditLogSchema.index({ targetId: 1, createdAt: -1 });
AuditLogSchema.index({ action: 1, createdAt: -1 });
AuditLogSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('AuditLog', AuditLogSchema);