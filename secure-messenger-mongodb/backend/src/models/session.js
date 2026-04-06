const mongoose = require('mongoose');

const sessionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    index: true
  },
  socketId: {
    type: String,
    unique: true,
    sparse: true
  },
  jwtToken: {
    type: String,
    required: true
  },
  refreshToken: {
    type: String,
    required: true
  },
  ipAddress: {
    type: String,
    required: true
  },
  userAgent: {
    type: String,
    required: true
  },
  deviceFingerprint: {
    type: String
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expires: 0 }
  },
  lastActivity: {
    type: Date,
    default: Date.now
  },
  isRevoked: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true
});

const auditLogSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  action: {
    type: String,
    required: true,
    enum: ['login', 'logout', 'message_sent', 'message_deleted', 'conversation_created', 
           'settings_changed', 'password_changed', 'mfa_enabled', 'mfa_disabled',
           'admin_action', 'vulnerability_scan', 'user_banned', 'user_unbanned']
  },
  resourceType: {
    type: String,
    enum: ['user', 'message', 'conversation', 'system', 'admin']
  },
  resourceId: {
    type: String
  },
  details: {
    type: mongoose.Schema.Types.Mixed
  },
  ipAddress: {
    type: String
  },
  userAgent: {
    type: String
  },
  status: {
    type: String,
    enum: ['success', 'failure', 'pending'],
    default: 'success'
  },
  timestamp: {
    type: Date,
    default: Date.now,
    index: { expires: '90d' } // Keep logs for 90 days
  }
});

auditLogSchema.index({ userId: 1, timestamp: -1 });
auditLogSchema.index({ action: 1, timestamp: -1 });

module.exports = {
  Session: mongoose.model('Session', sessionSchema),
  AuditLog: mongoose.model('AuditLog', auditLogSchema)
};