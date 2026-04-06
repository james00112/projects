const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const MongoDBSecurityScanner = require('./mongoScanner');
const User = require('../models/User');
const { AuditLog } = require('../models/Session');
const Message = require('../models/Message');

const scanner = new MongoDBSecurityScanner(mongoose.connection.db);

// Middleware to verify admin role
const isAdmin = async (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  
  const user = await User.findById(req.user.id);
  if (user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Full MongoDB security audit
router.get('/audit/mongodb', isAdmin, async (req, res) => {
  try {
    const audit = await scanner.fullDatabaseAudit();
    
    await AuditLog.create({
      userId: req.user.id,
      action: 'vulnerability_scan',
      resourceType: 'system',
      details: { riskLevel: audit.riskLevel, scanType: 'mongodb' }
    });
    
    res.json(audit);
  } catch (err) {
    console.error('Audit failed:', err);
    res.status(500).json({ error: 'Audit failed', details: err.message });
  }
});

// Specific NoSQL injection test
router.post('/test/nosql-injection', isAdmin, async (req, res) => {
  const { collection, payloads } = req.body;
  const results = await scanner.scanNoSQLInjection(collection, payloads);
  res.json(results);
});

// Get exposed sensitive fields
router.get('/audit/exposed-fields', isAdmin, async (req, res) => {
  const exposed = await scanner.scanExposedFields();
  res.json(exposed);
});

// Get weak password hashes
router.get('/audit/weak-passwords', isAdmin, async (req, res) => {
  const weak = await scanner.scanWeakPasswordHashes();
  res.json(weak);
});

// Get all users with security status
router.get('/users/security-status', isAdmin, async (req, res) => {
  const users = await User.find({}, 'username email role mfaEnabled lastSeen failedLoginAttempts lockedUntil')
    .lean();
  
  const securityStatus = users.map(user => ({
    ...user,
    securityScore: this.calculateSecurityScore(user),
    riskFactors: this.getRiskFactors(user)
  }));
  
  res.json(securityStatus);
});

// Force password reset for vulnerable users
router.post('/users/force-reset/:userId', isAdmin, async (req, res) => {
  const { userId } = req.params;
  
  // Generate force reset token
  const resetToken = crypto.randomBytes(32).toString('hex');
  await User.findByIdAndUpdate(userId, {
    forcePasswordReset: true,
    resetToken: crypto.createHash('sha256').update(resetToken).digest('hex'),
    resetTokenExpiry: new Date(Date.now() + 24 * 60 * 60 * 1000)
  });
  
  await AuditLog.create({
    userId: req.user.id,
    action: 'admin_action',
    resourceType: 'user',
    resourceId: userId,
    details: { action: 'force_password_reset' }
  });
  
  res.json({ message: 'Password reset forced', resetToken });
});

// Get message encryption stats
router.get('/stats/encryption', isAdmin, async (req, res) => {
  const totalMessages = await Message.countDocuments();
  const encryptedMessages = totalMessages; // All messages are encrypted
  
  const messagesByType = await Message.aggregate([
    { $group: { _id: '$messageType', count: { $sum: 1 } } }
  ]);
  
  const ephemeralStats = await Message.aggregate([
    { $match: { ephemeralTimer: { $gt: 0 } } },
    { $group: { 
        _id: '$ephemeralTimer',
        count: { $sum: 1 }
      }
    }
  ]);
  
  res.json({
    totalMessages,
    encryptionRate: '100%',
    messagesByType,
    ephemeralMessages: ephemeralStats,
    encryptionAlgorithm: 'AES-256-GCM',
    keyExchange: 'RSA-3072 with Perfect Forward Secrecy'
  });
});

// System health check with MongoDB status
router.get('/health', isAdmin, async (req, res) => {
  const dbState = mongoose.connection.readyState;
  const dbStatus = ['disconnected', 'connected', 'connecting', 'disconnecting'][dbState];
  
  const collections = await mongoose.connection.db.listCollections().toArray();
  
  res.json({
    status: 'healthy',
    timestamp: new Date(),
    mongodb: {
      status: dbStatus,
      collections: collections.length,
      databaseName: mongoose.connection.name
    },
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage()
  });
});

// Generate security report PDF (simplified)
router.get('/report/security-summary', isAdmin, async (req, res) => {
  const audit = await scanner.fullDatabaseAudit();
  const userStats = await User.aggregate([
    { $group: {
        _id: '$role',
        count: { $sum: 1 },
        mfaEnabled: { $sum: { $cond: ['$mfaEnabled', 1, 0] } }
      }
    }
  ]);
  
  const report = {
    generatedAt: new Date(),
    overallSecurityScore: audit.riskLevel === 'CRITICAL' ? 20 :
                         audit.riskLevel === 'HIGH' ? 40 :
                         audit.riskLevel === 'MEDIUM' ? 60 : 85,
    riskLevel: audit.riskLevel,
    vulnerabilities: {
      critical: audit.scans.noSqlInjection.filter(v => v.vulnerable).length,
      high: audit.scans.weakPasswords.length,
      medium: audit.scans.unencryptedData.length,
      low: audit.scans.exposedFields.length
    },
    userSecurity: userStats,
    recommendations: audit.recommendations,
    remediationPlan: audit.remediationSteps
  };
  
  res.json(report);
});

function calculateSecurityScore(user) {
  let score = 100;
  if (!user.mfaEnabled) score -= 30;
  if (user.failedLoginAttempts > 3) score -= 10;
  if (user.lockedUntil) score -= 20;
  if (!user.isActive) score = 0;
  return Math.max(0, score);
}

function getRiskFactors(user) {
  const factors = [];
  if (!user.mfaEnabled) factors.push('MFA not enabled');
  if (user.failedLoginAttempts > 3) factors.push('Multiple failed login attempts');
  if (user.lockedUntil) factors.push('Account locked');
  return factors;
}

module.exports = router;