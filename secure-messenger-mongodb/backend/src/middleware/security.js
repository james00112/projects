const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');
const hpp = require('hpp');
const cors = require('cors');
const { AuditLog } = require('../models/Session');

// Rate limiters
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: 'Too many login attempts, please try again later',
  standardHeaders: true,
  legacyHeaders: false
});

const messageLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60,
  message: 'Too many messages sent, slow down'
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: 'Too many requests'
});

// Security headers
const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"], // Adjust for React dev
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "ws:", "wss:"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
});

// Audit logger middleware
const auditLogger = async (req, res, next) => {
  const originalSend = res.send;
  
  res.send = function(data) {
    // Log after response is sent
    if (req.user && req.method !== 'GET') {
      AuditLog.create({
        userId: req.user.id,
        action: `${req.method}_${req.baseUrl}`,
        resourceType: 'api',
        details: {
          url: req.url,
          method: req.method,
          statusCode: res.statusCode,
          body: req.method === 'POST' ? 'REDACTED' : req.query
        },
        ipAddress: req.ip,
        userAgent: req.get('user-agent')
      }).catch(err => console.error('Audit log failed:', err));
    }
    originalSend.call(this, data);
  };
  
  next();
};

// Input validation
const validateInput = (schema) => {
  return (req, res, next) => {
    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }
    next();
  };
};

// Session revocation check
const checkSessionRevoked = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return next();
  
  const Session = require('../models/Session').Session;
  const session = await Session.findOne({ jwtToken: token });
  
  if (session && session.isRevoked) {
    return res.status(401).json({ error: 'Session revoked' });
  }
  
  next();
};

module.exports = {
  loginLimiter,
  messageLimiter,
  apiLimiter,
  securityHeaders,
  auditLogger,
  validateInput,
  checkSessionRevoked,
  mongoSanitize: mongoSanitize(),
  xss: xss(),
  hpp: hpp(),
  cors: cors({ origin: process.env.FRONTEND_URL, credentials: true })
};