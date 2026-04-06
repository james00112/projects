require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const http = require('http');
const securityMiddleware = require('./src/middleware/security');
const SecureWebSocket = require('./src/sockets/secureSocket');
const adminRoutes = require('./src/admin/adminRoutes');

const app = express();
const server = http.createServer(app);

// Connect to MongoDB with secure options
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
  family: 4
}).then(() => {
  console.log('✅ MongoDB connected securely');
  // Enable MongoDB encryption at rest warning
  console.log('⚠️  Ensure MongoDB encryption at rest is enabled in production');
}).catch(err => {
  console.error('MongoDB connection error:', err);
  process.exit(1);
});

// Apply security middleware
app.use(securityMiddleware.securityHeaders);
app.use(securityMiddleware.mongoSanitize);
app.use(securityMiddleware.xss);
app.use(securityMiddleware.hpp);
app.use(securityMiddleware.cors);
app.use(express.json({ limit: '10mb' }));
app.use(securityMiddleware.apiLimiter);
app.use(securityMiddleware.auditLogger);
app.use(securityMiddleware.checkSessionRevoked);

// Routes
app.use('/api/admin', adminRoutes);
app.use('/api/auth', require('./src/routes/auth'));
app.use('/api/users', require('./src/routes/users'));
app.use('/api/conversations', require('./src/routes/conversations'));

// Initialize secure WebSocket
const wsServer = new SecureWebSocket(server);

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🔒 Secure messenger server running on port ${PORT}`);
  console.log(`📡 WebSocket server ready`);
  console.log(`🛡️  Security features: AES-256-GCM, RSA-3072, Perfect Forward Secrecy`);
  console.log(`🗄️  MongoDB audit logging active`);
});