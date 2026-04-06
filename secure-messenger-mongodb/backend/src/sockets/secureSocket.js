const socketIO = require('socket.io');
const jwt = require('jsonwebtoken');
const CryptoManager = require('../encryption/cryptoManager');
const Message = require('../models/Message');
const Conversation = require('../models/Conversation');
const User = require('../models/User');
const { Session, AuditLog } = require('../models/Session');

class SecureWebSocket {
  constructor(server) {
    this.io = socketIO(server, {
      cors: {
        origin: process.env.FRONTEND_URL,
        credentials: true
      },
      pingTimeout: 60000,
      pingInterval: 25000
    });
    
    this.ephemeralKeys = new Map(); // Store ephemeral keys per session
    this.setupMiddleware();
    this.setupHandlers();
  }
  
  setupMiddleware() {
    this.io.use(async (socket, next) => {
      try {
        const token = socket.handshake.auth.token;
        if (!token) {
          return next(new Error('Authentication required'));
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);
        
        if (!user || !user.isActive) {
          return next(new Error('User not found or inactive'));
        }
        
        socket.userId = decoded.userId;
        socket.user = user;
        
        // Store session
        await Session.findOneAndUpdate(
          { jwtToken: token },
          { socketId: socket.id, lastActivity: new Date() }
        );
        
        next();
      } catch (err) {
        next(new Error('Invalid token'));
      }
    });
  }
  
  setupHandlers() {
    this.io.on('connection', (socket) => {
      console.log(`User ${socket.userId} connected`);
      
      // Join user's room for private messages
      socket.join(`user:${socket.userId}`);
      
      // Handle ephemeral key exchange for perfect forward secrecy
      socket.on('ephemeral-key-exchange', async (data) => {
        try {
          const { ephemeralPublicKey } = data;
          // Generate ephemeral key pair for this session
          const { publicKey, privateKey } = CryptoManager.generateEphemeralKeyPair();
          this.ephemeralKeys.set(socket.id, privateKey);
          
          // Compute shared secret
          const sharedSecret = CryptoManager.computeSharedSecret(
            ephemeralPublicKey,
            privateKey
          );
          
          // Store session key (will be used for this WebSocket session only)
          socket.sessionKey = sharedSecret;
          
          socket.emit('ephemeral-key-exchange-response', {
            ephemeralPublicKey: publicKey
          });
        } catch (err) {
          socket.emit('error', { message: 'Key exchange failed' });
        }
      });
      
      // Handle encrypted message
      socket.on('send-message', async (data) => {
        try {
          const { encryptedContent, iv, tag, salt, conversationId, messageType } = data;
          
          // Decrypt with session key
          const decrypted = CryptoManager.decryptMessage({
            encrypted: encryptedContent,
            iv,
            tag
          }, socket.sessionKey);
          
          const parsedMessage = JSON.parse(decrypted);
          
          // Verify integrity
          if (!CryptoManager.verifyIntegrity(parsedMessage.content, parsedMessage.hash)) {
            throw new Error('Message integrity check failed');
          }
          
          // Get conversation to determine recipients
          const conversation = await Conversation.findById(conversationId)
            .populate('participants');
          
          if (!conversation.participants.some(p => p._id.toString() === socket.userId)) {
            throw new Error('Not a participant');
          }
          
          // Encrypt with conversation's AES key (stored per participant)
          const conversationKey = await this.getConversationKey(conversationId, socket.userId);
          
          const encryptedForStorage = CryptoManager.encryptMessage(
            parsedMessage.content,
            conversationKey
          );
          
          // Save message to database
          const message = new Message({
            conversationId,
            from: socket.userId,
            to: conversation.participants.find(p => p._id.toString() !== socket.userId)._id,
            encryptedContent: encryptedForStorage.encrypted,
            iv: encryptedForStorage.iv,
            tag: encryptedForStorage.tag,
            salt: encryptedForStorage.salt,
            messageHash: CryptoManager.hashMessage(parsedMessage.content),
            messageType,
            ephemeralTimer: parsedMessage.ephemeralTimer || 0
          });
          
          await message.save();
          
          // Update conversation last message
          await Conversation.findByIdAndUpdate(conversationId, {
            lastMessage: message._id,
            lastMessageText: parsedMessage.content.substring(0, 500),
            lastMessageTime: new Date()
          });
          
          // Forward to recipients with their own encryption
          for (const participant of conversation.participants) {
            if (participant._id.toString() !== socket.userId) {
              const recipientKey = await this.getConversationKey(conversationId, participant._id);
              const encryptedForRecipient = CryptoManager.encryptMessage(
                parsedMessage.content,
                recipientKey
              );
              
              this.io.to(`user:${participant._id}`).emit('new-message', {
                messageId: message._id,
                from: socket.userId,
                conversationId,
                encryptedContent: encryptedForRecipient.encrypted,
                iv: encryptedForRecipient.iv,
                tag: encryptedForRecipient.tag,
                timestamp: message.createdAt
              });
            }
          }
          
          // Audit log
          await AuditLog.create({
            userId: socket.userId,
            action: 'message_sent',
            resourceType: 'message',
            resourceId: message._id,
            details: { conversationId, messageType }
          });
          
          socket.emit('message-sent', { messageId: message._id });
          
        } catch (err) {
          console.error('Message send error:', err);
          socket.emit('error', { message: 'Failed to send message' });
        }
      });
      
      // Handle read receipts
      socket.on('mark-read', async ({ messageId, conversationId }) => {
        try {
          await Message.updateOne(
            { _id: messageId },
            { isRead: true, readAt: new Date() }
          );
          
          // Update unread counts
          await Conversation.updateOne(
            { _id: conversationId, 'unreadCounts.userId': socket.userId },
            { $set: { 'unreadCounts.$.count': 0 } }
          );
        } catch (err) {
          console.error('Mark read error:', err);
        }
      });
      
      // Handle typing indicators
      socket.on('typing', ({ conversationId, isTyping }) => {
        socket.to(`conversation:${conversationId}`).emit('user-typing', {
          userId: socket.userId,
          isTyping
        });
      });
      
      // Handle disconnection
      socket.on('disconnect', async () => {
        console.log(`User ${socket.userId} disconnected`);
        this.ephemeralKeys.delete(socket.id);
        
        // Update last seen
        await User.findByIdAndUpdate(socket.userId, { lastSeen: new Date() });
      });
    });
  }
  
  async getConversationKey(conversationId, userId) {
    const conversation = await Conversation.findById(conversationId);
    const keyEntry = conversation.encryptedSymmetricKeys.find(
      k => k.userId.toString() === userId.toString()
    );
    
    if (!keyEntry) {
      throw new Error('No conversation key for user');
    }
    
    // Decrypt with user's private key (would need user's private key here)
    // In practice, you'd cache these or use a key management service
    const user = await User.findById(userId);
    const decryptedKey = CryptoManager.rsaDecrypt(keyEntry.encryptedKey, user.privateKey);
    
    return decryptedKey;
  }
}

module.exports = SecureWebSocket;