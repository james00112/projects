const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  conversationId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Conversation',
    required: true,
    index: true
  },
  from: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  to: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  encryptedContent: {
    type: String, // Base64 encoded AES encrypted message
    required: true
  },
  iv: {
    type: String, // Initialization vector
    required: true
  },
  tag: {
    type: String, // Authentication tag
    required: true
  },
  salt: {
    type: String, // Salt for key derivation
    required: true
  },
  messageHash: {
    type: String, // SHA-256 hash for integrity verification
    required: true
  },
  messageType: {
    type: String,
    enum: ['text', 'image', 'file', 'voice', 'video'],
    default: 'text'
  },
  fileMetadata: {
    filename: String,
    mimeType: String,
    size: Number,
    encryptedFileKey: String // Encrypted file encryption key
  },
  isRead: {
    type: Boolean,
    default: false
  },
  readAt: {
    type: Date
  },
  isDeleted: {
    type: Boolean,
    default: false
  },
  deletedFor: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  reactions: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    emoji: { type: String, maxlength: 2 }
  }],
  replyTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Message'
  },
  ephemeralTimer: {
    type: Number, // Seconds until auto-delete (0 = never)
    default: 0
  },
  expiresAt: {
    type: Date,
    index: { expires: 0 } // TTL index for auto-deletion
  }
}, {
  timestamps: true
});

// Compound indexes for efficient queries
messageSchema.index({ conversationId: 1, createdAt: -1 });
messageSchema.index({ from: 1, to: 1 });
messageSchema.index({ isRead: 1 });
messageSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Set expiration for ephemeral messages
messageSchema.pre('save', function(next) {
  if (this.ephemeralTimer > 0 && !this.expiresAt) {
    this.expiresAt = new Date(Date.now() + this.ephemeralTimer * 1000);
  }
  next();
});

module.exports = mongoose.model('Message', messageSchema);