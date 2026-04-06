const mongoose = require('mongoose');

const conversationSchema = new mongoose.Schema({
  participants: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }],
  isGroup: {
    type: Boolean,
    default: false
  },
  groupName: {
    type: String,
    trim: true,
    maxlength: 100
  },
  groupAvatar: {
    type: String
  },
  groupAdmin: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  encryptedSymmetricKeys: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    encryptedKey: { type: String } // RSA encrypted AES key for this conversation
  }],
  lastMessage: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Message'
  },
  lastMessageText: {
    type: String,
    maxlength: 500
  },
  lastMessageTime: {
    type: Date,
    default: Date.now
  },
  unreadCounts: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    count: { type: Number, default: 0 }
  }],
  mutedFor: [{
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    until: { type: Date }
  }],
  pinnedFor: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  isArchived: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }]
}, {
  timestamps: true
});

conversationSchema.index({ participants: 1 });
conversationSchema.index({ lastMessageTime: -1 });
conversationSchema.index({ isGroup: 1 });

module.exports = mongoose.model('Conversation', conversationSchema);