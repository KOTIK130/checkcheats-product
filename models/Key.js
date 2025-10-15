const mongoose = require('mongoose');
const crypto = require('crypto');

const keySchema = new mongoose.Schema({
  key: {
    type: String,
    unique: true,
    required: true
  },
  type: {
    type: String,
    enum: ['30days', '90days', '180days', '365days', 'lifetime'],
    required: true
  },
  status: {
    type: String,
    enum: ['active', 'used', 'expired', 'revoked'],
    default: 'active'
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  usedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  usedAt: {
    type: Date,
    default: null
  },
  expiresAt: {
    type: Date,
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, { timestamps: true });

// Generate unique key
keySchema.statics.generateKey = function() {
  const segments = [];
  for (let i = 0; i < 4; i++) {
    segments.push(crypto.randomBytes(2).toString('hex').toUpperCase());
  }
  return segments.join('-'); // Format: XXXX-XXXX-XXXX-XXXX
};

// Get subscription days based on key type
keySchema.methods.getSubscriptionDays = function() {
  const daysMap = {
    '30days': 30,
    '90days': 90,
    '180days': 180,
    '365days': 365,
    'lifetime': 36500 // 100 years
  };
  return daysMap[this.type] || 0;
};

// Activate key for user
keySchema.methods.activate = async function(userId) {
  if (this.status !== 'active') {
    throw new Error('Ключ недействителен или уже использован');
  }
  
  this.status = 'used';
  this.usedBy = userId;
  this.usedAt = new Date();
  
  const days = this.getSubscriptionDays();
  const expirationDate = new Date();
  expirationDate.setDate(expirationDate.getDate() + days);
  this.expiresAt = expirationDate;
  
  await this.save();
  return expirationDate;
};

module.exports = mongoose.model('Key', keySchema);