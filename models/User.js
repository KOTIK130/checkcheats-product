const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const userSchema = new mongoose.Schema({
  uid: {
    type: String,
    unique: true,
    required: true,
    default: () => Math.floor(100000 + Math.random() * 900000).toString() // 6-digit UID
  },
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 20
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  group: {
    type: String,
    enum: ['User', 'Admin', 'VIP', 'Moderator'],
    default: 'User'
  },
  hwid: {
    type: String,
    default: null
  },
  subscriptionExpires: {
    type: Date,
    default: null
  },
  downloadToken: {
    type: String,
    default: null
  },
  activatedKey: {
    type: String,
    default: null
  },
  registrationDate: {
    type: Date,
    default: Date.now
  },
  lastLogin: {
    type: Date,
    default: Date.now
  },
  isActive: {
    type: Boolean,
    default: true
  },
  isBanned: {
    type: Boolean,
    default: false
  }
}, { timestamps: true });

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

// Check if subscription is active
userSchema.methods.hasActiveSubscription = function() {
  if (!this.subscriptionExpires) return false;
  return new Date(this.subscriptionExpires) > new Date();
};

// Format subscription expiry date
userSchema.methods.getFormattedSubscriptionDate = function() {
  if (!this.subscriptionExpires) return 'Нет подписки';
  const date = new Date(this.subscriptionExpires);
  return date.toLocaleDateString('ru-RU', { 
    year: 'numeric', 
    month: '2-digit', 
    day: '2-digit' 
  }) + ' ' + date.toLocaleTimeString('ru-RU', {
    hour: '2-digit',
    minute: '2-digit'
  });
};

module.exports = mongoose.model('User', userSchema);