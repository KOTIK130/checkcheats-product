// models/User.js - MongoDB User Schema with License System
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ['user', 'admin', 'moderator'],
    default: 'user'
  },
  uid: {
    type: String,
    unique: true,
    sparse: true,
    uppercase: true
  },
  hwid: {
    type: String,
    default: null
  },
  subscriptionType: {
    type: String,
    enum: ['none', '30days', '90days', 'lifetime'],
    default: 'none'
  },
  subscriptionExpires: {
    type: Date,
    default: null
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: {
    type: Date
  }
}, {
  timestamps: true
});

userSchema.index({ username: 1 });
userSchema.index({ email: 1 });
userSchema.index({ uid: 1 });

module.exports = mongoose.model('User', userSchema);
