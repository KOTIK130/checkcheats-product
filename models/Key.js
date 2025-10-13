// models/Key.js - MongoDB License Key Schema
const mongoose = require('mongoose');

const keySchema = new mongoose.Schema({
  key: {
    type: String,
    required: true,
    unique: true,
    uppercase: true,
    trim: true
  },
  type: {
    type: String,
    enum: ['30days', '90days', 'lifetime'],
    required: true
  },
  status: {
    type: String,
    enum: ['active', 'used', 'expired', 'banned'],
    default: 'active'
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
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  expiresAt: {
    type: Date,
    default: null
  },
  notes: {
    type: String,
    default: ''
  }
}, {
  timestamps: true
});

keySchema.index({ key: 1 });
keySchema.index({ status: 1 });
keySchema.index({ usedBy: 1 });

module.exports = mongoose.model('Key', keySchema);
