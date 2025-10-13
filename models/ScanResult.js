// models/ScanResult.js - MongoDB Scan Result Schema
const mongoose = require('mongoose');

const scanResultSchema = new mongoose.Schema({
  sessionCode: {
    type: String,
    required: true,
    index: true
  },
  moderatorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  suspectId: {
    type: String,
    required: true
  },
  results: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  summary: {
    totalProcesses: Number,
    suspiciousProcesses: Number,
    riskLevel: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
      default: 'low'
    }
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Indexes for faster queries
scanResultSchema.index({ sessionCode: 1 });
scanResultSchema.index({ moderatorId: 1, createdAt: -1 });

module.exports = mongoose.model('ScanResult', scanResultSchema);
