// create-admin.js - Create test admin user
require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('./models/User');

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/checkcheats';

async function createAdmin() {
  try {
    await mongoose.connect(MONGODB_URI);
    console.log('✅ Connected to MongoDB');

    // Check if admin exists
    const existing = await User.findOne({ username: 'admin' });
    if (existing) {
      console.log('❌ Admin user already exists');
      process.exit(0);
    }

    // Create admin user
    const hashedPassword = await bcrypt.hash('admin123', 10);
    const admin = new User({
      username: 'admin',
      email: 'admin@checkcheats.com',
      password: hashedPassword,
      role: 'admin',
      uid: 'ADMIN-' + Math.random().toString(36).substr(2, 8).toUpperCase(),
      subscriptionType: 'lifetime',
      subscriptionExpires: null
    });

    await admin.save();
    console.log('✅ Admin user created successfully!');
    console.log('Username: admin');
    console.log('Password: admin123');
    console.log('UID:', admin.uid);

    process.exit(0);
  } catch (err) {
    console.error('❌ Error:', err.message);
    process.exit(1);
  }
}

createAdmin();
