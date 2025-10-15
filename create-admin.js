require('dotenv').config();
const mongoose = require('mongoose');
const User = require('./models/User');

async function createAdmin() {
    try {
        // Connect to MongoDB
        await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        
        console.log('✅ Connected to MongoDB');
        
        // Admin credentials
        const adminData = {
            username: 'admin',
            email: 'admin@nursultan.com',
            password: 'admin123', // Change this password!
            group: 'Admin'
        };
        
        // Check if admin already exists
        const existingAdmin = await User.findOne({ 
            $or: [
                { username: adminData.username },
                { email: adminData.email }
            ]
        });
        
        if (existingAdmin) {
            console.log('❌ Admin user already exists!');
            if (existingAdmin.group !== 'Admin') {
                existingAdmin.group = 'Admin';
                await existingAdmin.save();
                console.log('✅ Updated existing user to Admin');
            }
        } else {
            // Create new admin
            const admin = new User(adminData);
            await admin.save();
            
            console.log('✅ Admin user created successfully!');
            console.log('📧 Email:', adminData.email);
            console.log('👤 Username:', adminData.username);
            console.log('🔑 Password:', adminData.password);
            console.log('🆔 UID:', admin.uid);
            console.log('\n⚠️  IMPORTANT: Change the password after first login!');
        }
        
    } catch (error) {
        console.error('❌ Error:', error.message);
    } finally {
        await mongoose.connection.close();
        console.log('👋 Database connection closed');
        process.exit(0);
    }
}

createAdmin();