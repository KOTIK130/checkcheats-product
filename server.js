// server.js - CheckCheats Anti-Cheat Server with MongoDB
// Version 2.0.0 - Complete MongoDB Migration
const express = require('express');
const http = require('http');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const winston = require('winston');
require('dotenv').config();

const User = require('./models/User');
const Session = require('./models/Session');
const ScanResult = require('./models/ScanResult');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console({ format: winston.format.simple() })
  ]
});

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] },
  pingInterval: 10000,
  pingTimeout: 5000
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key-change-me';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/checkcheats';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => logger.info('MongoDB connected successfully'))
.catch(err => {
  logger.error('MongoDB connection error:', err);
  process.exit(1);
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests from this IP' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', limiter);

const activeSessions = new Map();

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1] || req.cookies.token;
  if (!token) {
    return res.status(401).json({ error: 'Access denied' });
  }
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

io.on('connection', (socket) => {
  logger.info('User connected: ' + socket.id);
  
  socket.on('join-session', async (data) => {
    const { code, type, hwid } = data;
    logger.info('Join attempt: code=' + code + ', type=' + type + ', socket=' + socket.id);
    
    if (!code || !type) {
      socket.emit('error', { message: 'Invalid data' });
      return;
    }
    
    try {
      const session = await Session.findOne({ 
        code, 
        expiresAt: { $gt: new Date() } 
      });
      
      if (!session) {
        socket.emit('error', { message: 'Session not found or expired' });
        return;
      }
      
      if (type === 'suspect') {
        socket.join(code);
        const sessionData = activeSessions.get(code) || {};
        sessionData.suspectSocket = socket;
        activeSessions.set(code, sessionData);
        
        session.status = 'active';
        await session.save();
        
        socket.emit('session-joined', { role: 'suspect', code });
        
        if (sessionData.moderatorSocket) {
          sessionData.moderatorSocket.emit('suspect-connected', { code });
        }
        
        logger.info('Suspect joined: ' + code);
      } 
      else if (type === 'moderator') {
        socket.join(code);
        const sessionData = activeSessions.get(code) || {};
        sessionData.moderatorSocket = socket;
        activeSessions.set(code, sessionData);
        
        socket.emit('session-joined', { role: 'moderator', code });
        
        if (sessionData.suspectSocket) {
          socket.emit('suspect-connected', { code });
        }
        
        logger.info('Moderator joined: ' + code);
      }
    } catch (err) {
      logger.error('Join session error:', err);
      socket.emit('error', { message: 'Server error' });
    }
  });
  
  socket.on('request-scan', async (data) => {
    const { code } = data;
    const sessionData = activeSessions.get(code);
    
    if (!sessionData || !sessionData.suspectSocket) {
      socket.emit('error', { message: 'Suspect not connected' });
      return;
    }
    
    try {
      const session = await Session.findOne({ code });
      if (session) {
        session.status = 'scanning';
        await session.save();
      }
      
      sessionData.suspectSocket.emit('scan-request', { code });
      logger.info('Scan requested for: ' + code);
    } catch (err) {
      logger.error('Request scan error:', err);
    }
  });
  
  socket.on('scan-results', async (data) => {
    const { code, results } = data;
    const sessionData = activeSessions.get(code);
    
    if (!sessionData) {
      socket.emit('error', { message: 'Session not found' });
      return;
    }
    
    try {
      const session = await Session.findOne({ code }).populate('moderatorId');
      if (session) {
        session.results = results;
        session.status = 'completed';
        await session.save();
        
        const scanResult = new ScanResult({
          sessionCode: code,
          moderatorId: session.moderatorId,
          suspectId: session.suspectId,
          results: results,
          summary: {
            totalProcesses: results.processes?.length || 0,
            suspiciousProcesses: results.suspicious?.length || 0,
            riskLevel: results.riskLevel || 'low'
          }
        });
        await scanResult.save();
        
        if (sessionData.moderatorSocket) {
          sessionData.moderatorSocket.emit('scan-results', { code, results });
        }
        
        logger.info('Scan completed for: ' + code);
      }
    } catch (err) {
      logger.error('Save scan results error:', err);
    }
  });
  
  socket.on('disconnect', () => {
    logger.info('User disconnected: ' + socket.id);
    
    for (let [code, sessionData] of activeSessions.entries()) {
      if (sessionData.moderatorSocket === socket || sessionData.suspectSocket === socket) {
        if (sessionData.moderatorSocket === socket) {
          sessionData.moderatorSocket = null;
          if (sessionData.suspectSocket) {
            sessionData.suspectSocket.emit('moderator-disconnected');
          }
        }
        if (sessionData.suspectSocket === socket) {
          sessionData.suspectSocket = null;
          if (sessionData.moderatorSocket) {
            sessionData.moderatorSocket.emit('suspect-disconnected');
          }
        }
        
        if (!sessionData.moderatorSocket && !sessionData.suspectSocket) {
          activeSessions.delete(code);
        }
      }
    }
  });
});

app.get('/', (req, res) => {
  const token = req.cookies.token;
  let user = null;
  if (token) {
    try {
      user = jwt.verify(token, JWT_SECRET);
    } catch (err) {}
  }
  res.render('index', { user });
});

app.get('/register', (req, res) => {
  res.render('register', { error: null, user: null });
});

app.get('/login', (req, res) => {
  res.render('login', { error: null, user: null });
});

app.get('/dashboard', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    const sessions = await Session.find({ moderatorId: req.user.userId })
      .sort({ createdAt: -1 })
      .limit(10);
    
    res.render('dashboard', { user, sessions });
  } catch (err) {
    logger.error('Dashboard error:', err);
    res.status(500).send('Server error');
  }
});

app.get('/products', (req, res) => {
  const token = req.cookies.token;
  let user = null;
  if (token) {
    try {
      user = jwt.verify(token, JWT_SECRET);
    } catch (err) {}
  }
  res.render('products', { user });
});

app.get('/change-password', authenticateToken, (req, res) => {
  res.render('change-password', { error: null, user: req.user });
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

app.get('/admin', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    const totalSessions = await Session.countDocuments();
    const activeSessionsCount = await Session.countDocuments({ 
      status: { $in: ['pending', 'active', 'scanning'] } 
    });
    const totalScans = await ScanResult.countDocuments();
    
    res.render('admin', { 
      user: req.user, 
      users, 
      stats: { totalSessions, activeSessions: activeSessionsCount, totalScans } 
    });
  } catch (err) {
    logger.error('Admin panel error:', err);
    res.status(500).send('Server error');
  }
});

app.post('/register', [
  body('username').isLength({ min: 3 }).trim().escape(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render('register', { error: errors.array(), user: null });
  }
  
  const { username, email, password } = req.body;
  
  try {
    const existingUser = await User.findOne({ 
      $or: [{ username }, { email }] 
    });
    
    if (existingUser) {
      return res.render('register', { 
        error: [{ msg: 'Username or email already exists' }], 
        user: null 
      });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username,
      email,
      password: hashedPassword
    });
    
    await user.save();
    logger.info('User registered: ' + username);
    
    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.cookie('token', token, { 
      httpOnly: true, 
      maxAge: 7 * 24 * 60 * 60 * 1000 
    });
    
    res.redirect('/dashboard');
  } catch (err) {
    logger.error('Registration error:', err);
    res.render('register', { 
      error: [{ msg: 'Server error' }], 
      user: null 
    });
  }
});

app.post('/login', [
  body('username').trim().escape(),
  body('password').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render('login', { error: errors.array(), user: null });
  }
  
  const { username, password } = req.body;
  
  try {
    const user = await User.findOne({ username });
    
    if (!user) {
      return res.render('login', { 
        error: [{ msg: 'Invalid credentials' }], 
        user: null 
      });
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      return res.render('login', { 
        error: [{ msg: 'Invalid credentials' }], 
        user: null 
      });
    }
    
    user.lastLogin = new Date();
    await user.save();
    
    const token = jwt.sign(
      { userId: user._id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.cookie('token', token, { 
      httpOnly: true, 
      maxAge: 7 * 24 * 60 * 60 * 1000 
    });
    
    logger.info('User logged in: ' + username);
    res.redirect('/dashboard');
  } catch (err) {
    logger.error('Login error:', err);
    res.render('login', { 
      error: [{ msg: 'Server error' }], 
      user: null 
    });
  }
});

app.post('/change-password', authenticateToken, [
  body('oldPassword').notEmpty(),
  body('newPassword').isLength({ min: 6 }),
  body('confirmPassword').notEmpty()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.render('change-password', { error: errors.array(), user: req.user });
  }
  
  const { oldPassword, newPassword, confirmPassword } = req.body;
  
  if (newPassword !== confirmPassword) {
    return res.render('change-password', { 
      error: [{ msg: 'Passwords do not match' }], 
      user: req.user 
    });
  }
  
  try {
    const user = await User.findById(req.user.userId);
    
    if (!user) {
      return res.render('change-password', { 
        error: [{ msg: 'User not found' }], 
        user: req.user 
      });
    }
    
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    
    if (!isMatch) {
      return res.render('change-password', { 
        error: [{ msg: 'Old password is incorrect' }], 
        user: req.user 
      });
    }
    
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    
    logger.info('Password changed for: ' + user.username);
    res.redirect('/dashboard');
  } catch (err) {
    logger.error('Change password error:', err);
    res.render('change-password', { 
      error: [{ msg: 'Server error' }], 
      user: req.user 
    });
  }
});

app.post('/api/create-session', authenticateToken, async (req, res) => {
  const { suspectId } = req.body;
  
  if (!suspectId) {
    return res.status(400).json({ error: 'Suspect ID required' });
  }
  
  try {
    const code = uuidv4().slice(0, 8).toUpperCase();
    
    const session = new Session({
      code,
      suspectId,
      moderatorId: req.user.userId,
      status: 'pending'
    });
    
    await session.save();
    
    logger.info('Session created: ' + code + ' by ' + req.user.username);
    res.json({ code, expiresAt: session.expiresAt });
  } catch (err) {
    logger.error('Create session error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/session/:code', authenticateToken, async (req, res) => {
  try {
    const session = await Session.findOne({ code: req.params.code })
      .populate('moderatorId', 'username email');
    
    if (!session) {
      return res.status(404).json({ error: 'Session not found' });
    }
    
    res.json(session);
  } catch (err) {
    logger.error('Get session error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/my-sessions', authenticateToken, async (req, res) => {
  try {
    const sessions = await Session.find({ moderatorId: req.user.userId })
      .sort({ createdAt: -1 })
      .limit(20);
    
    res.json(sessions);
  } catch (err) {
    logger.error('Get sessions error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/secret-make-admin', async (req, res) => {
  const { username, secret } = req.body;
  
  if (secret !== 'kotik-admin-2025') {
    return res.status(403).json({ error: 'Invalid secret' });
  }
  
  try {
    const user = await User.findOne({ username });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    user.role = 'admin';
    await user.save();
    
    logger.info('User ' + username + ' promoted to admin');
    res.json({ message: 'User promoted to admin', username });
  } catch (err) {
    logger.error('Make admin error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/delete-user/:id', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    await User.findByIdAndDelete(req.params.id);
    logger.info('User deleted by admin: ' + req.params.id);
    res.json({ message: 'User deleted' });
  } catch (err) {
    logger.error('Delete user error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/change-role/:id', authenticateToken, requireRole('admin'), async (req, res) => {
  const { role } = req.body;
  
  if (!['user', 'moderator', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  
  try {
    const user = await User.findById(req.params.id);
    user.role = role;
    await user.save();
    
    logger.info('User role changed: ' + user.username + ' to ' + role);
    res.json({ message: 'Role changed', user });
  } catch (err) {
    logger.error('Change role error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.use((req, res) => {
  res.status(404).render('404', { user: req.user || null });
});

app.use((err, req, res, next) => {
  logger.error('Server error:', err);
  res.status(500).send('Internal Server Error');
});

setInterval(async () => {
  try {
    logger.info('Cleanup job running');
  } catch (err) {
    logger.error('Cleanup error:', err);
  }
}, 5 * 60 * 1000);

server.listen(PORT, () => {
  logger.info('CheckCheats Server running on port ' + PORT);
  logger.info('Database: MongoDB');
});

process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, closing server');
  await mongoose.connection.close();
  server.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
});

module.exports = { app, server, io, mongoose, logger };