// server.js - Full Anti-Cheat Server with WebSocket Remote Scanning
// Version 1.2.0 - Enhanced with DB, Rate Limiting, Error Handling
// Author: KOTIK130 (with DAN tweaks)

// Core Modules
const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const winston = require('winston');

// Logging Setup
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

// App Setup
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] },
  pingInterval: 10000,
  pingTimeout: 5000
});

// Environment Config
require('dotenv').config();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-jwt-key-change-me';
const DB_PATH = process.env.DB_PATH || 'checkcheats.db';
const SESSION_TIMEOUT = parseInt(process.env.SESSION_TIMEOUT) || 3600000; // 1 hour

// Middleware
app.use(helmet()); // Security headers
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { error: 'Too many requests from this IP' },
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', limiter);
app.use('/auth/', limiter);

// Database Setup (SQLite)
let db;
function initDB() {
  db = new sqlite3.Database(DB_PATH);
  db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      email TEXT,
      role TEXT DEFAULT 'user',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      code TEXT UNIQUE NOT NULL,
      user_id INTEGER,
      suspect_hwid TEXT,
      moderator_socket_id TEXT,
      suspect_socket_id TEXT,
      results TEXT,
      status TEXT DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME DEFAULT (datetime('now', '+1 hour'))
    )`);
    logger.info('Database initialized');
  });
}
initDB();

// JWT Middleware
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

// Role Check Middleware
function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// WebSocket Handling
let activeSessions = new Map(); // code -> session data

io.on('connection', (socket) => {
  logger.info(`User connected: ${socket.id}`);
  
  socket.on('join-session', (data) => {
    const { code, type, hwid } = data;
    logger.info(`Join attempt: code=${code}, type=${type}, hwid=${hwid}, socket=${socket.id}`);
    
    if (!code || !type) {
      socket.emit('error', { message: 'Invalid data' });
      return;
    }
    
    db.get('SELECT * FROM sessions WHERE code = ? AND expires_at > datetime("now")', [code], (err, session) => {
      if (err) {
        logger.error(err);
        socket.emit('error', { message: 'DB error' });
        return;
      }
      if (!session) {
        socket.emit('error', { message: 'Session not found or expired' });
        return;
      }
      
      if (type === 'suspect') {
        if (session.suspect_socket_id) {
          socket.emit('error', { message: 'Suspect already connected' });
          return;
        }
        db.run('UPDATE sessions SET suspect_socket_id = ? WHERE code = ?', [socket.id, code]);
        activeSessions.set(code, { ...session, suspectSocket: socket });
        socket.emit('session-joined', { status: 'connected', code });
      } else if (type === 'moderator') {
        if (session.moderator_socket_id) {
          socket.emit('error', { message: 'Moderator already connected' });
          return;
        }
        db.run('UPDATE sessions SET moderator_socket_id = ? WHERE code = ?', [socket.id, code]);
        activeSessions.set(code, { ...session, moderatorSocket: socket });
        socket.emit('session-ready', { status: 'ready', code });
      }
    });
  });

  socket.on('request-scan', (code) => {
    logger.info(`Scan request for code: ${code}, from socket: ${socket.id}`);
    const session = activeSessions.get(code);
    if (session && session.suspectSocket) {
      session.suspectSocket.emit('scan-request', { from: 'moderator', code });
    } else {
      socket.emit('error', { message: 'No suspect connected' });
    }
  });

  socket.on('scan-allowed', (code) => {
    logger.info(`Scan allowed for code: ${code}`);
    const session = activeSessions.get(code);
    if (session) {
      session.suspectSocket.emit('start-scan', { code });
      db.run('UPDATE sessions SET status = "scanning" WHERE code = ?', [code]);
    }
  });

  socket.on('scan-results', (data) => {
    const { code, results } = data;
    logger.info(`Results received for code: ${code}, results count: ${results.length}`);
    const session = activeSessions.get(code);
    if (session && session.moderatorSocket) {
      session.moderatorSocket.emit('receive-results', { code, results });
      db.run('UPDATE sessions SET results = ?, status = "completed" WHERE code = ?', [JSON.stringify(results), code]);
      session.results = results;
    }
  });

  socket.on('disconnect', () => {
    logger.info(`User disconnected: ${socket.id}`);
    // Cleanup: find sessions with this socket and expire them
    for (let [code, session] of activeSessions.entries()) {
      if (session.suspectSocket?.id === socket.id || session.moderatorSocket?.id === socket.id) {
        db.run('UPDATE sessions SET status = "expired" WHERE code = ?', [code]);
        activeSessions.delete(code);
      }
    }
  });

  socket.on('error', (err) => {
    logger.error(`Socket error: ${err}`);
  });
});

// Routes - Public
app.get('/', (req, res) => {
  res.render('index', { title: 'CheckCheats Home' });
});

app.get('/login', (req, res) => {
  res.render('login', { title: 'Login', error: null });
});

app.get('/register', (req, res) => {
  res.render('register', { title: 'Register', error: null });
});

app.get('/products', authenticateToken, (req, res) => {
  res.render('products', { title: 'Products', user: req.user });
});

// Auth Routes
app.post('/register',
  [
    body('username').isLength({ min: 3 }).trim().escape(),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 })
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.render('register', { title: 'Register', error: errors.array() });
    }

    const { username, email, password } = req.body;
    try {
      const hashed = await bcrypt.hash(password, 12);
      db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashed], function(err) {
        if (err) {
          logger.error(err);
          return res.render('register', { title: 'Register', error: [{ msg: 'Username already exists' }] });
        }
        logger.info(`User registered: ${username}`);
        
        // Auto-login: create JWT and redirect to dashboard
        const userId = this.lastID;
        const token = jwt.sign(
          { id: userId, username, email, role: 'user' },
          process.env.JWT_SECRET || 'your_jwt_secret_key_here',
          { expiresIn: '7d' }
        );
        res.cookie('token', token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          maxAge: 7 * 24 * 60 * 60 * 1000
        });
        res.redirect('/dashboard');
      });
    } catch (err) {
      logger.error(err);
      res.status(500).render('register', { title: 'Register', error: [{ msg: 'Server error' }] });
    }
  }
);

app.post('/login',
  [
    body('username').trim().escape(),
    body('password').notEmpty()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.render('login', { title: 'Login', error: errors.array() });
    }

    const { username, password } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
      if (err || !user) {
        logger.warn(`Login failed for: ${username}`);
        return res.render('login', { title: 'Login', error: [{ msg: 'Invalid credentials' }] });
      }

      const valid = await bcrypt.compare(password, user.password);
      if (!valid) {
        logger.warn(`Login failed for: ${username}`);
        return res.render('login', { title: 'Login', error: [{ msg: 'Invalid credentials' }] });
      }

      const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
      res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
      logger.info(`User logged in: ${username}`);
      res.redirect('/dashboard');
    });
  }
);

// Protected Routes
app.get('/dashboard', authenticateToken, (req, res) => {
  res.render('dashboard', { title: 'Dashboard', user: req.user });
});

app.get('/admin', authenticateToken, requireRole('admin'), (req, res) => {
  db.all('SELECT * FROM sessions WHERE status != "expired" ORDER BY created_at DESC', (err, sessions) => {
    if (err) {
      logger.error(err);
      return res.status(500).render('admin', { title: 'Admin', error: 'DB error', sessions: [] });
    }
    res.render('admin', { title: 'Admin Panel', user: req.user, sessions });
  });
});

app.get('/change-password', authenticateToken, (req, res) => {
  res.render('change-password', { title: 'Change Password', error: null, user: req.user });
});

app.post('/change-password',
  [
    body('oldPassword').notEmpty(),
    body('newPassword').isLength({ min: 6 }),
    body('confirmPassword').custom((value, { req }) => value === req.body.newPassword)
  ],
  authenticateToken,
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.render('change-password', { title: 'Change Password', error: errors.array(), user: req.user });
    }

    const { oldPassword, newPassword } = req.body;
    db.get('SELECT * FROM users WHERE id = ?', [req.user.id], async (err, user) => {
      if (err || !user) {
        return res.status(500).render('change-password', { title: 'Change Password', error: [{ msg: 'User not found' }], user: req.user });
      }

      const validOld = await bcrypt.compare(oldPassword, user.password);
      if (!validOld) {
        return res.render('change-password', { title: 'Change Password', error: [{ msg: 'Invalid old password' }], user: req.user });
      }

      const hashedNew = await bcrypt.hash(newPassword, 12);
      db.run('UPDATE users SET password = ? WHERE id = ?', [hashedNew, req.user.id], (err) => {
        if (err) {
          logger.error(err);
          return res.render('change-password', { title: 'Change Password', error: [{ msg: 'Update failed' }], user: req.user });
        }
        logger.info(`Password changed for user: ${req.user.username}`);
        res.redirect('/dashboard');
      });
    });
  }
);

// API Routes for Sessions
app.post('/api/generate-code', authenticateToken, requireRole('admin'),
  (req, res) => {
    const code = uuidv4().slice(0, 8).toUpperCase();
    db.run('INSERT INTO sessions (id, code) VALUES (?, ?)', [uuidv4(), code], function(err) {
      if (err) {
        logger.error(err);
        return res.status(500).json({ error: 'Failed to generate code' });
      }
      logger.info(`Code generated: ${code} for user ${req.user.username}`);
      res.json({ code, message: 'Code generated successfully' });
    });
  }
);

app.get('/api/sessions/:code', authenticateToken, requireRole('admin'),
  (req, res) => {
    const { code } = req.params;
    db.get('SELECT * FROM sessions WHERE code = ? AND status != "expired"', [code], (err, session) => {
      if (err) {
        logger.error(err);
        return res.status(500).json({ error: 'DB error' });
      }
      if (!session) {
        return res.status(404).json({ error: 'Session not found' });
      }
      res.json({ session });
    });
  }
);

// Logout
app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

// Error Handling
app.use((err, req, res, next) => {
  logger.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

app.use((req, res) => {
  res.status(404).render('404', { title: 'Not Found' });
});

// View Engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Health Check
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Secret Admin Setup (Remove after use!)
app.post('/secret-make-admin', (req, res) => {
  const { email, secret } = req.body;
  if (secret !== 'GRANT_ME_ADMIN_2025') {
    return res.status(403).json({ error: 'Invalid secret' });
  }
  db.run('UPDATE users SET role = ? WHERE email = ?', ['admin', email], (err) => {
    if (err) {
      logger.error(`Failed to grant admin: ${err}`);
      return res.status(500).json({ error: 'Failed' });
    }
    logger.info(`Admin role granted to: ${email}`);
    res.json({ success: true, message: 'Admin role granted!' });
  });
});

// Server Start
server.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

// Graceful Shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received, closing server');
  db.close((err) => {
    if (err) logger.error(err);
    process.exit(0);
  });
  server.close(() => process.exit(0));
});

process.on('SIGINT', () => {
  logger.info('SIGINT received, closing server');
  db.close((err) => {
    if (err) logger.error(err);
    process.exit(0);
  });
  server.close(() => process.exit(0));
});

// Cleanup expired sessions every 5 min
setInterval(() => {
  db.run('DELETE FROM sessions WHERE expires_at < datetime("now")', (err) => {
    if (err) logger.error(err);
    else logger.info('Cleaned expired sessions');
  });
  // Clear activeSessions
  for (let [code] of activeSessions.entries()) {
    // Simulate check
    activeSessions.delete(code); // Placeholder for real check
  }
}, 5 * 60 * 1000);

// Export for testing
module.exports = { app, server, io, db, logger };
