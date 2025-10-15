require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Database connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('✅ MongoDB connected successfully');
}).catch(err => {
  console.error('❌ MongoDB connection error:', err);
  process.exit(1);
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

app.use(cors());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Слишком много запросов с этого IP, попробуйте позже.'
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: 'Слишком много попыток входа, попробуйте позже.'
});

app.use('/api/', limiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// Body parsing middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Session configuration
app.use(session({
  secret: process.env.JWT_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Models
const User = require('./models/User');
const Key = require('./models/Key');
const Product = require('./models/Product');

// Middleware to check authentication
const isAuthenticated = (req, res, next) => {
  if (req.session.userId) {
    next();
  } else {
    res.redirect('/login');
  }
};

const isAdmin = async (req, res, next) => {
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  
  try {
    const user = await User.findById(req.session.userId);
    if (user && user.group === 'Admin') {
      next();
    } else {
      res.status(403).render('error', { message: 'Доступ запрещён' });
    }
  } catch (error) {
    res.status(500).render('error', { message: 'Ошибка сервера' });
  }
};

// Routes

// Home page
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user });
});

// Products page
app.get('/products', async (req, res) => {
  try {
    const products = await Product.find({ isActive: true });
    res.render('products', { user: req.session.user, products });
  } catch (error) {
    res.status(500).render('error', { message: 'Ошибка загрузки продуктов' });
  }
});

// Login page
app.get('/login', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.render('login', { error: null });
});

// Register page
app.get('/register', (req, res) => {
  if (req.session.userId) {
    return res.redirect('/dashboard');
  }
  res.render('register', { error: null });
});

// Dashboard
app.get('/dashboard', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId).select('-password');
    if (!user) {
      req.session.destroy();
      return res.redirect('/login');
    }
    
    res.render('dashboard', { user });
  } catch (error) {
    res.status(500).render('error', { message: 'Ошибка загрузки панели' });
  }
});

// Admin panel
app.get('/admin', isAdmin, async (req, res) => {
  try {
    const stats = {
      totalUsers: await User.countDocuments(),
      totalKeys: await Key.countDocuments(),
      activeKeys: await Key.countDocuments({ status: 'active' }),
      usedKeys: await Key.countDocuments({ status: 'used' })
    };
    
    const recentUsers = await User.find().sort({ createdAt: -1 }).limit(10).select('-password');
    const recentKeys = await Key.find().sort({ createdAt: -1 }).limit(10).populate('createdBy usedBy', 'username');
    
    res.render('admin', { 
      user: req.session.user, 
      stats, 
      recentUsers, 
      recentKeys 
    });
  } catch (error) {
    res.status(500).render('error', { message: 'Ошибка загрузки админ-панели' });
  }
});

// API Routes

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Все поля обязательны' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Пароль должен быть не менее 6 символов' });
    }
    
    // Check if user exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Пользователь с таким email или логином уже существует' });
    }
    
    // Create new user
    const user = new User({
      username,
      email,
      password
    });
    
    await user.save();
    
    // Set session
    req.session.userId = user._id;
    req.session.user = {
      id: user._id,
      username: user.username,
      email: user.email,
      group: user.group
    };
    
    res.json({ success: true, redirect: '/dashboard' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Ошибка регистрации' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Введите логин и пароль' });
    }
    
    // Find user by username or email
    const user = await User.findOne({ 
      $or: [{ username }, { email: username }] 
    });
    
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }
    
    if (user.isBanned) {
      return res.status(403).json({ error: 'Ваш аккаунт заблокирован' });
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Set session
    req.session.userId = user._id;
    req.session.user = {
      id: user._id,
      username: user.username,
      email: user.email,
      group: user.group
    };
    
    res.json({ success: true, redirect: '/dashboard' });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Ошибка входа' });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Ошибка выхода' });
    }
    res.json({ success: true, redirect: '/' });
  });
});

// Activate key
app.post('/api/key/activate', isAuthenticated, async (req, res) => {
  try {
    const { key } = req.body;
    
    if (!key) {
      return res.status(400).json({ error: 'Введите ключ активации' });
    }
    
    const licenseKey = await Key.findOne({ key: key.trim() });
    
    if (!licenseKey) {
      return res.status(404).json({ error: 'Ключ не найден' });
    }
    
    if (licenseKey.status !== 'active') {
      return res.status(400).json({ error: 'Ключ уже использован или недействителен' });
    }
    
    const user = await User.findById(req.session.userId);
    
    // Activate key
    const expirationDate = await licenseKey.activate(user._id);
    
    // Update user subscription
    user.subscriptionExpires = expirationDate;
    user.activatedKey = key;
    await user.save();
    
    res.json({ 
      success: true, 
      message: 'Ключ успешно активирован',
      expiresAt: expirationDate
    });
  } catch (error) {
    console.error('Key activation error:', error);
    res.status(500).json({ error: 'Ошибка активации ключа' });
  }
});

// Download product (after key activation)
app.get('/api/download', isAuthenticated, async (req, res) => {
  try {
    const user = await User.findById(req.session.userId);
    
    if (!user.hasActiveSubscription()) {
      return res.status(403).json({ error: 'Требуется активная подписка' });
    }
    
    const product = await Product.findOne({ isActive: true });
    
    if (!product) {
      return res.status(404).json({ error: 'Продукт не найден' });
    }
    
    // Generate download token
    const downloadToken = require('crypto').randomBytes(32).toString('hex');
    user.downloadToken = downloadToken;
    await user.save();
    
    res.json({ 
      success: true,
      downloadUrl: `/api/download/${downloadToken}`,
      product: {
        name: product.name,
        version: product.version
      }
    });
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ error: 'Ошибка загрузки' });
  }
});

// Admin API Routes

// Generate key
app.post('/api/admin/generate-key', isAdmin, async (req, res) => {
  try {
    const { type } = req.body;
    
    if (!type || !['30days', '90days', '180days', '365days', 'lifetime'].includes(type)) {
      return res.status(400).json({ error: 'Неверный тип ключа' });
    }
    
    const key = new Key({
      key: Key.generateKey(),
      type,
      createdBy: req.session.userId
    });
    
    await key.save();
    
    res.json({ 
      success: true, 
      key: key.key,
      type: key.type
    });
  } catch (error) {
    console.error('Key generation error:', error);
    res.status(500).json({ error: 'Ошибка генерации ключа' });
  }
});

// Grant subscription
app.post('/api/admin/grant-subscription', isAdmin, async (req, res) => {
  try {
    const { userId, days } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }
    
    const expirationDate = new Date();
    expirationDate.setDate(expirationDate.getDate() + parseInt(days));
    
    user.subscriptionExpires = expirationDate;
    await user.save();
    
    res.json({ 
      success: true, 
      message: `Подписка выдана до ${expirationDate.toLocaleDateString()}`
    });
  } catch (error) {
    console.error('Grant subscription error:', error);
    res.status(500).json({ error: 'Ошибка выдачи подписки' });
  }
});

// Reset HWID
app.post('/api/admin/reset-hwid', isAdmin, async (req, res) => {
  try {
    const { userId } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }
    
    user.hwid = null;
    await user.save();
    
    res.json({ success: true, message: 'HWID сброшен' });
  } catch (error) {
    console.error('Reset HWID error:', error);
    res.status(500).json({ error: 'Ошибка сброса HWID' });
  }
});

// Find user by UID
app.get('/api/admin/find-user/:uid', isAdmin, async (req, res) => {
  try {
    const { uid } = req.params;
    
    const user = await User.findOne({ uid }).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }
    
    res.json({ success: true, user });
  } catch (error) {
    console.error('Find user error:', error);
    res.status(500).json({ error: 'Ошибка поиска пользователя' });
  }
});

// Error handler
app.use((req, res) => {
  res.status(404).render('error', { message: 'Страница не найдена' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📁 Environment: ${process.env.NODE_ENV || 'development'}`);
});