// server.js
import 'dotenv/config'
import express from 'express'
import path from 'path'
import crypto from 'crypto'
import cookieSession from 'cookie-session'
import bcrypt from 'bcryptjs'
import pg from 'pg'
import ejsLayouts from 'express-ejs-layouts'

const { Pool } = pg
const app = express()
const __dirname = path.resolve()

// ====== БД (PostgreSQL) ======
const pool = new Pool({
  connectionString: process.env.DATABASE_URL
})

// Создаём таблицы, если их нет
async function setupDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      uid SERIAL UNIQUE,
      email TEXT UNIQUE NOT NULL,
      username TEXT UNIQUE NOT NULL,
      passwordHash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      createdAt TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS licenses (
      id SERIAL PRIMARY KEY,
      key TEXT UNIQUE NOT NULL,
      plan TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'unbound',
      maxDevices INT NOT NULL DEFAULT 1,
      expiresAt TIMESTAMPTZ NOT NULL,
      createdAt TIMESTAMPTZ DEFAULT NOW(),
      userId INT REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS devices (
      id SERIAL PRIMARY KEY,
      licenseId INT NOT NULL REFERENCES licenses(id),
      hwid TEXT,
      firstSeenAt TIMESTAMPTZ DEFAULT NOW(),
      lastSeenAt TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE (licenseId, hwid)
    );
    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      provider TEXT NOT NULL,
      providerId TEXT UNIQUE NOT NULL,
      status TEXT NOT NULL,
      amount INT NOT NULL,
      currency TEXT NOT NULL,
      telegramId TEXT,
      createdAt TIMESTAMPTZ DEFAULT NOW(),
      userId INT,
      licenseKey TEXT
    );
  `)
}
setupDb().catch(console.error)

// ====== Middleware и шаблоны ======
app.use(express.urlencoded({ extended: true }))
app.use(express.json())
app.use(express.static(path.join(__dirname, 'public')))
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')
app.use(ejsLayouts)
app.set('layout', 'layout')

app.use(cookieSession({ name:'ccsess', keys:[process.env.SESSION_SECRET||'dev'], maxAge:30*24*3600*1000 }))
app.use((req, res, next) => { res.locals.user = req.session.user || null; next() })

// ====== Helpers ======
const toLocale = (d) => d ? new Date(d).toLocaleString() : ''
const genKeyPart = () => crypto.randomBytes(3).toString('hex').toUpperCase().slice(0, 5)

// ====== Routes ======
app.get('/', (req, res) => res.render('index', { title: 'Главная' }))
app.get('/products', (req, res) => {
  res.render('products', {
    title: 'Продукты',
    price: process.env.PRODUCT_PRICE_USDT || '1',
    botName: (process.env.TG_BOT_USERNAME || 'checkcheatsbuy_bot').replace(/^@/, '')
  })
})

app.get('/login', (req, res) => res.render('login', { title: 'Вход', error: null }))
app.post('/login', async (req, res) => {
  const { email, password } = req.body
  const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [String(email).toLowerCase()])
  const user = rows[0]
  if (!user || !bcrypt.compareSync(password, user.passwordhash)) {
    return res.render('login', { title: 'Вход', error: 'Неверные данные' })
  }
  req.session.user = { id: user.id, email: user.email, username: user.username, role: user.role }
  res.redirect('/dashboard')
})
app.post('/logout', (req, res) => { req.session = null; res.redirect('/') })

app.get('/register', (req, res) => res.render('register', { title: 'Регистрация', error: null }))
app.post('/register', async (req, res) => {
  const { email, username, password } = req.body
  if (!email || !username || !password || password.length < 6)
    return res.render('register', { title: 'Регистрация', error: 'Неверные данные' })
  
  const { rows: existing } = await pool.query('SELECT id FROM users WHERE email = $1 OR username = $2', [String(email).toLowerCase(), username])
  if (existing.length > 0)
    return res.render('register', { title: 'Регистрация', error: 'Email или логин занят' })
  
  const hash = bcrypt.hashSync(password, 10)
  const { rows: newUser } = await pool.query('INSERT INTO users (email, username, passwordHash) VALUES ($1, $2, $3) RETURNING id, role', [String(email).toLowerCase(), username, hash])
  req.session.user = { id: newUser[0].id, email, username, role: newUser[0].role }
  res.redirect('/dashboard')
})

// Middleware для проверки авторизации и роли админа
function requireAuth(req, res, next) { if (!req.session.user) return res.redirect('/login'); next() }
function requireAdmin(req, res, next) { if (req.session.user?.role !== 'admin') return res.status(403).send('Доступ запрещён'); next() }

// Функция для отрисовки дашборда
async function renderDashboard(req, res, msg = null) {
  const { rows: users } = await pool.query('SELECT * FROM users WHERE id = $1', [req.session.user.id]);
  const user = users[0];

  if (!user) {
    req.session = null;
    return res.redirect('/login');
  }

  const { rows: lics } = await pool.query('SELECT * FROM licenses WHERE userId = $1 AND status = $2 ORDER BY expiresat DESC LIMIT 1', [user.id, 'active']);
  const lic = lics[0];

  let hwid = '', expiresAt = '', canDownload = false;
  if (lic) {
    const { rows: devices } = await pool.query('SELECT * FROM devices WHERE licenseId = $1', [lic.id]);
    hwid = devices[0]?.hwid || '';
    expiresAt = toLocale(lic.expiresat);
    canDownload = lic.expiresat > new Date();
  }

  res.render('dashboard', {
    title: 'Кабинет',
    user: { ...user, createdAt: toLocale(user.createdat) },
    hwid, expiresAt, canDownload,
    downloadUrl: process.env.DOWNLOAD_URL || '#',
    msg: msg
  });
}

app.get('/dashboard', requireAuth, (req, res) => renderDashboard(req, res));

app.post('/key/activate', requireAuth, async (req, res) => {
  const key = String(req.body.key || '').trim().toUpperCase();
  const { rows: keyData } = await pool.query('SELECT * FROM licenses WHERE UPPER(key) = $1', [key]);
  const newLic = keyData[0];

  if (!newLic) return renderDashboard(req, res, 'Ошибка: Ключ не найден.');
  if (newLic.status !== 'unbound') return renderDashboard(req, res, 'Ошибка: Ключ уже был использован.');
  if (newLic.expiresat < new Date()) return renderDashboard(req, res, 'Ошибка: Срок действия этого ключа истёк.');
  if (!newLic.createdat) return renderDashboard(req, res, 'Ошибка: Неверный формат ключа. Обратитесь в поддержку.');

  const { rows: currentLics } = await pool.query('SELECT * FROM licenses WHERE userId = $1 AND status = $2 ORDER BY expiresat DESC LIMIT 1', [req.session.user.id, 'active']);
  const currentLic = currentLics[0];

  if (currentLic) {
    const durationMs = newLic.expiresat.getTime() - newLic.createdat.getTime();
    const newExpiresAt = new Date(currentLic.expiresat.getTime() + durationMs);
    await pool.query('UPDATE licenses SET expiresAt = $1 WHERE id = $2', [newExpiresAt, currentLic.id]);
    await pool.query('UPDATE licenses SET status = $1, userId = $2 WHERE id = $3', ['used', req.session.user.id, newLic.id]);
  } else {
    await pool.query('UPDATE licenses SET userId = $1, status = $2 WHERE id = $3', [req.session.user.id, 'active', newLic.id]);
    const { rows: devices } = await pool.query('SELECT id FROM devices WHERE licenseId = $1', [newLic.id]);
    if (devices.length === 0) await pool.query('INSERT INTO devices (licenseId) VALUES ($1)', [newLic.id]);
  }
  
  res.redirect('/dashboard');
});

app.post('/hwid/reset', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT id FROM licenses WHERE userId = $1 AND status = $2', [req.session.user.id, 'active'])
  if (rows[0]) await pool.query('UPDATE devices SET hwid = NULL WHERE licenseId = $1', [rows[0].id])
  res.redirect('/dashboard')
})

app.get('/change-password', requireAuth, (req, res) => {
  res.render('change-password', { title: 'Смена пароля', msg: null })
})

app.post('/change-password', requireAuth, async (req, res) => {
  const { oldPassword, newPassword } = req.body
  if (!oldPassword || !newPassword || newPassword.length < 6) {
    return res.render('change-password', { title: 'Смена пароля', msg: 'Неверные данные' })
  }
  const { rows } = await pool.query('SELECT passwordhash FROM users WHERE id = $1', [req.session.user.id])
  const user = rows[0]
  if (!bcrypt.compareSync(oldPassword, user.passwordhash)) {
    return res.render('change-password', { title: 'Смена пароля', msg: 'Старый пароль неверный' })
  }
  const newHash = bcrypt.hashSync(newPassword, 10)
  await pool.query('UPDATE users SET passwordhash = $1 WHERE id = $2', [newHash, req.session.user.id])
  res.render('change-password', { title: 'Смена пароля', msg: 'Пароль успешно изменён!' })
})

// ====== API для бота ======
app.post('/api/bot/new-key', async (req, res) => {
  const secret = req.headers['x-api-key'] || req.body?.secret
  if ((secret || '') !== (process.env.BOT_WEBHOOK_SECRET || ''))
    return res.status(401).json({ error: 'unauthorized' })
  
  const { key, plan = 'LIFETIME', expiresAt, maxDevices = 1, invoiceId, amount = 0, currency = 'USDT', telegramId } = req.body || {}
  if (!key || !expiresAt || !invoiceId) return res.status(400).json({ error: 'bad_request' })
  
  try {
    const expires = new Date(Number(expiresAt))
    await pool.query('INSERT INTO licenses (key, plan, expiresAt, maxDevices, createdAt) VALUES ($1, $2, $3, $4, NOW())', [String(key).toUpperCase(), plan, expires, Number(maxDevices)])
    await pool.query('INSERT INTO payments (provider, providerId, status, amount, currency, telegramId, licenseKey) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      ['cryptobot', String(invoiceId), 'paid', Number(amount), currency, String(telegramId || ''), String(key).toUpperCase()])
    return res.json({ ok: true })
  } catch (e) {
    return res.status(409).json({ error: 'exists' })
  }
})

// ====== Админ-панель ======
app.get('/admin', requireAuth, requireAdmin, (req, res) => {
  res.render('admin', { title: 'Админка', user: null, msg: null })
})

app.post('/admin/find-user', requireAuth, requireAdmin, async (req, res) => {
  const { uid } = req.body
  const { rows } = await pool.query('SELECT id, uid, email, username, role, createdAt FROM users WHERE uid = $1', [Number(uid)])
  const foundUser = rows[0]
  if (foundUser) {
    foundUser.createdAt = toLocale(foundUser.createdat)
  }
  res.render('admin', { title: 'Админка', user: foundUser, msg: foundUser ? null : 'Пользователь не найден' })
})

app.post('/admin/create-key', requireAuth, requireAdmin, async (req, res) => {
  const { days = 30, maxDevices = 1, plan = 'CUSTOM' } = req.body
  const key = `CheckCheats-${genKeyPart()}-${genKeyPart()}`
  const expiresAt = new Date(Date.now() + Number(days) * 24 * 3600 * 1000)
  await pool.query('INSERT INTO licenses (key, plan, expiresAt, maxDevices, createdAt) VALUES ($1, $2, $3, $4, NOW())', [key, plan, expiresAt, Number(maxDevices)])
  res.render('admin', { title: 'Админка', user: null, msg: `Создан ключ: ${key}` })
})

app.post('/admin/reset-subscription', requireAuth, requireAdmin, async (req, res) => {
  const { uid } = req.body;
  const { rows: users } = await pool.query('SELECT id FROM users WHERE uid = $1', [Number(uid)]);
  const user = users[0];

  if (!user) {
    return res.render('admin', { title: 'Админка', user: null, msg: `Пользователь с UID ${uid} не найден.` });
  }

  const { rows: lics } = await pool.query('SELECT id FROM licenses WHERE userId = $1 AND status = $2', [user.id, 'active']);
  if (lics.length > 0) {
    const licenseIds = lics.map(l => l.id);
    await pool.query('DELETE FROM devices WHERE licenseId = ANY($1::int[])', [licenseIds]);
    await pool.query('DELETE FROM licenses WHERE id = ANY($1::int[])', [licenseIds]);
    res.render('admin', { title: 'Админка', user: null, msg: `Подписка для пользователя с UID ${uid} успешно сброшена.` });
  } else {
    res.render('admin', { title: 'Админка', user: null, msg: `У пользователя с UID ${uid} нет активной подписки.` });
  }
});

const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log('Site on', PORT))
