import 'dotenv/config'
import express from 'express'
import path from 'path'
import fs from 'fs'
import cookieSession from 'cookie-session'
import bcrypt from 'bcryptjs'
import Database from 'better-sqlite3'
import ejsLayouts from 'express-ejs-layouts'

const app = express()
const __dirname = path.resolve()

// ====== БД (SQLite) ======
const dataDir =
  process.env.DATA_DIR || (process.env.RENDER ? '/tmp/cc-data' : path.join(__dirname, 'data'))
fs.mkdirSync(dataDir, { recursive: true })
const dbPath = path.join(dataDir, 'data.db')
const db = new Database(dbPath)
db.pragma('journal_mode = WAL')

// Таблицы (создадутся при первом старте)
db.exec(`
create table if not exists users (
  id integer primary key autoincrement,
  email text unique not null,
  username text unique not null,
  passwordHash text not null,
  role text not null default 'user',
  createdAt integer not null
);
create table if not exists licenses (
  id integer primary key autoincrement,
  key text unique not null,
  plan text not null,
  status text not null default 'unbound', -- unbound/active/blocked/expired
  maxDevices integer not null default 1,
  expiresAt integer not null,
  userId integer references users(id)
);
create table if not exists devices (
  id integer primary key autoincrement,
  licenseId integer not null references licenses(id),
  hwid text,
  firstSeenAt integer not null,
  lastSeenAt integer not null,
  status text not null default 'active',
  unique (licenseId, hwid)
);
create table if not exists payments (
  id integer primary key autoincrement,
  provider text not null,            -- cryptobot
  providerId text unique not null,   -- invoice_id
  status text not null,              -- pending/paid/failed
  amount integer not null,           -- в центах/копейках (или просто число)
  currency text not null,            -- USDT
  telegramId text,
  createdAt integer not null,
  userId integer,
  licenseKey text
);
`)

// ====== Middleware и шаблоны ======
app.use(express.urlencoded({ extended: true }))
app.use(express.json())
app.use(express.static(path.join(__dirname, 'public')))

app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')
app.use(ejsLayouts)
app.set('layout', 'layout')

app.use(
  cookieSession({
    name: 'ccsess',
    keys: [process.env.SESSION_SECRET || 'devsecret'],
    maxAge: 30 * 24 * 3600 * 1000
  })
)
app.use((req, res, next) => {
  res.locals.user = req.session.user || null
  next()
})

// ====== Helpers / Prepared ======
const now = () => Date.now()
const q = {
  userByEmail: db.prepare('select * from users where email=?'),
  userById: db.prepare('select * from users where id=?'),
  createUser: db.prepare('insert into users (email,username,passwordHash,createdAt) values (?,?,?,?)'),

  // Берём только активную лицензию пользователя (исправлено: строковый литерал 'active')
  userActiveLic: db.prepare(
    'select * from licenses where userId=? and status=? order by expiresAt desc limit 1'
  ),

  licDevices: db.prepare('select * from devices where licenseId=? order by id asc'),

  licByKey: db.prepare('select * from licenses where key=?'),
  createLic: db.prepare(
    'insert into licenses (key,plan,status,maxDevices,expiresAt) values (?,?,?,?,?)'
  ),
  // update с литералом 'active' корректен (в SQL строковые значение в одинарных кавычках)
  bindLic: db.prepare('update licenses set userId=?, status=\'active\' where id=?'),

  resetHwid: db.prepare('update devices set hwid=null where licenseId=?'),
  addDevice: db.prepare(
    'insert into devices (licenseId, hwid, firstSeenAt, lastSeenAt) values (?,?,?,?)'
  ),

  createPay: db.prepare(
    'insert into payments (provider,providerId,status,amount,currency,telegramId,createdAt,licenseKey) values (?,?,?,?,?,?,?,?)'
  )
}

// ====== Routes ======
app.get('/', (req, res) => res.render('index', { title: 'Главная' }))

app.get('/products', (req, res) => {
  const price =
    process.env.PRODUCT_PRICE_USDT || process.env.NEXT_PUBLIC_PRICE_USDT || '15'
  const botName = (process.env.TG_BOT_USERNAME || 'YourBotUsername').replace(/^@/, '')
  res.render('products', { title: 'Продукты', price, botName })
})

app.get('/login', (req, res) => res.render('login', { title: 'Вход', error: null }))
app.post('/login', (req, res) => {
  const email = String(req.body.email || '').toLowerCase()
  const pass = String(req.body.password || '')
  const u = q.userByEmail.get(email)
  if (!u || !bcrypt.compareSync(pass, u.passwordHash)) {
    return res.render('login', { title: 'Вход', error: 'Неверные данные' })
  }
  req.session.user = { id: u.id, email: u.email, username: u.username, role: u.role }
  res.redirect('/dashboard')
})

app.post('/logout', (req, res) => {
  req.session = null
  res.redirect('/')
})

app.get('/register', (req, res) =>
  res.render('register', { title: 'Регистрация', error: null })
)
app.post('/register', (req, res) => {
  const { email, username, password } = req.body
  if (!email || !username || !password || password.length < 6) {
    return res.render('register', { title: 'Регистрация', error: 'Неверные данные' })
  }
  if (q.userByEmail.get(String(email).toLowerCase())) {
    return res.render('register', { title: 'Регистрация', error: 'Email занят' })
  }
  const hash = bcrypt.hashSync(password, 10)
  const info = q.createUser.run(String(email).toLowerCase(), String(username), hash, now())
  req.session.user = { id: info.lastInsertRowid, email, username, role: 'user' }
  res.redirect('/dashboard')
})

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login')
  next()
}

app.get('/dashboard', requireAuth, (req, res) => {
  const u = q.userById.get(req.session.user.id)
  // берём активную лицензию (параметр 'active' передаём как строку)
  const lic = q.userActiveLic.get(u.id, 'active')

  let hwid = ''
  let expiresAt = ''
  let canDownload = false

  if (lic) {
    const d = q.licDevices.get(lic.id)
    hwid = d?.hwid || ''
    if (lic.expiresAt) {
      expiresAt = new Date(lic.expiresAt).toLocaleString()
      canDownload = true // раз лицензия активна, можно отдавать загрузку (и дата в будущем)
      if (lic.expiresAt <= now()) canDownload = false
    }
  }

  res.render('dashboard', {
    title: 'Кабинет',
    user: {
      uid: u.id,
      username: u.username,
      role: u.role,
      email: u.email,
      createdAt: new Date(u.createdAt).toLocaleString()
    },
    hwid,
    expiresAt,
    canDownload,
    downloadUrl: process.env.DOWNLOAD_URL || '#',
    msg: null
  })
})

app.post('/key/activate', requireAuth, (req, res) => {
  const key = String(req.body.key || '').trim().toUpperCase()
  const lic = q.licByKey.get(key)
  if (!lic) {
    return res.render('dashboard', {
      title: 'Кабинет',
      msg: 'Ключ не найден',
      user: req.session.user
    })
  }
  if (lic.userId && lic.userId !== req.session.user.id) {
    return res.render('dashboard', {
      title: 'Кабинет',
      msg: 'Ключ уже использован',
      user: req.session.user
    })
  }
  if (lic.status === 'blocked') {
    return res.render('dashboard', {
      title: 'Кабинет',
      msg: 'Ключ заблокирован',
      user: req.session.user
    })
  }
  q.bindLic.run(req.session.user.id, lic.id)
  const devs = q.licDevices.all(lic.id)
  if (devs.length === 0) q.addDevice.run(lic.id, null, now(), now())
  res.redirect('/dashboard')
})

app.post('/hwid/reset', requireAuth, (req, res) => {
  // сбрасываем HWID только на активной лицензии
  const lic = q.userActiveLic.get(req.session.user.id, 'active')
  if (lic) q.resetHwid.run(lic.id)
  res.redirect('/dashboard')
})

// ====== API для бота (регистрация ключа после оплаты) ======
// Бот делает POST c заголовком X-API-Key: BOT_WEBHOOK_SECRET
app.post('/api/bot/new-key', (req, res) => {
  const secret = req.headers['x-api-key'] || req.body?.secret
  if ((secret || '') !== (process.env.BOT_WEBHOOK_SECRET || '')) {
    return res.status(401).json({ error: 'unauthorized' })
  }
  const {
    key,
    plan = 'STARTER',
    expiresAt,
    maxDevices = 1,
    invoiceId,
    amount = 0,
    currency = 'USDT',
    telegramId
  } = req.body || {}

  if (!key || !expiresAt || !invoiceId) {
    return res.status(400).json({ error: 'bad_request' })
  }
  try {
    q.createLic.run(String(key).toUpperCase(), plan, 'unbound', Number(maxDevices), Number(expiresAt))
    q.createPay.run(
      'cryptobot',
      String(invoiceId),
      'paid',
      Number(amount),
      currency,
      String(telegramId || ''),
      now(),
      String(key).toUpperCase()
    )
    return res.json({ ok: true })
  } catch (e) {
    return res.status(409).json({ error: 'exists' })
  }
})

// ====== Start ======
const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log('Site on', PORT)
  console.log('DB path:', dbPath)
})
