import 'dotenv/config'
import express from 'express'
import path from 'path'
import cookieSession from 'cookie-session'
import bcrypt from 'bcryptjs'
import Database from 'better-sqlite3'
import ejsLayouts from 'express-ejs-layouts'

const app = express()
const __dirname = path.resolve()

// DB
const db = new Database(path.join(__dirname, 'data', 'data.db'))
db.pragma('journal_mode = WAL')
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
  status text not null default 'unbound',
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
  provider text not null,
  providerId text unique not null,
  status text not null,
  amount integer not null,
  currency text not null,
  telegramId text,
  createdAt integer not null,
  userId integer,
  licenseKey text
);
`)

// MW
app.use(express.urlencoded({ extended: true }))
app.use(express.json())
app.use('/styles.css', (req,res)=>res.sendFile(path.join(__dirname,'public','styles.css')))
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')
app.use(ejsLayouts)
app.set('layout', 'layout')
app.use(cookieSession({ name:'ccsess', keys:[process.env.SESSION_SECRET||'dev'], maxAge:30*24*3600*1000 }))
app.use((req,res,next)=>{ res.locals.user = req.session.user || null; next() })

// helpers (sql prepared)
const now = ()=>Date.now()
const q = {
  userByEmail: db.prepare('select * from users where email=?'),
  userById:    db.prepare('select * from users where id=?'),
  createUser:  db.prepare('insert into users (email,username,passwordHash,createdAt) values (?,?,?,?)'),
  userLic:     db.prepare('select * from licenses where userId=? order by id desc'),
  licDevices:  db.prepare('select * from devices where licenseId=? order by id asc'),
  licByKey:    db.prepare('select * from licenses where key=?'),
  createLic:   db.prepare('insert into licenses (key,plan,status,maxDevices,expiresAt) values (?,?,?,?,?)'),
  bindLic:     db.prepare('update licenses set userId=?, status="active" where id=?'),
  resetHwid:   db.prepare('update devices set hwid=null where licenseId=?'),
  addDevice:   db.prepare('insert into devices (licenseId,hwid,firstSeenAt,lastSeenAt) values (?,?,?,?)'),
  createPay:   db.prepare('insert into payments (provider,providerId,status,amount,currency,telegramId,createdAt,licenseKey) values (?,?,?,?,?,?,?,?)')
}

// routes
app.get('/', (req,res)=> res.render('index',{ title:'Главная' }))
app.get('/products', (req,res)=> res.render('products',{
  title:'Продукты',
  price: process.env.PRODUCT_PRICE_USDT || '15',
  botName: (process.env.TG_BOT_USERNAME||'YourBotUsername').replace('@','')
}))

app.get('/login', (req,res)=> res.render('login',{ title:'Вход', error:null }))
app.post('/login', (req,res)=>{
  const email = String(req.body.email||'').toLowerCase()
  const pass  = String(req.body.password||'')
  const u = q.userByEmail.get(email)
  if (!u || !bcrypt.compareSync(pass, u.passwordHash))
    return res.render('login',{title:'Вход', error:'Неверные данные'})
  req.session.user = { id:u.id, email:u.email, username:u.username, role:u.role }
  res.redirect('/dashboard')
})
app.post('/logout',(req,res)=>{ req.session=null; res.redirect('/') })

app.get('/register',(req,res)=> res.render('register',{title:'Регистрация', error:null }))
app.post('/register',(req,res)=>{
  const { email, username, password } = req.body
  if (!email||!username||!password||password.length<6)
    return res.render('register',{title:'Регистрация', error:'Неверные данные'})
  if (q.userByEmail.get(String(email).toLowerCase()))
    return res.render('register',{title:'Регистрация', error:'Email занят'})
  const hash = bcrypt.hashSync(password,10)
  const info = q.createUser.run(String(email).toLowerCase(), String(username), hash, now())
  req.session.user = { id: info.lastInsertRowid, email, username, role:'user' }
  res.redirect('/dashboard')
})

function requireAuth(req,res,next){ if(!req.session.user) return res.redirect('/login'); next() }

app.get('/dashboard', requireAuth, (req,res)=>{
  const u = q.userById.get(req.session.user.id)
  const lic = q.userLic.get(u.id)
  let hwid='', expiresAt='', canDownload=false
  if (lic) {
    const d = q.licDevices.get(lic.id)
    hwid = d?.hwid || ''
    if (lic.expiresAt) {
      expiresAt = new Date(lic.expiresAt).toLocaleString()
      canDownload = lic.status==='active' && lic.expiresAt>now()
    }
  }
  res.render('dashboard',{ title:'Кабинет',
    user: { uid:u.id, username:u.username, role:u.role, email:u.email, createdAt:new Date(u.createdAt).toLocaleString() },
    hwid, expiresAt, canDownload, downloadUrl: process.env.DOWNLOAD_URL, msg:null
  })
})

app.post('/key/activate', requireAuth, (req,res)=>{
  const key = String(req.body.key||'').trim().toUpperCase()
  const lic = q.licByKey.get(key)
  if (!lic) return res.render('dashboard',{title:'Кабинет', msg:'Ключ не найден', user:req.session.user})
  if (lic.userId && lic.userId !== req.session.user.id) return res.render('dashboard',{title:'Кабинет', msg:'Ключ уже использован', user:req.session.user})
  if (lic.status==='blocked') return res.render('dashboard',{title:'Кабинет', msg:'Ключ заблокирован', user:req.session.user})
  q.bindLic.run(req.session.user.id, lic.id)
  const devs = q.licDevices.all(lic.id)
  if (devs.length===0) q.addDevice.run(lic.id, null, now(), now())
  res.redirect('/dashboard')
})

app.post('/hwid/reset', requireAuth, (req,res)=>{
  const lic = q.userLic.get(req.session.user.id)
  if (lic) q.resetHwid.run(lic.id)
  res.redirect('/dashboard')
})

// API для бота: регистрация выданного ключа
app.post('/api/bot/new-key', (req,res)=>{
  const secret = req.headers['x-api-key'] || req.body?.secret
  if ((secret||'') !== (process.env.BOT_WEBHOOK_SECRET||'')) return res.status(401).json({error:'unauthorized'})
  const { key, plan='STARTER', expiresAt, maxDevices=1, invoiceId, amount=0, currency='USDT', telegramId } = req.body||{}
  if (!key || !expiresAt || !invoiceId) return res.status(400).json({error:'bad_request'})
  try {
    q.createLic.run(String(key).toUpperCase(), plan, 'unbound', Number(maxDevices), Number(expiresAt))
    q.createPay.run('cryptobot', String(invoiceId), 'paid', Number(amount), currency, String(telegramId||''), now(), String(key).toUpperCase())
    return res.json({ok:true})
  } catch (e) {
    return res.status(409).json({error:'exists'})
  }
})

const PORT = process.env.PORT || 3000
app.listen(PORT, ()=> console.log('Site on', PORT))
