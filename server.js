import 'dotenv/config'
import express from 'express'
import path from 'path'
import cookieSession from 'cookie-session'
import bcrypt from 'bcryptjs'
import Database from 'better-sqlite3'
import { Telegraf, Markup } from 'telegraf'
import axios from 'axios'

const app = express()
const __dirname = path.resolve()

// ——— DB ———
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
  provider text not null, -- cryptobot
  providerId text unique not null,
  status text not null,  -- pending/paid/failed
  amount integer not null,
  currency text not null,
  telegramId text,
  createdAt integer not null,
  userId integer,
  licenseKey text
);
`)

// ——— Middlewares ———
app.use(express.urlencoded({ extended: true }))
app.use(express.json())
app.use('/public', express.static(path.join(__dirname, 'public')))
app.use('/styles.css', (req,res)=>res.sendFile(path.join(__dirname,'public','styles.css')))
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')
app.engine('ejs', (path, data, cb) => {
  // поддержка layout()
  const ejs = (await import('ejs')).default
  data.layout = function(layoutPath, locals) {
    data._layoutFile = layoutPath
    Object.assign(data, locals)
  }
  ejs.renderFile(path, data, { async: true }, async (err, str) => {
    if (err) return cb(err)
    if (data._layoutFile) {
      const layoutPath = (data._layoutFile.endsWith('.ejs')) ? data._layoutFile : path.replace(/views\/.*$/, 'views/'+data._layoutFile+'.ejs')
      const content = str
      ejs.renderFile(layoutPath, { ...data, body: content }, { async: true }, cb)
    } else cb(null, str)
  })
})

app.use(cookieSession({
  name: 'ccsess',
  keys: [process.env.SESSION_SECRET || 'devsecret'],
  maxAge: 30 * 24 * 3600 * 1000
}))
app.use((req,res,next)=>{
  res.locals.user = req.session.user || null
  next()
})

// ——— Helpers ———
const now = () => Date.now()
const findUserByEmail = db.prepare('select * from users where email=?')
const findUserById = db.prepare('select * from users where id=?')
const createUser = db.prepare('insert into users (email,username,passwordHash,createdAt) values (?,?,?,?)')
const getUserLic = db.prepare('select * from licenses where userId=? order by id desc')
const getLicDevices = db.prepare('select * from devices where licenseId=? order by id asc')
const getLicenseByKey = db.prepare('select * from licenses where key=?')
const bindLicenseToUser = db.prepare('update licenses set userId=?, status="active" where id=?')
const resetHwidDevices = db.prepare('update devices set hwid=null where licenseId=?')
const createLicense = db.prepare('insert into licenses (key,plan,status,maxDevices,expiresAt) values (?,?,?,?,?)')
const createPayment = db.prepare('insert into payments (provider,providerId,status,amount,currency,telegramId,createdAt) values (?,?,?,?,?,?,?)')
const updatePayment = db.prepare('update payments set status=?, licenseKey=? where providerId=?')

// ——— Routes ———
app.get('/', (req,res)=> res.render('index', { title:'Главная' }))
app.get('/products', (req,res)=> res.render('products', {
  title:'Продукты',
  price: process.env.PRODUCT_PRICE_USDT || '15',
  botName: 'YourBotUsername'.replace('@','')
}))

app.get('/login', (req,res)=> res.render('login', { title:'Вход', error:null }))
app.post('/login', (req,res)=>{
  const { email, password } = req.body
  const user = findUserByEmail.get(String(email).toLowerCase())
  if (!user) return res.render('login', { title:'Вход', error:'Неверные данные' })
  const ok = bcrypt.compareSync(password, user.passwordHash)
  if (!ok) return res.render('login', { title:'Вход', error:'Неверные данные' })
  req.session.user = { id:user.id, email:user.email, username:user.username, role:user.role, uid:user.id }
  res.redirect('/dashboard')
})
app.post('/logout', (req,res)=>{ req.session = null; res.redirect('/') })

app.get('/register', (req,res)=> res.render('register', { title:'Регистрация', error:null }))
app.post('/register', (req,res)=>{
  const { email, username, password } = req.body
  if (!email || !username || !password || password.length<6) return res.render('register',{title:'Регистрация', error:'Неверные данные'})
  if (findUserByEmail.get(String(email).toLowerCase())) return res.render('register',{title:'Регистрация', error:'Email занят'})
  const hash = bcrypt.hashSync(password,10)
  const info = createUser.run(String(email).toLowerCase(), String(username), hash, now())
  req.session.user = { id: info.lastInsertRowid, email, username, role:'user', uid: info.lastInsertRowid }
  res.redirect('/dashboard')
})

function requireAuth(req,res,next){ if(!req.session.user) return res.redirect('/login'); next() }

app.get('/dashboard', requireAuth, (req,res)=>{
  const user = findUserById.get(req.session.user.id)
  let lic = getUserLic.get(user.id)
  let hwid = '', expiresAt = ''
  let canDownload = false
  if (lic) {
    const dev = getLicDevices.get(lic.id)
    hwid = dev?.hwid || ''
    if (lic.expiresAt) {
      expiresAt = new Date(lic.expiresAt).toLocaleString()
      canDownload = lic.status==='active' && lic.expiresAt > Date.now()
    }
  }
  res.render('dashboard',{ title:'Кабинет',
    user: { uid:user.id, username:user.username, role:user.role, email:user.email, createdAt:new Date(user.createdAt).toLocaleString() },
    hwid, expiresAt, canDownload, downloadUrl: process.env.DOWNLOAD_URL, msg:null
  })
})

app.post('/key/activate', requireAuth, (req,res)=>{
  const key = String(req.body.key||'').trim().toUpperCase()
  if (!key) return res.redirect('/dashboard')
  const lic = getLicenseByKey.get(key)
  if (!lic) return res.render('dashboard',{ title:'Кабинет', msg:'Ключ не найден', user:req.session.user })
  if (lic.userId && lic.userId !== req.session.user.id) return res.render('dashboard',{ title:'Кабинет', msg:'Ключ уже использован', user:req.session.user })
  if (lic.status==='blocked') return res.render('dashboard',{ title:'Кабинет', msg:'Ключ заблокирован', user:req.session.user })
  bindLicenseToUser.run(req.session.user.id, lic.id)
  // если нет устройства — создадим пустое (без hwid)
  const devs = getLicDevices.all(lic.id)
  if (devs.length===0) db.prepare('insert into devices (licenseId,hwid,firstSeenAt,lastSeenAt) values (?,?,?,?)').run(lic.id, null, now(), now())
  res.redirect('/dashboard')
})

app.post('/hwid/reset', requireAuth, (req,res)=>{
  const lic = getUserLic.get(req.session.user.id)
  if (!lic) return res.redirect('/dashboard')
  resetHwidDevices.run(lic.id)
  res.redirect('/dashboard')
})

// ——— Telegram Bot + CryptoBot ———
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN
const CRYPTOPAY_TOKEN = process.env.CRYPTOPAY_TOKEN
let bot = null

if (TELEGRAM_BOT_TOKEN && CRYPTOPAY_TOKEN) {
  bot = new Telegraf(TELEGRAM_BOT_TOKEN)
  const PRICE = Number(process.env.PRODUCT_PRICE_USDT || 15)
  const CR = axios.create({
    baseURL: 'https://pay.crypt.bot/api',
    headers: { 'Crypto-Pay-API-Token': CRYPTOPAY_TOKEN }
  })
  async function createInvoiceUSDT(amount, desc) {
    const r = await CR.post('/createInvoice', { asset:'USDT', amount, description:desc })
    if (!r.data?.ok) throw new Error('cryptobot')
    return r.data.result
  }
  async function getInvoice(id) {
    const r = await CR.get('/getInvoices', { params:{ invoice_ids:id } })
    if (!r.data?.ok) throw new Error('cryptobot')
    return r.data.result.items[0]
  }
  function genKey() {
    const rnd = Math.random().toString(36).slice(2).toUpperCase()
    return `CC-${Date.now()}-${rnd}`
  }
  bot.start(async (ctx)=>{
    const kb = Markup.keyboard([['CheckCheats'], ['О программе'], ['Связь с Админом']]).resize()
    await ctx.reply('Выберите:', kb)
    if (ctx.startPayload==='cc') {
      await ctx.reply(`Товар: CheckCheats\nЦена: ${PRICE} USDT`,
        Markup.inlineKeyboard([ Markup.button.callback(`Купить за ${PRICE} USDT`,'buy_cc') ]))
    }
  })
  bot.hears('CheckCheats', async (ctx)=>{
    await ctx.reply(`CheckCheats — лаунчер/сканер.\nЦена: ${PRICE} USDT`,
      Markup.inlineKeyboard([ Markup.button.callback(`Купить за ${PRICE} USDT`,'buy_cc') ]))
  })
  bot.hears('О программе', (ctx)=> ctx.reply('Описание и сайт: '+(process.env.SITE_URL||'http://localhost:3000')))
  bot.hears('Связь с Админом', (ctx)=> ctx.reply('Напишите: '+(process.env.ADMIN_CONTACT||'@admin')))

  bot.action('buy_cc', async (ctx)=>{
    try {
      const inv = await createInvoiceUSDT(PRICE, 'CheckCheats License')
      createPayment.run('cryptobot', String(inv.invoice_id), 'pending', Math.round(PRICE*100), 'USDT', String(ctx.from.id), now())
      await ctx.reply(`Счёт создан. Оплатите: ${inv.pay_url}\nПосле оплаты бот пришлёт ключ.`)
      const timer = setInterval(async ()=>{
        try {
          const cur = await getInvoice(inv.invoice_id)
          if (cur.status==='paid') {
            clearInterval(timer)
            const key = genKey()
            const expires = Date.now() + 180*24*3600*1000 // 6 месяцев
            createLicense.run(key, 'STARTER', 'unbound', 1, expires)
            updatePayment.run('paid', key, String(inv.invoice_id))
            await ctx.reply(`Оплата получена!\nВаш ключ: ${key}\nАктивируйте ключ в личном кабинете на сайте.`)
          }
        } catch {}
      }, 5000)
    } catch (e) {
      await ctx.reply('Ошибка создания счёта, попробуйте позже.')
    }
  })
}

// ——— Слушаем ———
const PORT = process.env.PORT || 3000
app.listen(PORT, ()=>{
  console.log('Web listening on', PORT)
  if (bot) bot.launch().then(()=>console.log('Bot launched'))
})
