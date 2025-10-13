# 🚀 Деплой на Render.com - Пошаговая Инструкция

## ✅ Что уже готово:
- `render.yaml` создан и загружен в GitHub
- `package.json` настроен
- `.gitignore` обновлён
- **Всё закоммичено в GitHub!**

---

## 📋 Шаг 1: Регистрация на Render.com

1. Открой https://render.com/
2. Нажми **"Get Started"** или **"Sign Up"**
3. Выбери **"Sign up with GitHub"**
4. Авторизуй Render.com для доступа к твоим репозиториям

---

## 📋 Шаг 2: Создание нового Web Service

1. После логина нажми **"New +"** (правый верхний угол)
2. Выбери **"Web Service"**
3. Найди репозиторий **`KOTIK130/checkcheats-product`**
4. Нажми **"Connect"** напротив него

---

## 📋 Шаг 3: Настройка Web Service

Render автоматически найдёт `render.yaml`, но если нет - настрой вручную:

### **General Settings:**
- **Name:** `checkcheats-server` (можно любое)
- **Region:** `Frankfurt (EU Central)` или ближайший к тебе
- **Branch:** `main`

### **Build & Deploy:**
- **Runtime:** `Node`
- **Build Command:** `npm install`
- **Start Command:** `npm start`

### **Environment Variables:**
Render сам подставит из `render.yaml`, но проверь:

| Key | Value |
|-----|-------|
| `NODE_ENV` | `production` |
| `PORT` | `10000` (Render автоматически) |
| `JWT_SECRET` | *(будет сгенерирован автоматически)* |
| `SESSION_TIMEOUT` | `3600000` |
| `DB_PATH` | `/opt/render/project/src/checkcheats.db` |

### **Instance Type:**
- Выбери **"Free"** (для тестирования, достаточно!)

---

## 📋 Шаг 4: Deploy!

1. Нажми **"Create Web Service"**
2. Render начнёт билд (займёт 2-3 минуты)
3. Следи за логами в реальном времени
4. Когда увидишь **"Your service is live 🎉"** - готово!

---

## 📋 Шаг 5: Получи URL сервера

После успешного деплоя ты увидишь:
- **URL:** Что-то типа `https://checkcheats-server-XXXX.onrender.com`
- **Скопируй этот URL!**

---

## 📋 Шаг 6: Создай первого пользователя

1. Открой в браузере: `https://ваш-сервер.onrender.com/register`
2. Зарегистрируй модератора:
   - Username: `admin`
   - Email: `admin@checkcheats.com`
   - Password: `your_password`
3. Проверь что сервер работает: `https://ваш-сервер.onrender.com/health`

---

## 📋 Шаг 7: Обновляю приложения

Теперь я обновлю **CheaterCheck** и **ModerationCheck**, чтобы они подключались к твоему серверу на Render!

**Сообщи мне URL сервера**, и я обновлю код!

---

## 🔧 Настройки для Production:

### **Если нужен HTTPS (уже включён!):**
✅ Render автоматически выдаёт SSL сертификат

### **Если нужна кастомная доменная зона:**
1. В настройках сервиса → **"Settings"**
2. Прокрути до **"Custom Domain"**
3. Добавь свой домен (например: `checkcheats.yourdomain.com`)
4. Настрой DNS записи как указано

### **Автоматические деплои:**
✅ Уже настроены! При каждом `git push` в `main` → Render автоматически пере-деплоит

### **Логи:**
- В Dashboard сервиса → вкладка **"Logs"**
- Там видны все запросы, ошибки, подключения

---

## ⚠️ Важно про Free Plan:

1. **Сервер "засыпает" после 15 минут бездействия**
   - При первом запросе "просыпается" (займёт ~30 секунд)
   - Решение: использовать "cron job" для пинга каждые 10 минут

2. **Ограничения Free плана:**
   - 750 часов в месяц (достаточно!)
   - 512 MB RAM
   - Shared CPU

3. **Upgrade на платный план ($7/мес):**
   - Сервер НЕ засыпает
   - Больше памяти и CPU
   - Лучше для production

---

## 🐛 Troubleshooting:

### **Проблема: "Build failed"**
- Проверь логи в Render
- Убедись что `package.json` валиден
- Проверь версию Node.js (должна быть >= 14)

### **Проблема: "Service unavailable"**
- Сервер может "просыпаться" (если Free plan)
- Подожди 30 секунд и попробуй снова

### **Проблема: "Database not found"**
- SQLite база создаётся автоматически при первом запуске
- Проверь что `DB_PATH` правильный в Environment Variables

---

## 📝 После деплоя:

1. ✅ Тестируй регистрацию: `/register`
2. ✅ Тестируй логин: `/login`
3. ✅ Проверь health check: `/health`
4. ✅ **Дай мне URL, я обновлю приложения!**

---

## 🎯 Следующие шаги:

После того как получишь URL:
1. Я обновлю `CheaterCheck` - поменяю `localhost:3000` на твой URL
2. Я обновлю `ModerationCheck` - поменяю URL для API и WebSocket
3. Пересоберу оба приложения
4. Ты сможешь тестировать через интернет!

---

## 💡 Полезные ссылки:

- **Render Dashboard:** https://dashboard.render.com/
- **Render Docs:** https://render.com/docs
- **Твой репозиторий:** https://github.com/KOTIK130/checkcheats-product
- **WebSocket на Render:** https://render.com/docs/websockets

---

**🎉 Жду твой URL сервера!**
