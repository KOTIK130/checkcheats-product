// test-license-system.js - Test license key system via API
require('dotenv').config();
const axios = require('axios');

const BASE_URL = 'http://localhost:10000';

let adminToken = '';
let testUserId = '';
let testKey = '';

async function test() {
  try {
    console.log('🧪 ТЕСТИРОВАНИЕ СИСТЕМЫ ЛИЦЕНЗИЙ');
    console.log('='.repeat(50));

    // 1. Login as admin
    console.log('\n1️⃣ Логин как админ...');
    const loginRes = await axios.post(`${BASE_URL}/api/auth/login`, {
      username: 'admin',
      password: 'admin123'
    });
    adminToken = loginRes.data.token;
    console.log('✅ Админ залогинен! Token:', adminToken.substring(0, 20) + '...');

    // 2. Generate key
    console.log('\n2️⃣ Генерация лицензионного ключа (30 дней)...');
    const keyRes = await axios.post(`${BASE_URL}/api/admin/generate-key`, {
      type: '30days',
      count: 1
    }, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    testKey = keyRes.data.keys[0].key;
    console.log('✅ Ключ сгенерирован:', testKey);

    // 3. Register test user
    console.log('\n3️⃣ Регистрация тестового пользователя...');
    const registerRes = await axios.post(`${BASE_URL}/api/auth/register`, {
      username: 'testuser_' + Date.now(),
      email: `test${Date.now()}@test.com`,
      password: 'Test123!'
    });
    const userToken = registerRes.data.token;
    console.log('✅ Пользователь зарегистрирован! Token:', userToken.substring(0, 20) + '...');

    // 4. Activate key
    console.log('\n4️⃣ Активация ключа...');
    const activateRes = await axios.post(`${BASE_URL}/api/license/activate`, {
      key: testKey,
      hwid: 'TEST-HWID-' + Math.random().toString(36).substring(7).toUpperCase()
    }, {
      headers: { Authorization: `Bearer ${userToken}` }
    });
    console.log('✅ Ключ активирован!');
    console.log('   Тип подписки:', activateRes.data.subscriptionType);
    console.log('   Истекает:', activateRes.data.subscriptionExpires);
    testUserId = activateRes.data.userId;

    // 5. Search by UID
    console.log('\n5️⃣ Поиск пользователя по UID...');
    const uid = activateRes.data.uid;
    const searchRes = await axios.post(`${BASE_URL}/api/admin/search-uid`, {
      uid: uid
    }, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    console.log('✅ Пользователь найден!');
    console.log('   Username:', searchRes.data.user.username);
    console.log('   Email:', searchRes.data.user.email);
    console.log('   HWID:', searchRes.data.user.hwid);

    // 6. Reset HWID
    console.log('\n6️⃣ Сброс HWID...');
    const resetRes = await axios.post(`${BASE_URL}/api/admin/reset-hwid`, {
      uid: uid
    }, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    console.log('✅ HWID сброшен!', resetRes.data.message);

    // 7. List all keys
    console.log('\n7️⃣ Получение списка всех ключей...');
    const keysRes = await axios.get(`${BASE_URL}/api/admin/keys`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    console.log(`✅ Всего ключей: ${keysRes.data.keys.length}`);
    console.log(`   Активных: ${keysRes.data.keys.filter(k => k.status === 'active').length}`);
    console.log(`   Использованных: ${keysRes.data.keys.filter(k => k.status === 'used').length}`);

    console.log('\n' + '='.repeat(50));
    console.log('🎉 ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО!');
    process.exit(0);

  } catch (err) {
    console.error('\n❌ ОШИБКА:', err.response?.data || err.message);
    process.exit(1);
  }
}

test();
