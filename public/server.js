const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' })); // Увеличил лимит для фото
app.use(express.static('public'));

// ========== ХРАНИЛИЩЕ ДАННЫХ (в памяти сервера) ==========
let users = [];
let complaints = [];
let applications = [];

// ========== ТЕСТОВЫЙ МАРШРУТ ==========
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

app.get('/api/test', (req, res) => {
  res.json({ message: 'Server is working!' });
});

// ========== API ДЛЯ ПОЛЬЗОВАТЕЛЕЙ ==========

// Получить всех пользователей
app.get('/api/users', (req, res) => {
  res.json(users);
});

// Регистрация
app.post('/api/users/register', (req, res) => {
  const { username, password, minecraft } = req.body;
  
  // Проверяем, есть ли уже такой пользователь
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ error: 'Пользователь уже существует' });
  }
  
  const newUser = {
    id: Date.now(),
    username,
    password,
    minecraft,
    registered: new Date().toLocaleString()
  };
  
  users.push(newUser);
  res.json({ 
    success: true, 
    user: { 
      username: newUser.username, 
      minecraft: newUser.minecraft 
    } 
  });
});

// Вход
app.post('/api/users/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  
  if (user) {
    res.json({ 
      success: true, 
      user: { 
        username: user.username, 
        minecraft: user.minecraft 
      } 
    });
  } else {
    res.status(401).json({ error: 'Неверный логин или пароль' });
  }
});

// ========== API ДЛЯ ЖАЛОБ ==========

// Получить ВСЕ жалобы (без фильтрации!)
app.get('/api/complaints', (req, res) => {
  res.json(complaints);
});

// Создать новую жалобу
app.post('/api/complaints', (req, res) => {
  const complaint = req.body;
  complaint.id = Date.now();
  complaints.push(complaint);
  console.log('✅ Новая жалоба:', complaint);
  res.json({ success: true, complaint });
});

// Обновить жалобу (принять/отклонить/ответить)
app.put('/api/complaints/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const index = complaints.findIndex(c => c.id === id);
  
  if (index !== -1) {
    complaints[index] = { ...complaints[index], ...req.body };
    console.log('✅ Жалоба обновлена:', complaints[index]);
    res.json({ success: true, complaint: complaints[index] });
  } else {
    res.status(404).json({ error: 'Жалоба не найдена' });
  }
});

// Удалить жалобу
app.delete('/api/complaints/:id', (req, res) => {
  const id = parseInt(req.params.id);
  complaints = complaints.filter(c => c.id !== id);
  console.log('✅ Жалоба удалена, id:', id);
  res.json({ success: true });
});

// ========== API ДЛЯ ЗАЯВОК ==========

// Получить ВСЕ заявки (без фильтрации!)
app.get('/api/applications', (req, res) => {
  res.json(applications);
});

// Создать новую заявку
app.post('/api/applications', (req, res) => {
  const application = req.body;
  application.id = Date.now();
  applications.push(application);
  console.log('✅ Новая заявка:', application);
  res.json({ success: true, application });
});

// Обновить заявку (принять/отклонить/ответить)
app.put('/api/applications/:id', (req, res) => {
  const id = parseInt(req.params.id);
  const index = applications.findIndex(a => a.id === id);
  
  if (index !== -1) {
    applications[index] = { ...applications[index], ...req.body };
    console.log('✅ Заявка обновлена:', applications[index]);
    res.json({ success: true, application: applications[index] });
  } else {
    res.status(404).json({ error: 'Заявка не найдена' });
  }
});

// Удалить заявку
app.delete('/api/applications/:id', (req, res) => {
  const id = parseInt(req.params.id);
  applications = applications.filter(a => a.id !== id);
  console.log('✅ Заявка удалена, id:', id);
  res.json({ success: true });
});

// ========== АДМИН-ФУНКЦИИ ==========

// Получить статистику
app.get('/api/stats', (req, res) => {
  res.json({
    users: users.length,
    complaints: complaints.length,
    applications: applications.length,
    pendingComplaints: complaints.filter(c => c.status === 'pending').length,
    pendingApplications: applications.filter(a => a.status === 'pending').length
  });
});

// Очистить все данные (только для тестирования!)
app.post('/api/clear', (req, res) => {
  users = [];
  complaints = [];
  applications = [];
  console.log('⚠️ Все данные очищены');
  res.json({ success: true, message: 'Все данные очищены' });
});

// ========== ЗАПУСК СЕРВЕРА ==========
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server is running on port ${PORT}`);
  console.log(`📡 Test API: http://localhost:${PORT}/api/test`);
  console.log(`📊 Stats API: http://localhost:${PORT}/api/stats`);
  console.log(`👥 Users: 0 | Жалобы: 0 | Заявки: 0`);
});


