const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// ========== ХРАНИЛИЩЕ ДАННЫХ ==========
// ВНИМАНИЕ: на Vercel данные НЕ сохраняются между перезапусками!
// Нужно использовать базу данных, но пока оставим так
let users = [];
let complaints = [];
let applications = [];

// Тестовые данные
users = [
    { username: 'milk123', password: '123', minecraft: 'milk123', registered: 'сейчас' },
    { username: 'Xchik_', password: '123', minecraft: 'Xchik_', registered: 'сейчас' },
    { username: 'milfa', password: '123', minecraft: 'milfa', registered: 'сейчас' }
];

complaints = [
    {
        id: 1,
        complainant: 'Игрок1',
        accused: 'Грифер',
        ruleNumber: '2.1',
        description: 'Разрушил дом',
        photos: [],
        status: 'pending',
        date: 'только что',
        userId: 'test',
        userMinecraft: 'Игрок1',
        ownerResponse: null
    }
];

applications = [
    {
        id: 1,
        userId: 'test',
        userMinecraft: 'Кандидат',
        nickname: 'Кандидат',
        name: 'Иван',
        age: '20',
        timezone: 'UTC+3',
        experience: 'Был хелпером',
        why: 'Хочу помогать',
        status: 'pending',
        date: 'только что',
        ownerResponse: null
    }
];

// ========== API МАРШРУТЫ ==========

// Тест
app.get('/api/test', (req, res) => {
    res.json({ 
        message: '✅ MoonGrief на Vercel работает!',
        time: new Date().toLocaleString(),
        stats: {
            users: users.length,
            complaints: complaints.length,
            applications: applications.length
        }
    });
});

// Пользователи
app.get('/api/users', (req, res) => {
    res.json(users);
});

app.post('/api/users/register', (req, res) => {
    const { username, password, minecraft } = req.body;
    
    if (users.find(u => u.username === username)) {
        return res.status(400).json({ error: 'Пользователь уже есть' });
    }
    
    const newUser = {
        id: Date.now(),
        username,
        password,
        minecraft,
        registered: new Date().toLocaleString()
    };
    
    users.push(newUser);
    res.json({ success: true, user: { username, minecraft } });
});

app.post('/api/users/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username && u.password === password);
    
    if (user) {
        res.json({ success: true, user: { username: user.username, minecraft: user.minecraft } });
    } else {
        res.status(401).json({ error: 'Неверно' });
    }
});

// Жалобы
app.get('/api/complaints', (req, res) => {
    res.json(complaints);
});

app.post('/api/complaints', (req, res) => {
    const complaint = req.body;
    complaint.id = Date.now();
    complaints.push(complaint);
    res.json({ success: true, complaint });
});

app.put('/api/complaints/:id', (req, res) => {
    const id = parseInt(req.params.id);
    const index = complaints.findIndex(c => c.id === id);
    if (index !== -1) {
        complaints[index] = { ...complaints[index], ...req.body };
        res.json({ success: true, complaint: complaints[index] });
    } else {
        res.status(404).json({ error: 'Не найдено' });
    }
});

app.delete('/api/complaints/:id', (req, res) => {
    const id = parseInt(req.params.id);
    complaints = complaints.filter(c => c.id !== id);
    res.json({ success: true });
});

// Заявки
app.get('/api/applications', (req, res) => {
    res.json(applications);
});

app.post('/api/applications', (req, res) => {
    const application = req.body;
    application.id = Date.now();
    applications.push(application);
    res.json({ success: true, application });
});

app.put('/api/applications/:id', (req, res) => {
    const id = parseInt(req.params.id);
    const index = applications.findIndex(a => a.id === id);
    if (index !== -1) {
        applications[index] = { ...applications[index], ...req.body };
        res.json({ success: true, application: applications[index] });
    } else {
        res.status(404).json({ error: 'Не найдено' });
    }
});

app.delete('/api/applications/:id', (req, res) => {
    const id = parseInt(req.params.id);
    applications = applications.filter(a => a.id !== id);
    res.json({ success: true });
});

// Статистика
app.get('/api/stats', (req, res) => {
    res.json({
        users: users.length,
        complaints: complaints.length,
        applications: applications.length,
        pendingComplaints: complaints.filter(c => c.status === 'pending').length,
        pendingApplications: applications.filter(a => a.status === 'pending').length
    });
});

// ========== ЭКСПОРТ для Vercel ==========
module.exports = app;
