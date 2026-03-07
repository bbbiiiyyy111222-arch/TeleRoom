const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true }));

// Статические файлы из папки public
app.use(express.static(path.join(__dirname, 'public')));

// ========== ХРАНИЛИЩЕ ДАННЫХ ==========
let users = [];
let complaints = [];
let applications = [];

// Попытка загрузить данные из файлов (чтобы не терялись при перезапуске)
try {
    if (fs.existsSync('data.json')) {
        const data = JSON.parse(fs.readFileSync('data.json', 'utf8'));
        users = data.users || [];
        complaints = data.complaints || [];
        applications = data.applications || [];
        console.log('📁 Данные загружены из файла');
    }
} catch (e) {
    console.log('📁 Файл данных не найден, создаем новый');
}

// Функция сохранения данных
function saveData() {
    const data = {
        users,
        complaints,
        applications,
        savedAt: new Date().toISOString()
    };
    fs.writeFileSync('data.json', JSON.stringify(data, null, 2));
    console.log('💾 Данные сохранены');
}

// ========== ГЛАВНАЯ СТРАНИЦА ==========
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ========== ТЕСТОВЫЙ МАРШРУТ ==========
app.get('/api/test', (req, res) => {
    res.json({
        status: '✅ MoonGrief Server работает!',
        time: new Date().toLocaleString(),
        stats: {
            users: users.length,
            complaints: complaints.length,
            applications: applications.length
        },
        endpoints: {
            users: '/api/users',
            complaints: '/api/complaints',
            applications: '/api/applications',
            stats: '/api/stats'
        }
    });
});

// ========== API ДЛЯ ПОЛЬЗОВАТЕЛЕЙ ==========
app.get('/api/users', (req, res) => {
    res.json(users.map(u => ({
        username: u.username,
        minecraft: u.minecraft,
        registered: u.registered
    })));
});

app.post('/api/users/register', (req, res) => {
    try {
        const { username, password, minecraft } = req.body;
        
        if (!username || !password || !minecraft) {
            return res.status(400).json({ error: 'Все поля обязательны' });
        }
        
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
        saveData();
        
        console.log(`✅ Новый пользователь: ${username} (${minecraft})`);
        res.json({
            success: true,
            user: {
                username: newUser.username,
                minecraft: newUser.minecraft
            }
        });
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/users/login', (req, res) => {
    try {
        const { username, password } = req.body;
        const user = users.find(u => u.username === username && u.password === password);
        
        if (user) {
            console.log(`✅ Вход: ${username}`);
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
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ========== API ДЛЯ ЖАЛОБ ==========
app.get('/api/complaints', (req, res) => {
    res.json(complaints);
});

app.post('/api/complaints', (req, res) => {
    try {
        const complaint = req.body;
        complaint.id = Date.now();
        complaint.createdAt = new Date().toLocaleString();
        complaints.push(complaint);
        saveData();
        
        console.log(`✅ Новая жалоба от ${complaint.complainant} на ${complaint.accused}`);
        res.json({ success: true, complaint });
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.put('/api/complaints/:id', (req, res) => {
    try {
        const id = parseInt(req.params.id);
        const index = complaints.findIndex(c => c.id === id);
        
        if (index !== -1) {
            complaints[index] = { ...complaints[index], ...req.body };
            saveData();
            console.log(`✅ Жалоба ${id} обновлена`);
            res.json({ success: true, complaint: complaints[index] });
        } else {
            res.status(404).json({ error: 'Жалоба не найдена' });
        }
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.delete('/api/complaints/:id', (req, res) => {
    try {
        const id = parseInt(req.params.id);
        complaints = complaints.filter(c => c.id !== id);
        saveData();
        console.log(`✅ Жалоба ${id} удалена`);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ========== API ДЛЯ ЗАЯВОК ==========
app.get('/api/applications', (req, res) => {
    res.json(applications);
});

app.post('/api/applications', (req, res) => {
    try {
        const application = req.body;
        application.id = Date.now();
        application.createdAt = new Date().toLocaleString();
        applications.push(application);
        saveData();
        
        console.log(`✅ Новая заявка от ${application.userMinecraft}`);
        res.json({ success: true, application });
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.put('/api/applications/:id', (req, res) => {
    try {
        const id = parseInt(req.params.id);
        const index = applications.findIndex(a => a.id === id);
        
        if (index !== -1) {
            applications[index] = { ...applications[index], ...req.body };
            saveData();
            console.log(`✅ Заявка ${id} обновлена`);
            res.json({ success: true, application: applications[index] });
        } else {
            res.status(404).json({ error: 'Заявка не найдена' });
        }
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.delete('/api/applications/:id', (req, res) => {
    try {
        const id = parseInt(req.params.id);
        applications = applications.filter(a => a.id !== id);
        saveData();
        console.log(`✅ Заявка ${id} удалена`);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ========== СТАТИСТИКА ==========
app.get('/api/stats', (req, res) => {
    res.json({
        users: users.length,
        complaints: complaints.length,
        applications: applications.length,
        pendingComplaints: complaints.filter(c => c.status === 'pending').length,
        pendingApplications: applications.filter(a => a.status === 'pending').length,
        acceptedComplaints: complaints.filter(c => c.status === 'accepted').length,
        acceptedApplications: applications.filter(a => a.status === 'accepted').length,
        rejectedComplaints: complaints.filter(c => c.status === 'rejected').length,
        rejectedApplications: applications.filter(a => a.status === 'rejected').length
    });
});

// ========== ОЧИСТКА ВСЕХ ДАННЫХ (ОСТОРОЖНО!) ==========
app.post('/api/clear-all', (req, res) => {
    users = [];
    complaints = [];
    applications = [];
    saveData();
    console.log('⚠️ ВСЕ ДАННЫЕ ОЧИЩЕНЫ');
    res.json({ success: true, message: 'Все данные удалены' });
});

// ========== ЗАПУСК СЕРВЕРА ==========
app.listen(PORT, '0.0.0.0', () => {
    console.log('\n' + '='.repeat(50));
    console.log('🌙 MoonGrief Forum Server v1.0');
    console.log('='.repeat(50));
    console.log(`✅ Сервер запущен: http://localhost:${PORT}`);
    console.log(`📡 Тестовый API: http://localhost:${PORT}/api/test`);
    console.log(`📊 Статистика: http://localhost:${PORT}/api/stats`);
    console.log(`👥 Пользователи: ${users.length}`);
    console.log(`⚠️ Жалобы: ${complaints.length}`);
    console.log(`📝 Заявки: ${applications.length}`);
    console.log('='.repeat(50) + '\n');
});
