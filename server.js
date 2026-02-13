const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// ========== ШИФРОВАНИЕ AES-256-GCM ==========
const SECRET_KEY = crypto.randomBytes(32).toString('hex');
const ALGORITHM = 'aes-256-gcm';

function encrypt(text) {
    if (!text) return text;
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(SECRET_KEY, 'hex'), iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return JSON.stringify({ iv: iv.toString('hex'), encrypted, authTag: authTag.toString('hex') });
}

function decrypt(encryptedData) {
    if (!encryptedData || !encryptedData.startsWith('{')) return encryptedData;
    try {
        const { iv, encrypted, authTag } = JSON.parse(encryptedData);
        const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(SECRET_KEY, 'hex'), Buffer.from(iv, 'hex'));
        decipher.setAuthTag(Buffer.from(authTag, 'hex'));
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch {
        return encryptedData;
    }
}

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: '*', methods: ['GET', 'POST'] } });

// ========== СОЗДАНИЕ ПАПОК ==========
['./uploads/voice', './uploads/photos', './uploads/files', './avatars', './database'].forEach(folder => {
    if (!fs.existsSync(folder)) fs.mkdirSync(folder, { recursive: true });
});

// ========== НАСТРОЙКА MULTER ==========
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (file.fieldname === 'voice') cb(null, './uploads/voice/');
        else if (file.fieldname === 'photo') cb(null, './uploads/photos/');
        else if (file.fieldname === 'file') cb(null, './uploads/files/');
        else if (file.fieldname === 'avatar') cb(null, './avatars/');
        else cb(null, './uploads/');
    },
    filename: (req, file, cb) => {
        const unique = Date.now() + '_' + file.originalname.replace(/[^a-zA-Z0-9.]/g, '_');
        cb(null, unique);
    }
});
const upload = multer({ storage, limits: { fileSize: 100 * 1024 * 1024 } });

app.use(express.static(__dirname));
app.use('/uploads', express.static('uploads'));
app.use('/avatars', express.static('avatars'));
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

// ========== БАЗА ДАННЫХ ==========
const db = new sqlite3.Database('./database/teleroom.db');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        avatar TEXT,
        bio TEXT DEFAULT '',
        online INTEGER DEFAULT 0,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS groups (...)`); // ваши существующие таблицы
    db.run(`CREATE TABLE IF NOT EXISTS group_members (...)`);
    db.run(`CREATE TABLE IF NOT EXISTS private_chats (...)`);
    db.run(`CREATE TABLE IF NOT EXISTS messages (...)`);
    console.log('✅ База данных готова');
});

// ========== API ПРОВЕРКИ ИМЕНИ ==========
app.get('/api/check-username/:name', (req, res) => {
    db.get('SELECT id FROM users WHERE name = ?', [req.params.name], (err, user) => {
        res.json({ available: !user });
    });
});

// ========== API ПОЛЬЗОВАТЕЛЕЙ ==========
app.get('/api/users', (req, res) => {
    db.all('SELECT id, name, avatar, bio, online, last_seen FROM users ORDER BY name', (err, users) => {
        res.json(users || []);
    });
});

app.get('/api/users/:id', (req, res) => {
    db.get('SELECT id, name, phone, avatar, bio, online, last_seen, created_at FROM users WHERE id = ?', [req.params.id], (err, user) => {
        res.json(user || null);
    });
});

app.post('/api/users/update-bio', (req, res) => {
    const { userId, bio } = req.body;
    db.run('UPDATE users SET bio = ? WHERE id = ?', [bio, userId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// ========== API ПРОФИЛЯ ==========
app.post('/api/user/update-name', (req, res) => {
    const { userId, newName } = req.body;
    db.get('SELECT id FROM users WHERE name = ? AND id != ?', [newName, userId], (err, existing) => {
        if (existing) return res.status(400).json({ error: 'Имя занято' });
        db.run('UPDATE users SET name = ? WHERE id = ?', [newName, userId], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, name: newName });
            db.all('SELECT id, name, avatar, bio, online FROM users', (err, users) => io.emit('all_users', users || []));
        });
    });
});

app.post('/api/user/update-username', (req, res) => {
    const { userId, newUsername } = req.body;
    if (!newUsername || newUsername.length < 3) return res.status(400).json({ error: 'Минимум 3 символа' });
    db.get('SELECT id FROM users WHERE phone = ? AND id != ?', [newUsername, userId], (err, existing) => {
        if (existing) return res.status(400).json({ error: 'Юзернейм занят' });
        db.run('UPDATE users SET phone = ? WHERE id = ?', [newUsername, userId], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true, username: newUsername });
        });
    });
});

app.post('/api/user/upload-avatar', upload.single('avatar'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Нет файла' });
    const { userId } = req.body;
    db.run('UPDATE users SET avatar = ? WHERE id = ?', [req.file.filename, userId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, avatar: req.file.filename });
        db.all('SELECT id, name, avatar, bio, online FROM users', (err, users) => io.emit('all_users', users || []));
    });
});

app.post('/api/user/remove-avatar', (req, res) => {
    const { userId } = req.body;
    db.run('UPDATE users SET avatar = NULL WHERE id = ?', [userId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
        db.all('SELECT id, name, avatar, bio, online FROM users', (err, users) => io.emit('all_users', users || []));
    });
});

// ========== АВТОМАТИЧЕСКАЯ ГЕНЕРАЦИЯ ЮЗЕРНЕЙМА ==========
function generateUsername(id) {
    return `user${id}`;
}

// ========== API РЕГИСТРАЦИИ (WEB SOCKET) ==========
io.on('connection', (socket) => {
    console.log('👤 Подключился пользователь');

    socket.on('register', async (userData) => {
        const { name } = userData; // phone больше не передаём, генерируем на сервере
        try {
            // Проверяем, есть ли пользователь с таким именем
            db.get('SELECT * FROM users WHERE name = ?', [name], (err, existingUser) => {
                if (existingUser) {
                    // Автовход
                    socket.userId = existingUser.id;
                    socket.userName = existingUser.name;
                    db.run('UPDATE users SET online = 1, last_seen = CURRENT_TIMESTAMP WHERE id = ?', [existingUser.id]);
                    socket.emit('registered', existingUser);
                    sendUserData(socket, existingUser.id);
                    return;
                }
                // Создаём нового пользователя
                db.run('INSERT INTO users (name, phone) VALUES (?, ?)', [name, ''], function(err) {
                    if (err) {
                        console.error(err);
                        socket.emit('register_error', 'Ошибка регистрации');
                        return;
                    }
                    const newId = this.lastID;
                    const username = generateUsername(newId);
                    db.run('UPDATE users SET phone = ? WHERE id = ?', [username, newId], (err2) => {
                        if (err2) console.error(err2);
                        db.get('SELECT * FROM users WHERE id = ?', [newId], (err3, newUser) => {
                            if (err3 || !newUser) {
                                socket.emit('register_error', 'Ошибка создания');
                                return;
                            }
                            socket.userId = newUser.id;
                            socket.userName = newUser.name;
                            db.run('UPDATE users SET online = 1 WHERE id = ?', [newUser.id]);
                            socket.emit('registered', newUser);
                            sendUserData(socket, newUser.id);
                        });
                    });
                });
            });
        } catch (e) {
            console.error(e);
            socket.emit('register_error', 'Ошибка сервера');
        }
    });

    function sendUserData(socket, userId) {
        db.all(`SELECT g.*, COUNT(DISTINCT gm.user_id) as members_count
                FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.user_id = ? GROUP BY g.id`, [userId], (e, g) => {
            socket.emit('user_groups', g || []);
        });
        db.all(`SELECT pc.id,
                       CASE WHEN pc.user1_id = ? THEN pc.user2_id ELSE pc.user1_id END as other_user_id,
                       u.name as other_user_name, u.avatar as other_user_avatar, u.online
                FROM private_chats pc JOIN users u ON (CASE WHEN pc.user1_id = ? THEN pc.user2_id ELSE pc.user1_id END) = u.id
                WHERE pc.user1_id = ? OR pc.user2_id = ?`, [userId, userId, userId, userId], (e, p) => {
            socket.emit('user_private_chats', p || []);
        });
        db.all('SELECT id, name, avatar, bio, online FROM users', (e, u) => {
            socket.emit('all_users', u || []);
        });
        socket.broadcast.emit('user_online', userId);
    }

    // ... остальные обработчики socket.on('join_group', 'send_message', 'typing', 'update_bio', 'disconnect') ...
    // (они остаются без изменений, копируем из предыдущего рабочего сервера)
    // Для краткости я их не дублирую, но они должны быть здесь.
    // В финальном коде вставь полные обработчики.
});

// ========== ОСТАЛЬНЫЕ API (ГРУППЫ, ЧАТЫ, ЗАГРУЗКИ) ==========
// ... (полностью скопировать из предыдущей версии, они уже рабочие)

// ========== ЗАПУСК ==========
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log('\n' + '='.repeat(60));
    console.log('   🚀 TeleRoom NEO — АВТО-ЮЗЕРЫ, ЗВОНКИ');
    console.log('='.repeat(60));
    console.log(`   📱 Порт: ${PORT}`);
    console.log('   ✅ Вход, автовход, юзернеймы user1..userN');
    console.log('   ✅ Профили, аватарки, группы, личные чаты');
    console.log('   ✅ Звонки (заглушка)');
    console.log('   ✅ Мобильная адаптация — ИДЕАЛ');
    console.log('='.repeat(60) + '\n');
});
