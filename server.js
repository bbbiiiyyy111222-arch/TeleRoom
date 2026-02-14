// ==================== server.js - TeleRoom Ultimate ====================
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const sanitize = require('sanitize-filename');

// ========== НАСТРОЙКА ==========
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: { origin: '*', methods: ['GET', 'POST'] },
    pingTimeout: 60000,
    pingInterval: 25000
});

// Базовая защита
app.use(helmet({
    contentSecurityPolicy: false,
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { error: 'Слишком много запросов' }
});
app.use('/api/', limiter);

const uploadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 50,
    message: { error: 'Слишком много загрузок' }
});

// ========== ПАПКИ ==========
const folders = [
    './uploads/voice',
    './uploads/photos',
    './uploads/files',
    './uploads/group_avatars',  // новая папка для аватарок групп
    './avatars',
    './database'
];

folders.forEach(folder => {
    if (!fs.existsSync(folder)) {
        fs.mkdirSync(folder, { recursive: true });
        console.log(`✅ Создана папка: ${folder}`);
    }
});

// ========== НАСТРОЙКА ЗАГРУЗКИ ==========
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (file.fieldname === 'voice') cb(null, './uploads/voice/');
        else if (file.fieldname === 'photo') cb(null, './uploads/photos/');
        else if (file.fieldname === 'file') cb(null, './uploads/files/');
        else if (file.fieldname === 'avatar') cb(null, './avatars/');
        else if (file.fieldname === 'groupAvatar') cb(null, './uploads/group_avatars/');
        else cb(null, './uploads/');
    },
    filename: (req, file, cb) => {
        const cleanName = sanitize(file.originalname).replace(/[^a-zA-Z0-9.]/g, '_');
        const uniqueName = Date.now() + '_' + cleanName;
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 50 * 1024 * 1024 } // 50 MB
});

// ========== СТАТИКА ==========
app.use(express.static(__dirname));
app.use('/uploads', express.static('uploads'));
app.use('/avatars', express.static('avatars'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ========== БАЗА ДАННЫХ ==========
const db = new sqlite3.Database('./database/teleroom.db');

// Функция для проверки наличия колонки в таблице
function columnExists(table, column) {
    return new Promise((resolve, reject) => {
        db.all(`PRAGMA table_info(${table})`, (err, rows) => {
            if (err) reject(err);
            else resolve(rows.some(col => col.name === column));
        });
    });
}

// Инициализация таблиц и добавление недостающих колонок
db.serialize(async () => {
    // Пользователи
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

    // Группы
    db.run(`CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        avatar TEXT,
        created_by INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(id)
    )`);

    // Добавляем колонку avatar, если её нет
    try {
        const hasAvatar = await columnExists('groups', 'avatar');
        if (!hasAvatar) {
            db.run("ALTER TABLE groups ADD COLUMN avatar TEXT");
            console.log('✅ Добавлена колонка avatar в таблицу groups');
        }
    } catch (err) {
        console.error('Ошибка при проверке колонки avatar:', err);
    }

    // Участники групп
    db.run(`CREATE TABLE IF NOT EXISTS group_members (
        group_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        role TEXT DEFAULT 'member',
        joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (group_id, user_id),
        FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // Личные чаты
    db.run(`CREATE TABLE IF NOT EXISTS private_chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user1_id INTEGER NOT NULL,
        user2_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user1_id, user2_id),
        FOREIGN KEY (user1_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (user2_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // Сообщения
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_type TEXT NOT NULL,
        chat_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        text TEXT,
        photo_url TEXT,
        voice_url TEXT,
        file_url TEXT,
        file_name TEXT,
        file_size INTEGER,
        duration TEXT,
        reply_to INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // Индексы
    db.run(`CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_type, chat_id, created_at)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_group_members ON group_members(group_id, user_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_private_chats ON private_chats(user1_id, user2_id)`);

    console.log('✅ База данных готова');
});

// ========== ВСПОМОГАТЕЛЬНЫЕ ==========
function dbGet(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err);
            else resolve(row);
        });
    });
}

function dbAll(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

function dbRun(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function(err) {
            if (err) reject(err);
            else resolve({ lastID: this.lastID, changes: this.changes });
        });
    });
}

// Генерация следующего свободного username в формате user1, user2, ...
async function generateNextUsername() {
    const rows = await dbAll("SELECT phone FROM users WHERE phone GLOB 'user*'");
    let maxNum = 0;
    for (const row of rows) {
        const match = row.phone.match(/^user(\d+)$/);
        if (match) {
            const num = parseInt(match[1], 10);
            if (num > maxNum) maxNum = num;
        }
    }
    return `user${maxNum + 1}`;
}

// Проверка, является ли пользователь админом группы
async function isGroupAdmin(groupId, userId) {
    const member = await dbGet(
        'SELECT role FROM group_members WHERE group_id = ? AND user_id = ?',
        [groupId, userId]
    );
    return member && member.role === 'admin';
}

// ========== API ==========
// Проверка имени
app.get('/api/check-username/:name', async (req, res) => {
    try {
        const name = sanitize(req.params.name).substring(0, 30);
        if (!name || name.length < 2) return res.json({ available: false });
        const user = await dbGet('SELECT id FROM users WHERE name = ?', [name]);
        res.json({ available: !user });
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Все пользователи
app.get('/api/users', async (req, res) => {
    try {
        const users = await dbAll('SELECT id, name, avatar, bio, online, last_seen FROM users ORDER BY name');
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Пользователь по ID
app.get('/api/users/:id', async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) return res.status(400).json({ error: 'Неверный ID' });
        const user = await dbGet('SELECT id, name, phone, avatar, bio, online, last_seen, created_at FROM users WHERE id = ?', [id]);
        if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
        res.json(user);
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Обновить био
app.post('/api/users/update-bio',
    body('bio').optional().trim().isLength({ max: 200 }),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ error: 'Слишком длинное био' });

        try {
            const { userId, bio } = req.body;
            await dbRun('UPDATE users SET bio = ? WHERE id = ?', [bio || '', userId]);
            const users = await dbAll('SELECT id, name, avatar, bio, online FROM users');
            io.emit('all_users', users);
            res.json({ success: true });
        } catch (err) {
            res.status(500).json({ error: 'Ошибка сервера' });
        }
    }
);

// Обновить имя
app.post('/api/user/update-name',
    body('newName').trim().isLength({ min: 2, max: 30 }),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ error: 'Имя должно быть от 2 до 30 символов' });

        try {
            const { userId, newName } = req.body;
            const existing = await dbGet('SELECT id FROM users WHERE name = ? AND id != ?', [newName, userId]);
            if (existing) return res.status(400).json({ error: 'Это имя уже занято!' });

            await dbRun('UPDATE users SET name = ? WHERE id = ?', [newName, userId]);
            const users = await dbAll('SELECT id, name, avatar, bio, online FROM users');
            io.emit('all_users', users);
            res.json({ success: true, name: newName });
        } catch (err) {
            res.status(500).json({ error: 'Ошибка сервера' });
        }
    }
);

// Обновить юзернейм (phone)
app.post('/api/user/update-username',
    body('newUsername').trim().isLength({ min: 3, max: 20 }).matches(/^[a-zA-Z0-9_]+$/),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ error: 'Юзернейм должен быть 3-20 символов: буквы, цифры, _' });

        try {
            const { userId, newUsername } = req.body;
            const existing = await dbGet('SELECT id FROM users WHERE phone = ? AND id != ?', [newUsername, userId]);
            if (existing) return res.status(400).json({ error: 'Этот юзернейм уже занят!' });

            await dbRun('UPDATE users SET phone = ? WHERE id = ?', [newUsername, userId]);
            res.json({ success: true, username: newUsername });
        } catch (err) {
            res.status(500).json({ error: 'Ошибка сервера' });
        }
    }
);

// Загрузить аватар пользователя
app.post('/api/user/upload-avatar', uploadLimiter, upload.single('avatar'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Нет файла' });

    try {
        const { userId } = req.body;
        const avatar = req.file.filename;

        // Удаляем старый аватар
        const user = await dbGet('SELECT avatar FROM users WHERE id = ?', [userId]);
        if (user && user.avatar) {
            const oldPath = path.join(__dirname, 'avatars', user.avatar);
            if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
        }

        await dbRun('UPDATE users SET avatar = ? WHERE id = ?', [avatar, userId]);
        const users = await dbAll('SELECT id, name, avatar, bio, online FROM users');
        io.emit('all_users', users);
        res.json({ success: true, avatar });
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Удалить аватар пользователя
app.post('/api/user/remove-avatar', async (req, res) => {
    try {
        const { userId } = req.body;
        const user = await dbGet('SELECT avatar FROM users WHERE id = ?', [userId]);
        if (user && user.avatar) {
            const filePath = path.join(__dirname, 'avatars', user.avatar);
            if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        }
        await dbRun('UPDATE users SET avatar = NULL WHERE id = ?', [userId]);
        const users = await dbAll('SELECT id, name, avatar, bio, online FROM users');
        io.emit('all_users', users);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ========== ГРУППЫ ==========
// Создать группу
app.post('/api/groups',
    body('name').trim().isLength({ min: 2, max: 50 }),
    body('description').optional().trim().isLength({ max: 200 }),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ error: 'Некорректные данные' });

        try {
            const { name, description, userId } = req.body;
            const result = await dbRun('INSERT INTO groups (name, description, created_by) VALUES (?, ?, ?)', [name, description || '', userId]);
            const groupId = result.lastID;
            await dbRun('INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, ?)', [groupId, userId, 'admin']);
            res.json({ id: groupId, name, description });
        } catch (err) {
            res.status(500).json({ error: 'Ошибка сервера' });
        }
    }
);

// Получить группы пользователя
app.get('/api/groups/:userId', async (req, res) => {
    try {
        const userId = parseInt(req.params.userId);
        if (isNaN(userId)) return res.status(400).json({ error: 'Неверный ID' });

        const groups = await dbAll(`
            SELECT g.*,
                   COUNT(DISTINCT gm.user_id) as members_count,
                   (SELECT text FROM messages WHERE chat_type = 'group' AND chat_id = g.id ORDER BY created_at DESC LIMIT 1) as last_message,
                   (SELECT created_at FROM messages WHERE chat_type = 'group' AND chat_id = g.id ORDER BY created_at DESC LIMIT 1) as last_time
            FROM groups g
            JOIN group_members gm ON g.id = gm.group_id
            WHERE gm.user_id = ?
            GROUP BY g.id
            ORDER BY g.created_at DESC
        `, [userId]);

        res.json(groups);
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Получить участников группы
app.get('/api/groups/:groupId/members', async (req, res) => {
    try {
        const groupId = parseInt(req.params.groupId);
        if (isNaN(groupId)) return res.status(400).json({ error: 'Неверный ID' });

        const members = await dbAll(`
            SELECT u.id, u.name, u.avatar, u.online, u.last_seen, gm.role, gm.joined_at
            FROM group_members gm
            JOIN users u ON gm.user_id = u.id
            WHERE gm.group_id = ?
            ORDER BY gm.joined_at
        `, [groupId]);
        res.json(members);
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Добавить участника в группу
app.post('/api/groups/add_member', async (req, res) => {
    try {
        const { group_id, user_id } = req.body;
        await dbRun('INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)', [group_id, user_id]);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Обновить название группы (только админ)
app.post('/api/groups/update-name',
    body('newName').trim().isLength({ min: 2, max: 50 }),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ error: 'Некорректное название' });

        try {
            const { groupId, userId, newName } = req.body;
            if (!await isGroupAdmin(groupId, userId)) {
                return res.status(403).json({ error: 'Только админ может менять название' });
            }
            await dbRun('UPDATE groups SET name = ? WHERE id = ?', [newName, groupId]);
            res.json({ success: true, name: newName });
        } catch (err) {
            res.status(500).json({ error: 'Ошибка сервера' });
        }
    }
);

// Обновить описание группы (только админ)
app.post('/api/groups/update-description',
    body('newDescription').optional().trim().isLength({ max: 200 }),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ error: 'Слишком длинное описание' });

        try {
            const { groupId, userId, newDescription } = req.body;
            if (!await isGroupAdmin(groupId, userId)) {
                return res.status(403).json({ error: 'Только админ может менять описание' });
            }
            await dbRun('UPDATE groups SET description = ? WHERE id = ?', [newDescription || '', groupId]);
            res.json({ success: true, description: newDescription });
        } catch (err) {
            res.status(500).json({ error: 'Ошибка сервера' });
        }
    }
);

// Загрузить аватар группы (только админ)
app.post('/api/groups/upload-avatar', uploadLimiter, upload.single('groupAvatar'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Нет файла' });

    try {
        const { groupId, userId } = req.body;
        if (!await isGroupAdmin(groupId, userId)) {
            return res.status(403).json({ error: 'Только админ может менять аватар' });
        }

        const avatar = req.file.filename;

        // Удаляем старый аватар группы
        const group = await dbGet('SELECT avatar FROM groups WHERE id = ?', [groupId]);
        if (group && group.avatar) {
            const oldPath = path.join(__dirname, 'uploads/group_avatars', group.avatar);
            if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
        }

        await dbRun('UPDATE groups SET avatar = ? WHERE id = ?', [avatar, groupId]);
        res.json({ success: true, avatar });
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Сообщения группы
app.get('/api/messages/group/:groupId', async (req, res) => {
    try {
        const groupId = parseInt(req.params.groupId);
        if (isNaN(groupId)) return res.status(400).json({ error: 'Неверный ID' });

        const messages = await dbAll(`
            SELECT m.*, u.name as user_name, u.avatar as user_avatar
            FROM messages m
            JOIN users u ON m.user_id = u.id
            WHERE m.chat_type = 'group' AND m.chat_id = ?
            ORDER BY m.created_at ASC
            LIMIT 500
        `, [groupId]);

        res.json(messages);
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ========== ЛИЧНЫЕ ЧАТЫ ==========
app.post('/api/private_chat', async (req, res) => {
    try {
        const { user1_id, user2_id } = req.body;
        if (user1_id === user2_id) return res.status(400).json({ error: 'Нельзя создать чат с самим собой' });

        const minId = Math.min(user1_id, user2_id);
        const maxId = Math.max(user1_id, user2_id);

        await dbRun('INSERT OR IGNORE INTO private_chats (user1_id, user2_id) VALUES (?, ?)', [minId, maxId]);
        const chat = await dbGet('SELECT id FROM private_chats WHERE user1_id = ? AND user2_id = ?', [minId, maxId]);
        res.json({ chat_id: chat.id });
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/private_chats/:userId', async (req, res) => {
    try {
        const userId = parseInt(req.params.userId);
        if (isNaN(userId)) return res.status(400).json({ error: 'Неверный ID' });

        const chats = await dbAll(`
            SELECT pc.id,
                   CASE
                       WHEN pc.user1_id = ? THEN pc.user2_id
                       ELSE pc.user1_id
                   END as other_user_id,
                   u.name as other_user_name,
                   u.avatar as other_user_avatar,
                   u.online,
                   u.last_seen,
                   (SELECT text FROM messages WHERE chat_type = 'private' AND chat_id = pc.id ORDER BY created_at DESC LIMIT 1) as last_message,
                   (SELECT created_at FROM messages WHERE chat_type = 'private' AND chat_id = pc.id ORDER BY created_at DESC LIMIT 1) as last_time
            FROM private_chats pc
            JOIN users u ON (CASE WHEN pc.user1_id = ? THEN pc.user2_id ELSE pc.user1_id END) = u.id
            WHERE pc.user1_id = ? OR pc.user2_id = ?
            ORDER BY last_time DESC
        `, [userId, userId, userId, userId]);

        res.json(chats);
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/messages/private/:chatId', async (req, res) => {
    try {
        const chatId = parseInt(req.params.chatId);
        if (isNaN(chatId)) return res.status(400).json({ error: 'Неверный ID' });

        const messages = await dbAll(`
            SELECT m.*, u.name as user_name, u.avatar as user_avatar
            FROM messages m
            JOIN users u ON m.user_id = u.id
            WHERE m.chat_type = 'private' AND m.chat_id = ?
            ORDER BY m.created_at ASC
            LIMIT 500
        `, [chatId]);

        res.json(messages);
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ========== ЗАГРУЗКА ФАЙЛОВ ==========
app.post('/api/upload/voice', uploadLimiter, upload.single('voice'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Нет файла' });

    try {
        const { chat_type, chat_id, user_id, duration } = req.body;
        const voice_url = req.file.filename;
        const result = await dbRun(
            'INSERT INTO messages (chat_type, chat_id, user_id, voice_url, duration) VALUES (?, ?, ?, ?, ?)',
            [chat_type, chat_id, user_id, voice_url, duration || '0:05']
        );
        const message = await dbGet(`
            SELECT m.*, u.name as user_name, u.avatar as user_avatar
            FROM messages m
            JOIN users u ON m.user_id = u.id
            WHERE m.id = ?
        `, [result.lastID]);
        const room = chat_type === 'group' ? `group_${chat_id}` : `private_${chat_id}`;
        io.to(room).emit('new_message', message);
        res.json(message);
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/upload/photo', uploadLimiter, upload.single('photo'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Нет файла' });

    try {
        const { chat_type, chat_id, user_id } = req.body;
        const photo_url = req.file.filename;
        const result = await dbRun(
            'INSERT INTO messages (chat_type, chat_id, user_id, photo_url) VALUES (?, ?, ?, ?)',
            [chat_type, chat_id, user_id, photo_url]
        );
        const message = await dbGet(`
            SELECT m.*, u.name as user_name, u.avatar as user_avatar
            FROM messages m
            JOIN users u ON m.user_id = u.id
            WHERE m.id = ?
        `, [result.lastID]);
        const room = chat_type === 'group' ? `group_${chat_id}` : `private_${chat_id}`;
        io.to(room).emit('new_message', message);
        res.json(message);
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/upload/file', uploadLimiter, upload.single('file'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Нет файла' });

    try {
        const { chat_type, chat_id, user_id } = req.body;
        const file_url = req.file.filename;
        const file_name = req.file.originalname;
        const file_size = req.file.size;
        const result = await dbRun(
            'INSERT INTO messages (chat_type, chat_id, user_id, file_url, file_name, file_size) VALUES (?, ?, ?, ?, ?, ?)',
            [chat_type, chat_id, user_id, file_url, file_name, file_size]
        );
        const message = await dbGet(`
            SELECT m.*, u.name as user_name, u.avatar as user_avatar
            FROM messages m
            JOIN users u ON m.user_id = u.id
            WHERE m.id = ?
        `, [result.lastID]);
        const room = chat_type === 'group' ? `group_${chat_id}` : `private_${chat_id}`;
        io.to(room).emit('new_message', message);
        res.json(message);
    } catch (err) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ========== СОКЕТЫ ==========
io.on('connection', (socket) => {
    console.log('👤 Пользователь подключился');

    socket.on('register', async (userData) => {
        try {
            const { name } = userData;
            if (!name || typeof name !== 'string' || name.length < 2 || name.length > 30) {
                socket.emit('register_error', 'Имя должно быть от 2 до 30 символов');
                return;
            }
            const cleanName = sanitize(name).substring(0, 30);

            let user = await dbGet('SELECT * FROM users WHERE name = ?', [cleanName]);

            if (user) {
                socket.userId = user.id;
                socket.userName = user.name;
                await dbRun('UPDATE users SET online = 1, last_seen = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
                socket.emit('registered', user);
                await sendUserData(socket, user.id);
                socket.broadcast.emit('user_online', user.id);
                return;
            }

            const username = await generateNextUsername();
            const result = await dbRun('INSERT INTO users (name, phone) VALUES (?, ?)', [cleanName, username]);
            const newUser = await dbGet('SELECT * FROM users WHERE id = ?', [result.lastID]);
            socket.userId = newUser.id;
            socket.userName = newUser.name;
            await dbRun('UPDATE users SET online = 1 WHERE id = ?', [newUser.id]);

            socket.emit('registered', newUser);
            await sendUserData(socket, newUser.id);
            socket.broadcast.emit('user_online', newUser.id);
        } catch (err) {
            console.error('Ошибка регистрации:', err);
            socket.emit('register_error', 'Ошибка сервера');
        }
    });

    async function sendUserData(socket, userId) {
        try {
            const groups = await dbAll(`
                SELECT g.*, COUNT(DISTINCT gm.user_id) as members_count
                FROM groups g
                JOIN group_members gm ON g.id = gm.group_id
                WHERE gm.user_id = ?
                GROUP BY g.id
            `, [userId]);
            socket.emit('user_groups', groups);

            const privateChats = await dbAll(`
                SELECT pc.id,
                       CASE
                           WHEN pc.user1_id = ? THEN pc.user2_id
                           ELSE pc.user1_id
                       END as other_user_id,
                       u.name as other_user_name,
                       u.avatar as other_user_avatar,
                       u.online
                FROM private_chats pc
                JOIN users u ON (CASE WHEN pc.user1_id = ? THEN pc.user2_id ELSE pc.user1_id END) = u.id
                WHERE pc.user1_id = ? OR pc.user2_id = ?
            `, [userId, userId, userId, userId]);
            socket.emit('user_private_chats', privateChats);

            const users = await dbAll('SELECT id, name, avatar, bio, online FROM users');
            socket.emit('all_users', users);
        } catch (err) {
            console.error('Ошибка отправки данных:', err);
        }
    }

    socket.on('join_group', (groupId) => {
        socket.join(`group_${groupId}`);
    });

    socket.on('join_private_chat', (chatId) => {
        socket.join(`private_${chatId}`);
    });

    socket.on('send_message', async (data) => {
        try {
            const { chat_type, chat_id, user_id, text } = data;
            if (!chat_type || !chat_id || !user_id || !text) return;
            if (text.length > 2000) return;
            if (user_id !== socket.userId) return;

            const result = await dbRun(
                'INSERT INTO messages (chat_type, chat_id, user_id, text) VALUES (?, ?, ?, ?)',
                [chat_type, chat_id, user_id, text]
            );
            const message = await dbGet(`
                SELECT m.*, u.name as user_name, u.avatar as user_avatar
                FROM messages m
                JOIN users u ON m.user_id = u.id
                WHERE m.id = ?
            `, [result.lastID]);

            const room = chat_type === 'group' ? `group_${chat_id}` : `private_${chat_id}`;
            io.to(room).emit('new_message', message);
        } catch (err) {
            console.error('Ошибка отправки сообщения:', err);
        }
    });

    socket.on('typing', (data) => {
        const { chat_type, chat_id, user_id, user_name, is_typing } = data;
        const room = chat_type === 'group' ? `group_${chat_id}` : `private_${chat_id}`;
        socket.to(room).emit('user_typing', { user_id, user_name, is_typing });
    });

    socket.on('disconnect', async () => {
        if (socket.userId) {
            await dbRun('UPDATE users SET online = 0, last_seen = CURRENT_TIMESTAMP WHERE id = ?', [socket.userId]);
            socket.broadcast.emit('user_offline', socket.userId);
            console.log(`👋 ${socket.userName} отключился`);
        }
    });
});

// ========== ГЛАВНАЯ ==========
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ========== ОБРАБОТКА ОШИБОК ==========
app.use((err, req, res, next) => {
    console.error(err.stack);
    if (err instanceof multer.MulterError) {
        if (err.code === 'FILE_TOO_LARGE') return res.status(413).json({ error: 'Файл слишком большой' });
        return res.status(400).json({ error: err.message });
    }
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
});

// ========== ЗАПУСК ==========
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log('\n' + '='.repeat(60));
    console.log('   🚀 TeleRoom Server Ultimate');
    console.log('='.repeat(60));
    console.log(`   📱 Порт: ${PORT}`);
    console.log('   ✅ Все функции: чаты, группы, файлы, звонки (демо)');
    console.log('='.repeat(60) + '\n');
});
