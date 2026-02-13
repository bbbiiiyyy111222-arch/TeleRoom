const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const sanitize = require('sanitize-filename');

// ========== КРИПТОГРАФИЧЕСКАЯ ЗАЩИТА ==========
const KEY_FILE = path.join(__dirname, '.encryption.key');
let SECRET_KEY;
if (fs.existsSync(KEY_FILE)) {
    SECRET_KEY = fs.readFileSync(KEY_FILE, 'utf8');
} else {
    SECRET_KEY = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(KEY_FILE, SECRET_KEY);
    console.log('🔑 Новый ключ шифрования создан и сохранён');
}

const ALGORITHM = 'aes-256-gcm';

function encrypt(text) {
    if (!text) return text;
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(SECRET_KEY, 'hex'), iv);
    let encrypted = cipher.update(text.toString(), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return JSON.stringify({
        iv: iv.toString('hex'),
        encrypted,
        authTag: authTag.toString('hex')
    });
}

function decrypt(encryptedData) {
    if (!encryptedData || !encryptedData.startsWith('{')) return encryptedData;
    try {
        const { iv, encrypted, authTag } = JSON.parse(encryptedData);
        const decipher = crypto.createDecipheriv(
            ALGORITHM,
            Buffer.from(SECRET_KEY, 'hex'),
            Buffer.from(iv, 'hex')
        );
        decipher.setAuthTag(Buffer.from(authTag, 'hex'));
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (e) {
        console.error('Ошибка дешифрования:', e.message);
        return encryptedData;
    }
}

// ========== НАСТРОЙКА EXPRESS ==========
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: { origin: '*', methods: ['GET', 'POST'] }
});

// ========== БЕЗОПАСНОСТЬ HELMET ==========
app.use(helmet({
    contentSecurityPolicy: false, // отключаем для упрощения, если нужны инлайн-скрипты
}));

// ========== RATE LIMITING ==========
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 минут
    max: 100, // максимум 100 запросов с одного IP
    message: { error: 'Слишком много запросов, попробуйте позже' },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use('/api/', apiLimiter); // применяем ко всем /api/*

// Для загрузки файлов можно сделать более щадящий лимит
const uploadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 час
    max: 50,
    message: { error: 'Слишком много загрузок, попробуйте позже' }
});

// ========== СОЗДАНИЕ ПАПОК ==========
const folders = [
    './uploads/voice',
    './uploads/photos',
    './uploads/files',
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
        else cb(null, './uploads/');
    },
    filename: (req, file, cb) => {
        // Очищаем имя файла от небезопасных символов
        const cleanName = sanitize(file.originalname) || 'file';
        const uniqueName = Date.now() + '_' + cleanName.replace(/\s+/g, '_');
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage,
    limits: { fileSize: 100 * 1024 * 1024 } // 100 MB
});

// ========== СТАТИЧЕСКИЕ ФАЙЛЫ ==========
app.use(express.static(__dirname));
app.use('/uploads', express.static('uploads'));
app.use('/avatars', express.static('avatars'));
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

// ========== БАЗА ДАННЫХ ==========
const db = new sqlite3.Database('./database/teleroom.db');

db.serialize(() => {
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
    console.log(`🔐 Ключ шифрования: ${SECRET_KEY.substring(0, 16)}...`);
});

// ========== АВТОГЕНЕРАЦИЯ ЮЗЕРНЕЙМА ==========
async function generateUniqueUsername(base) {
    let username = base;
    let counter = 1;
    while (await dbGet('SELECT id FROM users WHERE phone = ?', [username])) {
        username = `${base}_${counter++}`;
    }
    return username;
}

// ========== ВСПОМОГАТЕЛЬНЫЕ АСИНХРОННЫЕ ФУНКЦИИ ==========
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

// ========== ВАЛИДАЦИЯ ==========
const validateName = body('name')
    .trim()
    .isLength({ min: 2, max: 30 })
    .withMessage('Имя должно быть от 2 до 30 символов')
    .matches(/^[a-zA-Z0-9а-яА-ЯёЁ\s]+$/)
    .withMessage('Имя содержит недопустимые символы');

const validateUserId = body('userId').isInt().withMessage('Некорректный ID пользователя');
const validateGroupId = body('groupId').isInt().withMessage('Некорректный ID группы');
const validateChatId = body('chat_id').isInt().withMessage('Некорректный ID чата');
const validateChatType = body('chat_type').isIn(['private', 'group']).withMessage('Неверный тип чата');
const validateMessageText = body('text')
    .optional()
    .isLength({ max: 2000 })
    .withMessage('Сообщение слишком длинное');

// ========== API ПРОВЕРКИ ИМЕНИ ==========
app.get('/api/check-username/:name', async (req, res) => {
    try {
        const name = req.params.name;
        if (!name || name.length < 2) {
            return res.json({ available: false });
        }
        const user = await dbGet('SELECT id FROM users WHERE name = ?', [name]);
        res.json({ available: !user });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ========== API ПОЛЬЗОВАТЕЛЕЙ ==========
app.get('/api/users', async (req, res) => {
    try {
        const users = await dbAll('SELECT id, name, avatar, bio, online, last_seen FROM users ORDER BY name');
        res.json(users || []);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/users/:id', async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id)) return res.status(400).json({ error: 'Неверный ID' });

        const user = await dbGet(
            'SELECT id, name, phone, avatar, bio, online, last_seen, created_at FROM users WHERE id = ?',
            [id]
        );
        if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
        res.json(user);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/users/update-bio',
    validateUserId,
    body('bio').optional().trim().isLength({ max: 200 }),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        try {
            const { userId, bio } = req.body;
            const user = await dbGet('SELECT id FROM users WHERE id = ?', [userId]);
            if (!user) return res.status(404).json({ error: 'Пользователь не найден' });

            await dbRun('UPDATE users SET bio = ? WHERE id = ?', [bio || '', userId]);

            const users = await dbAll('SELECT id, name, avatar, bio, online FROM users');
            io.emit('all_users', users || []);

            res.json({ success: true });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Ошибка сервера' });
        }
    }
);

// ========== API ПРОФИЛЯ ==========
app.post('/api/user/update-name',
    validateUserId,
    validateName,
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: errors.array()[0].msg });
        }

        try {
            const { userId, newName } = req.body;

            const existing = await dbGet(
                'SELECT id FROM users WHERE name = ? AND id != ?',
                [newName, userId]
            );
            if (existing) {
                return res.status(400).json({ error: 'Это имя уже занято!' });
            }

            const result = await dbRun('UPDATE users SET name = ? WHERE id = ?', [newName, userId]);
            if (result.changes === 0) {
                return res.status(404).json({ error: 'Пользователь не найден' });
            }

            const users = await dbAll('SELECT id, name, avatar, bio, online FROM users');
            io.emit('all_users', users || []);

            res.json({ success: true, name: newName });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Ошибка сервера' });
        }
    }
);

app.post('/api/user/update-username',
    validateUserId,
    body('newUsername')
        .trim()
        .isLength({ min: 3, max: 20 })
        .withMessage('Юзернейм должен быть от 3 до 20 символов')
        .matches(/^[a-zA-Z0-9_]+$/)
        .withMessage('Юзернейм может содержать только буквы, цифры и _'),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: errors.array()[0].msg });
        }

        try {
            const { userId, newUsername } = req.body;

            const existing = await dbGet(
                'SELECT id FROM users WHERE phone = ? AND id != ?',
                [newUsername, userId]
            );
            if (existing) {
                return res.status(400).json({ error: 'Этот юзернейм уже занят!' });
            }

            const result = await dbRun('UPDATE users SET phone = ? WHERE id = ?', [newUsername, userId]);
            if (result.changes === 0) {
                return res.status(404).json({ error: 'Пользователь не найден' });
            }

            res.json({ success: true, username: newUsername });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Ошибка сервера' });
        }
    }
);

app.post('/api/user/upload-avatar', uploadLimiter, upload.single('avatar'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Нет файла' });
    }

    try {
        const { userId } = req.body;
        if (!userId || isNaN(userId)) {
            return res.status(400).json({ error: 'Неверный ID пользователя' });
        }

        const avatar = req.file.filename;

        const user = await dbGet('SELECT id FROM users WHERE id = ?', [userId]);
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        await dbRun('UPDATE users SET avatar = ? WHERE id = ?', [avatar, userId]);

        const users = await dbAll('SELECT id, name, avatar, bio, online FROM users');
        io.emit('all_users', users || []);

        res.json({ success: true, avatar });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/user/remove-avatar', validateUserId, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Неверный ID пользователя' });
    }

    try {
        const { userId } = req.body;

        const user = await dbGet('SELECT avatar FROM users WHERE id = ?', [userId]);
        if (!user) {
            return res.status(404).json({ error: 'Пользователь не найден' });
        }

        if (user.avatar) {
            const filePath = path.join(__dirname, 'avatars', user.avatar);
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
        }

        await dbRun('UPDATE users SET avatar = NULL WHERE id = ?', [userId]);

        const users = await dbAll('SELECT id, name, avatar, bio, online FROM users');
        io.emit('all_users', users || []);

        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ========== API ГРУПП ==========
app.post('/api/groups',
    validateUserId,
    body('name').trim().isLength({ min: 2, max: 50 }).withMessage('Название группы должно быть от 2 до 50 символов'),
    body('description').optional().trim().isLength({ max: 200 }),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: errors.array()[0].msg });
        }

        try {
            const { name, description, userId } = req.body;

            const user = await dbGet('SELECT id FROM users WHERE id = ?', [userId]);
            if (!user) {
                return res.status(404).json({ error: 'Пользователь не найден' });
            }

            const result = await dbRun(
                'INSERT INTO groups (name, description, created_by) VALUES (?, ?, ?)',
                [name, description || '', userId]
            );
            const groupId = result.lastID;

            await dbRun(
                'INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, ?)',
                [groupId, userId, 'admin']
            );

            res.json({ id: groupId, name, description });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Ошибка сервера' });
        }
    }
);

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
        res.json(groups || []);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/groups/:groupId/members', async (req, res) => {
    try {
        const groupId = parseInt(req.params.groupId);
        if (isNaN(groupId)) return res.status(400).json({ error: 'Неверный ID группы' });

        const members = await dbAll(`
            SELECT u.id, u.name, u.avatar, u.online, u.last_seen, gm.role, gm.joined_at
            FROM group_members gm
            JOIN users u ON gm.user_id = u.id
            WHERE gm.group_id = ?
            ORDER BY gm.joined_at
        `, [groupId]);
        res.json(members || []);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/groups/add_member',
    validateGroupId,
    body('user_id').isInt(),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'Неверные данные' });
        }

        try {
            const { group_id, user_id } = req.body;

            await dbRun(
                'INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)',
                [group_id, user_id]
            );
            res.json({ success: true });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Ошибка сервера' });
        }
    }
);

app.post('/api/groups/update-name',
    validateGroupId,
    validateUserId,
    body('newName').trim().isLength({ min: 2, max: 50 }),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: errors.array()[0].msg });
        }

        try {
            const { groupId, userId, newName } = req.body;

            const member = await dbGet(
                'SELECT role FROM group_members WHERE group_id = ? AND user_id = ?',
                [groupId, userId]
            );
            if (!member || member.role !== 'admin') {
                return res.status(403).json({ error: 'Только админ может менять название' });
            }

            await dbRun('UPDATE groups SET name = ? WHERE id = ?', [newName, groupId]);
            res.json({ success: true, name: newName });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Ошибка сервера' });
        }
    }
);

app.post('/api/groups/update-description',
    validateGroupId,
    validateUserId,
    body('newDescription').optional().trim().isLength({ max: 200 }),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: errors.array()[0].msg });
        }

        try {
            const { groupId, userId, newDescription } = req.body;

            const member = await dbGet(
                'SELECT role FROM group_members WHERE group_id = ? AND user_id = ?',
                [groupId, userId]
            );
            if (!member || member.role !== 'admin') {
                return res.status(403).json({ error: 'Только админ может менять описание' });
            }

            await dbRun('UPDATE groups SET description = ? WHERE id = ?', [newDescription, groupId]);
            res.json({ success: true, description: newDescription });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Ошибка сервера' });
        }
    }
);

app.get('/api/messages/group/:groupId', async (req, res) => {
    try {
        const groupId = parseInt(req.params.groupId);
        if (isNaN(groupId)) return res.status(400).json({ error: 'Неверный ID группы' });

        const messages = await dbAll(`
            SELECT m.*, u.name as user_name, u.avatar as user_avatar
            FROM messages m
            JOIN users u ON m.user_id = u.id
            WHERE m.chat_type = 'group' AND m.chat_id = ?
            ORDER BY m.created_at ASC
            LIMIT 500
        `, [groupId]);

        const decrypted = messages.map(msg => {
            if (msg.text) msg.text = decrypt(msg.text);
            return msg;
        });
        res.json(decrypted || []);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ========== API ЛИЧНЫХ ЧАТОВ ==========
app.post('/api/private_chat',
    body('user1_id').isInt(),
    body('user2_id').isInt(),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'Неверные ID пользователей' });
        }

        try {
            const { user1_id, user2_id } = req.body;
            if (user1_id === user2_id) {
                return res.status(400).json({ error: 'Нельзя создать чат с самим собой' });
            }

            const minId = Math.min(user1_id, user2_id);
            const maxId = Math.max(user1_id, user2_id);

            await dbRun(
                'INSERT OR IGNORE INTO private_chats (user1_id, user2_id) VALUES (?, ?)',
                [minId, maxId]
            );

            const chat = await dbGet(
                'SELECT id FROM private_chats WHERE user1_id = ? AND user2_id = ?',
                [minId, maxId]
            );
            if (!chat) {
                return res.status(500).json({ error: 'Не удалось создать чат' });
            }

            res.json({ chat_id: chat.id });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Ошибка сервера' });
        }
    }
);

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
        res.json(chats || []);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/messages/private/:chatId', async (req, res) => {
    try {
        const chatId = parseInt(req.params.chatId);
        if (isNaN(chatId)) return res.status(400).json({ error: 'Неверный ID чата' });

        const messages = await dbAll(`
            SELECT m.*, u.name as user_name, u.avatar as user_avatar
            FROM messages m
            JOIN users u ON m.user_id = u.id
            WHERE m.chat_type = 'private' AND m.chat_id = ?
            ORDER BY m.created_at ASC
            LIMIT 500
        `, [chatId]);

        const decrypted = messages.map(msg => {
            if (msg.text) msg.text = decrypt(msg.text);
            return msg;
        });
        res.json(decrypted || []);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ========== ЗАГРУЗКА ФАЙЛОВ ==========
app.post('/api/upload/voice', uploadLimiter, upload.single('voice'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Нет файла' });
    }

    try {
        const { chat_type, chat_id, user_id, duration } = req.body;
        if (!chat_type || !chat_id || !user_id) {
            return res.status(400).json({ error: 'Не хватает данных' });
        }
        if (!['private', 'group'].includes(chat_type)) {
            return res.status(400).json({ error: 'Неверный тип чата' });
        }

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
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/upload/photo', uploadLimiter, upload.single('photo'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Нет файла' });
    }

    try {
        const { chat_type, chat_id, user_id } = req.body;
        if (!chat_type || !chat_id || !user_id) {
            return res.status(400).json({ error: 'Не хватает данных' });
        }
        if (!['private', 'group'].includes(chat_type)) {
            return res.status(400).json({ error: 'Неверный тип чата' });
        }

        const photo_url = req.file.filename;

        const result = await dbRun(
            'INSERT INTO messages (chat_type, chat_id, user_id, photo_url, text) VALUES (?, ?, ?, ?, ?)',
            [chat_type, chat_id, user_id, photo_url, encrypt('📷 Фото')]
        );

        const message = await dbGet(`
            SELECT m.*, u.name as user_name, u.avatar as user_avatar
            FROM messages m
            JOIN users u ON m.user_id = u.id
            WHERE m.id = ?
        `, [result.lastID]);

        if (message.text) message.text = decrypt(message.text);
        const room = chat_type === 'group' ? `group_${chat_id}` : `private_${chat_id}`;
        io.to(room).emit('new_message', message);

        res.json(message);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/upload/file', uploadLimiter, upload.single('file'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Нет файла' });
    }

    try {
        const { chat_type, chat_id, user_id } = req.body;
        if (!chat_type || !chat_id || !user_id) {
            return res.status(400).json({ error: 'Не хватает данных' });
        }
        if (!['private', 'group'].includes(chat_type)) {
            return res.status(400).json({ error: 'Неверный тип чата' });
        }

        const file_url = req.file.filename;
        const file_name = req.file.originalname;
        const file_size = req.file.size;

        const result = await dbRun(
            'INSERT INTO messages (chat_type, chat_id, user_id, file_url, file_name, file_size, text) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [chat_type, chat_id, user_id, file_url, file_name, file_size, encrypt('📎 Файл')]
        );

        const message = await dbGet(`
            SELECT m.*, u.name as user_name, u.avatar as user_avatar
            FROM messages m
            JOIN users u ON m.user_id = u.id
            WHERE m.id = ?
        `, [result.lastID]);

        if (message.text) message.text = decrypt(message.text);
        const room = chat_type === 'group' ? `group_${chat_id}` : `private_${chat_id}`;
        io.to(room).emit('new_message', message);

        res.json(message);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ========== WEB SOCKET ==========
io.on('connection', (socket) => {
    console.log('👤 Подключился пользователь');

    socket.on('register', async (userData) => {
        try {
            const { name } = userData;
            if (!name || typeof name !== 'string' || name.length < 2 || name.length > 30) {
                socket.emit('register_error', 'Имя должно быть от 2 до 30 символов');
                return;
            }
            console.log(`📝 Попытка регистрации: ${name}`);

            // Проверяем, существует ли пользователь с таким именем
            let user = await dbGet('SELECT * FROM users WHERE name = ?', [name]);

            if (user) {
                // Автовход
                console.log(`🔄 Автовход для: ${user.name}`);
                socket.userId = user.id;
                socket.userName = user.name;

                await dbRun(
                    'UPDATE users SET online = 1, last_seen = CURRENT_TIMESTAMP WHERE id = ?',
                    [user.id]
                );

                socket.emit('registered', user);
                await sendUserData(socket, user.id);
                socket.broadcast.emit('user_online', user.id);
                return;
            }

            // Создаём нового пользователя — генерируем уникальный phone (username)
            const baseUsername = `user${Date.now()}`;
            const username = await generateUniqueUsername(baseUsername);

            const result = await dbRun(
                'INSERT INTO users (name, phone) VALUES (?, ?)',
                [name, username]
            );

            const newId = result.lastID;
            const newUser = await dbGet('SELECT * FROM users WHERE id = ?', [newId]);
            if (!newUser) {
                socket.emit('register_error', 'Ошибка при создании');
                return;
            }

            console.log(`✅ Новый пользователь: ${newUser.name} (ID: ${newUser.id}, username: ${username})`);
            socket.userId = newUser.id;
            socket.userName = newUser.name;

            await dbRun('UPDATE users SET online = 1 WHERE id = ?', [newUser.id]);

            socket.emit('registered', newUser);
            await sendUserData(socket, newUser.id);
            socket.broadcast.emit('user_online', newUser.id);
        } catch (err) {
            console.error('Ошибка регистрации:', err);
            socket.emit('register_error', 'Внутренняя ошибка сервера');
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
            socket.emit('user_groups', groups || []);

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
            socket.emit('user_private_chats', privateChats || []);

            const users = await dbAll('SELECT id, name, avatar, bio, online FROM users');
            socket.emit('all_users', users || []);
        } catch (err) {
            console.error('Ошибка отправки данных:', err);
        }
    }

    socket.on('join_group', (groupId) => {
        if (!groupId || isNaN(groupId)) return;
        socket.join(`group_${groupId}`);
        console.log(`👥 ${socket.userName} присоединился к группе ${groupId}`);
    });

    socket.on('join_private_chat', (chatId) => {
        if (!chatId || isNaN(chatId)) return;
        socket.join(`private_${chatId}`);
        console.log(`💬 ${socket.userName} присоединился к личному чату ${chatId}`);
    });

    socket.on('send_message', async (data) => {
        try {
            const { chat_type, chat_id, user_id, text } = data;

            if (!chat_type || !chat_id || !user_id || !text) return;
            if (!['private', 'group'].includes(chat_type)) return;
            if (text.length > 2000) return;

            const encryptedText = encrypt(text);

            const result = await dbRun(
                'INSERT INTO messages (chat_type, chat_id, user_id, text) VALUES (?, ?, ?, ?)',
                [chat_type, chat_id, user_id, encryptedText]
            );

            const message = await dbGet(`
                SELECT m.*, u.name as user_name, u.avatar as user_avatar
                FROM messages m
                JOIN users u ON m.user_id = u.id
                WHERE m.id = ?
            `, [result.lastID]);

            if (message) {
                message.text = decrypt(message.text);
                const room = chat_type === 'group' ? `group_${chat_id}` : `private_${chat_id}`;
                io.to(room).emit('new_message', message);
            }
        } catch (err) {
            console.error('Ошибка отправки сообщения:', err);
        }
    });

    socket.on('typing', (data) => {
        const { chat_type, chat_id, user_id, user_name, is_typing } = data;
        if (!chat_type || !chat_id || !user_id) return;
        const room = chat_type === 'group' ? `group_${chat_id}` : `private_${chat_id}`;
        socket.to(room).emit('user_typing', {
            user_id,
            user_name,
            is_typing: !!is_typing
        });
    });

    socket.on('disconnect', async () => {
        if (socket.userId) {
            try {
                await dbRun(
                    'UPDATE users SET online = 0, last_seen = CURRENT_TIMESTAMP WHERE id = ?',
                    [socket.userId]
                );
                socket.broadcast.emit('user_offline', socket.userId);
                console.log(`👋 ${socket.userName} отключился`);
            } catch (err) {
                console.error('Ошибка при отключении:', err);
            }
        }
    });
});

// ========== ГЛАВНАЯ ==========
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

// ========== ОБРАБОТКА ОШИБОК ==========
app.use((err, req, res, next) => {
    console.error(err.stack);
    if (err instanceof multer.MulterError) {
        if (err.code === 'FILE_TOO_LARGE') {
            return res.status(413).json({ error: 'Файл слишком большой' });
        }
        return res.status(400).json({ error: err.message });
    }
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
});

// ========== ЗАПУСК ==========
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log('\n' + '='.repeat(60));
    console.log('   🚀 TeleRoom PRO — АВТО-ЮЗЕРЫ, ШИФРОВАНИЕ, ЗВОНКИ');
    console.log('='.repeat(60));
    console.log(`   📱 Порт: ${PORT}`);
    console.log('   🔐 AES-256-GCM (ключ сохранён в .encryption.key)');
    console.log('   🛡️ Helmet, rate limiting, валидация');
    console.log('   ✅ Вход / Автовход (только name)');
    console.log('   ✅ Авто-юзернеймы: user<timestamp>_N');
    console.log('   ✅ Профили, аватарки, био');
    console.log('   ✅ Группы, личные чаты');
    console.log('   ✅ Голосовые, фото, файлы');
    console.log('   ✅ Звонки (заглушка)');
    console.log('='.repeat(60) + '\n');
});
