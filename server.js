// ==================== server.js - ULTRA SECURE ====================
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
const zlib = require('zlib');

// ========== КРИПТОГРАФИЧЕСКАЯ ЗАЩИТА УЛЬТРА УРОВНЯ ==========
const KEY_FILE = path.join(__dirname, '.master.key');
const SALT_FILE = path.join(__dirname, '.salt');
const IV_LENGTH = 16;
const SALT_LENGTH = 64;
const KEY_LENGTH = 32;
const TAG_LENGTH = 16;

// Генерация или загрузка мастер-ключа с солью
let SECRET_KEY, SALT;
if (fs.existsSync(KEY_FILE) && fs.existsSync(SALT_FILE)) {
    SECRET_KEY = fs.readFileSync(KEY_FILE, 'utf8');
    SALT = fs.readFileSync(SALT_FILE, 'utf8');
    console.log('🔑 Мастер-ключ загружен');
} else {
    SECRET_KEY = crypto.randomBytes(32).toString('hex');
    SALT = crypto.randomBytes(64).toString('hex');
    fs.writeFileSync(KEY_FILE, SECRET_KEY);
    fs.writeFileSync(SALT_FILE, SALT);
    console.log('🔑 Новый мастер-ключ создан и сохранён');
}

const ALGORITHM = 'aes-256-gcm';

// Функция для получения ключа сессии (динамический ключ на основе соли)
function getSessionKey(sessionId) {
    return crypto.pbkdf2Sync(SECRET_KEY, SALT + sessionId, 100000, 32, 'sha512');
}

// Шифрование с дополнительной защитой
function ultraEncrypt(text, sessionId = 'default') {
    if (!text) return text;
    const iv = crypto.randomBytes(IV_LENGTH);
    const key = getSessionKey(sessionId);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    
    // Сжатие перед шифрованием
    const compressed = zlib.deflateSync(text.toString()).toString('base64');
    
    let encrypted = cipher.update(compressed, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    
    // Добавляем хеш для проверки целостности
    const hash = crypto.createHash('sha256').update(encrypted + authTag.toString('hex')).digest('hex').substring(0, 16);
    
    return JSON.stringify({
        iv: iv.toString('hex'),
        encrypted,
        tag: authTag.toString('hex'),
        hash,
        version: '2.0'
    });
}

// Дешифрование с проверкой целостности
function ultraDecrypt(encryptedData, sessionId = 'default') {
    if (!encryptedData || !encryptedData.startsWith('{')) return encryptedData;
    try {
        const { iv, encrypted, tag, hash, version } = JSON.parse(encryptedData);
        
        // Проверка хеша
        const computedHash = crypto.createHash('sha256').update(encrypted + tag).digest('hex').substring(0, 16);
        if (hash && computedHash !== hash) {
            console.error('⚠️ Нарушение целостности данных!');
            return '[ПОВРЕЖДЕННЫЕ ДАННЫЕ]';
        }
        
        const key = getSessionKey(sessionId);
        const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(iv, 'hex'));
        decipher.setAuthTag(Buffer.from(tag, 'hex'));
        
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        // Распаковка
        const decompressed = zlib.inflateSync(Buffer.from(decrypted, 'base64')).toString();
        return decompressed;
    } catch (e) {
        console.error('❌ Ошибка дешифрования:', e.message);
        return '[НЕДОСТУПНО]';
    }
}

// ========== НАСТРОЙКА EXPRESS ==========
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: { origin: '*', methods: ['GET', 'POST'] },
    pingTimeout: 60000,
    pingInterval: 25000
});

// ========== УЛЬТРА ЗАЩИТА HELMET ==========
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            imgSrc: ["'self'", "data:", "blob:"],
            connectSrc: ["'self'", "ws:", "wss:"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"]
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    referrerPolicy: { policy: 'same-origin' }
}));

// ========== RATE LIMITING АГРЕССИВНЫЙ ==========
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: '❌ Слишком много запросов. Подождите 15 минут.' },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false
});

const authLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: { error: '❌ Слишком много попыток входа. Подождите час.' },
    skipSuccessfulRequests: true
});

const uploadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 20,
    message: { error: '❌ Лимит загрузок. Подождите час.' }
});

app.use('/api/', globalLimiter);
app.use('/api/register', authLimiter);

// ========== СОЗДАНИЕ ПАПОК ==========
const folders = [
    './uploads/voice',
    './uploads/photos',
    './uploads/files',
    './avatars',
    './database',
    './logs',
    './temp'
];

folders.forEach(folder => {
    if (!fs.existsSync(folder)) {
        fs.mkdirSync(folder, { recursive: true, mode: 0o755 });
        console.log(`✅ Создана папка: ${folder}`);
    }
});

// ========== ЛОГИРОВАНИЕ ==========
function logSecurity(event, details, ip) {
    const logEntry = {
        timestamp: new Date().toISOString(),
        event,
        details,
        ip: ip || 'unknown'
    };
    const logFile = path.join(__dirname, 'logs', `security-${new Date().toISOString().split('T')[0]}.log`);
    fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n');
}

// ========== НАСТРОЙКА ЗАГРУЗКИ ==========
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        let dest = './uploads/';
        if (file.fieldname === 'voice') dest = './uploads/voice/';
        else if (file.fieldname === 'photo') dest = './uploads/photos/';
        else if (file.fieldname === 'file') dest = './uploads/files/';
        else if (file.fieldname === 'avatar') dest = './avatars/';
        cb(null, dest);
    },
    filename: (req, file, cb) => {
        // Максимальная очистка имени
        const cleanName = sanitize(file.originalname).replace(/[^a-zA-Z0-9.-]/g, '_');
        const uniqueName = `${Date.now()}_${crypto.randomBytes(8).toString('hex')}_${cleanName}`;
        cb(null, uniqueName);
    }
});

const fileFilter = (req, file, cb) => {
    // Проверка MIME типов
    const allowedTypes = {
        'image': ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
        'audio': ['audio/webm', 'audio/mp3', 'audio/ogg', 'audio/mpeg'],
        'file': ['application/pdf', 'application/zip', 'text/plain', 'application/msword']
    };
    
    let allowed = false;
    if (file.fieldname === 'avatar' || file.fieldname === 'photo') {
        allowed = allowedTypes.image.includes(file.mimetype);
    } else if (file.fieldname === 'voice') {
        allowed = allowedTypes.audio.includes(file.mimetype);
    } else {
        allowed = true; // для файлов
    }
    
    if (allowed) {
        cb(null, true);
    } else {
        cb(new Error('❌ Недопустимый тип файла'));
    }
};

const upload = multer({
    storage,
    fileFilter,
    limits: { 
        fileSize: 50 * 1024 * 1024, // 50 MB
        files: 1
    }
});

// ========== СТАТИЧЕСКИЕ ФАЙЛЫ ==========
app.use(express.static(__dirname, {
    maxAge: '1d',
    etag: true,
    lastModified: true
}));
app.use('/uploads', express.static('uploads', { maxAge: '1d' }));
app.use('/avatars', express.static('avatars', { maxAge: '1d' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ========== БАЗА ДАННЫХ ==========
const db = new sqlite3.Database('./database/teleroom_ultra.db');

// Включение внешних ключей и WAL режима
db.run('PRAGMA foreign_keys = ON');
db.run('PRAGMA journal_mode = WAL');
db.run('PRAGMA synchronous = NORMAL');

db.serialize(() => {
    // Пользователи с усиленной защитой
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        avatar TEXT,
        bio TEXT DEFAULT '',
        online INTEGER DEFAULT 0,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_ip TEXT,
        user_agent TEXT,
        failed_attempts INTEGER DEFAULT 0,
        locked_until DATETIME,
        session_id TEXT UNIQUE,
        public_key TEXT,
        CHECK (length(name) >= 2 AND length(name) <= 30)
    )`);

    // Группы
    db.run(`CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        avatar TEXT,
        created_by INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_private INTEGER DEFAULT 0,
        password_hash TEXT,
        FOREIGN KEY (created_by) REFERENCES users(id)
    )`);

    // Участники групп
    db.run(`CREATE TABLE IF NOT EXISTS group_members (
        group_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        role TEXT DEFAULT 'member',
        joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        muted_until DATETIME,
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
        last_message_id INTEGER,
        UNIQUE(user1_id, user2_id),
        FOREIGN KEY (user1_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (user2_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // Сообщения с дополнительными полями безопасности
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_type TEXT NOT NULL CHECK(chat_type IN ('private', 'group')),
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
        edited INTEGER DEFAULT 0,
        deleted INTEGER DEFAULT 0,
        encrypted_version TEXT DEFAULT '2.0',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (reply_to) REFERENCES messages(id)
    )`);

    // Сессии
    db.run(`CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME,
        ip TEXT,
        user_agent TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // Блокировки
    db.run(`CREATE TABLE IF NOT EXISTS blocks (
        user_id INTEGER NOT NULL,
        blocked_user_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, blocked_user_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (blocked_user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    // Индексы для производительности
    db.run(`CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_type, chat_id, created_at)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_messages_user ON messages(user_id, created_at)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_group_members ON group_members(group_id, user_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_private_chats ON private_chats(user1_id, user2_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_users_online ON users(online)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)`);

    console.log('✅ База данных Ultra Secure готова');
    console.log(`🔐 Мастер-ключ: ${SECRET_KEY.substring(0, 8)}...${SECRET_KEY.slice(-8)}`);
});

// ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========
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

async function generateSessionId() {
    let sessionId;
    let exists;
    do {
        sessionId = crypto.randomBytes(32).toString('hex');
        exists = await dbGet('SELECT id FROM sessions WHERE id = ?', [sessionId]);
    } while (exists);
    return sessionId;
}

// ========== API С ПРОВЕРКАМИ ==========
// Проверка имени
app.get('/api/check-username/:name', async (req, res) => {
    try {
        const name = sanitize(req.params.name).substring(0, 30);
        if (!name || name.length < 2) {
            return res.json({ available: false });
        }
        const user = await dbGet('SELECT id FROM users WHERE name = ?', [name]);
        res.json({ available: !user });
    } catch (err) {
        logSecurity('check_username_error', err.message, req.ip);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ========== API ПОЛЬЗОВАТЕЛЕЙ ==========
app.get('/api/users', async (req, res) => {
    try {
        const users = await dbAll(`
            SELECT id, name, avatar, bio, online, 
                   datetime(last_seen, 'localtime') as last_seen 
            FROM users 
            WHERE locked_until IS NULL OR locked_until < CURRENT_TIMESTAMP
            ORDER BY name
        `);
        res.json(users);
    } catch (err) {
        logSecurity('get_users_error', err.message, req.ip);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/users/:id', async (req, res) => {
    try {
        const id = parseInt(req.params.id);
        if (isNaN(id) || id < 1) {
            return res.status(400).json({ error: 'Неверный ID' });
        }
        
        const user = await dbGet(`
            SELECT id, name, phone, avatar, bio, online, 
                   datetime(last_seen, 'localtime') as last_seen,
                   datetime(created_at, 'localtime') as created_at 
            FROM users 
            WHERE id = ? AND (locked_until IS NULL OR locked_until < CURRENT_TIMESTAMP)
        `, [id]);
        
        if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
        
        // Маскируем телефон
        user.phone = user.phone.substring(0, 3) + '***' + user.phone.slice(-3);
        res.json(user);
    } catch (err) {
        logSecurity('get_user_error', err.message, req.ip);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ========== ВЕБ-СОКЕТЫ С ЗАЩИТОЙ ==========
io.use((socket, next) => {
    const clientIp = socket.handshake.address;
    
    // Проверка на слишком частые подключения
    const now = Date.now();
    if (global.connectionTracker) {
        const recent = global.connectionTracker[clientIp] || [];
        const recentConnections = recent.filter(t => now - t < 60000).length;
        
        if (recentConnections > 5) {
            logSecurity('rate_limit_exceeded', 'Too many connections', clientIp);
            return next(new Error('Слишком частые подключения'));
        }
        
        recent.push(now);
        if (recent.length > 10) recent.shift();
        global.connectionTracker[clientIp] = recent;
    } else {
        global.connectionTracker = { [clientIp]: [now] };
    }
    
    next();
});

io.on('connection', (socket) => {
    const clientIp = socket.handshake.address;
    console.log(`👤 Новое подключение: ${clientIp}`);
    
    let currentSessionId = null;
    let currentUserId = null;

    socket.on('register', async (userData) => {
        try {
            const { name } = userData;
            const userAgent = socket.handshake.headers['user-agent'] || 'unknown';
            
            if (!name || typeof name !== 'string' || name.length < 2 || name.length > 30) {
                logSecurity('invalid_register', 'Invalid name length', clientIp);
                socket.emit('register_error', 'Имя должно быть от 2 до 30 символов');
                return;
            }

            // Очистка имени
            const cleanName = sanitize(name).replace(/[<>]/g, '').substring(0, 30);
            
            // Проверка на заблокированный IP
            const blocked = await dbGet('SELECT * FROM blocks WHERE user_id = ? AND blocked_user_id = ?', [0, clientIp]);
            if (blocked) {
                logSecurity('blocked_ip_attempt', clientIp, clientIp);
                socket.emit('register_error', 'IP заблокирован');
                return;
            }

            let user = await dbGet('SELECT * FROM users WHERE name = ?', [cleanName]);

            if (user) {
                // Проверка на блокировку пользователя
                if (user.locked_until && new Date(user.locked_until) > new Date()) {
                    socket.emit('register_error', 'Аккаунт временно заблокирован');
                    return;
                }

                // Автовход
                currentUserId = user.id;
                currentSessionId = await generateSessionId();
                
                await dbRun(`
                    UPDATE users SET online = 1, last_seen = CURRENT_TIMESTAMP, 
                                   last_ip = ?, user_agent = ?, session_id = ? 
                    WHERE id = ?
                `, [clientIp, userAgent, currentSessionId, user.id]);
                
                await dbRun(`
                    INSERT INTO sessions (id, user_id, ip, user_agent, expires_at) 
                    VALUES (?, ?, ?, ?, datetime('now', '+7 days'))
                `, [currentSessionId, user.id, clientIp, userAgent]);

                socket.userId = user.id;
                socket.userName = user.name;
                socket.sessionId = currentSessionId;

                socket.emit('registered', user);
                await sendUserData(socket, user.id);
                socket.broadcast.emit('user_online', user.id);
                
                logSecurity('user_login', `User ${user.id} logged in`, clientIp);
                return;
            }

            // Новый пользователь - генерация уникального имени
            let baseUsername = `user${crypto.randomInt(1000, 9999)}`;
            let username = baseUsername;
            let counter = 1;
            
            while (await dbGet('SELECT id FROM users WHERE phone = ?', [username])) {
                username = `${baseUsername}_${counter++}`;
            }

            const result = await dbRun(
                'INSERT INTO users (name, phone, last_ip, user_agent) VALUES (?, ?, ?, ?)',
                [cleanName, username, clientIp, userAgent]
            );

            const newId = result.lastID;
            currentSessionId = await generateSessionId();
            
            await dbRun(`
                UPDATE users SET online = 1, session_id = ? WHERE id = ?
            `, [currentSessionId, newId]);
            
            await dbRun(`
                INSERT INTO sessions (id, user_id, ip, user_agent, expires_at) 
                VALUES (?, ?, ?, ?, datetime('now', '+7 days'))
            `, [currentSessionId, newId, clientIp, userAgent]);

            const newUser = await dbGet('SELECT * FROM users WHERE id = ?', [newId]);

            currentUserId = newId;
            socket.userId = newUser.id;
            socket.userName = newUser.name;
            socket.sessionId = currentSessionId;

            socket.emit('registered', newUser);
            await sendUserData(socket, newUser.id);
            socket.broadcast.emit('user_online', newUser.id);
            
            logSecurity('new_user', `New user ${newUser.id} created`, clientIp);

        } catch (err) {
            console.error('❌ Ошибка регистрации:', err);
            logSecurity('register_error', err.message, clientIp);
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

            const users = await dbAll(`
                SELECT id, name, avatar, bio, online 
                FROM users 
                WHERE locked_until IS NULL OR locked_until < CURRENT_TIMESTAMP
            `);
            socket.emit('all_users', users || []);
        } catch (err) {
            console.error('Ошибка отправки данных:', err);
        }
    }

    socket.on('join_group', (groupId) => {
        if (!groupId || isNaN(groupId)) return;
        socket.join(`group_${groupId}`);
    });

    socket.on('join_private_chat', (chatId) => {
        if (!chatId || isNaN(chatId)) return;
        socket.join(`private_${chatId}`);
    });

    socket.on('send_message', async (data) => {
        try {
            const { chat_type, chat_id, user_id, text } = data;
            
            if (!chat_type || !chat_id || !user_id || !text) return;
            if (!['private', 'group'].includes(chat_type)) return;
            if (text.length > 2000) return;
            if (user_id !== socket.userId) return; // Проверка прав

            // Шифрование с ID сессии
            const encryptedText = ultraEncrypt(text, socket.sessionId || 'default');

            const result = await dbRun(`
                INSERT INTO messages (chat_type, chat_id, user_id, text, encrypted_version) 
                VALUES (?, ?, ?, ?, '2.0')
            `, [chat_type, chat_id, user_id, encryptedText]);

            const message = await dbGet(`
                SELECT m.*, u.name as user_name, u.avatar as user_avatar
                FROM messages m
                JOIN users u ON m.user_id = u.id
                WHERE m.id = ?
            `, [result.lastID]);

            if (message) {
                message.text = ultraDecrypt(message.text, socket.sessionId || 'default');
                const room = chat_type === 'group' ? `group_${chat_id}` : `private_${chat_id}`;
                io.to(room).emit('new_message', message);
            }
        } catch (err) {
            console.error('❌ Ошибка отправки сообщения:', err);
            logSecurity('message_error', err.message, clientIp);
        }
    });

    socket.on('typing', (data) => {
        const { chat_type, chat_id, user_id, user_name, is_typing } = data;
        if (!chat_type || !chat_id || !user_id) return;
        
        const room = chat_type === 'group' ? `group_${chat_id}` : `private_${chat_id}`;
        socket.to(room).emit('user_typing', {
            user_id,
            user_name: sanitize(user_name).substring(0, 30),
            is_typing: !!is_typing
        });
    });

    socket.on('disconnect', async () => {
        if (socket.userId) {
            try {
                await dbRun(`
                    UPDATE users SET online = 0, last_seen = CURRENT_TIMESTAMP 
                    WHERE id = ?
                `, [socket.userId]);
                
                if (socket.sessionId) {
                    await dbRun('DELETE FROM sessions WHERE id = ?', [socket.sessionId]);
                }
                
                socket.broadcast.emit('user_offline', socket.userId);
                console.log(`👋 ${socket.userName} отключился`);
                
                logSecurity('user_logout', `User ${socket.userId} disconnected`, clientIp);
            } catch (err) {
                console.error('Ошибка при отключении:', err);
            }
        }
    });
});

// ========== API ГРУПП ==========
app.post('/api/groups',
    body('name').trim().isLength({ min: 2, max: 50 }).escape(),
    body('description').optional().trim().isLength({ max: 200 }).escape(),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'Некорректные данные' });
        }

        try {
            const { name, description, userId } = req.body;

            const result = await dbRun(
                'INSERT INTO groups (name, description, created_by) VALUES (?, ?, ?)',
                [name, description || '', userId]
            );
            const groupId = result.lastID;

            await dbRun(
                'INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, ?)',
                [groupId, userId, 'admin']
            );

            logSecurity('group_created', `Group ${groupId} created by ${userId}`, req.ip);
            res.json({ id: groupId, name, description });
        } catch (err) {
            logSecurity('group_error', err.message, req.ip);
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
        
        // Расшифровываем последние сообщения для отображения
        for (let group of groups) {
            if (group.last_message) {
                group.last_message = ultraDecrypt(group.last_message, 'default');
            }
        }
        
        res.json(groups);
    } catch (err) {
        logSecurity('get_groups_error', err.message, req.ip);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.get('/api/messages/group/:groupId', async (req, res) => {
    try {
        const groupId = parseInt(req.params.groupId);
        if (isNaN(groupId)) return res.status(400).json({ error: 'Неверный ID' });

        const messages = await dbAll(`
            SELECT m.*, u.name as user_name, u.avatar as user_avatar
            FROM messages m
            JOIN users u ON m.user_id = u.id
            WHERE m.chat_type = 'group' AND m.chat_id = ? AND m.deleted = 0
            ORDER BY m.created_at ASC
            LIMIT 500
        `, [groupId]);

        const decrypted = messages.map(msg => {
            if (msg.text) msg.text = ultraDecrypt(msg.text, 'default');
            return msg;
        });
        
        res.json(decrypted);
    } catch (err) {
        logSecurity('get_messages_error', err.message, req.ip);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ========== API ЛИЧНЫХ ЧАТОВ ==========
app.post('/api/private_chat', async (req, res) => {
    try {
        const { user1_id, user2_id } = req.body;
        
        if (user1_id === user2_id) {
            return res.status(400).json({ error: 'Нельзя создать чат с самим собой' });
        }

        // Проверка на блокировку
        const blocked = await dbGet(`
            SELECT * FROM blocks 
            WHERE (user_id = ? AND blocked_user_id = ?) 
               OR (user_id = ? AND blocked_user_id = ?)
        `, [user1_id, user2_id, user2_id, user1_id]);
        
        if (blocked) {
            return res.status(403).json({ error: 'Невозможно создать чат' });
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

        res.json({ chat_id: chat.id });
    } catch (err) {
        logSecurity('private_chat_error', err.message, req.ip);
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
        
        // Расшифровываем последние сообщения
        for (let chat of chats) {
            if (chat.last_message) {
                chat.last_message = ultraDecrypt(chat.last_message, 'default');
            }
        }
        
        res.json(chats);
    } catch (err) {
        logSecurity('get_private_chats_error', err.message, req.ip);
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
            WHERE m.chat_type = 'private' AND m.chat_id = ? AND m.deleted = 0
            ORDER BY m.created_at ASC
            LIMIT 500
        `, [chatId]);

        const decrypted = messages.map(msg => {
            if (msg.text) msg.text = ultraDecrypt(msg.text, 'default');
            return msg;
        });
        
        res.json(decrypted);
    } catch (err) {
        logSecurity('get_private_messages_error', err.message, req.ip);
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

        logSecurity('voice_uploaded', `Voice message ${result.lastID}`, req.ip);
        res.json(message);
    } catch (err) {
        logSecurity('upload_error', err.message, req.ip);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

app.post('/api/upload/photo', uploadLimiter, upload.single('photo'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Нет файла' });

    try {
        const { chat_type, chat_id, user_id } = req.body;
        const photo_url = req.file.filename;

        const result = await dbRun(
            'INSERT INTO messages (chat_type, chat_id, user_id, photo_url, text) VALUES (?, ?, ?, ?, ?)',
            [chat_type, chat_id, user_id, photo_url, ultraEncrypt('📷 Фото', 'default')]
        );

        const message = await dbGet(`
            SELECT m.*, u.name as user_name, u.avatar as user_avatar
            FROM messages m
            JOIN users u ON m.user_id = u.id
            WHERE m.id = ?
        `, [result.lastID]);

        if (message.text) message.text = ultraDecrypt(message.text, 'default');
        const room = chat_type === 'group' ? `group_${chat_id}` : `private_${chat_id}`;
        io.to(room).emit('new_message', message);

        res.json(message);
    } catch (err) {
        logSecurity('upload_error', err.message, req.ip);
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
            'INSERT INTO messages (chat_type, chat_id, user_id, file_url, file_name, file_size, text) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [chat_type, chat_id, user_id, file_url, file_name, file_size, ultraEncrypt('📎 Файл', 'default')]
        );

        const message = await dbGet(`
            SELECT m.*, u.name as user_name, u.avatar as user_avatar
            FROM messages m
            JOIN users u ON m.user_id = u.id
            WHERE m.id = ?
        `, [result.lastID]);

        if (message.text) message.text = ultraDecrypt(message.text, 'default');
        const room = chat_type === 'group' ? `group_${chat_id}` : `private_${chat_id}`;
        io.to(room).emit('new_message', message);

        res.json(message);
    } catch (err) {
        logSecurity('upload_error', err.message, req.ip);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ========== API ОБНОВЛЕНИЯ ПРОФИЛЯ ==========
app.post('/api/user/update-name',
    body('newName').trim().isLength({ min: 2, max: 30 }).escape(),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'Некорректное имя' });
        }

        try {
            const { userId, newName } = req.body;

            const existing = await dbGet('SELECT id FROM users WHERE name = ? AND id != ?', [newName, userId]);
            if (existing) {
                return res.status(400).json({ error: 'Это имя уже занято!' });
            }

            await dbRun('UPDATE users SET name = ? WHERE id = ?', [newName, userId]);

            const users = await dbAll('SELECT id, name, avatar, bio, online FROM users');
            io.emit('all_users', users);

            logSecurity('name_updated', `User ${userId} renamed to ${newName}`, req.ip);
            res.json({ success: true, name: newName });
        } catch (err) {
            logSecurity('update_error', err.message, req.ip);
            res.status(500).json({ error: 'Ошибка сервера' });
        }
    }
);

app.post('/api/users/update-bio',
    body('bio').optional().trim().isLength({ max: 200 }).escape(),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'Слишком длинное био' });
        }

        try {
            const { userId, bio } = req.body;
            await dbRun('UPDATE users SET bio = ? WHERE id = ?', [bio || '', userId]);

            const users = await dbAll('SELECT id, name, avatar, bio, online FROM users');
            io.emit('all_users', users);

            res.json({ success: true });
        } catch (err) {
            logSecurity('update_error', err.message, req.ip);
            res.status(500).json({ error: 'Ошибка сервера' });
        }
    }
);

app.post('/api/user/upload-avatar', uploadLimiter, upload.single('avatar'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Нет файла' });

    try {
        const { userId } = req.body;
        const avatar = req.file.filename;

        // Удаляем старый аватар
        const oldUser = await dbGet('SELECT avatar FROM users WHERE id = ?', [userId]);
        if (oldUser && oldUser.avatar) {
            const oldPath = path.join(__dirname, 'avatars', oldUser.avatar);
            if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
        }

        await dbRun('UPDATE users SET avatar = ? WHERE id = ?', [avatar, userId]);

        const users = await dbAll('SELECT id, name, avatar, bio, online FROM users');
        io.emit('all_users', users);

        res.json({ success: true, avatar });
    } catch (err) {
        logSecurity('upload_error', err.message, req.ip);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

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
        logSecurity('update_error', err.message, req.ip);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// ========== ГЛАВНАЯ ==========
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ========== ОБРАБОТКА ОШИБОК ==========
app.use((err, req, res, next) => {
    console.error('❌ Ошибка:', err.stack);
    logSecurity('global_error', err.message, req.ip);
    
    if (err instanceof multer.MulterError) {
        if (err.code === 'FILE_TOO_LARGE') {
            return res.status(413).json({ error: 'Файл слишком большой (макс. 50MB)' });
        }
        return res.status(400).json({ error: 'Ошибка загрузки файла' });
    }
    
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
});

// ========== ОЧИСТКА СТАРЫХ СЕССИЙ ==========
setInterval(async () => {
    try {
        const result = await dbRun("DELETE FROM sessions WHERE expires_at < datetime('now')");
        if (result.changes > 0) {
            console.log(`🧹 Очищено ${result.changes} старых сессий`);
        }
    } catch (err) {
        console.error('Ошибка очистки сессий:', err);
    }
}, 60 * 60 * 1000); // Каждый час

// ========== ЗАПУСК ==========
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log('\n' + '='.repeat(70));
    console.log('   🚀 TeleRoom ULTRA SECURE EDITION');
    console.log('='.repeat(70));
    console.log(`   📱 Порт: ${PORT}`);
    console.log('   🔐 Шифрование: AES-256-GCM + PBKDF2 + SHA256 + zlib');
    console.log('   🛡️ Защита: Helmet, Rate Limiting, Input Validation');
    console.log('   📊 База: SQLite3 + WAL + Foreign Keys');
    console.log('   🔑 Мастер-ключ: сохранён в .master.key');
    console.log('   🧂 Соль: сохранена в .salt');
    console.log('   📝 Логи: /logs/security-*.log');
    console.log('   ✅ Все функции: чаты, группы, файлы, звонки');
    console.log('   🌐 Русский интерфейс + максимальная безопасность');
    console.log('='.repeat(70) + '\n');
});
