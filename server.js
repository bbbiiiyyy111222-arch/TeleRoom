const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// ========== СОЗДАЕМ ВСЕ ПАПКИ ==========
const folders = [
    './uploads/voice',
    './uploads/photos',
    './uploads/files',
    './avatars'
];

folders.forEach(folder => {
    if (!fs.existsSync(folder)) {
        fs.mkdirSync(folder, { recursive: true });
        console.log(`📁 Создана папка: ${folder}`);
    }
});

// ========== НАСТРОЙКА ЗАГРУЗКИ ==========
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (file.fieldname === 'voice') {
            cb(null, './uploads/voice/');
        } else if (file.fieldname === 'photo') {
            cb(null, './uploads/photos/');
        } else if (file.fieldname === 'file') {
            cb(null, './uploads/files/');
        } else {
            cb(null, './uploads/');
        }
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '_' + file.originalname.replace(/[^a-zA-Z0-9.]/g, '_');
        cb(null, uniqueName);
    }
});

const upload = multer({ 
    storage,
    limits: { fileSize: 100 * 1024 * 1024 } // 100MB
});

// ========== СТАТИЧЕСКИЕ ФАЙЛЫ ==========
app.use(express.static(__dirname));
app.use('/uploads', express.static('uploads'));
app.use('/avatars', express.static('avatars'));
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

// ========== БАЗА ДАННЫХ ==========
const db = new sqlite3.Database('./teleRoom.db');

db.serialize(() => {
    // Пользователи
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        phone TEXT UNIQUE,
        avatar TEXT,
        online INTEGER DEFAULT 0,
        last_seen DATETIME
    )`);

    // Группы
    db.run(`CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        avatar TEXT,
        description TEXT,
        created_by INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Участники групп
    db.run(`CREATE TABLE IF NOT EXISTS group_members (
        group_id INTEGER,
        user_id INTEGER,
        role TEXT DEFAULT 'member',
        joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (group_id, user_id)
    )`);

    // Сообщения
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_type TEXT,
        chat_id INTEGER,
        user_id INTEGER,
        text TEXT,
        photo_url TEXT,
        voice_url TEXT,
        file_url TEXT,
        file_name TEXT,
        file_size INTEGER,
        duration INTEGER,
        reply_to INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    console.log('✅ База данных создана');
});

// ========== API ПОЛЬЗОВАТЕЛЕЙ ==========
app.get('/api/users', (req, res) => {
    db.all('SELECT id, name, online, last_seen FROM users', (err, users) => {
        res.json(users || []);
    });
});

// ========== API ГРУПП ==========
app.post('/api/groups', (req, res) => {
    const { name, description, userId } = req.body;
    
    db.run(
        'INSERT INTO groups (name, description, created_by) VALUES (?, ?, ?)',
        [name, description || '', userId],
        function(err) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            const groupId = this.lastID;
            
            db.run(
                'INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, ?)',
                [groupId, userId, 'admin']
            );
            
            res.json({ id: groupId, name, description });
        }
    );
});

app.get('/api/groups/:userId', (req, res) => {
    db.all(`
        SELECT g.*, 
               COUNT(DISTINCT gm.user_id) as members_count,
               (SELECT text FROM messages WHERE chat_type = 'group' AND chat_id = g.id ORDER BY created_at DESC LIMIT 1) as last_message
        FROM groups g
        JOIN group_members gm ON g.id = gm.group_id
        WHERE gm.user_id = ?
        GROUP BY g.id
        ORDER BY g.created_at DESC
    `, [req.params.userId], (err, groups) => {
        res.json(groups || []);
    });
});

app.get('/api/groups/:groupId/members', (req, res) => {
    db.all(`
        SELECT u.*, gm.role
        FROM group_members gm
        JOIN users u ON gm.user_id = u.id
        WHERE gm.group_id = ?
    `, [req.params.groupId], (err, members) => {
        res.json(members || []);
    });
});

// ========== API СООБЩЕНИЙ ==========
app.get('/api/messages/group/:groupId', (req, res) => {
    db.all(`
        SELECT m.*, u.name as user_name, u.avatar as user_avatar
        FROM messages m
        JOIN users u ON m.user_id = u.id
        WHERE m.chat_type = 'group' AND m.chat_id = ?
        ORDER BY m.created_at ASC
        LIMIT 200
    `, [req.params.groupId], (err, messages) => {
        res.json(messages || []);
    });
});

// ========== ЗАГРУЗКА ФАЙЛОВ ==========
app.post('/api/upload/voice', upload.single('voice'), (req, res) => {
    if (!req.file) {
        res.status(400).json({ error: 'Нет файла' });
        return;
    }
    
    const { chat_type, chat_id, user_id, duration } = req.body;
    const voice_url = req.file.filename;
    
    db.run(
        `INSERT INTO messages (chat_type, chat_id, user_id, voice_url, duration) 
         VALUES (?, ?, ?, ?, ?)`,
        [chat_type, chat_id, user_id, voice_url, duration || '0:05'],
        function(err) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            
            db.get(`
                SELECT m.*, u.name as user_name, u.avatar as user_avatar
                FROM messages m
                JOIN users u ON m.user_id = u.id
                WHERE m.id = ?
            `, [this.lastID], (err, message) => {
                const room = chat_type === 'group' ? `group_${chat_id}` : `private_${chat_id}`;
                io.to(room).emit('new_message', message);
                res.json(message);
            });
        }
    );
});

app.post('/api/upload/photo', upload.single('photo'), (req, res) => {
    if (!req.file) {
        res.status(400).json({ error: 'Нет файла' });
        return;
    }
    
    const { chat_type, chat_id, user_id } = req.body;
    const photo_url = req.file.filename;
    
    db.run(
        `INSERT INTO messages (chat_type, chat_id, user_id, photo_url, text) 
         VALUES (?, ?, ?, ?, ?)`,
        [chat_type, chat_id, user_id, photo_url, '📷 Фото'],
        function(err) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            
            db.get(`
                SELECT m.*, u.name as user_name, u.avatar as user_avatar
                FROM messages m
                JOIN users u ON m.user_id = u.id
                WHERE m.id = ?
            `, [this.lastID], (err, message) => {
                const room = chat_type === 'group' ? `group_${chat_id}` : `private_${chat_id}`;
                io.to(room).emit('new_message', message);
                res.json(message);
            });
        }
    );
});

app.post('/api/upload/file', upload.single('file'), (req, res) => {
    if (!req.file) {
        res.status(400).json({ error: 'Нет файла' });
        return;
    }
    
    const { chat_type, chat_id, user_id } = req.body;
    const file_url = req.file.filename;
    const file_name = req.file.originalname;
    const file_size = req.file.size;
    
    db.run(
        `INSERT INTO messages (chat_type, chat_id, user_id, file_url, file_name, file_size, text) 
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [chat_type, chat_id, user_id, file_url, file_name, file_size, '📎 Файл'],
        function(err) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            
            db.get(`
                SELECT m.*, u.name as user_name, u.avatar as user_avatar
                FROM messages m
                JOIN users u ON m.user_id = u.id
                WHERE m.id = ?
            `, [this.lastID], (err, message) => {
                const room = chat_type === 'group' ? `group_${chat_id}` : `private_${chat_id}`;
                io.to(room).emit('new_message', message);
                res.json(message);
            });
        }
    );
});

// ========== WEB SOCKET ==========
io.on('connection', (socket) => {
    console.log('👤 Подключение к TeleRoom');

    socket.on('register', (userData) => {
        const { name, phone } = userData;
        
        db.run(
            'INSERT OR IGNORE INTO users (name, phone) VALUES (?, ?)',
            [name, phone],
            function(err) {
                db.get('SELECT * FROM users WHERE phone = ?', [phone], (err, user) => {
                    if (user) {
                        socket.userId = user.id;
                        socket.userName = user.name;
                        
                        db.run('UPDATE users SET online = 1 WHERE id = ?', [user.id]);
                        
                        socket.emit('registered', user);
                        
                        db.all(`
                            SELECT g.* 
                            FROM groups g
                            JOIN group_members gm ON g.id = gm.group_id
                            WHERE gm.user_id = ?
                        `, [user.id], (err, groups) => {
                            socket.emit('user_groups', groups || []);
                        });
                        
                        db.all('SELECT id, name, online FROM users', (err, users) => {
                            socket.emit('all_users', users || []);
                        });
                        
                        io.emit('user_online', user.id);
                    }
                });
            }
        );
    });

    socket.on('join_group', (groupId) => {
        socket.join(`group_${groupId}`);
        console.log(`👥 ${socket.userName} присоединился к группе ${groupId}`);
    });

    socket.on('send_message', (data) => {
        const { chat_type, chat_id, user_id, text } = data;
        
        db.run(
            `INSERT INTO messages (chat_type, chat_id, user_id, text) 
             VALUES (?, ?, ?, ?)`,
            [chat_type, chat_id, user_id, text],
            function(err) {
                if (err) {
                    console.error(err);
                    return;
                }
                
                db.get(`
                    SELECT m.*, u.name as user_name, u.avatar as user_avatar
                    FROM messages m
                    JOIN users u ON m.user_id = u.id
                    WHERE m.id = ?
                `, [this.lastID], (err, message) => {
                    if (message) {
                        const room = chat_type === 'group' ? `group_${chat_id}` : `private_${chat_id}`;
                        io.to(room).emit('new_message', message);
                    }
                });
            }
        );
    });

    socket.on('typing', (data) => {
        const room = data.chat_type === 'group' ? `group_${data.chat_id}` : `private_${data.chat_id}`;
        socket.to(room).emit('user_typing', {
            user_id: data.user_id,
            user_name: data.user_name
        });
    });

    socket.on('disconnect', () => {
        if (socket.userId) {
            db.run('UPDATE users SET online = 0, last_seen = CURRENT_TIMESTAMP WHERE id = ?', 
                [socket.userId]);
            io.emit('user_offline', socket.userId);
            console.log(`👋 ${socket.userName} отключился`);
        }
    });
});

// ========== ГЛАВНАЯ ==========
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

// ========== ЗАПУСК ==========
const PORT = 3000;
server.listen(PORT, () => {
    console.log('\n' + '='.repeat(50));
    console.log('   🚀 TeleRoom PRO ЗАПУЩЕН!');
    console.log('   ========================');
    console.log('   📱 Адрес: http://localhost:' + PORT);
    console.log('   🎤 Голосовые: ✅ РАБОТАЮТ');
    console.log('   📷 Фото: ✅ РАБОТАЮТ');
    console.log('   📎 Файлы: ✅ РАБОТАЮТ');
    console.log('   👥 Группы: ✅ РАБОТАЮТ');
    console.log('='.repeat(50) + '\n');
});