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
    cors: { origin: '*', methods: ['GET', 'POST'] }
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
        else cb(null, './uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '_' + file.originalname.replace(/[^a-zA-Z0-9.]/g, '_');
        cb(null, uniqueName);
    }
});

const upload = multer({ storage });

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
        name TEXT NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        avatar TEXT,
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
        PRIMARY KEY (group_id, user_id)
    )`);

    // Личные чаты
    db.run(`CREATE TABLE IF NOT EXISTS private_chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user1_id INTEGER NOT NULL,
        user2_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user1_id, user2_id)
    )`);

    // Сообщения (ПОЛНАЯ ВЕРСИЯ)
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
        FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    console.log('✅ База данных готова');
});

// ========== API ПОЛЬЗОВАТЕЛЕЙ ==========
app.get('/api/users', (req, res) => {
    db.all('SELECT id, name, phone, online, last_seen FROM users ORDER BY name', (err, users) => {
        res.json(users || []);
    });
});

// ПОИСК ПОЛЬЗОВАТЕЛЕЙ
app.get('/api/users/search/:query', (req, res) => {
    const query = `%${req.params.query}%`;
    db.all('SELECT id, name, phone, online, last_seen FROM users WHERE name LIKE ? OR phone LIKE ? ORDER BY name LIMIT 20', 
        [query, query], 
        (err, users) => {
            res.json(users || []);
        }
    );
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
               (SELECT text FROM messages WHERE chat_type = 'group' AND chat_id = g.id ORDER BY created_at DESC LIMIT 1) as last_message,
               (SELECT created_at FROM messages WHERE chat_type = 'group' AND chat_id = g.id ORDER BY created_at DESC LIMIT 1) as last_time
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
        SELECT u.id, u.name, u.online, u.last_seen, gm.role, gm.joined_at
        FROM group_members gm
        JOIN users u ON gm.user_id = u.id
        WHERE gm.group_id = ?
        ORDER BY gm.joined_at
    `, [req.params.groupId], (err, members) => {
        res.json(members || []);
    });
});

// ДОБАВЛЕНИЕ УЧАСТНИКА В ГРУППУ
app.post('/api/groups/add_member', (req, res) => {
    const { group_id, user_id } = req.body;
    
    db.run(
        'INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)',
        [group_id, user_id],
        function(err) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            res.json({ success: true });
        }
    );
});

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

// ========== API ЛИЧНЫХ ЧАТОВ ==========
app.post('/api/private_chat', (req, res) => {
    const { user1_id, user2_id } = req.body;
    
    const minId = Math.min(user1_id, user2_id);
    const maxId = Math.max(user1_id, user2_id);
    
    db.run(
        'INSERT OR IGNORE INTO private_chats (user1_id, user2_id) VALUES (?, ?)',
        [minId, maxId],
        function(err) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            
            db.get(
                'SELECT id FROM private_chats WHERE user1_id = ? AND user2_id = ?',
                [minId, maxId],
                (err, chat) => {
                    res.json({ chat_id: chat.id });
                }
            );
        }
    );
});

app.get('/api/private_chats/:userId', (req, res) => {
    const userId = parseInt(req.params.userId);
    
    db.all(`
        SELECT pc.id, 
               CASE 
                   WHEN pc.user1_id = ? THEN pc.user2_id 
                   ELSE pc.user1_id 
               END as other_user_id,
               u.name as other_user_name,
               u.online,
               u.last_seen,
               (SELECT text FROM messages WHERE chat_type = 'private' AND chat_id = pc.id ORDER BY created_at DESC LIMIT 1) as last_message,
               (SELECT created_at FROM messages WHERE chat_type = 'private' AND chat_id = pc.id ORDER BY created_at DESC LIMIT 1) as last_time
        FROM private_chats pc
        JOIN users u ON (CASE WHEN pc.user1_id = ? THEN pc.user2_id ELSE pc.user1_id END) = u.id
        WHERE pc.user1_id = ? OR pc.user2_id = ?
        ORDER BY last_time DESC
    `, [userId, userId, userId, userId], (err, chats) => {
        res.json(chats || []);
    });
});

app.get('/api/messages/private/:chatId', (req, res) => {
    db.all(`
        SELECT m.*, u.name as user_name, u.avatar as user_avatar
        FROM messages m
        JOIN users u ON m.user_id = u.id
        WHERE m.chat_type = 'private' AND m.chat_id = ?
        ORDER BY m.created_at ASC
        LIMIT 200
    `, [req.params.chatId], (err, messages) => {
        res.json(messages || []);
    });
});

// ========== ЗАГРУЗКА ФАЙЛОВ ==========
app.post('/api/upload/voice', upload.single('voice'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Нет файла' });
    
    const { chat_type, chat_id, user_id, duration } = req.body;
    const voice_url = req.file.filename;
    
    db.run(
        'INSERT INTO messages (chat_type, chat_id, user_id, voice_url, duration) VALUES (?, ?, ?, ?, ?)',
        [chat_type, chat_id, user_id, voice_url, duration || '0:05'],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            
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
    if (!req.file) return res.status(400).json({ error: 'Нет файла' });
    
    const { chat_type, chat_id, user_id } = req.body;
    const photo_url = req.file.filename;
    
    db.run(
        'INSERT INTO messages (chat_type, chat_id, user_id, photo_url, text) VALUES (?, ?, ?, ?, ?)',
        [chat_type, chat_id, user_id, photo_url, '📷 Фото'],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            
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
    if (!req.file) return res.status(400).json({ error: 'Нет файла' });
    
    const { chat_type, chat_id, user_id } = req.body;
    const file_url = req.file.filename;
    const file_name = req.file.originalname;
    const file_size = req.file.size;
    
    db.run(
        'INSERT INTO messages (chat_type, chat_id, user_id, file_url, file_name, file_size, text) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [chat_type, chat_id, user_id, file_url, file_name, file_size, '📎 Файл'],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            
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
    console.log('👤 Подключился пользователь');

    socket.on('register', (userData) => {
        const { name, phone } = userData;
        
        db.get('SELECT * FROM users WHERE phone = ?', [phone], (err, existingUser) => {
            if (existingUser) {
                socket.userId = existingUser.id;
                socket.userName = existingUser.name;
                
                db.run('UPDATE users SET online = 1, last_seen = CURRENT_TIMESTAMP WHERE id = ?', [existingUser.id]);
                
                socket.emit('registered', existingUser);
                
                db.all(`
                    SELECT g.*, COUNT(DISTINCT gm.user_id) as members_count
                    FROM groups g
                    JOIN group_members gm ON g.id = gm.group_id
                    WHERE gm.user_id = ?
                    GROUP BY g.id
                `, [existingUser.id], (err, groups) => {
                    socket.emit('user_groups', groups || []);
                });
                
                db.all(`
                    SELECT pc.id, 
                           CASE 
                               WHEN pc.user1_id = ? THEN pc.user2_id 
                               ELSE pc.user1_id 
                           END as other_user_id,
                           u.name as other_user_name,
                           u.online
                    FROM private_chats pc
                    JOIN users u ON (CASE WHEN pc.user1_id = ? THEN pc.user2_id ELSE pc.user1_id END) = u.id
                    WHERE pc.user1_id = ? OR pc.user2_id = ?
                `, [existingUser.id, existingUser.id, existingUser.id, existingUser.id], (err, privateChats) => {
                    socket.emit('user_private_chats', privateChats || []);
                });
                
                db.all('SELECT id, name, phone, online FROM users', (err, users) => {
                    socket.emit('all_users', users || []);
                });
                
                socket.broadcast.emit('user_online', existingUser.id);
            } else {
                db.run(
                    'INSERT INTO users (name, phone) VALUES (?, ?)',
                    [name, phone],
                    function(err) {
                        db.get('SELECT * FROM users WHERE id = ?', [this.lastID], (err, newUser) => {
                            socket.userId = newUser.id;
                            socket.userName = newUser.name;
                            
                            db.run('UPDATE users SET online = 1 WHERE id = ?', [newUser.id]);
                            
                            socket.emit('registered', newUser);
                            
                            db.all('SELECT id, name, phone, online FROM users', (err, users) => {
                                socket.emit('all_users', users || []);
                            });
                            
                            socket.broadcast.emit('user_online', newUser.id);
                        });
                    }
                );
            }
        });
    });

    socket.on('join_group', (groupId) => {
        socket.join(`group_${groupId}`);
        console.log(`👥 ${socket.userName} присоединился к группе ${groupId}`);
    });

    socket.on('join_private_chat', (chatId) => {
        socket.join(`private_${chatId}`);
        console.log(`💬 ${socket.userName} присоединился к личному чату ${chatId}`);
    });

    socket.on('send_message', (data) => {
        const { chat_type, chat_id, user_id, text } = data;
        
        db.run(
            'INSERT INTO messages (chat_type, chat_id, user_id, text) VALUES (?, ?, ?, ?)',
            [chat_type, chat_id, user_id, text],
            function(err) {
                if (err) return console.error(err);
                
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
            db.run('UPDATE users SET online = 0, last_seen = CURRENT_TIMESTAMP WHERE id = ?', [socket.userId]);
            socket.broadcast.emit('user_offline', socket.userId);
            console.log(`👋 ${socket.userName} отключился`);
        }
    });
});

// ========== ГЛАВНАЯ ==========
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

// ========== ЗАПУСК ==========
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log('\n' + '='.repeat(60));
    console.log('   🚀 TeleRoom PRO - ЗАПУЩЕН!');
    console.log('='.repeat(60));
    console.log(`   📱 Порт: ${PORT}`);
    console.log('='.repeat(60) + '\n');
});
