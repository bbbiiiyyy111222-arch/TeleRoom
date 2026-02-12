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
        else if (file.fieldname === 'avatar') cb(null, './avatars/');
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

    db.run(`CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        avatar TEXT,
        created_by INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS group_members (
        group_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        role TEXT DEFAULT 'member',
        joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (group_id, user_id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS private_chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user1_id INTEGER NOT NULL,
        user2_id INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user1_id, user2_id)
    )`);

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

// ========== API ПРОВЕРКИ ИМЕНИ ==========
app.get('/api/check-username/:name', (req, res) => {
    const name = req.params.name;
    db.get('SELECT id FROM users WHERE name = ?', [name], (err, user) => {
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
    db.get('SELECT id, name, avatar, bio, online, last_seen, created_at FROM users WHERE id = ?', 
        [req.params.id], 
        (err, user) => {
            res.json(user || null);
        }
    );
});

app.post('/api/users/update-bio', (req, res) => {
    const { userId, bio } = req.body;
    db.run('UPDATE users SET bio = ? WHERE id = ?', [bio, userId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

// ========== API ПРОФИЛЯ - ПОЛНОСТЬЮ РАБОЧИЕ ==========

// 1. ИЗМЕНЕНИЕ ИМЕНИ
app.post('/api/user/update-name', (req, res) => {
    const { userId, newName } = req.body;
    
    db.get('SELECT id FROM users WHERE name = ? AND id != ?', [newName, userId], (err, existing) => {
        if (existing) {
            res.status(400).json({ error: 'Это имя уже занято!' });
            return;
        }
        
        db.run('UPDATE users SET name = ? WHERE id = ?', [newName, userId], function(err) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            res.json({ success: true, name: newName });
            
            db.all('SELECT id, name, avatar, bio, online FROM users', (err, users) => {
                io.emit('all_users', users || []);
            });
        });
    });
});

// 2. ИЗМЕНЕНИЕ ЮЗЕРНЕЙМА (phone)
app.post('/api/user/update-username', (req, res) => {
    const { userId, newUsername } = req.body;
    
    if (!newUsername || newUsername.length < 3) {
        res.status(400).json({ error: 'Юзернейм должен быть минимум 3 символа' });
        return;
    }
    
    db.get('SELECT id FROM users WHERE phone = ? AND id != ?', [newUsername, userId], (err, existing) => {
        if (existing) {
            res.status(400).json({ error: 'Этот юзернейм уже занят!' });
            return;
        }
        
        db.run('UPDATE users SET phone = ? WHERE id = ?', [newUsername, userId], function(err) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            res.json({ success: true, username: newUsername });
        });
    });
});

// 3. ЗАГРУЗКА АВАТАРКИ
app.post('/api/user/upload-avatar', upload.single('avatar'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Нет файла' });
    
    const { userId } = req.body;
    const avatar = req.file.filename;
    
    db.run('UPDATE users SET avatar = ? WHERE id = ?', [avatar, userId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        
        res.json({ success: true, avatar });
        
        db.all('SELECT id, name, avatar, bio, online FROM users', (err, users) => {
            io.emit('all_users', users || []);
        });
    });
});

// 4. УДАЛЕНИЕ АВАТАРКИ (НОВАЯ ФУНКЦИЯ)
app.post('/api/user/remove-avatar', (req, res) => {
    const { userId } = req.body;
    
    db.run('UPDATE users SET avatar = NULL WHERE id = ?', [userId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        
        res.json({ success: true });
        
        db.all('SELECT id, name, avatar, bio, online FROM users', (err, users) => {
            io.emit('all_users', users || []);
        });
    });
});

// 5. ПОЛУЧЕНИЕ ПРОФИЛЯ (НОВАЯ ФУНКЦИЯ)
app.get('/api/user/profile/:userId', (req, res) => {
    db.get('SELECT id, name, phone, avatar, bio, online, last_seen, created_at FROM users WHERE id = ?', 
        [req.params.userId], 
        (err, user) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(user || null);
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
        SELECT u.id, u.name, u.avatar, u.online, u.last_seen, gm.role, gm.joined_at
        FROM group_members gm
        JOIN users u ON gm.user_id = u.id
        WHERE gm.group_id = ?
        ORDER BY gm.joined_at
    `, [req.params.groupId], (err, members) => {
        res.json(members || []);
    });
});

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

app.post('/api/groups/update-name', (req, res) => {
    const { groupId, userId, newName } = req.body;
    
    db.get('SELECT role FROM group_members WHERE group_id = ? AND user_id = ?', [groupId, userId], (err, member) => {
        if (!member || member.role !== 'admin') {
            res.status(403).json({ error: 'Только админ может менять название' });
            return;
        }
        
        db.run('UPDATE groups SET name = ? WHERE id = ?', [newName, groupId], function(err) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            res.json({ success: true, name: newName });
        });
    });
});

app.post('/api/groups/update-description', (req, res) => {
    const { groupId, userId, newDescription } = req.body;
    
    db.get('SELECT role FROM group_members WHERE group_id = ? AND user_id = ?', [groupId, userId], (err, member) => {
        if (!member || member.role !== 'admin') {
            res.status(403).json({ error: 'Только админ может менять описание' });
            return;
        }
        
        db.run('UPDATE groups SET description = ? WHERE id = ?', [newDescription, groupId], function(err) {
            if (err) {
                res.status(500).json({ error: err.message });
                return;
            }
            res.json({ success: true, description: newDescription });
        });
    });
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
                    if (!chat) return res.status(404).json({ error: 'Чат не создан' });
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
               u.avatar as other_user_avatar,
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
                if (!message) return res.status(404).json({ error: 'Сообщение не найдено' });
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
                if (!message) return res.status(404).json({ error: 'Сообщение не найдено' });
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
                if (!message) return res.status(404).json({ error: 'Сообщение не найдено' });
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
        console.log(`📝 Попытка регистрации: ${name}, ${phone}`);
        
        // Проверяем по phone (ID пользователя)
        db.get('SELECT * FROM users WHERE phone = ?', [phone], (err, existingUser) => {
            if (existingUser) {
                // Автовход
                console.log(`🔄 Автовход для: ${existingUser.name}`);
                socket.userId = existingUser.id;
                socket.userName = existingUser.name;
                
                db.run('UPDATE users SET online = 1, last_seen = CURRENT_TIMESTAMP WHERE id = ?', [existingUser.id]);
                
                socket.emit('registered', existingUser);
                console.log(`✅ Отправлено registered для ${existingUser.name}`);
                
                // Отправляем данные
                db.all(`SELECT g.*, COUNT(DISTINCT gm.user_id) as members_count
                        FROM groups g
                        JOIN group_members gm ON g.id = gm.group_id
                        WHERE gm.user_id = ?
                        GROUP BY g.id`, [existingUser.id], (err, groups) => {
                    socket.emit('user_groups', groups || []);
                });
                
                db.all(`SELECT pc.id, 
                               CASE 
                                   WHEN pc.user1_id = ? THEN pc.user2_id 
                                   ELSE pc.user1_id 
                               END as other_user_id,
                               u.name as other_user_name,
                               u.avatar as other_user_avatar,
                               u.online
                        FROM private_chats pc
                        JOIN users u ON (CASE WHEN pc.user1_id = ? THEN pc.user2_id ELSE pc.user1_id END) = u.id
                        WHERE pc.user1_id = ? OR pc.user2_id = ?`, 
                        [existingUser.id, existingUser.id, existingUser.id, existingUser.id], 
                        (err, privateChats) => {
                    socket.emit('user_private_chats', privateChats || []);
                });
                
                db.all('SELECT id, name, avatar, bio, online FROM users', (err, users) => {
                    socket.emit('all_users', users || []);
                });
                
                socket.broadcast.emit('user_online', existingUser.id);
                return;
            }
            
            // Новый пользователь - проверяем имя
            db.get('SELECT * FROM users WHERE name = ?', [name], (err, existingName) => {
                if (existingName) {
                    console.log(`❌ Имя ${name} уже занято`);
                    socket.emit('register_error', 'Это имя уже занято! Выберите другое.');
                    return;
                }
                
                // Создаём нового пользователя
                db.run('INSERT INTO users (name, phone) VALUES (?, ?)', [name, phone], function(err) {
                    if (err) {
                        console.error('Ошибка создания пользователя:', err);
                        socket.emit('register_error', 'Ошибка при регистрации');
                        return;
                    }
                    
                    db.get('SELECT * FROM users WHERE id = ?', [this.lastID], (err, newUser) => {
                        if (err || !newUser) {
                            socket.emit('register_error', 'Ошибка при создании');
                            return;
                        }
                        
                        console.log(`✅ Новый пользователь: ${newUser.name} (ID: ${newUser.id})`);
                        socket.userId = newUser.id;
                        socket.userName = newUser.name;
                        
                        db.run('UPDATE users SET online = 1 WHERE id = ?', [newUser.id]);
                        
                        socket.emit('registered', newUser);
                        console.log(`✅ Отправлено registered для ${newUser.name}`);
                        
                        db.all('SELECT id, name, avatar, bio, online FROM users', (err, users) => {
                            socket.emit('all_users', users || []);
                        });
                        
                        socket.broadcast.emit('user_online', newUser.id);
                    });
                });
            });
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

    socket.on('update_bio', (data) => {
        const { userId, bio } = data;
        db.run('UPDATE users SET bio = ? WHERE id = ?', [bio, userId], function(err) {
            if (!err) {
                db.all('SELECT id, name, avatar, bio, online FROM users', (err, users) => {
                    io.emit('all_users', users || []);
                });
            }
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
    console.log('   ✅ ВХОД - РАБОТАЕТ (НЕ ТРОГАЛ)');
    console.log('   ✅ Имена - УНИКАЛЬНЫЕ');
    console.log('   ✅ Юзернейм - МОЖНО МЕНЯТЬ');
    console.log('   ✅ Аватарка - МОЖНО ЗАГРУЖАТЬ');
    console.log('   ✅ Аватарка - МОЖНО УДАЛЯТЬ');
    console.log('   ✅ Био - МОЖНО РЕДАКТИРОВАТЬ');
    console.log('   ✅ Группы - РАБОТАЮТ');
    console.log('   ✅ Личные чаты - РАБОТАЮТ');
    console.log('='.repeat(60) + '\n');
});
