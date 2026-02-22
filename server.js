const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const xss = require('xss'); // Не забудь: npm install xss

const app = express();
const server = http.createServer(app);

// Настройка Socket.io с поддержкой CORS для Zeabur
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

// --- МЕГА ЗАЩИТА ---
app.use(helmet({ contentSecurityPolicy: false })); // Защита заголовков

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: "Система защиты: Слишком много запросов. Подождите 15 минут."
});
app.use(limiter);
app.use(express.static(path.join(__dirname, 'public')));

// --- РАБОТА С БАЗОЙ (SQLite) ---
const db = new sqlite3.Database('./database.db');
db.run("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, user TEXT, text TEXT, time TEXT)");

// --- ЛОГИКА МЕССЕНДЖЕРА ---
io.on('connection', (socket) => {
    console.log('Подключен узел:', socket.id);

    // Отправка последних 50 сообщений при входе
    db.all("SELECT * FROM messages ORDER BY id DESC LIMIT 50", (err, rows) => {
        if (!err) socket.emit('history', rows.reverse());
    });

    socket.on('chatMessage', (data) => {
        // Защита от пустых сообщений и гигантского спама
        if (!data.text || data.text.length > 500) return;

        const msgData = {
            user: xss(data.user || 'Аноним').substring(0, 20),
            text: xss(data.text),
            time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        };

        // Сохраняем в базу
        db.run("INSERT INTO messages (user, text, time) VALUES (?, ?, ?)", [msgData.user, msgData.text, msgData.time]);

        // Трансляция всем
        io.emit('message', msgData);
    });
});

// --- ЗАПУСК ---
// Zeabur передает порт через process.env.PORT, если его нет — используем 3000
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(🚀 TeleRoom Supreme запущен на порту ${PORT});
});
