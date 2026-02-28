const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Zeabur сам дает порт
const PORT = process.env.PORT || 3000;

// Раздаем статические файлы
app.use(express.static(path.join(__dirname, '/')));

// Хранилище сообщений
let messages = [];

io.on('connection', (socket) => {
    console.log('✅ Новый пользователь подключился');
    
    // Отправляем историю новому пользователю
    socket.emit('history', messages);
    
    // Получаем сообщение
    socket.on('chatMessage', (data) => {
        const msg = {
            user: data.user || 'Аноним',
            text: data.text,
            time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })
        };
        
        messages.push(msg);
        // Храним только последние 50 сообщений
        if (messages.length > 50) messages.shift();
        
        // Отправляем всем
        io.emit('message', msg);
    });
    
    socket.on('disconnect', () => {
        console.log('❌ Пользователь отключился');
    });
});

// Слушаем на всех интерфейсах
server.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Сервер ЗАПУЩЕН на порту ${PORT}`);
    console.log(`📱 Открой приложение по адресу: http://localhost:${PORT} (локально)`);
});
