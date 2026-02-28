const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const PORT = process.env.PORT || 3000;

// Отдаем статические файлы
app.use(express.static(path.join(__dirname, '/')));

// Хранилище сообщений
let messages = [];

io.on('connection', (socket) => {
    console.log('Кто-то подключился');
    
    // Отправляем историю
    socket.emit('history', messages);
    
    // Получаем сообщение
    socket.on('chatMessage', (data) => {
        const msg = {
            user: data.user || 'Аноним',
            text: data.text,
            time: new Date().toLocaleTimeString()
        };
        
        messages.push(msg);
        if (messages.length > 50) messages.shift();
        
        // Рассылаем всем
        io.emit('message', msg);
    });
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});
