const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 3000;

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.use(express.static(path.join(__dirname, '/')));

let messages = [];

io.on('connection', (socket) => {
  console.log('Новый пользователь');
  
  socket.emit('history', messages);
  
  socket.on('chatMessage', (data) => {
    const msg = {
      user: data.user || 'Аноним',
      text: data.text,
      time: new Date().toLocaleTimeString()
    };
    messages.push(msg);
    io.emit('message', msg);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log('СЕРВЕР РАБОТАЕТ НА ПОРТУ', PORT);
});
