// ========== API ПРОФИЛЯ ==========
// Обновление имени пользователя
app.post('/api/user/update-name', (req, res) => {
    const { userId, newName } = req.body;
    
    // Проверяем, свободно ли имя
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
            
            // Уведомляем всех об изменении
            db.all('SELECT id, name, avatar, bio, online FROM users', (err, users) => {
                io.emit('all_users', users || []);
            });
        });
    });
});

// Обновление юзернейма (phone)
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

// Загрузка аватарки
app.post('/api/user/upload-avatar', upload.single('avatar'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Нет файла' });
    
    const { userId } = req.body;
    const avatar = req.file.filename;
    
    db.run('UPDATE users SET avatar = ? WHERE id = ?', [avatar, userId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        
        res.json({ success: true, avatar });
        
        // Обновляем всех
        db.all('SELECT id, name, avatar, bio, online FROM users', (err, users) => {
            io.emit('all_users', users || []);
        });
    });
});

// ========== API ГРУПП - ДОПОЛНИТЕЛЬНЫЕ ==========
// Обновление названия группы
app.post('/api/groups/update-name', (req, res) => {
    const { groupId, userId, newName } = req.body;
    
    // Проверяем, админ ли
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

// Обновление описания группы
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
