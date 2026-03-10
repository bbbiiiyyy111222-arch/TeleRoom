// ==============================================
// MOONGRIEF-FORUM - ОСНОВНОЙ СКРИПТ
// ==============================================

console.log('🌙 MoonGrief-Forum загружается...');

let currentUser = null;
let currentDevice = localStorage.getItem('mg_device') || null;

// ==============================================
// ВЫБОР УСТРОЙСТВА
// ==============================================

window.selectDevice = function(device) {
    localStorage.setItem('mg_device', device);
    currentDevice = device;
    
    document.getElementById('deviceChoice').style.display = 'none';
    document.getElementById('mainSite').style.display = 'block';
    
    if (device === 'mobile') {
        document.body.classList.add('mobile-view');
        document.getElementById('deviceSwitch').style.display = 'block';
    } else {
        document.body.classList.remove('mobile-view');
        document.getElementById('deviceSwitch').style.display = 'none';
    }
    
    loadUserData();
};

window.showDeviceChoice = function() {
    document.getElementById('mainSite').style.display = 'none';
    document.getElementById('deviceChoice').style.display = 'flex';
};

// ==============================================
// КОПИРОВАНИЕ IP
// ==============================================

window.copyIP = function() {
    navigator.clipboard.writeText('Moongrief.aurorix.pro').then(() => {
        alert('📋 IP скопирован!');
    });
};

// ==============================================
// НАВИГАЦИЯ
// ==============================================

window.showSection = function(sectionId) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-btn').forEach(b => {
        b.classList.remove('active');
        b.style.background = 'none';
        b.style.color = '#b0b0ff';
    });
    
    document.getElementById(sectionId).classList.add('active');
    event.target.classList.add('active');
    event.target.style.background = '#4a4a8a';
    event.target.style.color = 'white';
};

window.switchPlatform = function(platform) {
    document.getElementById('ttForm').classList.remove('active');
    document.getElementById('ytForm').classList.remove('active');
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    
    if (platform === 'tt') {
        document.getElementById('ttForm').classList.add('active');
        document.querySelectorAll('.tab')[0].classList.add('active');
    } else {
        document.getElementById('ytForm').classList.add('active');
        document.querySelectorAll('.tab')[1].classList.add('active');
    }
};

// ==============================================
// АВТОРИЗАЦИЯ
// ==============================================

window.login = async function() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    
    if (!username || !password) {
        alert('Введите ник и пароль');
        return;
    }
    
    // Используем функцию из db.js
    if (window.checkUser) {
        const user = await window.checkUser(username, password);
        
        if (user) {
            currentUser = user;
            localStorage.setItem('mg_currentUser', JSON.stringify(user));
            
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('userInfo').style.display = 'flex';
            document.getElementById('currentUser').textContent = username;
            
            if (username === 'milfa' || username === 'milk123' || username === 'Xchik_') {
                document.getElementById('adminLink').style.display = 'inline-block';
            }
            
            alert(`🌙 Добро пожаловать, ${username}!`);
            
            document.getElementById('username').value = '';
            document.getElementById('password').value = '';
            
            // Загружаем личные заявки
            loadPersonalComplaints();
            loadPersonalMedia();
            loadPersonalHelpers();
        } else {
            alert('❌ Неверный ник или пароль');
        }
    } else {
        alert('❌ Ошибка подключения к базе данных');
    }
};

window.logout = function() {
    currentUser = null;
    localStorage.removeItem('mg_currentUser');
    
    document.getElementById('loginForm').style.display = 'flex';
    document.getElementById('userInfo').style.display = 'none';
    document.getElementById('adminLink').style.display = 'none';
    
    document.getElementById('complaintsList').innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои жалобы</div>';
    document.getElementById('mediaList').innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои анкеты</div>';
    document.getElementById('applicationsList').innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои анкеты</div>';
};

// ==============================================
// ЗАГРУЗКА ЛИЧНЫХ ЗАЯВОК
// ==============================================

async function loadPersonalComplaints() {
    const list = document.getElementById('complaintsList');
    if (!list) return;
    
    if (!currentUser) {
        list.innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои жалобы</div>';
        return;
    }
    
    if (window.getUserComplaints) {
        const userComplaints = await window.getUserComplaints(currentUser.username);
        
        if (userComplaints.length === 0) {
            list.innerHTML = '<div class="empty-list">📭 У вас пока нет жалоб</div>';
            return;
        }
        
        let html = '';
        userComplaints.forEach(c => {
            html += `
                <div class="complaint-card">
                    <div class="complaint-header">
                        <span class="complaint-title">${c.title || 'Жалоба'}</span>
                        <span class="complaint-status status-${c.status === 'НОВАЯ' ? 'new' : 'accepted'}">${c.status || 'НОВАЯ'}</span>
                    </div>
                    <div class="complaint-body">
                        <p><strong>Нарушитель:</strong> ${c.target || c.against || 'Не указан'}</p>
                        <p><strong>Описание:</strong> ${c.description || 'Нет описания'}</p>
                        <p><strong>Дата:</strong> ${c.date || 'Неизвестно'}</p>
                    </div>
                </div>
            `;
        });
        
        list.innerHTML = html;
    }
}

async function loadPersonalMedia() {
    const list = document.getElementById('mediaList');
    if (!list) return;
    
    if (!currentUser) {
        list.innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои анкеты</div>';
        return;
    }
    
    if (window.getUserMediaApplications) {
        const userMedia = await window.getUserMediaApplications(currentUser.username);
        
        if (userMedia.length === 0) {
            list.innerHTML = '<div class="empty-list">📭 У вас пока нет медиа-заявок</div>';
            return;
        }
        
        let html = '';
        userMedia.forEach(m => {
            html += `
                <div class="media-card">
                    <div class="media-header">
                        <span class="media-title">${m.platform === 'tt' ? '📱 TikTok' : '▶️ YouTube'}</span>
                        <span class="media-status status-new">${m.status || 'НОВАЯ'}</span>
                    </div>
                    <div class="media-body">
                        <p><strong>Ник:</strong> ${m.nickname || 'Не указан'}</p>
                        <p><strong>Подписчики:</strong> ${m.subscribers || '0'}</p>
                        <p><strong>Дата:</strong> ${m.date || 'Неизвестно'}</p>
                    </div>
                </div>
            `;
        });
        
        list.innerHTML = html;
    }
}

async function loadPersonalHelpers() {
    const list = document.getElementById('applicationsList');
    if (!list) return;
    
    if (!currentUser) {
        list.innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои анкеты</div>';
        return;
    }
    
    if (window.getUserHelperApplications) {
        const userHelpers = await window.getUserHelperApplications(currentUser.username);
        
        if (userHelpers.length === 0) {
            list.innerHTML = '<div class="empty-list">📭 У вас пока нет анкет</div>';
            return;
        }
        
        let html = '';
        userHelpers.forEach(h => {
            html += `
                <div class="application-card">
                    <div class="application-header">
                        <span class="application-title">👮 Анкета на хелпера</span>
                        <span class="application-status status-new">${h.status || 'НОВАЯ'}</span>
                    </div>
                    <div class="application-body">
                        <p><strong>Ник:</strong> ${h.nickname || 'Не указан'}</p>
                        <p><strong>Дата:</strong> ${h.date || 'Неизвестно'}</p>
                    </div>
                </div>
            `;
        });
        
        list.innerHTML = html;
    }
}

// ==============================================
// ОТПРАВКА ФОРМ (ИСПОЛЬЗУЕМ Supabase)
// ==============================================

window.submitComplaint = async function() {
    if (!currentUser) {
        alert('Сначала войдите');
        return;
    }
    
    const title = document.getElementById('compTitle')?.value;
    const target = document.getElementById('compTarget')?.value;
    const desc = document.getElementById('compDesc')?.value;
    
    if (!title || !target || !desc) {
        alert('Заполните все поля');
        return;
    }
    
    if (window.saveComplaint) {
        const complaint = {
            user: currentUser.username,
            title: title,
            target: target,
            desc: desc
        };
        
        const result = await window.saveComplaint(complaint);
        
        if (result) {
            alert('✅ Жалоба отправлена!');
            document.getElementById('compTitle').value = '';
            document.getElementById('compTarget').value = '';
            document.getElementById('compDesc').value = '';
            loadPersonalComplaints();
        } else {
            alert('❌ Ошибка при отправке');
        }
    }
};

window.submitTT = async function() {
    if (!currentUser) {
        alert('Сначала войдите');
        return;
    }
    
    const age = document.getElementById('ttAge')?.value;
    const name = document.getElementById('ttName')?.value;
    const nick = document.getElementById('ttNick')?.value;
    const subs = document.getElementById('ttSubs')?.value;
    const link = document.getElementById('ttLink')?.value;
    
    if (!age || !name || !nick || !subs || !link) {
        alert('Заполните все поля');
        return;
    }
    
    if (window.saveMediaApplication) {
        const mediaApp = {
            user: currentUser.username,
            type: 'tt',
            age: age,
            name: name,
            nick: nick,
            subs: subs,
            link: link
        };
        
        const result = await window.saveMediaApplication(mediaApp);
        
        if (result) {
            alert('✅ Заявка на TikTok отправлена!');
            document.getElementById('ttAge').value = '';
            document.getElementById('ttName').value = '';
            document.getElementById('ttNick').value = '';
            document.getElementById('ttSubs').value = '';
            document.getElementById('ttLink').value = '';
            loadPersonalMedia();
        } else {
            alert('❌ Ошибка при отправке');
        }
    }
};

window.submitYT = async function() {
    if (!currentUser) {
        alert('Сначала войдите');
        return;
    }
    
    const age = document.getElementById('ytAge')?.value;
    const name = document.getElementById('ytName')?.value;
    const nick = document.getElementById('ytNick')?.value;
    const subs = document.getElementById('ytSubs')?.value;
    const link = document.getElementById('ytLink')?.value;
    
    if (!age || !name || !nick || !subs || !link) {
        alert('Заполните все поля');
        return;
    }
    
    if (window.saveMediaApplication) {
        const mediaApp = {
            user: currentUser.username,
            type: 'yt',
            age: age,
            name: name,
            nick: nick,
            subs: subs,
            link: link
        };
        
        const result = await window.saveMediaApplication(mediaApp);
        
        if (result) {
            alert('✅ Заявка на YouTube отправлена!');
            document.getElementById('ytAge').value = '';
            document.getElementById('ytName').value = '';
            document.getElementById('ytNick').value = '';
            document.getElementById('ytSubs').value = '';
            document.getElementById('ytLink').value = '';
            loadPersonalMedia();
        } else {
            alert('❌ Ошибка при отправке');
        }
    }
};

window.submitHelper = async function() {
    if (!currentUser) {
        alert('Сначала войдите');
        return;
    }
    
    const nick = document.getElementById('helpNick')?.value;
    const name = document.getElementById('helpName')?.value;
    const age = document.getElementById('helpAge')?.value;
    const tz = document.getElementById('helpTz')?.value;
    const exp = document.getElementById('helpExp')?.value;
    const why = document.getElementById('helpWhy')?.value;
    
    if (!nick || !name || !age || !tz || !exp || !why) {
        alert('Заполните все поля');
        return;
    }
    
    if (window.saveHelperApplication) {
        const helperApp = {
            user: currentUser.username,
            nick: nick,
            name: name,
            age: age,
            tz: tz,
            exp: exp,
            why: why
        };
        
        const result = await window.saveHelperApplication(helperApp);
        
        if (result) {
            alert('✅ Анкета отправлена!');
            document.getElementById('helpNick').value = '';
            document.getElementById('helpName').value = '';
            document.getElementById('helpAge').value = '';
            document.getElementById('helpTz').value = '';
            document.getElementById('helpExp').value = '';
            document.getElementById('helpWhy').value = '';
            loadPersonalHelpers();
        } else {
            alert('❌ Ошибка при отправке');
        }
    }
};

// ==============================================
// МОДАЛКИ
// ==============================================

window.showRegister = function() {
    document.getElementById('registerModal').style.display = 'flex';
};

window.closeModal = function() {
    document.getElementById('registerModal').style.display = 'none';
};

window.showChangePassword = function() {
    if (!currentUser) {
        alert('Сначала войдите');
        return;
    }
    document.getElementById('changePassModal').style.display = 'flex';
};

window.closeChangePass = function() {
    document.getElementById('changePassModal').style.display = 'none';
};

window.register = async function() {
    const username = document.getElementById('regUser')?.value;
    const password = document.getElementById('regPass')?.value;
    const confirm = document.getElementById('regPass2')?.value;
    
    if (!username || !password || !confirm) {
        alert('Заполните все поля');
        return;
    }
    
    if (password !== confirm) {
        alert('Пароли не совпадают');
        return;
    }
    
    alert('Функция регистрации временно отключена');
    closeModal();
};

window.changePassword = function() {
    alert('Функция смены пароля временно отключена');
    closeChangePass();
};

// ==============================================
// ЗАГРУЗКА ПРИ СТАРТЕ
// ==============================================

async function loadUserData() {
    const savedUser = localStorage.getItem('mg_currentUser');
    if (savedUser) {
        currentUser = JSON.parse(savedUser);
        
        document.getElementById('loginForm').style.display = 'none';
        document.getElementById('userInfo').style.display = 'flex';
        document.getElementById('currentUser').textContent = currentUser.username;
        
        if (currentUser.username === 'milfa' || currentUser.username === 'milk123' || currentUser.username === 'Xchik_') {
            document.getElementById('adminLink').style.display = 'inline-block';
        }
        
        await loadPersonalComplaints();
        await loadPersonalMedia();
        await loadPersonalHelpers();
    }
}

document.addEventListener('DOMContentLoaded', async function() {
    console.log('🌙 MoonGrief-Forum запущен');
    
    const savedDevice = localStorage.getItem('mg_device');
    if (savedDevice) {
        document.getElementById('deviceChoice').style.display = 'none';
        document.getElementById('mainSite').style.display = 'block';
        if (savedDevice === 'mobile') {
            document.body.classList.add('mobile-view');
            document.getElementById('deviceSwitch').style.display = 'block';
        }
        await loadUserData();
    }
});
