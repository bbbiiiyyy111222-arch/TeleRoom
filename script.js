// ==============================================
// MOONGRIEF-FORUM - РАБОЧИЙ СКРИПТ
// ==============================================

// ==================== ДАННЫЕ ====================
let users = JSON.parse(localStorage.getItem('mg_users')) || [];
let complaints = JSON.parse(localStorage.getItem('mg_complaints')) || [];
let media = JSON.parse(localStorage.getItem('mg_media')) || [];
let helpers = JSON.parse(localStorage.getItem('mg_helpers')) || [];

let currentUser = JSON.parse(localStorage.getItem('mg_currentUser')) || null;
let currentDevice = localStorage.getItem('mg_device') || null;

// Админы (OWNER)
const admins = ['milfa', 'milk123', 'Xchik_'];

// ==================== СОХРАНЕНИЕ ====================
function saveData() {
    localStorage.setItem('mg_users', JSON.stringify(users));
    localStorage.setItem('mg_complaints', JSON.stringify(complaints));
    localStorage.setItem('mg_media', JSON.stringify(media));
    localStorage.setItem('mg_helpers', JSON.stringify(helpers));
    
    if (currentUser) {
        localStorage.setItem('mg_currentUser', JSON.stringify(currentUser));
    } else {
        localStorage.removeItem('mg_currentUser');
    }
}

// ==================== ВЫБОР УСТРОЙСТВА ====================
function selectDevice(device) {
    console.log('Выбрано устройство:', device);
    
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
}

function showDeviceChoice() {
    document.getElementById('mainSite').style.display = 'none';
    document.getElementById('deviceChoice').style.display = 'flex';
}

// ==================== КОПИРОВАНИЕ IP ====================
function copyIP() {
    navigator.clipboard.writeText('Moongrief.aurorix.pro').then(() => {
        alert('📋 IP скопирован! Заходи на сервер!');
    }).catch(() => {
        alert('❌ Ошибка копирования');
    });
}

// ==================== ПЕРЕКЛЮЧЕНИЕ РАЗДЕЛОВ ====================
function showSection(sectionId) {
    // Скрываем все разделы
    document.querySelectorAll('.section').forEach(section => {
        section.style.display = 'none';
    });
    
    // Убираем активный класс со всех кнопок
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.style.background = 'none';
        btn.style.color = '#b0b0ff';
        btn.style.border = '1px solid #4a4a8a';
    });
    
    // Показываем выбранный раздел
    document.getElementById(sectionId).style.display = 'block';
    
    // Активируем кнопку
    event.target.style.background = '#4a4a8a';
    event.target.style.color = 'white';
    event.target.style.border = 'none';
    
    console.log('Переключено на раздел:', sectionId);
}

// ==================== ПЕРЕКЛЮЧЕНИЕ ПЛАТФОРМ (TIKTOK/YOUTUBE) ====================
function switchPlatform(platform) {
    // Скрываем все формы
    document.getElementById('ttForm').style.display = 'none';
    document.getElementById('ytForm').style.display = 'none';
    
    // Убираем активный класс со всех табов
    document.querySelectorAll('.tab').forEach(tab => {
        tab.style.background = '#2a2a4a';
        tab.style.color = '#b0b0ff';
        tab.style.border = '1px solid #4a4a8a';
    });
    
    // Показываем выбранную форму
    if (platform === 'tt') {
        document.getElementById('ttForm').style.display = 'block';
        document.querySelectorAll('.tab')[0].style.background = '#4a4a8a';
        document.querySelectorAll('.tab')[0].style.color = 'white';
        document.querySelectorAll('.tab')[0].style.border = 'none';
    } else {
        document.getElementById('ytForm').style.display = 'block';
        document.querySelectorAll('.tab')[1].style.background = '#4a4a8a';
        document.querySelectorAll('.tab')[1].style.color = 'white';
        document.querySelectorAll('.tab')[1].style.border = 'none';
    }
}

// ==================== ЗАГРУЗКА ДАННЫХ ПОЛЬЗОВАТЕЛЯ ====================
function loadUserData() {
    const loginForm = document.getElementById('loginForm');
    const userInfo = document.getElementById('userInfo');
    const currentUserSpan = document.getElementById('currentUser');
    const adminLink = document.getElementById('adminLink');
    const complaintsList = document.getElementById('complaintsList');
    const mediaList = document.getElementById('mediaList');
    const applicationsList = document.getElementById('applicationsList');
    
    if (currentUser) {
        if (loginForm) loginForm.style.display = 'none';
        if (userInfo) userInfo.style.display = 'flex';
        if (currentUserSpan) currentUserSpan.textContent = currentUser.username;
        
        if (adminLink && admins.includes(currentUser.username)) {
            adminLink.style.display = 'inline-block';
        }
        
        // Загружаем личные заявки
        loadPersonalComplaints();
        loadPersonalMedia();
        loadPersonalApplications();
    } else {
        if (loginForm) loginForm.style.display = 'flex';
        if (userInfo) userInfo.style.display = 'none';
        if (adminLink) adminLink.style.display = 'none';
        
        if (complaintsList) complaintsList.innerHTML = '<div style="text-align:center; padding:30px; background:#1a1a2a; border-radius:10px; color:#7a7aaa;">🌙 Войдите чтобы увидеть свои жалобы</div>';
        if (mediaList) mediaList.innerHTML = '<div style="text-align:center; padding:30px; background:#1a1a2a; border-radius:10px; color:#7a7aaa;">🌙 Войдите чтобы увидеть свои анкеты</div>';
        if (applicationsList) applicationsList.innerHTML = '<div style="text-align:center; padding:30px; background:#1a1a2a; border-radius:10px; color:#7a7aaa;">🌙 Войдите чтобы увидеть свои анкеты</div>';
    }
}

// ==================== ЛИЧНЫЕ СПИСКИ ====================
function loadPersonalComplaints() {
    const list = document.getElementById('complaintsList');
    if (!list) return;
    
    if (!currentUser) {
        list.innerHTML = '<div style="text-align:center; padding:30px; background:#1a1a2a; border-radius:10px; color:#7a7aaa;">🌙 Войдите чтобы увидеть свои жалобы</div>';
        return;
    }
    
    const userComplaints = complaints.filter(c => c.user === currentUser.username);
    
    if (userComplaints.length === 0) {
        list.innerHTML = '<div style="text-align:center; padding:30px; background:#1a1a2a; border-radius:10px; color:#7a7aaa;">📭 У вас пока нет жалоб</div>';
        return;
    }
    
    let html = '';
    userComplaints.forEach(c => {
        html += `
            <div style="background:#1a1a2a; border-left:4px solid #4a4a8a; border-radius:10px; padding:15px; margin-bottom:10px;">
                <div style="display:flex; justify-content:space-between; margin-bottom:10px;">
                    <span style="color:#b0b0ff; font-weight:bold;">${c.title}</span>
                    <span style="background:#4a4a8a; color:white; padding:2px 10px; border-radius:15px; font-size:10px;">${c.status}</span>
                </div>
                <div style="color:#c0c0ff; font-size:11px;">
                    <p><strong>Нарушитель:</strong> ${c.target}</p>
                    <p><strong>Описание:</strong> ${c.desc}</p>
                    <p><strong>Дата:</strong> ${c.date}</p>
                </div>
            </div>
        `;
    });
    
    list.innerHTML = html;
}

function loadPersonalMedia() {
    const list = document.getElementById('mediaList');
    if (!list) return;
    
    if (!currentUser) {
        list.innerHTML = '<div style="text-align:center; padding:30px; background:#1a1a2a; border-radius:10px; color:#7a7aaa;">🌙 Войдите чтобы увидеть свои анкеты</div>';
        return;
    }
    
    const userMedia = media.filter(m => m.user === currentUser.username);
    
    if (userMedia.length === 0) {
        list.innerHTML = '<div style="text-align:center; padding:30px; background:#1a1a2a; border-radius:10px; color:#7a7aaa;">📭 У вас пока нет анкет</div>';
        return;
    }
    
    let html = '';
    userMedia.forEach(m => {
        const platformIcon = m.type === 'tt' ? '📱' : '▶️';
        const platformName = m.type === 'tt' ? 'TikTok' : 'YouTube';
        
        html += `
            <div style="background:#1a1a2a; border-left:4px solid #4a4a8a; border-radius:10px; padding:15px; margin-bottom:10px;">
                <div style="display:flex; justify-content:space-between; margin-bottom:10px;">
                    <span style="color:#b0b0ff; font-weight:bold;">${platformIcon} ${platformName}</span>
                    <span style="background:#4a4a8a; color:white; padding:2px 10px; border-radius:15px; font-size:10px;">${m.status}</span>
                </div>
                <div style="color:#c0c0ff; font-size:11px;">
                    <p><strong>Ник:</strong> ${m.nick}</p>
                    <p><strong>Подписчики:</strong> ${m.subs}</p>
                    <p><strong>Дата:</strong> ${m.date}</p>
                </div>
            </div>
        `;
    });
    
    list.innerHTML = html;
}

function loadPersonalApplications() {
    const list = document.getElementById('applicationsList');
    if (!list) return;
    
    if (!currentUser) {
        list.innerHTML = '<div style="text-align:center; padding:30px; background:#1a1a2a; border-radius:10px; color:#7a7aaa;">🌙 Войдите чтобы увидеть свои анкеты</div>';
        return;
    }
    
    const userHelpers = helpers.filter(h => h.user === currentUser.username);
    
    if (userHelpers.length === 0) {
        list.innerHTML = '<div style="text-align:center; padding:30px; background:#1a1a2a; border-radius:10px; color:#7a7aaa;">📭 У вас пока нет анкет</div>';
        return;
    }
    
    let html = '';
    userHelpers.forEach(h => {
        html += `
            <div style="background:#1a1a2a; border-left:4px solid #4a4a8a; border-radius:10px; padding:15px; margin-bottom:10px;">
                <div style="display:flex; justify-content:space-between; margin-bottom:10px;">
                    <span style="color:#b0b0ff; font-weight:bold;">👮 Хелпер</span>
                    <span style="background:#4a4a8a; color:white; padding:2px 10px; border-radius:15px; font-size:10px;">${h.status}</span>
                </div>
                <div style="color:#c0c0ff; font-size:11px;">
                    <p><strong>Ник:</strong> ${h.nick}</p>
                    <p><strong>Возраст:</strong> ${h.age}</p>
                    <p><strong>Дата:</strong> ${h.date}</p>
                </div>
            </div>
        `;
    });
    
    list.innerHTML = html;
}

// ==================== АВТОРИЗАЦИЯ ====================
function login() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    
    if (!username || !password) {
        alert('Введите ник и пароль');
        return;
    }
    
    const user = users.find(u => u.username === username && u.password === password);
    
    if (user) {
        currentUser = user;
        saveData();
        
        document.getElementById('loginForm').style.display = 'none';
        document.getElementById('userInfo').style.display = 'flex';
        document.getElementById('currentUser').textContent = username;
        
        if (admins.includes(username)) {
            document.getElementById('adminLink').style.display = 'inline-block';
        }
        
        alert(`🌙 Добро пожаловать, ${username}!`);
        
        document.getElementById('username').value = '';
        document.getElementById('password').value = '';
        
        loadPersonalComplaints();
        loadPersonalMedia();
        loadPersonalApplications();
    } else {
        alert('❌ Неверный ник или пароль');
    }
}

function register() {
    const username = document.getElementById('regUser').value.trim();
    const password = document.getElementById('regPass').value;
    const confirm = document.getElementById('regPass2').value;
    
    if (!username || !password || !confirm) {
        alert('Заполните все поля');
        return;
    }
    
    if (password !== confirm) {
        alert('Пароли не совпадают');
        return;
    }
    
    if (password.length < 4) {
        alert('Пароль должен быть минимум 4 символа');
        return;
    }
    
    if (users.some(u => u.username === username)) {
        alert('Пользователь уже существует');
        return;
    }
    
    const newUser = {
        username,
        password,
        role: admins.includes(username) ? 'admin' : 'user'
    };
    
    users.push(newUser);
    saveData();
    
    alert('✅ Регистрация успешна! Теперь войдите.');
    closeModal();
}

function logout() {
    currentUser = null;
    saveData();
    
    document.getElementById('loginForm').style.display = 'flex';
    document.getElementById('userInfo').style.display = 'none';
    document.getElementById('adminLink').style.display = 'none';
    
    alert('🚪 Вы вышли из аккаунта');
    
    document.getElementById('complaintsList').innerHTML = '<div style="text-align:center; padding:30px; background:#1a1a2a; border-radius:10px; color:#7a7aaa;">🌙 Войдите чтобы увидеть свои жалобы</div>';
    document.getElementById('mediaList').innerHTML = '<div style="text-align:center; padding:30px; background:#1a1a2a; border-radius:10px; color:#7a7aaa;">🌙 Войдите чтобы увидеть свои анкеты</div>';
    document.getElementById('applicationsList').innerHTML = '<div style="text-align:center; padding:30px; background:#1a1a2a; border-radius:10px; color:#7a7aaa;">🌙 Войдите чтобы увидеть свои анкеты</div>';
}

function showChangePassword() {
    if (!currentUser) {
        alert('Сначала войдите');
        return;
    }
    document.getElementById('changePassModal').style.display = 'flex';
}

function changePassword() {
    const oldPass = document.getElementById('oldPass').value;
    const newPass = document.getElementById('newPass').value;
    const confirm = document.getElementById('newPass2').value;
    
    if (!oldPass || !newPass || !confirm) {
        alert('Заполните все поля');
        return;
    }
    
    if (newPass !== confirm) {
        alert('Новые пароли не совпадают');
        return;
    }
    
    if (currentUser.password !== oldPass) {
        alert('Неверный старый пароль');
        return;
    }
    
    currentUser.password = newPass;
    
    const index = users.findIndex(u => u.username === currentUser.username);
    if (index !== -1) {
        users[index].password = newPass;
    }
    
    saveData();
    alert('🔑 Пароль изменен!');
    closeChangePass();
}

// ==================== ОТПРАВКА ФОРМ ====================
function submitComplaint() {
    if (!currentUser) {
        alert('Сначала войдите');
        return;
    }
    
    const title = document.getElementById('compTitle').value.trim();
    const target = document.getElementById('compTarget').value.trim();
    const desc = document.getElementById('compDesc').value.trim();
    
    if (!title || !target || !desc) {
        alert('Заполните все поля');
        return;
    }
    
    const newComplaint = {
        id: Date.now(),
        user: currentUser.username,
        title: title,
        target: target,
        desc: desc,
        status: 'НОВАЯ',
        date: new Date().toLocaleString()
    };
    
    complaints.push(newComplaint);
    saveData();
    
    alert('⚠️ Жалоба отправлена! Срок рассмотрения: 24 часа');
    
    document.getElementById('compTitle').value = '';
    document.getElementById('compTarget').value = '';
    document.getElementById('compDesc').value = '';
    
    loadPersonalComplaints();
}

function submitTT() {
    if (!currentUser) {
        alert('Сначала войдите');
        return;
    }
    
    const age = document.getElementById('ttAge').value;
    const name = document.getElementById('ttName').value.trim();
    const nick = document.getElementById('ttNick').value.trim();
    const subs = document.getElementById('ttSubs').value.trim();
    const link = document.getElementById('ttLink').value.trim();
    
    if (!age || !name || !nick || !subs || !link) {
        alert('Заполните все поля');
        return;
    }
    
    const newMedia = {
        id: Date.now(),
        type: 'tt',
        user: currentUser.username,
        age: age,
        name: name,
        nick: nick,
        subs: subs,
        link: link,
        status: 'НОВАЯ',
        date: new Date().toLocaleString()
    };
    
    media.push(newMedia);
    saveData();
    
    alert('📱 Анкета на TikTok отправлена! Срок рассмотрения: 24 часа');
    
    document.getElementById('ttAge').value = '';
    document.getElementById('ttName').value = '';
    document.getElementById('ttNick').value = '';
    document.getElementById('ttSubs').value = '';
    document.getElementById('ttLink').value = '';
    
    loadPersonalMedia();
}

function submitYT() {
    if (!currentUser) {
        alert('Сначала войдите');
        return;
    }
    
    const age = document.getElementById('ytAge').value;
    const name = document.getElementById('ytName').value.trim();
    const nick = document.getElementById('ytNick').value.trim();
    const subs = document.getElementById('ytSubs').value.trim();
    const link = document.getElementById('ytLink').value.trim();
    
    if (!age || !name || !nick || !subs || !link) {
        alert('Заполните все поля');
        return;
    }
    
    const newMedia = {
        id: Date.now(),
        type: 'yt',
        user: currentUser.username,
        age: age,
        name: name,
        nick: nick,
        subs: subs,
        link: link,
        status: 'НОВАЯ',
        date: new Date().toLocaleString()
    };
    
    media.push(newMedia);
    saveData();
    
    alert('▶️ Анкета на YouTube отправлена! Срок рассмотрения: 24 часа');
    
    document.getElementById('ytAge').value = '';
    document.getElementById('ytName').value = '';
    document.getElementById('ytNick').value = '';
    document.getElementById('ytSubs').value = '';
    document.getElementById('ytLink').value = '';
    
    loadPersonalMedia();
}

function submitHelper() {
    if (!currentUser) {
        alert('Сначала войдите');
        return;
    }
    
    const nick = document.getElementById('helpNick').value.trim();
    const name = document.getElementById('helpName').value.trim();
    const age = document.getElementById('helpAge').value;
    const tz = document.getElementById('helpTz').value;
    const exp = document.getElementById('helpExp').value.trim();
    const why = document.getElementById('helpWhy').value.trim();
    
    if (!nick || !name || !age || !tz || !exp || !why) {
        alert('Заполните все поля');
        return;
    }
    
    const newHelper = {
        id: Date.now(),
        user: currentUser.username,
        nick: nick,
        name: name,
        age: age,
        tz: tz,
        exp: exp,
        why: why,
        status: 'НОВАЯ',
        date: new Date().toLocaleString()
    };
    
    helpers.push(newHelper);
    saveData();
    
    alert('👮 Анкета на хелпера отправлена! Срок рассмотрения: 24 часа');
    
    document.getElementById('helpNick').value = '';
    document.getElementById('helpName').value = '';
    document.getElementById('helpAge').value = '';
    document.getElementById('helpTz').value = 'ЧАСОВОЙ ПОЯС';
    document.getElementById('helpExp').value = '';
    document.getElementById('helpWhy').value = '';
    
    loadPersonalApplications();
}

// ==================== МОДАЛКИ ====================
function showRegister() {
    document.getElementById('registerModal').style.display = 'flex';
}

function closeModal() {
    document.getElementById('registerModal').style.display = 'none';
}

function closeChangePass() {
    document.getElementById('changePassModal').style.display = 'none';
}

// ==================== ИНИЦИАЛИЗАЦИЯ ====================
document.addEventListener('DOMContentLoaded', function() {
    console.log('MoonGrief-Forum загружен');
    
    const savedDevice = localStorage.getItem('mg_device');
    
    if (savedDevice) {
        document.getElementById('deviceChoice').style.display = 'none';
        document.getElementById('mainSite').style.display = 'block';
        
        if (savedDevice === 'mobile') {
            document.body.classList.add('mobile-view');
            document.getElementById('deviceSwitch').style.display = 'block';
        }
        
        currentDevice = savedDevice;
        loadUserData();
    } else {
        document.getElementById('deviceChoice').style.display = 'flex';
    }
    
    // Показываем первый раздел
    document.getElementById('rules').style.display = 'block';
});

// Закрытие модалок по клику вне
window.onclick = function(event) {
    if (event.target.classList.contains('modal')) {
        event.target.style.display = 'none';
    }
}
