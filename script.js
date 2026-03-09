// ==============================================
// MOONGRIEF-FORUM - ОСНОВНОЙ СКРИПТ
// ==============================================

// Данные
let users = JSON.parse(localStorage.getItem('mg_users')) || [];
let complaints = JSON.parse(localStorage.getItem('mg_complaints')) || [];
let media = JSON.parse(localStorage.getItem('mg_media')) || [];
let helpers = JSON.parse(localStorage.getItem('mg_helpers')) || [];

let currentUser = JSON.parse(localStorage.getItem('mg_currentUser')) || null;
let currentDevice = localStorage.getItem('mg_device') || null;

// Админы
const admins = ['milfa', 'milk123', 'Xchik_'];

// ==============================================
// СОХРАНЕНИЕ ДАННЫХ
// ==============================================

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

// ==============================================
// ВЫБОР УСТРОЙСТВА - ИСПРАВЛЕНО
// ==============================================

function selectDevice(device) {
    console.log('Выбрано устройство:', device); // Для отладки
    
    // Сохраняем выбор
    localStorage.setItem('mg_device', device);
    currentDevice = device;
    
    // Скрываем экран выбора
    const deviceChoice = document.getElementById('deviceChoice');
    deviceChoice.style.display = 'none';
    
    // Показываем основной сайт
    const mainSite = document.getElementById('mainSite');
    mainSite.style.display = 'block';
    
    // Применяем класс для мобильной версии если нужно
    if (device === 'mobile') {
        document.body.classList.add('mobile-view');
        document.getElementById('deviceSwitch').style.display = 'block';
    } else {
        document.body.classList.remove('mobile-view');
        document.getElementById('deviceSwitch').style.display = 'none';
    }
    
    // Загружаем данные пользователя
    loadUserData();
    
    // Показываем уведомление
    showNotification(`🌙 ${device === 'mobile' ? 'Мобильная' : 'ПК'} версия активирована`, 'success');
}

function showDeviceChoice() {
    // Скрываем основной сайт
    document.getElementById('mainSite').style.display = 'none';
    
    // Показываем экран выбора
    const deviceChoice = document.getElementById('deviceChoice');
    deviceChoice.style.display = 'flex';
}
        
        // Загружаем данные пользователя
        loadUserData();
    }, 300);
}

function showDeviceChoice() {
    const mainSite = document.getElementById('mainSite');
    const deviceChoice = document.getElementById('deviceChoice');
    
    mainSite.style.opacity = '0';
    
    setTimeout(() => {
        mainSite.style.display = 'none';
        deviceChoice.style.display = 'flex';
        setTimeout(() => deviceChoice.style.opacity = '1', 50);
    }, 300);
}

// ==============================================
// КОПИРОВАНИЕ IP
// ==============================================

function copyIP() {
    navigator.clipboard.writeText('Moongrief.aurorix.pro').then(() => {
        showNotification('📋 IP скопирован!', 'success');
    }).catch(() => {
        showNotification('❌ Ошибка копирования', 'error');
    });
}

// ==============================================
// УВЕДОМЛЕНИЯ
// ==============================================

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <span>${type === 'success' ? '✅' : type === 'error' ? '❌' : '🌙'}</span>
        <span>${message}</span>
    `;
    
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${type === 'success' ? '#4a9a7a' : type === 'error' ? '#9a4a4a' : '#4a4a8a'};
        color: white;
        padding: 12px 20px;
        border-radius: 5px;
        font-family: 'Roboto', sans-serif;
        font-size: 13px;
        z-index: 10000;
        display: flex;
        align-items: center;
        gap: 10px;
        box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// ==============================================
// НАВИГАЦИЯ
// ==============================================

function showSection(sectionId, event) {
    if (event) {
        event.preventDefault();
    }
    
    // Скрываем все секции
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active-section');
    });
    
    // Показываем нужную секцию
    document.getElementById(sectionId).classList.add('active-section');
    
    // Обновляем активную ссылку
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    
    if (event) {
        event.target.classList.add('active');
    } else {
        const link = document.querySelector(`.nav-link[href="#${sectionId}"]`);
        if (link) link.classList.add('active');
    }
    
    // Сохраняем последнюю секцию
    if (currentUser) {
        localStorage.setItem('mg_lastSection', sectionId);
    }
}

// ==============================================
// ПЕРЕКЛЮЧЕНИЕ ПЛАТФОРМ
// ==============================================

function switchPlatform(platform) {
    document.getElementById('ttForm').classList.remove('active');
    document.getElementById('ytForm').classList.remove('active');
    document.getElementById('switchTT').classList.remove('active');
    document.getElementById('switchYT').classList.remove('active');
    
    if (platform === 'tt') {
        document.getElementById('ttForm').classList.add('active');
        document.getElementById('switchTT').classList.add('active');
    } else {
        document.getElementById('ytForm').classList.add('active');
        document.getElementById('switchYT').classList.add('active');
    }
}

// ==============================================
// ЗАГРУЗКА ДАННЫХ ПОЛЬЗОВАТЕЛЯ
// ==============================================

function loadUserData() {
    if (currentUser) {
        document.getElementById('loginForm').style.display = 'none';
        document.getElementById('userInfo').style.display = 'flex';
        document.getElementById('currentUser').textContent = currentUser.username;
        
        if (admins.includes(currentUser.username)) {
            document.getElementById('adminLink').style.display = 'inline-block';
        }
        
        // Загружаем личные заявки
        loadPersonalComplaints();
        loadPersonalMedia();
        loadPersonalHelpers();
    } else {
        document.getElementById('loginForm').style.display = 'flex';
        document.getElementById('userInfo').style.display = 'none';
        document.getElementById('adminLink').style.display = 'none';
        
        // Показываем пустые списки
        document.getElementById('complaintsList').innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои жалобы</div>';
        document.getElementById('mediaList').innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои заявки</div>';
        document.getElementById('applicationsList').innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои анкеты</div>';
    }
}

// ==============================================
// АВТОРИЗАЦИЯ
// ==============================================

function login() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    
    if (!username || !password) {
        showNotification('Введите ник и пароль', 'error');
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
        
        showNotification(`🌙 Добро пожаловать, ${username}!`, 'success');
        
        // Загружаем личные заявки
        loadPersonalComplaints();
        loadPersonalMedia();
        loadPersonalHelpers();
        
        // Очищаем поля
        document.getElementById('username').value = '';
        document.getElementById('password').value = '';
    } else {
        showNotification('Неверный ник или пароль', 'error');
    }
}

function register(event) {
    if (event) event.preventDefault();
    
    const username = document.getElementById('regUsername').value.trim();
    const password = document.getElementById('regPassword').value;
    const confirm = document.getElementById('regConfirmPassword').value;
    
    if (!username || !password || !confirm) {
        showNotification('Заполните все поля', 'error');
        return;
    }
    
    if (password !== confirm) {
        showNotification('Пароли не совпадают', 'error');
        return;
    }
    
    if (password.length < 4) {
        showNotification('Пароль должен быть минимум 4 символа', 'error');
        return;
    }
    
    if (users.some(u => u.username === username)) {
        showNotification('Пользователь уже существует', 'error');
        return;
    }
    
    // Определяем роль (админы по списку)
    const role = admins.includes(username) ? 'admin' : 'user';
    
    const newUser = {
        username,
        password,
        role,
        createdAt: new Date().toLocaleString()
    };
    
    users.push(newUser);
    saveData();
    
    showNotification('✅ Аккаунт создан! Теперь войдите.', 'success');
    closeModal();
}

function logout() {
    currentUser = null;
    saveData();
    
    document.getElementById('loginForm').style.display = 'flex';
    document.getElementById('userInfo').style.display = 'none';
    document.getElementById('adminLink').style.display = 'none';
    
    showNotification('🚪 Вы вышли из аккаунта', 'info');
    
    // Очищаем списки
    document.getElementById('complaintsList').innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои жалобы</div>';
    document.getElementById('mediaList').innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои заявки</div>';
    document.getElementById('applicationsList').innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои анкеты</div>';
}

function changePassword(event) {
    if (event) event.preventDefault();
    
    if (!currentUser) {
        showNotification('Сначала войдите', 'error');
        return;
    }
    
    const oldPass = document.getElementById('oldPassword').value;
    const newPass = document.getElementById('newPassword').value;
    const confirm = document.getElementById('confirmPassword').value;
    
    if (!oldPass || !newPass || !confirm) {
        showNotification('Заполните все поля', 'error');
        return;
    }
    
    if (newPass !== confirm) {
        showNotification('Новые пароли не совпадают', 'error');
        return;
    }
    
    if (currentUser.password !== oldPass) {
        showNotification('Неверный старый пароль', 'error');
        return;
    }
    
    // Обновляем пароль
    currentUser.password = newPass;
    
    // Обновляем в массиве
    const index = users.findIndex(u => u.username === currentUser.username);
    if (index !== -1) {
        users[index].password = newPass;
    }
    
    saveData();
    showNotification('🔑 Пароль изменен!', 'success');
    closeChangePassword();
}

// ==============================================
// ЗАГРУЗКА ЛИЧНЫХ ЗАЯВОК
// ==============================================

function loadPersonalComplaints() {
    const list = document.getElementById('complaintsList');
    
    if (!currentUser) {
        list.innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои жалобы</div>';
        return;
    }
    
    const userComplaints = complaints.filter(c => c.user === currentUser.username);
    
    if (userComplaints.length === 0) {
        list.innerHTML = '<div class="empty-list">📭 У вас пока нет жалоб</div>';
        return;
    }
    
    list.innerHTML = userComplaints.map(c => `
        <div class="complaint-card">
            <div class="complaint-header">
                <span class="complaint-title">${c.title}</span>
                <span class="complaint-status status-${c.status}">${getStatusText(c.status)}</span>
            </div>
            <div class="complaint-body">
                <p><strong>Нарушитель:</strong> ${c.target}</p>
                <p><strong>Описание:</strong> ${c.desc}</p>
                <p><strong>Дата:</strong> ${c.date}</p>
            </div>
        </div>
    `).join('');
}

function loadPersonalMedia() {
    const list = document.getElementById('mediaList');
    
    if (!currentUser) {
        list.innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои заявки</div>';
        return;
    }
    
    const userMedia = media.filter(m => m.user === currentUser.username);
    
    if (userMedia.length === 0) {
        list.innerHTML = '<div class="empty-list">📭 У вас пока нет медиа-заявок</div>';
        return;
    }
    
    list.innerHTML = userMedia.map(m => `
        <div class="media-card">
            <div class="media-header">
                <span class="media-title">${m.type === 'tt' ? '📱 TikTok' : '▶️ YouTube'}</span>
                <span class="media-status status-${m.status}">${getStatusText(m.status)}</span>
            </div>
            <div class="media-body">
                <p><strong>Ник:</strong> ${m.nick}</p>
                <p><strong>Подписчики:</strong> ${m.subs}</p>
                <p><strong>Дата:</strong> ${m.date}</p>
            </div>
        </div>
    `).join('');
}

function loadPersonalHelpers() {
    const list = document.getElementById('applicationsList');
    
    if (!currentUser) {
        list.innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои анкеты</div>';
        return;
    }
    
    const userHelpers = helpers.filter(h => h.user === currentUser.username);
    
    if (userHelpers.length === 0) {
        list.innerHTML = '<div class="empty-list">📭 У вас пока нет анкет</div>';
        return;
    }
    
    list.innerHTML = userHelpers.map(h => `
        <div class="application-card">
            <div class="application-header">
                <span class="application-title">👮 Анкета на хелпера</span>
                <span class="application-status status-${h.status}">${getStatusText(h.status)}</span>
            </div>
            <div class="application-body">
                <p><strong>Ник:</strong> ${h.nick}</p>
                <p><strong>Возраст:</strong> ${h.age}</p>
                <p><strong>Дата:</strong> ${h.date}</p>
            </div>
        </div>
    `).join('');
}

function getStatusText(status) {
    switch(status) {
        case 'new': return 'НОВАЯ';
        case 'accepted': return 'ПРИНЯТО';
        case 'rejected': return 'ОТКЛОНЕНО';
        default: return status;
    }
}

// ==============================================
// ОТПРАВКА ФОРМ
// ==============================================

function submitComplaint(event) {
    if (event) event.preventDefault();
    
    if (!currentUser) {
        showNotification('Сначала войдите в аккаунт', 'error');
        return;
    }
    
    const title = document.getElementById('complaintTitle').value.trim();
    const target = document.getElementById('complaintAgainst').value.trim();
    const desc = document.getElementById('complaintDesc').value.trim();
    
    if (!title || !target || !desc) {
        showNotification('Заполните все поля', 'error');
        return;
    }
    
    const newComplaint = {
        id: Date.now(),
        user: currentUser.username,
        title: title,
        target: target,
        desc: desc,
        status: 'new',
        date: new Date().toLocaleString()
    };
    
    complaints.push(newComplaint);
    saveData();
    
    showNotification('⚠️ Жалоба отправлена!', 'success');
    
    document.getElementById('complaintForm').reset();
    loadPersonalComplaints();
}

function submitTTMedia(event) {
    if (event) event.preventDefault();
    
    if (!currentUser) {
        showNotification('Сначала войдите в аккаунт', 'error');
        return;
    }
    
    const age = document.getElementById('ttAge').value;
    const name = document.getElementById('ttName').value.trim();
    const nick = document.getElementById('ttNickname').value.trim();
    const subs = document.getElementById('ttSubs').value.trim();
    const views = document.getElementById('ttViews').value.trim();
    const link = document.getElementById('ttLink').value.trim();
    
    if (!age || !name || !nick || !subs || !views || !link) {
        showNotification('Заполните все поля', 'error');
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
        views: views,
        link: link,
        status: 'new',
        date: new Date().toLocaleString()
    };
    
    media.push(newMedia);
    saveData();
    
    showNotification('📱 Заявка на TikTok отправлена!', 'success');
    
    document.getElementById('ttMediaForm').reset();
    loadPersonalMedia();
}

function submitYTMedia(event) {
    if (event) event.preventDefault();
    
    if (!currentUser) {
        showNotification('Сначала войдите в аккаунт', 'error');
        return;
    }
    
    const age = document.getElementById('ytAge').value;
    const name = document.getElementById('ytName').value.trim();
    const nick = document.getElementById('ytNickname').value.trim();
    const subs = document.getElementById('ytSubs').value.trim();
    const views = document.getElementById('ytViews').value.trim();
    const link = document.getElementById('ytLink').value.trim();
    
    if (!age || !name || !nick || !subs || !views || !link) {
        showNotification('Заполните все поля', 'error');
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
        views: views,
        link: link,
        status: 'new',
        date: new Date().toLocaleString()
    };
    
    media.push(newMedia);
    saveData();
    
    showNotification('▶️ Заявка на YouTube отправлена!', 'success');
    
    document.getElementById('ytMediaForm').reset();
    loadPersonalMedia();
}

function submitApplication(event) {
    if (event) event.preventDefault();
    
    if (!currentUser) {
        showNotification('Сначала войдите в аккаунт', 'error');
        return;
    }
    
    const nick = document.getElementById('helperNickname').value.trim();
    const name = document.getElementById('helperName').value.trim();
    const age = document.getElementById('helperAge').value;
    const tz = document.getElementById('helperTimezone').value;
    const exp = document.getElementById('helperExperience').value.trim();
    const reason = document.getElementById('helperReason').value.trim();
    const additional = document.getElementById('helperAdditional').value.trim();
    
    if (!nick || !name || !age || !tz || !exp || !reason) {
        showNotification('Заполните обязательные поля', 'error');
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
        reason: reason,
        additional: additional,
        status: 'new',
        date: new Date().toLocaleString()
    };
    
    helpers.push(newHelper);
    saveData();
    
    showNotification('👮 Анкета отправлена!', 'success');
    
    document.getElementById('helperForm').reset();
    loadPersonalHelpers();
}

// ==============================================
// МОДАЛЬНЫЕ ОКНА
// ==============================================

function showRegister() {
    document.getElementById('registerModal').style.display = 'flex';
}

function closeModal() {
    document.getElementById('registerModal').style.display = 'none';
}

function showChangePassword() {
    if (!currentUser) {
        showNotification('Сначала войдите в аккаунт', 'error');
        return;
    }
    document.getElementById('changePasswordModal').style.display = 'flex';
}

function closeChangePassword() {
    document.getElementById('changePasswordModal').style.display = 'none';
}

// ==============================================
// ИНИЦИАЛИЗАЦИЯ
// ==============================================

document.addEventListener('DOMContentLoaded', function() {
    // Показываем выбор устройства или основной сайт
    if (currentDevice) {
        selectDevice(currentDevice);
    } else {
        document.getElementById('deviceChoice').style.display = 'flex';
    }
    
    // Загружаем последнюю секцию
    const lastSection = localStorage.getItem('mg_lastSection') || 'rules';
    showSection(lastSection, null);
    
    // Загружаем данные пользователя
    loadUserData();
    
    // Добавляем стили для анимаций
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        @keyframes slideOut {
            from { transform: translateX(0); opacity: 1; }
            to { transform: translateX(100%); opacity: 0; }
        }
        
        .notification {
            pointer-events: none;
        }
    `;
    document.head.appendChild(style);
});

// Закрытие модалок по клику вне
window.onclick = function(event) {
    const registerModal = document.getElementById('registerModal');
    const changeModal = document.getElementById('changePasswordModal');
    
    if (event.target === registerModal) closeModal();
    if (event.target === changeModal) closeChangePassword();
}
