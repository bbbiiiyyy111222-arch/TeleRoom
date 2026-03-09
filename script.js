// ==============================================
// MOONGRIEF-FORUM - ПОЛНЫЙ СКРИПТ
// ==============================================

// ==================== ДАННЫЕ ====================
let users = JSON.parse(localStorage.getItem('mg_users')) || [];
let complaints = JSON.parse(localStorage.getItem('mg_complaints')) || [];
let media = JSON.parse(localStorage.getItem('mg_media')) || [];
let helpers = JSON.parse(localStorage.getItem('mg_helpers')) || [];

let currentUser = JSON.parse(localStorage.getItem('mg_currentUser')) || null;
let currentDevice = localStorage.getItem('mg_device') || null;

// Админы
const admins = ['milfa', 'milk123', 'Xchik_'];

// ==================== ВЫБОР УСТРОЙСТВА ====================
function selectDevice(device) {
    console.log('Выбрано устройство:', device);
    
    localStorage.setItem('mg_device', device);
    currentDevice = device;
    
    const deviceChoice = document.getElementById('deviceChoice');
    const mainSite = document.getElementById('mainSite');
    const deviceSwitch = document.getElementById('deviceSwitch');
    
    if (deviceChoice) deviceChoice.style.display = 'none';
    if (mainSite) mainSite.style.display = 'block';
    
    if (device === 'mobile') {
        document.body.classList.add('mobile-view');
        if (deviceSwitch) deviceSwitch.style.display = 'block';
    } else {
        document.body.classList.remove('mobile-view');
        if (deviceSwitch) deviceSwitch.style.display = 'none';
    }
    
    loadUserData();
}

function showDeviceChoice() {
    const deviceChoice = document.getElementById('deviceChoice');
    const mainSite = document.getElementById('mainSite');
    
    if (mainSite) mainSite.style.display = 'none';
    if (deviceChoice) deviceChoice.style.display = 'flex';
}

// ==================== IP ====================
function copyIP() {
    navigator.clipboard.writeText('Moongrief.aurorix.pro').then(() => {
        alert('📋 IP скопирован!');
    }).catch(() => {
        alert('❌ Ошибка копирования');
    });
}

// ==================== НАВИГАЦИЯ ====================
function showSection(sectionId, event) {
    if (event) event.preventDefault();
    
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active-section'));
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    
    const section = document.getElementById(sectionId);
    if (section) section.classList.add('active-section');
    
    if (event && event.target) event.target.classList.add('active');
    
    if (currentUser) {
        localStorage.setItem('mg_lastSection', sectionId);
    }
}

// ==================== ПЕРЕКЛЮЧЕНИЕ ПЛАТФОРМ ====================
function switchPlatform(platform) {
    const ttForm = document.getElementById('ttForm');
    const ytForm = document.getElementById('ytForm');
    const ttBtn = document.getElementById('switchTT');
    const ytBtn = document.getElementById('switchYT');
    
    if (ttForm) ttForm.classList.remove('active');
    if (ytForm) ytForm.classList.remove('active');
    if (ttBtn) ttBtn.classList.remove('active');
    if (ytBtn) ytBtn.classList.remove('active');
    
    if (platform === 'tt') {
        if (ttForm) ttForm.classList.add('active');
        if (ttBtn) ttBtn.classList.add('active');
    } else {
        if (ytForm) ytForm.classList.add('active');
        if (ytBtn) ytBtn.classList.add('active');
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
    const helpersList = document.getElementById('applicationsList');
    
    if (currentUser) {
        if (loginForm) loginForm.style.display = 'none';
        if (userInfo) userInfo.style.display = 'flex';
        if (currentUserSpan) currentUserSpan.textContent = currentUser.username;
        
        if (adminLink && admins.includes(currentUser.username)) {
            adminLink.style.display = 'inline-block';
        }
        
        loadPersonalComplaints();
        loadPersonalMedia();
        loadPersonalHelpers();
    } else {
        if (loginForm) loginForm.style.display = 'flex';
        if (userInfo) userInfo.style.display = 'none';
        if (adminLink) adminLink.style.display = 'none';
        
        if (complaintsList) complaintsList.innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои жалобы</div>';
        if (mediaList) mediaList.innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои заявки</div>';
        if (helpersList) helpersList.innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои анкеты</div>';
    }
}

// ==================== ЛИЧНЫЕ СПИСКИ ====================
function loadPersonalComplaints() {
    const list = document.getElementById('complaintsList');
    if (!list) return;
    
    if (!currentUser) {
        list.innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои жалобы</div>';
        return;
    }
    
    const userComplaints = complaints.filter(c => c.user === currentUser.username);
    
    if (userComplaints.length === 0) {
        list.innerHTML = '<div class="empty-list">📭 У вас пока нет жалоб</div>';
        return;
    }
    
    let html = '';
    userComplaints.forEach(c => {
        html += `
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
        `;
    });
    
    list.innerHTML = html;
}

function loadPersonalMedia() {
    const list = document.getElementById('mediaList');
    if (!list) return;
    
    if (!currentUser) {
        list.innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои заявки</div>';
        return;
    }
    
    const userMedia = media.filter(m => m.user === currentUser.username);
    
    if (userMedia.length === 0) {
        list.innerHTML = '<div class="empty-list">📭 У вас пока нет медиа-заявок</div>';
        return;
    }
    
    let html = '';
    userMedia.forEach(m => {
        const platformIcon = m.type === 'tt' ? '📱' : '▶️';
        const platformName = m.type === 'tt' ? 'TikTok' : 'YouTube';
        
        html += `
            <div class="media-card">
                <div class="media-header">
                    <span class="media-title">${platformIcon} ${platformName}</span>
                    <span class="media-status status-${m.status}">${getStatusText(m.status)}</span>
                </div>
                <div class="media-body">
                    <p><strong>Ник:</strong> ${m.nick}</p>
                    <p><strong>Подписчики:</strong> ${m.subs}</p>
                    <p><strong>Дата:</strong> ${m.date}</p>
                </div>
            </div>
        `;
    });
    
    list.innerHTML = html;
}

function loadPersonalHelpers() {
    const list = document.getElementById('applicationsList');
    if (!list) return;
    
    if (!currentUser) {
        list.innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои анкеты</div>';
        return;
    }
    
    const userHelpers = helpers.filter(h => h.user === currentUser.username);
    
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
                    <span class="application-status status-${h.status}">${getStatusText(h.status)}</span>
                </div>
                <div class="application-body">
                    <p><strong>Ник:</strong> ${h.nick}</p>
                    <p><strong>Возраст:</strong> ${h.age}</p>
                    <p><strong>Дата:</strong> ${h.date}</p>
                </div>
            </div>
        `;
    });
    
    list.innerHTML = html;
}

function getStatusText(status) {
    switch(status) {
        case 'new': return 'НОВАЯ';
        case 'accepted': return 'ПРИНЯТО';
        case 'rejected': return 'ОТКЛОНЕНО';
        default: return status;
    }
}

// ==================== АВТОРИЗАЦИЯ ====================
function login() {
    const usernameInput = document.getElementById('username');
    const passwordInput = document.getElementById('password');
    
    if (!usernameInput || !passwordInput) return;
    
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    
    if (!username || !password) {
        alert('Введите ник и пароль');
        return;
    }
    
    const user = users.find(u => u.username === username && u.password === password);
    
    if (user) {
        currentUser = user;
        localStorage.setItem('mg_currentUser', JSON.stringify(user));
        
        const loginForm = document.getElementById('loginForm');
        const userInfo = document.getElementById('userInfo');
        const currentUserSpan = document.getElementById('currentUser');
        const adminLink = document.getElementById('adminLink');
        
        if (loginForm) loginForm.style.display = 'none';
        if (userInfo) userInfo.style.display = 'flex';
        if (currentUserSpan) currentUserSpan.textContent = username;
        
        if (adminLink && admins.includes(username)) {
            adminLink.style.display = 'inline-block';
        }
        
        alert(`Добро пожаловать, ${username}!`);
        
        usernameInput.value = '';
        passwordInput.value = '';
        
        loadPersonalComplaints();
        loadPersonalMedia();
        loadPersonalHelpers();
    } else {
        alert('Неверный ник или пароль');
    }
}

function register() {
    const usernameInput = document.getElementById('regUsername');
    const passwordInput = document.getElementById('regPassword');
    const confirmInput = document.getElementById('regConfirmPassword');
    
    if (!usernameInput || !passwordInput || !confirmInput) return;
    
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    const confirm = confirmInput.value;
    
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
    localStorage.setItem('mg_users', JSON.stringify(users));
    
    alert('Регистрация успешна! Теперь войдите.');
    closeModal();
}

function logout() {
    currentUser = null;
    localStorage.removeItem('mg_currentUser');
    
    const loginForm = document.getElementById('loginForm');
    const userInfo = document.getElementById('userInfo');
    const adminLink = document.getElementById('adminLink');
    const complaintsList = document.getElementById('complaintsList');
    const mediaList = document.getElementById('mediaList');
    const helpersList = document.getElementById('applicationsList');
    
    if (loginForm) loginForm.style.display = 'flex';
    if (userInfo) userInfo.style.display = 'none';
    if (adminLink) adminLink.style.display = 'none';
    
    if (complaintsList) complaintsList.innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои жалобы</div>';
    if (mediaList) mediaList.innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои заявки</div>';
    if (helpersList) helpersList.innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои анкеты</div>';
    
    alert('Вы вышли из аккаунта');
}

function showChangePassword() {
    if (!currentUser) {
        alert('Сначала войдите');
        return;
    }
    const modal = document.getElementById('changePasswordModal');
    if (modal) modal.style.display = 'flex';
}

function changePassword() {
    const oldPassInput = document.getElementById('oldPassword');
    const newPassInput = document.getElementById('newPassword');
    const confirmInput = document.getElementById('confirmPassword');
    
    if (!oldPassInput || !newPassInput || !confirmInput) return;
    
    const oldPass = oldPassInput.value;
    const newPass = newPassInput.value;
    const confirm = confirmInput.value;
    
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
    
    localStorage.setItem('mg_users', JSON.stringify(users));
    localStorage.setItem('mg_currentUser', JSON.stringify(currentUser));
    
    alert('Пароль изменен!');
    closeChangePassword();
}

// ==================== ОТПРАВКА ФОРМ ====================
function submitComplaint(event) {
    if (event) event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите');
        return;
    }
    
    const titleInput = document.getElementById('complaintTitle');
    const targetInput = document.getElementById('complaintAgainst');
    const descInput = document.getElementById('complaintDesc');
    
    if (!titleInput || !targetInput || !descInput) return;
    
    const title = titleInput.value.trim();
    const target = targetInput.value.trim();
    const desc = descInput.value.trim();
    
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
        status: 'new',
        date: new Date().toLocaleString()
    };
    
    complaints.push(newComplaint);
    localStorage.setItem('mg_complaints', JSON.stringify(complaints));
    
    alert('Жалоба отправлена!');
    
    titleInput.value = '';
    targetInput.value = '';
    descInput.value = '';
    
    loadPersonalComplaints();
}

function submitTTMedia(event) {
    if (event) event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите');
        return;
    }
    
    const ageInput = document.getElementById('ttAge');
    const nameInput = document.getElementById('ttName');
    const nickInput = document.getElementById('ttNickname');
    const subsInput = document.getElementById('ttSubs');
    const viewsInput = document.getElementById('ttViews');
    const linkInput = document.getElementById('ttLink');
    
    if (!ageInput || !nameInput || !nickInput || !subsInput || !viewsInput || !linkInput) return;
    
    const age = ageInput.value;
    const name = nameInput.value.trim();
    const nick = nickInput.value.trim();
    const subs = subsInput.value.trim();
    const views = viewsInput.value.trim();
    const link = linkInput.value.trim();
    
    if (!age || !name || !nick || !subs || !views || !link) {
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
        views: views,
        link: link,
        status: 'new',
        date: new Date().toLocaleString()
    };
    
    media.push(newMedia);
    localStorage.setItem('mg_media', JSON.stringify(media));
    
    alert('Заявка на TikTok отправлена!');
    
    ageInput.value = '';
    nameInput.value = '';
    nickInput.value = '';
    subsInput.value = '';
    viewsInput.value = '';
    linkInput.value = '';
    
    loadPersonalMedia();
}

function submitYTMedia(event) {
    if (event) event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите');
        return;
    }
    
    const ageInput = document.getElementById('ytAge');
    const nameInput = document.getElementById('ytName');
    const nickInput = document.getElementById('ytNickname');
    const subsInput = document.getElementById('ytSubs');
    const viewsInput = document.getElementById('ytViews');
    const linkInput = document.getElementById('ytLink');
    
    if (!ageInput || !nameInput || !nickInput || !subsInput || !viewsInput || !linkInput) return;
    
    const age = ageInput.value;
    const name = nameInput.value.trim();
    const nick = nickInput.value.trim();
    const subs = subsInput.value.trim();
    const views = viewsInput.value.trim();
    const link = linkInput.value.trim();
    
    if (!age || !name || !nick || !subs || !views || !link) {
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
        views: views,
        link: link,
        status: 'new',
        date: new Date().toLocaleString()
    };
    
    media.push(newMedia);
    localStorage.setItem('mg_media', JSON.stringify(media));
    
    alert('Заявка на YouTube отправлена!');
    
    ageInput.value = '';
    nameInput.value = '';
    nickInput.value = '';
    subsInput.value = '';
    viewsInput.value = '';
    linkInput.value = '';
    
    loadPersonalMedia();
}

function submitApplication(event) {
    if (event) event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите');
        return;
    }
    
    const nickInput = document.getElementById('helperNickname');
    const nameInput = document.getElementById('helperName');
    const ageInput = document.getElementById('helperAge');
    const tzInput = document.getElementById('helperTimezone');
    const expInput = document.getElementById('helperExperience');
    const reasonInput = document.getElementById('helperReason');
    const additionalInput = document.getElementById('helperAdditional');
    
    if (!nickInput || !nameInput || !ageInput || !tzInput || !expInput || !reasonInput) return;
    
    const nick = nickInput.value.trim();
    const name = nameInput.value.trim();
    const age = ageInput.value;
    const tz = tzInput.value;
    const exp = expInput.value.trim();
    const reason = reasonInput.value.trim();
    const additional = additionalInput ? additionalInput.value.trim() : '';
    
    if (!nick || !name || !age || !tz || !exp || !reason) {
        alert('Заполните обязательные поля');
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
    localStorage.setItem('mg_helpers', JSON.stringify(helpers));
    
    alert('Анкета отправлена!');
    
    nickInput.value = '';
    nameInput.value = '';
    ageInput.value = '';
    tzInput.value = '';
    expInput.value = '';
    reasonInput.value = '';
    if (additionalInput) additionalInput.value = '';
    
    loadPersonalHelpers();
}

// ==================== МОДАЛКИ ====================
function showRegister() {
    const modal = document.getElementById('registerModal');
    if (modal) modal.style.display = 'flex';
}

function closeModal() {
    const modal = document.getElementById('registerModal');
    if (modal) modal.style.display = 'none';
}

function closeChangePassword() {
    const modal = document.getElementById('changePasswordModal');
    if (modal) modal.style.display = 'none';
}

// ==================== ИНИЦИАЛИЗАЦИЯ ====================
document.addEventListener('DOMContentLoaded', function() {
    console.log('MoonGrief-Forum загружен');
    
    const savedDevice = localStorage.getItem('mg_device');
    const deviceChoice = document.getElementById('deviceChoice');
    const mainSite = document.getElementById('mainSite');
    
    if (savedDevice && deviceChoice && mainSite) {
        deviceChoice.style.display = 'none';
        mainSite.style.display = 'block';
        
        if (savedDevice === 'mobile') {
            document.body.classList.add('mobile-view');
            const deviceSwitch = document.getElementById('deviceSwitch');
            if (deviceSwitch) deviceSwitch.style.display = 'block';
        }
        
        currentDevice = savedDevice;
        loadUserData();
    } else {
        if (deviceChoice) deviceChoice.style.display = 'flex';
        if (mainSite) mainSite.style.display = 'none';
    }
    
    // Загружаем последнюю секцию
    const lastSection = localStorage.getItem('mg_lastSection') || 'rules';
    const section = document.getElementById(lastSection);
    if (section) {
        document.querySelectorAll('.section').forEach(s => s.classList.remove('active-section'));
        section.classList.add('active-section');
        
        const activeLink = document.querySelector(`.nav-link[href="#${lastSection}"]`);
        if (activeLink) {
            document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
            activeLink.classList.add('active');
        }
    }
});

// Закрытие модалок по клику вне
window.onclick = function(event) {
    if (event.target.classList.contains('modal')) {
        event.target.style.display = 'none';
    }
};
