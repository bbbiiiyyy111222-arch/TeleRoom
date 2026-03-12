// ==============================================
// MOONGRIEF-FORUM - ОСНОВНОЙ СКРИПТ (ИСПРАВЛЕННЫЙ)
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
    }).catch(() => {
        alert('❌ Ошибка копирования');
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
    if (event && event.target) {
        event.target.classList.add('active');
        event.target.style.background = '#4a4a8a';
        event.target.style.color = 'white';
    }
};

window.switchPlatform = function(platform) {
    const ttForm = document.getElementById('ttForm');
    const ytForm = document.getElementById('ytForm');
    const tabs = document.querySelectorAll('.tab');
    
    if (ttForm) ttForm.classList.remove('active');
    if (ytForm) ytForm.classList.remove('active');
    tabs.forEach(t => t.classList.remove('active'));
    
    if (platform === 'tt') {
        if (ttForm) ttForm.classList.add('active');
        if (tabs[0]) tabs[0].classList.add('active');
    } else {
        if (ytForm) ytForm.classList.add('active');
        if (tabs[1]) tabs[1].classList.add('active');
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
    
    // Проверка по списку пользователей (без базы)
    const users = {
        'milfa': { password: 'abaregen', role: 'owner' },
        'milk123': { password: 'curatormilk122', role: 'owner' },
        'Xchik_': { password: 'Danil2012qw', role: 'owner' },
        'milfchka_Ezka': { password: 'abaregen', role: 'user' },
        'KevinOdindyn': { password: '876kop', role: 'user' }
    };
    
    if (users[username] && users[username].password === password) {
        currentUser = {
            username: username,
            role: users[username].role
        };
        
        localStorage.setItem('mg_currentUser', JSON.stringify(currentUser));
        
        document.getElementById('loginForm').style.display = 'none';
        document.getElementById('userInfo').style.display = 'flex';
        document.getElementById('currentUser').textContent = username;
        
        if (users[username].role === 'owner') {
            document.getElementById('adminLink').style.display = 'inline-block';
            // Показываем блок проблем для админов
            const adminProblemBlock = document.getElementById('adminProblemBlock');
            if (adminProblemBlock) adminProblemBlock.style.display = 'block';
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
};

window.logout = function() {
    currentUser = null;
    localStorage.removeItem('mg_currentUser');
    
    document.getElementById('loginForm').style.display = 'flex';
    document.getElementById('userInfo').style.display = 'none';
    document.getElementById('adminLink').style.display = 'none';
    
    // Скрываем блок проблем для админов
    const adminProblemBlock = document.getElementById('adminProblemBlock');
    if (adminProblemBlock) adminProblemBlock.style.display = 'none';
    
    document.getElementById('complaintsList').innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои жалобы</div>';
    document.getElementById('mediaList').innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои анкеты</div>';
    document.getElementById('applicationsList').innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои анкеты</div>';
};

// ==============================================
// ЗАГРУЗКА ЛИЧНЫХ ЗАЯВОК
// ==============================================

function loadPersonalComplaints() {
    const list = document.getElementById('complaintsList');
    if (!list) return;
    
    if (!currentUser) {
        list.innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои жалобы</div>';
        return;
    }
    
    // Загружаем из localStorage
    const complaints = JSON.parse(localStorage.getItem('mg_complaints')) || [];
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
                    <span class="complaint-title">${c.title || 'Жалоба'}</span>
                    <span class="complaint-status status-new">${c.status || 'НОВАЯ'}</span>
                </div>
                <div class="complaint-body">
                    <p><strong>Нарушитель:</strong> ${c.target || 'Не указан'}</p>
                    <p><strong>Описание:</strong> ${c.desc || 'Нет описания'}</p>
                    <p><strong>Дата:</strong> ${c.date || new Date().toLocaleString()}</p>
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
        list.innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои анкеты</div>';
        return;
    }
    
    // Загружаем из localStorage
    const media = JSON.parse(localStorage.getItem('mg_media')) || [];
    const userMedia = media.filter(m => m.user === currentUser.username);
    
    if (userMedia.length === 0) {
        list.innerHTML = '<div class="empty-list">📭 У вас пока нет медиа-заявок</div>';
        return;
    }
    
    let html = '';
    userMedia.forEach(m => {
        html += `
            <div class="media-card">
                <div class="media-header">
                    <span class="media-title">${m.type === 'tt' ? '📱 TikTok' : '▶️ YouTube'}</span>
                    <span class="media-status status-new">${m.status || 'НОВАЯ'}</span>
                </div>
                <div class="media-body">
                    <p><strong>Ник:</strong> ${m.nick || 'Не указан'}</p>
                    <p><strong>Подписчики:</strong> ${m.subs || '0'}</p>
                    <p><strong>Дата:</strong> ${m.date || new Date().toLocaleString()}</p>
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
    
    // Загружаем из localStorage
    const helpers = JSON.parse(localStorage.getItem('mg_helpers')) || [];
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
                    <span class="application-status status-new">${h.status || 'НОВАЯ'}</span>
                </div>
                <div class="application-body">
                    <p><strong>Ник:</strong> ${h.nick || 'Не указан'}</p>
                    <p><strong>Дата:</strong> ${h.date || new Date().toLocaleString()}</p>
                </div>
            </div>
        `;
    });
    
    list.innerHTML = html;
}

// ==============================================
// ОТПРАВКА ФОРМ (СОХРАНЕНИЕ В localStorage)
// ==============================================

window.submitComplaint = function(event) {
    if (event) event.preventDefault();
    
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
    
    const complaints = JSON.parse(localStorage.getItem('mg_complaints')) || [];
    
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
    localStorage.setItem('mg_complaints', JSON.stringify(complaints));
    
    alert('✅ Жалоба отправлена!');
    document.getElementById('compTitle').value = '';
    document.getElementById('compTarget').value = '';
    document.getElementById('compDesc').value = '';
    loadPersonalComplaints();
};

window.submitTT = function(event) {
    if (event) event.preventDefault();
    
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
    
    const media = JSON.parse(localStorage.getItem('mg_media')) || [];
    
    const newMedia = {
        id: Date.now(),
        user: currentUser.username,
        type: 'tt',
        age: age,
        name: name,
        nick: nick,
        subs: subs,
        link: link,
        status: 'НОВАЯ',
        date: new Date().toLocaleString()
    };
    
    media.push(newMedia);
    localStorage.setItem('mg_media', JSON.stringify(media));
    
    alert('✅ Заявка на TikTok отправлена!');
    document.getElementById('ttAge').value = '';
    document.getElementById('ttName').value = '';
    document.getElementById('ttNick').value = '';
    document.getElementById('ttSubs').value = '';
    document.getElementById('ttLink').value = '';
    loadPersonalMedia();
};

window.submitYT = function(event) {
    if (event) event.preventDefault();
    
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
    
    const media = JSON.parse(localStorage.getItem('mg_media')) || [];
    
    const newMedia = {
        id: Date.now(),
        user: currentUser.username,
        type: 'yt',
        age: age,
        name: name,
        nick: nick,
        subs: subs,
        link: link,
        status: 'НОВАЯ',
        date: new Date().toLocaleString()
    };
    
    media.push(newMedia);
    localStorage.setItem('mg_media', JSON.stringify(media));
    
    alert('✅ Заявка на YouTube отправлена!');
    document.getElementById('ytAge').value = '';
    document.getElementById('ytName').value = '';
    document.getElementById('ytNick').value = '';
    document.getElementById('ytSubs').value = '';
    document.getElementById('ytLink').value = '';
    loadPersonalMedia();
};

window.submitHelper = function(event) {
    if (event) event.preventDefault();
    
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
    
    const helpers = JSON.parse(localStorage.getItem('mg_helpers')) || [];
    
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
    localStorage.setItem('mg_helpers', JSON.stringify(helpers));
    
    alert('✅ Анкета отправлена!');
    document.getElementById('helpNick').value = '';
    document.getElementById('helpName').value = '';
    document.getElementById('helpAge').value = '';
    document.getElementById('helpTz').value = '';
    document.getElementById('helpExp').value = '';
    document.getElementById('helpWhy').value = '';
    loadPersonalHelpers();
};

// ==============================================
// ФУНКЦИЯ ДЛЯ ПРОБЛЕМ (ТОЛЬКО ДЛЯ АДМИНОВ)
// ==============================================

window.addProblem = function(event) {
    event.preventDefault();
    
    if (!currentUser || currentUser.role !== 'owner') {
        alert('❌ Только администратор может добавлять проблемы');
        return;
    }
    
    const title = document.getElementById('problemTitle')?.value;
    const desc = document.getElementById('problemDesc')?.value;
    const solution = document.getElementById('problemSolution')?.value;
    
    if (!title || !desc || !solution) {
        alert('Заполните все поля');
        return;
    }
    
    // Здесь можно сохранять проблемы в localStorage
    alert('✅ Проблема добавлена!');
    document.getElementById('problemForm').reset();
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

window.register = function() {
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
        
        if (currentUser.role === 'owner') {
            document.getElementById('adminLink').style.display = 'inline-block';
            // Показываем блок проблем для админов
            const adminProblemBlock = document.getElementById('adminProblemBlock');
            if (adminProblemBlock) adminProblemBlock.style.display = 'block';
        }
        
        loadPersonalComplaints();
        loadPersonalMedia();
        loadPersonalHelpers();
    }
}

document.addEventListener('DOMContentLoaded', function() {
    console.log('🌙 MoonGrief-Forum запущен');
    
    const savedDevice = localStorage.getItem('mg_device');
    if (savedDevice) {
        document.getElementById('deviceChoice').style.display = 'none';
        document.getElementById('mainSite').style.display = 'block';
        if (savedDevice === 'mobile') {
            document.body.classList.add('mobile-view');
            document.getElementById('deviceSwitch').style.display = 'block';
        }
        loadUserData();
    }
});

// ==============================================
// ФУНКЦИИ ДЛЯ РАБОТЫ С ФОТО
// ==============================================

let currentPhotoData = null;

window.handlePhotoSelect = function(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    // Проверка размера (макс 5MB)
    if (file.size > 5 * 1024 * 1024) {
        alert('❌ Файл слишком большой! Максимум 5MB');
        return;
    }
    
    // Проверка типа
    if (!file.type.startsWith('image/')) {
        alert('❌ Можно загружать только изображения');
        return;
    }
    
    const reader = new FileReader();
    reader.onload = function(e) {
        currentPhotoData = e.target.result;
        
        const preview = document.getElementById('photoPreview');
        const previewImg = document.getElementById('previewImage');
        const photoName = document.getElementById('photoName');
        
        previewImg.src = e.target.result;
        preview.style.display = 'block';
        photoName.textContent = file.name;
    };
    reader.readAsDataURL(file);
};

window.removePhoto = function() {
    currentPhotoData = null;
    document.getElementById('photoPreview').style.display = 'none';
    document.getElementById('photoName').textContent = '';
    document.getElementById('problemPhoto').value = '';
};

window.addProblem = function(event) {
    event.preventDefault();
    
    if (!currentUser || currentUser.role !== 'owner') {
        alert('❌ Только администратор может добавлять проблемы');
        return;
    }
    
    const title = document.getElementById('problemTitle').value;
    const desc = document.getElementById('problemDesc').value;
    const solution = document.getElementById('problemSolution').value;
    
    if (!title || !desc || !solution) {
        alert('❌ Заполните все поля');
        return;
    }
    
    // Создаем объект проблемы
    const problem = {
        id: Date.now(),
        title: title,
        description: desc,
        solution: solution,
        photo: currentPhotoData,
        date: new Date().toLocaleString(),
        author: currentUser.username
    };
    
    // Сохраняем в localStorage
    const problems = JSON.parse(localStorage.getItem('mg_problems')) || [];
    problems.push(problem);
    localStorage.setItem('mg_problems', JSON.stringify(problems));
    
    alert('✅ Проблема добавлена' + (currentPhotoData ? ' с фото' : ''));
    
    // Очищаем форму
    document.getElementById('problemForm').reset();
    removePhoto();
    
    // Обновляем список
    loadProblems();
};

// Загрузка списка проблем
function loadProblems() {
    const list = document.getElementById('problemsList');
    if (!list) return;
    
    const problems = JSON.parse(localStorage.getItem('mg_problems')) || [];
    
    if (problems.length === 0) {
        list.innerHTML = '<div class="empty-list">📭 Список проблем пуст</div>';
        return;
    }
    
    let html = '';
    problems.reverse().forEach(p => {
        html += `
            <div class="problem-card">
                <div class="problem-header">
                    <span class="problem-title">⚠️ ${p.title}</span>
                    <span class="problem-date">${p.date}</span>
                </div>
                <div class="problem-body">
                    <p><strong>📝 Описание:</strong> ${p.description}</p>
                    <p><strong>✅ Решение:</strong> ${p.solution}</p>
                    ${p.photo ? `
                    <div class="problem-photo">
                        <img src="${p.photo}" alt="Фото проблемы">
                    </div>
                    ` : ''}
                    <p><small>👤 Добавил: ${p.author}</small></p>
                </div>
            </div>
        `;
    });
    
    list.innerHTML = html;
}

// Вызываем загрузку при открытии раздела
document.addEventListener('DOMContentLoaded', function() {
    // ... существующий код ...
    loadProblems();
});
