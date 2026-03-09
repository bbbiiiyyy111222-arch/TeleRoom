// ==============================================
// ОСНОВНОЙ СКРИПТ BLADEBOX - ПОЛНАЯ ВЕРСИЯ
// ==============================================

// Данные
let users = [];
let complaints = [];
let applications = [];
let mediaApplications = [];
let currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;

// ВСЕ OWNER
const OWNERS = ['milfa', 'milk123', 'Xchik_'];

// ==============================================
// ФУНКЦИЯ ДЛЯ ОТОБРАЖЕНИЯ ВРЕМЕНИ
// ==============================================

function formatDate(dateString) {
    const date = new Date(dateString);
    
    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const year = date.getFullYear();
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');
    
    return `${day}.${month}.${year}, ${hours}:${minutes}:${seconds}`;
}

// ==============================================
// ПЕРЕКЛЮЧЕНИЕ ПЛАТФОРМ (TT/YT)
// ==============================================

function switchPlatform(platform) {
    // Скрываем все формы
    document.getElementById('ttForm').classList.remove('active');
    document.getElementById('ytForm').classList.remove('active');
    
    // Убираем активный класс у кнопок
    document.getElementById('switchTT').classList.remove('active');
    document.getElementById('switchYT').classList.remove('active');
    
    // Показываем выбранную форму
    if (platform === 'tt') {
        document.getElementById('ttForm').classList.add('active');
        document.getElementById('switchTT').classList.add('active');
    } else {
        document.getElementById('ytForm').classList.add('active');
        document.getElementById('switchYT').classList.add('active');
    }
}

// ==============================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ СТАТУСОВ
// ==============================================

function getStatusText(status) {
    const statuses = {
        'new': '🆕 Новая',
        'accepted': '✅ Принята',
        'rejected': '❌ Отклонена',
        'resolved': '📝 Отвечено'
    };
    return statuses[status] || '🆕 Новая';
}

function getStatusClass(status) {
    const classes = {
        'new': 'status-new',
        'accepted': 'status-accepted',
        'rejected': 'status-rejected',
        'resolved': 'status-resolved'
    };
    return classes[status] || 'status-new';
}

// ==============================================
// ЗАГРУЗКА ПРИ СТАРТЕ
// ==============================================

document.addEventListener('DOMContentLoaded', async function() {
    console.log('Страница загружена');
    
    try {
        await loadDataFromDB();
        updateAuth();
        await loadLists();
        checkAdminLink();
        showDefaultSection();
    } catch (error) {
        console.error('Ошибка при загрузке:', error);
    }
});

// Показать правила по умолчанию
function showDefaultSection() {
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active-section');
    });
    document.getElementById('rules').classList.add('active-section');
    
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    const rulesLink = document.querySelector('[href="#rules"]');
    if (rulesLink) rulesLink.classList.add('active');
}

// Показать секцию
function showSection(sectionId, event) {
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active-section');
    });
    
    document.getElementById(sectionId).classList.add('active-section');
    
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    
    if (event && event.target) {
        event.target.classList.add('active');
    } else {
        const link = document.querySelector(`[href="#${sectionId}"]`);
        if (link) link.classList.add('active');
    }
}

// Загрузка данных из базы
async function loadDataFromDB() {
    try {
        users = await window.getUsers() || [];
        complaints = await window.getComplaints() || [];
        applications = await window.getApplications() || [];
        mediaApplications = await window.getMediaApplications() || [];
        
        console.log('Загружено из базы:', { users, complaints, applications, mediaApplications });
    } catch (error) {
        console.error('Ошибка загрузки из БД:', error);
        users = [];
        complaints = [];
        applications = [];
        mediaApplications = [];
    }
}

// Копирование IP
function copyIP() {
    navigator.clipboard.writeText('bladebox.aurorix.pro');
    alert('IP скопирован в буфер обмена!');
}

// ==============================================
// АВТОРИЗАЦИЯ
// ==============================================

async function login() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    
    if (!username || !password) {
        alert('Введите ник и пароль!');
        return;
    }
    
    try {
        users = await window.getUsers();
        const user = users.find(u => u.username === username && u.password === password);
        
        if (user) {
            currentUser = user;
            localStorage.setItem('currentUser', JSON.stringify(currentUser));
            updateAuth();
            checkAdminLink();
            alert('Добро пожаловать, ' + username + '!');
        } else {
            alert('Неверный ник или пароль!');
        }
    } catch (error) {
        console.error('Ошибка авторизации:', error);
        alert('Ошибка при авторизации');
    }
}

function logout() {
    currentUser = null;
    localStorage.removeItem('currentUser');
    updateAuth();
    checkAdminLink();
    if (window.location.pathname.includes('admin.html')) {
        window.location.href = 'index.html';
    }
}

function updateAuth() {
    const userInfo = document.getElementById('userInfo');
    const loginForm = document.getElementById('loginForm');
    const currentUserSpan = document.getElementById('currentUser');
    
    if (currentUser) {
        userInfo.style.display = 'flex';
        loginForm.style.display = 'none';
        
        if (OWNERS.includes(currentUser.username)) {
            currentUserSpan.textContent = '👑 ' + currentUser.username + ' (OWNER)';
        } else {
            currentUserSpan.textContent = '👤 ' + currentUser.username;
        }
    } else {
        userInfo.style.display = 'none';
        loginForm.style.display = 'flex';
    }
}

// ==============================================
// РЕГИСТРАЦИЯ
// ==============================================

function showRegister() {
    document.getElementById('registerModal').style.display = 'block';
}

function closeModal() {
    document.getElementById('registerModal').style.display = 'none';
    document.getElementById('regUsername').value = '';
    document.getElementById('regPassword').value = '';
    document.getElementById('regConfirmPassword').value = '';
}

async function register(event) {
    event.preventDefault();
    
    const username = document.getElementById('regUsername').value.trim();
    const password = document.getElementById('regPassword').value.trim();
    const confirm = document.getElementById('regConfirmPassword').value.trim();
    
    if (!username || !password) {
        alert('Заполните все поля!');
        return;
    }
    
    if (password !== confirm) {
        alert('Пароли не совпадают!');
        return;
    }
    
    if (password.length < 3) {
        alert('Пароль должен быть минимум 3 символа');
        return;
    }
    
    try {
        users = await window.getUsers();
        const existingUser = users.find(u => u.username === username);
        
        if (existingUser) {
            if (OWNERS.includes(username)) {
                const updated = await window.updateUserPassword(username, password);
                if (updated) {
                    currentUser = { username, password };
                    localStorage.setItem('currentUser', JSON.stringify(currentUser));
                    alert('Пароль установлен! Добро пожаловать, ' + username + '!');
                    closeModal();
                    updateAuth();
                    checkAdminLink();
                } else {
                    alert('Ошибка при установке пароля!');
                }
            } else {
                alert('Пользователь уже существует!');
            }
            return;
        }
        
        const saved = await window.saveUser(username, password);
        
        if (saved) {
            currentUser = { username, password };
            localStorage.setItem('currentUser', JSON.stringify(currentUser));
            
            alert('Регистрация успешна! Добро пожаловать, ' + username + '!');
            closeModal();
            updateAuth();
            checkAdminLink();
        } else {
            alert('Ошибка при регистрации!');
        }
    } catch (error) {
        console.error('Ошибка регистрации:', error);
        alert('Ошибка при регистрации');
    }
}

// ==============================================
// СМЕНА ПАРОЛЯ
// ==============================================

function showChangePassword() {
    if (!currentUser) {
        alert('Сначала войдите в систему!');
        return;
    }
    document.getElementById('changePasswordModal').style.display = 'block';
}

function closeChangePassword() {
    document.getElementById('changePasswordModal').style.display = 'none';
    document.getElementById('oldPassword').value = '';
    document.getElementById('newPassword').value = '';
    document.getElementById('confirmPassword').value = '';
}

async function changePassword(event) {
    event.preventDefault();
    
    const oldPass = document.getElementById('oldPassword').value;
    const newPass = document.getElementById('newPassword').value;
    const confirm = document.getElementById('confirmPassword').value;
    
    if (!currentUser) {
        alert('❌ Ошибка авторизации');
        return;
    }
    
    if (!oldPass || !newPass || !confirm) {
        alert('❌ Заполните все поля!');
        return;
    }
    
    if (newPass !== confirm) {
        alert('❌ Новые пароли не совпадают!');
        return;
    }
    
    if (newPass.length < 3) {
        alert('❌ Пароль должен быть минимум 3 символа');
        return;
    }
    
    try {
        const result = await window.changePassword(currentUser.username, oldPass, newPass);
        
        if (result && result.success) {
            currentUser.password = newPass;
            localStorage.setItem('currentUser', JSON.stringify(currentUser));
            
            alert('✅ Пароль успешно изменен!');
            closeChangePassword();
        } else {
            alert('❌ ' + (result?.message || 'Ошибка при смене пароля'));
        }
    } catch (error) {
        console.error('Ошибка смены пароля:', error);
        alert('❌ Ошибка при смене пароля');
    }
}

// Проверка доступа к админке
function checkAdminLink() {
    const link = document.getElementById('adminLink');
    if (link) {
        if (currentUser && OWNERS.includes(currentUser.username)) {
            link.style.display = 'inline-block';
        } else {
            link.style.display = 'none';
        }
    }
}

// ==============================================
// ОТПРАВКА ЖАЛОБ
// ==============================================

async function submitComplaint(event) {
    event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите в систему!');
        return;
    }
    
    try {
        const complaint = {
            id: Date.now(),
            title: document.getElementById('complaintTitle').value,
            against: document.getElementById('complaintAgainst').value,
            description: document.getElementById('complaintDesc').value,
            author: currentUser.username,
            date: new Date().toISOString(),
            status: 'new',
            response: null
        };
        
        const saved = await window.saveComplaint(complaint);
        
        if (saved) {
            alert('✅ Жалоба отправлена!');
            document.getElementById('complaintForm').reset();
            await loadLists();
        } else {
            alert('❌ Ошибка при отправке жалобы!');
        }
    } catch (error) {
        console.error('Ошибка:', error);
        alert('❌ Ошибка при отправке жалобы');
    }
}

// ==============================================
// ОТПРАВКА МЕДИА-ЗАЯВОК (TIKTOK)
// ==============================================

async function submitTTMedia(event) {
    event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите в систему!');
        return;
    }
    
    try {
        const mediaApp = {
            id: Date.now(),
            platform: 'tiktok',
            age: document.getElementById('ttAge').value,
            name: document.getElementById('ttName').value,
            nickname: document.getElementById('ttNickname').value,
            subscribers: document.getElementById('ttSubs').value,
            views: document.getElementById('ttViews').value,
            link: document.getElementById('ttLink').value,
            author: currentUser.username,
            date: new Date().toISOString(),
            status: 'new',
            response: null
        };
        
        const saved = await window.saveMediaApplication(mediaApp);
        
        if (saved) {
            alert('✅ Заявка на TikTok отправлена!');
            document.getElementById('ttMediaForm').reset();
            await loadLists();
        } else {
            alert('❌ Ошибка при отправке заявки!');
        }
    } catch (error) {
        console.error('Ошибка:', error);
        alert('❌ Ошибка при отправке заявки');
    }
}

// ==============================================
// ОТПРАВКА МЕДИА-ЗАЯВОК (YOUTUBE)
// ==============================================

async function submitYTMedia(event) {
    event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите в систему!');
        return;
    }
    
    try {
        const mediaApp = {
            id: Date.now(),
            platform: 'youtube',
            age: document.getElementById('ytAge').value,
            name: document.getElementById('ytName').value,
            nickname: document.getElementById('ytNickname').value,
            subscribers: document.getElementById('ytSubs').value,
            views: document.getElementById('ytViews').value,
            link: document.getElementById('ytLink').value,
            author: currentUser.username,
            date: new Date().toISOString(),
            status: 'new',
            response: null
        };
        
        const saved = await window.saveMediaApplication(mediaApp);
        
        if (saved) {
            alert('✅ Заявка на YouTube отправлена!');
            document.getElementById('ytMediaForm').reset();
            await loadLists();
        } else {
            alert('❌ Ошибка при отправке заявки!');
        }
    } catch (error) {
        console.error('Ошибка:', error);
        alert('❌ Ошибка при отправке заявки');
    }
}

// ==============================================
// ОТПРАВКА АНКЕТ НА ХЕЛПЕРА
// ==============================================

async function submitApplication(event) {
    event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите в систему!');
        return;
    }
    
    try {
        const application = {
            id: Date.now(),
            nickname: document.getElementById('helperNickname').value,
            name: document.getElementById('helperName').value,
            age: document.getElementById('helperAge').value,
            timezone: document.getElementById('helperTimezone').value,
            experience: document.getElementById('helperExperience').value,
            reason: document.getElementById('helperReason').value,
            additional: document.getElementById('helperAdditional').value || 'Не указано',
            author: currentUser.username,
            date: new Date().toISOString(),
            status: 'new',
            response: null
        };
        
        const saved = await window.saveApplication(application);
        
        if (saved) {
            alert('✅ Анкета отправлена!');
            document.getElementById('helperForm').reset();
            await loadLists();
        } else {
            alert('❌ Ошибка при отправке анкеты!');
        }
    } catch (error) {
        console.error('Ошибка:', error);
        alert('❌ Ошибка при отправке анкеты');
    }
}

// ==============================================
// ЗАГРУЗКА ЖАЛОБ
// ==============================================

async function loadComplaints() {
    const list = document.getElementById('complaintsList');
    if (!list) return;
    
    try {
        complaints = await window.getComplaints() || [];
        
        if (complaints.length === 0) {
            list.innerHTML = '<div class="empty-state">⚔️ <h3>Нет жалоб</h3><p>Пока никто не подавал жалоб</p></div>';
            return;
        }
        
        let html = '';
        complaints.sort((a, b) => new Date(b.date) - new Date(a.date)).forEach(c => {
            const formattedDate = formatDate(c.date);
            
            html += `
                <div class="complaint-card" onclick="openComplaintDetails(${c.id})">
                    <div class="complaint-header">
                        <span class="complaint-title">${c.title || 'Жалоба'}</span>
                        <span class="complaint-status ${getStatusClass(c.status)}">${getStatusText(c.status)}</span>
                    </div>
                    <div class="complaint-body">
                        <p><strong>👤 От:</strong> ${c.author}</p>
                        <p><strong>🎯 На:</strong> ${c.against}</p>
                        <p><strong>📝 Описание:</strong> ${c.description.substring(0, 50)}${c.description.length > 50 ? '...' : ''}</p>
                        <p><strong>📅 Дата:</strong> ${formattedDate}</p>
                        ${c.response ? `<p><strong>💬 Ответ:</strong> ${c.response.substring(0, 30)}${c.response.length > 30 ? '...' : ''}</p>` : ''}
                    </div>
                </div>
            `;
        });
        
        list.innerHTML = html;
    } catch (error) {
        console.error('Ошибка загрузки жалоб:', error);
        list.innerHTML = '<div class="error-state">❌ Ошибка загрузки</div>';
    }
}

// ==============================================
// ЗАГРУЗКА МЕДИА-ЗАЯВОК
// ==============================================

async function loadMediaApplications() {
    const list = document.getElementById('mediaList');
    if (!list) return;
    
    try {
        mediaApplications = await window.getMediaApplications() || [];
        
        if (mediaApplications.length === 0) {
            list.innerHTML = '<div class="empty-state">📱 <h3>Нет заявок на медию</h3><p>Пока никто не подавал заявки</p></div>';
            return;
        }
        
        let html = '';
        mediaApplications.sort((a, b) => new Date(b.date) - new Date(a.date)).forEach(m => {
            const formattedDate = formatDate(m.date);
            const platformIcon = m.platform === 'tiktok' ? '📱' : '▶️';
            const platformName = m.platform === 'tiktok' ? 'TikTok' : 'YouTube';
            
            html += `
                <div class="media-card" onclick="openMediaDetails(${m.id})">
                    <div class="media-header">
                        <span class="media-title">${platformIcon} ${platformName} | ${m.nickname}</span>
                        <span class="media-status ${getStatusClass(m.status)}">${getStatusText(m.status)}</span>
                    </div>
                    <div class="media-body">
                        <p><strong>👤 Имя:</strong> ${m.name}</p>
                        <p><strong>📅 Возраст:</strong> ${m.age}</p>
                        <p><strong>📊 Подписчики:</strong> ${m.subscribers}</p>
                        <p><strong>📅 Дата:</strong> ${formattedDate}</p>
                        ${m.response ? `<p><strong>💬 Ответ:</strong> ${m.response.substring(0, 30)}${m.response.length > 30 ? '...' : ''}</p>` : ''}
                    </div>
                </div>
            `;
        });
        
        list.innerHTML = html;
    } catch (error) {
        console.error('Ошибка загрузки медиа-заявок:', error);
        list.innerHTML = '<div class="error-state">❌ Ошибка загрузки</div>';
    }
}

// ==============================================
// ЗАГРУЗКА АНКЕТ НА ХЕЛПЕРА
// ==============================================

async function loadApplications() {
    const list = document.getElementById('applicationsList');
    if (!list) return;
    
    try {
        applications = await window.getApplications() || [];
        
        if (applications.length === 0) {
            list.innerHTML = '<div class="empty-state">👮 <h3>Нет анкет</h3><p>Пока никто не подавал заявки</p></div>';
            return;
        }
        
        let html = '';
        applications.sort((a, b) => new Date(b.date) - new Date(a.date)).forEach(a => {
            const formattedDate = formatDate(a.date);
            
            html += `
                <div class="application-card" onclick="openApplicationDetails(${a.id})">
                    <div class="application-header">
                        <span class="application-title">👮 Анкета от ${a.author}</span>
                        <span class="application-status ${getStatusClass(a.status)}">${getStatusText(a.status)}</span>
                    </div>
                    <div class="application-body">
                        <p><strong>🎮 Ник:</strong> ${a.nickname}</p>
                        <p><strong>👤 Имя:</strong> ${a.name}</p>
                        <p><strong>📅 Дата:</strong> ${formattedDate}</p>
                        ${a.response ? `<p><strong>💬 Ответ:</strong> ${a.response.substring(0, 30)}${a.response.length > 30 ? '...' : ''}</p>` : ''}
                    </div>
                </div>
            `;
        });
        
        list.innerHTML = html;
    } catch (error) {
        console.error('Ошибка загрузки анкет:', error);
        list.innerHTML = '<div class="error-state">❌ Ошибка загрузки</div>';
    }
}

// ==============================================
// ЗАГРУЗКА ВСЕХ СПИСКОВ
// ==============================================

async function loadLists() {
    await loadComplaints();
    await loadMediaApplications();
    await loadApplications();
}

// ==============================================
// ДЕТАЛЬНЫЙ ПРОСМОТР
// ==============================================

function openComplaintDetails(id) {
    const complaint = complaints.find(c => c.id === id);
    if (!complaint) return;
    
    const formattedDate = formatDate(complaint.date);
    
    let message = `📋 ЖАЛОБА\n\n`;
    message += `👤 От: ${complaint.author}\n`;
    message += `🎯 На: ${complaint.against}\n`;
    message += `📝 Описание: ${complaint.description}\n`;
    message += `📅 Дата: ${formattedDate}\n`;
    message += `📊 Статус: ${getStatusText(complaint.status)}\n`;
    
    if (complaint.response) {
        message += `\n💬 Ответ: ${complaint.response}`;
    }
    
    alert(message);
}

function openMediaDetails(id) {
    const media = mediaApplications.find(m => m.id === id);
    if (!media) return;
    
    const formattedDate = formatDate(media.date);
    const platformName = media.platform === 'tiktok' ? 'TikTok' : 'YouTube';
    const platformIcon = media.platform === 'tiktok' ? '📱' : '▶️';
    
    let message = `${platformIcon} ЗАЯВКА НА ${platformName}\n\n`;
    message += `👤 Имя: ${media.name}\n`;
    message += `📅 Возраст: ${media.age}\n`;
    message += `🎮 Никнейм: ${media.nickname}\n`;
    message += `📊 Подписчики: ${media.subscribers}\n`;
    message += `👀 Просмотры: ${media.views}\n`;
    message += `🔗 Ссылка: ${media.link}\n`;
    message += `👤 От: ${media.author}\n`;
    message += `📅 Дата: ${formattedDate}\n`;
    message += `📊 Статус: ${getStatusText(media.status)}\n`;
    
    if (media.response) {
        message += `\n💬 Ответ: ${media.response}`;
    }
    
    alert(message);
}

function openApplicationDetails(id) {
    const application = applications.find(a => a.id === id);
    if (!application) return;
    
    const formattedDate = formatDate(application.date);
    
    let message = `👮 АНКЕТА НА ХЕЛПЕРА\n\n`;
    message += `🎮 Ник: ${application.nickname}\n`;
    message += `👤 Имя: ${application.name}\n`;
    message += `📅 Возраст: ${application.age}\n`;
    message += `🌍 Часовой пояс: ${application.timezone}\n`;
    message += `💼 Опыт: ${application.experience}\n`;
    message += `❓ Мотивация: ${application.reason}\n`;
    
    if (application.additional) {
        message += `📝 Дополнительно: ${application.additional}\n`;
    }
    
    message += `👤 От: ${application.author}\n`;
    message += `📅 Дата: ${formattedDate}\n`;
    message += `📊 Статус: ${getStatusText(application.status)}\n`;
    
    if (application.response) {
        message += `\n💬 Ответ: ${application.response}`;
    }
    
    alert(message);
}
