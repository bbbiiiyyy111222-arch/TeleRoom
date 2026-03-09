// ==============================================
// ОСНОВНОЙ СКРИПТ BLADEBOX - РАБОЧАЯ ВЕРСИЯ
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
// ПЕРЕКЛЮЧЕНИЕ ПЛАТФОРМ (TT/YT)
// ==============================================

function switchPlatform(platform) {
    const ttForm = document.getElementById('ttForm');
    const ytForm = document.getElementById('ytForm');
    const switchTT = document.getElementById('switchTT');
    const switchYT = document.getElementById('switchYT');
    
    if (!ttForm || !ytForm || !switchTT || !switchYT) return;
    
    ttForm.classList.remove('active');
    ytForm.classList.remove('active');
    switchTT.classList.remove('active');
    switchYT.classList.remove('active');
    
    if (platform === 'tt') {
        ttForm.classList.add('active');
        switchTT.classList.add('active');
    } else {
        ytForm.classList.add('active');
        switchYT.classList.add('active');
    }
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
    const sections = document.querySelectorAll('.section');
    const rulesLink = document.querySelector('[href="#rules"]');
    
    sections.forEach(section => {
        section.classList.remove('active-section');
    });
    
    const rulesSection = document.getElementById('rules');
    if (rulesSection) rulesSection.classList.add('active-section');
    
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    
    if (rulesLink) rulesLink.classList.add('active');
}

// Показать секцию - ИСПРАВЛЕНО!
window.showSection = function(sectionId, event) {
    const sections = document.querySelectorAll('.section');
    const targetSection = document.getElementById(sectionId);
    
    sections.forEach(section => {
        section.classList.remove('active-section');
    });
    
    if (targetSection) targetSection.classList.add('active-section');
    
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    
    if (event && event.target) {
        event.target.classList.add('active');
    } else {
        const link = document.querySelector(`[href="#${sectionId}"]`);
        if (link) link.classList.add('active');
    }
};

// Загрузка данных из базы
async function loadDataFromDB() {
    try {
        if (typeof window.getUsers === 'function') {
            users = await window.getUsers() || [];
        }
        if (typeof window.getComplaints === 'function') {
            complaints = await window.getComplaints() || [];
        }
        if (typeof window.getApplications === 'function') {
            applications = await window.getApplications() || [];
        }
        if (typeof window.getMediaApplications === 'function') {
            mediaApplications = await window.getMediaApplications() || [];
        }
        
        console.log('Загружено из базы:', { users, complaints, applications, mediaApplications });
    } catch (error) {
        console.error('Ошибка загрузки из БД:', error);
    }
}

// Копирование IP
window.copyIP = function() {
    navigator.clipboard.writeText('bladebox.aurorix.pro');
    alert('IP скопирован в буфер обмена!');
};

// ==============================================
// АВТОРИЗАЦИЯ
// ==============================================

window.login = async function() {
    const username = document.getElementById('username')?.value.trim();
    const password = document.getElementById('password')?.value.trim();
    
    if (!username || !password) {
        alert('Введите ник и пароль!');
        return;
    }
    
    try {
        if (typeof window.getUsers === 'function') {
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
        }
    } catch (error) {
        console.error('Ошибка авторизации:', error);
        alert('Ошибка при авторизации');
    }
};

window.logout = function() {
    currentUser = null;
    localStorage.removeItem('currentUser');
    updateAuth();
    checkAdminLink();
    if (window.location.pathname.includes('admin.html')) {
        window.location.href = 'index.html';
    }
};

function updateAuth() {
    const userInfo = document.getElementById('userInfo');
    const loginForm = document.getElementById('loginForm');
    const currentUserSpan = document.getElementById('currentUser');
    
    if (!userInfo || !loginForm || !currentUserSpan) return;
    
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

window.showRegister = function() {
    const modal = document.getElementById('registerModal');
    if (modal) modal.style.display = 'block';
};

window.closeModal = function() {
    const modal = document.getElementById('registerModal');
    if (modal) modal.style.display = 'none';
    
    const regUsername = document.getElementById('regUsername');
    const regPassword = document.getElementById('regPassword');
    const regConfirm = document.getElementById('regConfirmPassword');
    
    if (regUsername) regUsername.value = '';
    if (regPassword) regPassword.value = '';
    if (regConfirm) regConfirm.value = '';
};

window.register = async function(event) {
    event.preventDefault();
    
    const username = document.getElementById('regUsername')?.value.trim();
    const password = document.getElementById('regPassword')?.value.trim();
    const confirm = document.getElementById('regConfirmPassword')?.value.trim();
    
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
        if (typeof window.getUsers === 'function') {
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
            
            if (typeof window.saveUser === 'function') {
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
            }
        }
    } catch (error) {
        console.error('Ошибка регистрации:', error);
        alert('Ошибка при регистрации');
    }
};

// ==============================================
// СМЕНА ПАРОЛЯ
// ==============================================

window.showChangePassword = function() {
    if (!currentUser) {
        alert('Сначала войдите в систему!');
        return;
    }
    const modal = document.getElementById('changePasswordModal');
    if (modal) modal.style.display = 'block';
};

window.closeChangePassword = function() {
    const modal = document.getElementById('changePasswordModal');
    if (modal) modal.style.display = 'none';
    
    const oldPass = document.getElementById('oldPassword');
    const newPass = document.getElementById('newPassword');
    const confirm = document.getElementById('confirmPassword');
    
    if (oldPass) oldPass.value = '';
    if (newPass) newPass.value = '';
    if (confirm) confirm.value = '';
};

window.changePassword = async function(event) {
    event.preventDefault();
    
    const oldPass = document.getElementById('oldPassword')?.value;
    const newPass = document.getElementById('newPassword')?.value;
    const confirm = document.getElementById('confirmPassword')?.value;
    
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
        if (typeof window.changePassword === 'function') {
            const result = await window.changePassword(currentUser.username, oldPass, newPass);
            
            if (result && result.success) {
                currentUser.password = newPass;
                localStorage.setItem('currentUser', JSON.stringify(currentUser));
                
                alert('✅ Пароль успешно изменен!');
                closeChangePassword();
            } else {
                alert('❌ ' + (result?.message || 'Ошибка при смене пароля'));
            }
        }
    } catch (error) {
        console.error('Ошибка смены пароля:', error);
        alert('❌ Ошибка при смене пароля');
    }
};

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

window.submitComplaint = async function(event) {
    event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите в систему!');
        return;
    }
    
    const title = document.getElementById('complaintTitle')?.value;
    const against = document.getElementById('complaintAgainst')?.value;
    const desc = document.getElementById('complaintDesc')?.value;
    
    if (!title || !against || !desc) {
        alert('Заполните все поля!');
        return;
    }
    
    try {
        const complaint = {
            id: Date.now(),
            title: title,
            against: against,
            description: desc,
            author: currentUser.username,
            date: new Date().toISOString(),
            status: 'new',
            response: null
        };
        
        if (typeof window.saveComplaint === 'function') {
            const saved = await window.saveComplaint(complaint);
            
            if (saved) {
                alert('✅ Жалоба отправлена!');
                document.getElementById('complaintForm')?.reset();
                await loadLists();
            } else {
                alert('❌ Ошибка при отправке жалобы!');
            }
        }
    } catch (error) {
        console.error('Ошибка:', error);
        alert('❌ Ошибка при отправке жалобы');
    }
};

// ==============================================
// ОТПРАВКА МЕДИА-ЗАЯВОК (TIKTOK)
// ==============================================

window.submitTTMedia = async function(event) {
    event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите в систему!');
        return;
    }
    
    const age = document.getElementById('ttAge')?.value;
    const name = document.getElementById('ttName')?.value;
    const nickname = document.getElementById('ttNickname')?.value;
    const subs = document.getElementById('ttSubs')?.value;
    const views = document.getElementById('ttViews')?.value;
    const link = document.getElementById('ttLink')?.value;
    
    if (!age || !name || !nickname || !subs || !views || !link) {
        alert('Заполните все поля!');
        return;
    }
    
    try {
        const mediaApp = {
            id: Date.now(),
            platform: 'tiktok',
            age: age,
            name: name,
            nickname: nickname,
            subscribers: subs,
            views: views,
            link: link,
            author: currentUser.username,
            date: new Date().toISOString(),
            status: 'new',
            response: null
        };
        
        if (typeof window.saveMediaApplication === 'function') {
            const saved = await window.saveMediaApplication(mediaApp);
            
            if (saved) {
                alert('✅ Заявка на TikTok отправлена!');
                document.getElementById('ttMediaForm')?.reset();
                await loadLists();
            } else {
                alert('❌ Ошибка при отправке заявки!');
            }
        }
    } catch (error) {
        console.error('Ошибка:', error);
        alert('❌ Ошибка при отправке заявки');
    }
};

// ==============================================
// ОТПРАВКА МЕДИА-ЗАЯВОК (YOUTUBE)
// ==============================================

window.submitYTMedia = async function(event) {
    event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите в систему!');
        return;
    }
    
    const age = document.getElementById('ytAge')?.value;
    const name = document.getElementById('ytName')?.value;
    const nickname = document.getElementById('ytNickname')?.value;
    const subs = document.getElementById('ytSubs')?.value;
    const views = document.getElementById('ytViews')?.value;
    const link = document.getElementById('ytLink')?.value;
    
    if (!age || !name || !nickname || !subs || !views || !link) {
        alert('Заполните все поля!');
        return;
    }
    
    try {
        const mediaApp = {
            id: Date.now(),
            platform: 'youtube',
            age: age,
            name: name,
            nickname: nickname,
            subscribers: subs,
            views: views,
            link: link,
            author: currentUser.username,
            date: new Date().toISOString(),
            status: 'new',
            response: null
        };
        
        if (typeof window.saveMediaApplication === 'function') {
            const saved = await window.saveMediaApplication(mediaApp);
            
            if (saved) {
                alert('✅ Заявка на YouTube отправлена!');
                document.getElementById('ytMediaForm')?.reset();
                await loadLists();
            } else {
                alert('❌ Ошибка при отправке заявки!');
            }
        }
    } catch (error) {
        console.error('Ошибка:', error);
        alert('❌ Ошибка при отправке заявки');
    }
};

// ==============================================
// ОТПРАВКА АНКЕТ НА ХЕЛПЕРА
// ==============================================

window.submitApplication = async function(event) {
    event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите в систему!');
        return;
    }
    
    const nickname = document.getElementById('helperNickname')?.value;
    const name = document.getElementById('helperName')?.value;
    const age = document.getElementById('helperAge')?.value;
    const timezone = document.getElementById('helperTimezone')?.value;
    const experience = document.getElementById('helperExperience')?.value;
    const reason = document.getElementById('helperReason')?.value;
    const additional = document.getElementById('helperAdditional')?.value || 'Не указано';
    
    if (!nickname || !name || !age || !timezone || !experience || !reason) {
        alert('Заполните все поля!');
        return;
    }
    
    try {
        const application = {
            id: Date.now(),
            nickname: nickname,
            name: name,
            age: age,
            timezone: timezone,
            experience: experience,
            reason: reason,
            additional: additional,
            author: currentUser.username,
            date: new Date().toISOString(),
            status: 'new',
            response: null
        };
        
        if (typeof window.saveApplication === 'function') {
            const saved = await window.saveApplication(application);
            
            if (saved) {
                alert('✅ Анкета отправлена!');
                document.getElementById('helperForm')?.reset();
                await loadLists();
            } else {
                alert('❌ Ошибка при отправке анкеты!');
            }
        }
    } catch (error) {
        console.error('Ошибка:', error);
        alert('❌ Ошибка при отправке анкеты');
    }
};

// ==============================================
// ЗАГРУЗКА ЖАЛОБ
// ==============================================

async function loadComplaints() {
    const list = document.getElementById('complaintsList');
    if (!list) return;
    
    try {
        if (typeof window.getComplaints === 'function') {
            complaints = await window.getComplaints() || [];
        }
        
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
        if (typeof window.getMediaApplications === 'function') {
            mediaApplications = await window.getMediaApplications() || [];
        }
        
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
        if (typeof window.getApplications === 'function') {
            applications = await window.getApplications() || [];
        }
        
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

window.openComplaintDetails = function(id) {
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
};

window.openMediaDetails = function(id) {
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
};

window.openApplicationDetails = function(id) {
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
};
