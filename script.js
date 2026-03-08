// ==============================================
// ОСНОВНОЙ СКРИПТ MOONGRIEF
// ==============================================

// Данные
let users = [];
let complaints = [];
let applications = [];
let currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;

// ВСЕ OWNER
const OWNERS = ['milfa', 'milk123', 'Xchik_'];

// Загрузка
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
        
        console.log('Загружено из базы:', { users, complaints, applications });
    } catch (error) {
        console.error('Ошибка загрузки из БД:', error);
        users = [];
        complaints = [];
        applications = [];
    }
}

// Копирование IP
function copyIP() {
    navigator.clipboard.writeText('Moongrief.aurorix.pro');
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
// СМЕНА ПАРОЛЯ (НОВАЯ ФУНКЦИЯ)
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
            // Обновляем текущего пользователя с новым паролем
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
// ОТПРАВКА АНКЕТ
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
// ЗАГРУЗКА СПИСКОВ
// ==============================================

async function loadLists() {
    await loadComplaints();
    await loadApplications();
}

async function loadComplaints() {
    const list = document.getElementById('complaintsList');
    if (!list) return;
    
    try {
        complaints = await window.getComplaints() || [];
        
        if (complaints.length === 0) {
            list.innerHTML = '<p style="color: #666; text-align: center;">📭 Пока нет жалоб</p>';
            return;
        }
        
        list.innerHTML = '';
        complaints.forEach(c => {
            let statusText = {
                'new': '🆕 Новая',
                'accepted': '✅ Принята',
                'rejected': '❌ Отклонена',
                'resolved': '📝 Отвечено'
            }[c.status] || '🆕 Новая';
            
            list.innerHTML += `
                <div class="request-card">
                    <div class="request-header">
                        <span>${c.title}</span>
                        <span class="request-status status-${c.status}">${statusText}</span>
                    </div>
                    <div class="request-details">
                        <p><strong>От:</strong> ${c.author}</p>
                        <p><strong>На:</strong> ${c.against}</p>
                        <p><strong>Описание:</strong> ${c.description}</p>
                        <p><small>${new Date(c.date).toLocaleString()}</small></p>
                    </div>
                    ${c.response ? `<p><strong>Ответ:</strong> ${c.response}</p>` : ''}
                </div>
            `;
        });
    } catch (error) {
        console.error('Ошибка загрузки жалоб:', error);
        list.innerHTML = '<p style="color: red; text-align: center;">❌ Ошибка загрузки жалоб</p>';
    }
}

async function loadApplications() {
    const list = document.getElementById('applicationsList');
    if (!list) return;
    
    try {
        applications = await window.getApplications() || [];
        
        if (applications.length === 0) {
            list.innerHTML = '<p style="color: #666; text-align: center;">📭 Пока нет заявок</p>';
            return;
        }
        
        list.innerHTML = '';
        applications.forEach(a => {
            let statusText = {
                'new': '🆕 Новая',
                'accepted': '✅ Принята',
                'rejected': '❌ Отклонена',
                'resolved': '📝 Отвечено'
            }[a.status] || '🆕 Новая';
            
            list.innerHTML += `
                <div class="request-card">
                    <div class="request-header">
                        <span>Анкета от ${a.author}</span>
                        <span class="request-status status-${a.status}">${statusText}</span>
                    </div>
                    <div class="request-details">
                        <p><strong>Ник:</strong> ${a.nickname}</p>
                        <p><strong>Имя:</strong> ${a.name}</p>
                        <p><strong>Возраст:</strong> ${a.age}</p>
                        <p><strong>Часовой пояс:</strong> ${a.timezone}</p>
                        <p><strong>Опыт:</strong> ${a.experience}</p>
                        <p><strong>Мотивация:</strong> ${a.reason}</p>
                        <p><small>${new Date(a.date).toLocaleString()}</small></p>
                    </div>
                    ${a.response ? `<p><strong>Ответ:</strong> ${a.response}</p>` : ''}
                </div>
            `;
        });
    } catch (error) {
        console.error('Ошибка загрузки заявок:', error);
        list.innerHTML = '<p style="color: red; text-align: center;">❌ Ошибка загрузки заявок</p>';
    }
}

function getStatus(status) {
    const statuses = {
        'new': '🆕 Новая',
        'accepted': '✅ Принята',
        'rejected': '❌ Отклонена',
        'resolved': '📝 Отвечено'
    };
    return statuses[status] || '🆕 Новая';
}
// ==============================================
// КРАСИВОЕ ОТОБРАЖЕНИЕ ЖАЛОБ И ЗАЯВОК
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

// Переопределяем функцию загрузки жалоб
async function loadComplaints() {
    const list = document.getElementById('complaintsList');
    if (!list) return;
    
    try {
        complaints = await window.getComplaints() || [];
        
        if (complaints.length === 0) {
            list.innerHTML = '<div class="empty-state">🌙 <h3>Нет жалоб</h3></div>';
            return;
        }
        
        let html = '';
        complaints.sort((a, b) => new Date(b.date) - new Date(a.date)).forEach(c => {
            html += `
                <div class="complaint-card">
                    <div class="complaint-header">
                        <span class="complaint-title">${c.title || 'Жалоба'}</span>
                        <span class="complaint-status ${getStatusClass(c.status)}">${getStatusText(c.status)}</span>
                    </div>
                    <div class="complaint-body">
                        <p><strong>👤 От:</strong> ${c.author}</p>
                        <p><strong>🎯 На:</strong> ${c.against}</p>
                        <p><strong>📝 Описание:</strong> ${c.description}</p>
                        <p><strong>📅 Дата:</strong> ${new Date(c.date).toLocaleString()}</p>
                        ${c.response ? `<p><strong>💬 Ответ:</strong> ${c.response}</p>` : ''}
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

// Переопределяем функцию загрузки заявок
async function loadApplications() {
    const list = document.getElementById('applicationsList');
    if (!list) return;
    
    try {
        applications = await window.getApplications() || [];
        
        if (applications.length === 0) {
            list.innerHTML = '<div class="empty-state">🌙 <h3>Нет заявок</h3></div>';
            return;
        }
        
        let html = '';
        applications.sort((a, b) => new Date(b.date) - new Date(a.date)).forEach(a => {
            html += `
                <div class="application-card">
                    <div class="application-header">
                        <span class="application-title">👮 Анкета от ${a.author}</span>
                        <span class="application-status ${getStatusClass(a.status)}">${getStatusText(a.status)}</span>
                    </div>
                    <div class="application-body">
                        <p><strong>🎮 Ник:</strong> ${a.nickname}</p>
                        <p><strong>👤 Имя:</strong> ${a.name}</p>
                        <p><strong>📅 Возраст:</strong> ${a.age}</p>
                        <p><strong>🌍 Часовой пояс:</strong> ${a.timezone}</p>
                        <p><strong>💼 Опыт:</strong> ${a.experience}</p>
                        <p><strong>❓ Мотивация:</strong> ${a.reason}</p>
                        ${a.additional ? `<p><strong>📝 Дополнительно:</strong> ${a.additional}</p>` : ''}
                        <p><strong>📅 Дата:</strong> ${new Date(a.date).toLocaleString()}</p>
                        ${a.response ? `<p><strong>💬 Ответ:</strong> ${a.response}</p>` : ''}
                    </div>
                </div>
            `;
        });
        
        list.innerHTML = html;
    } catch (error) {
        console.error('Ошибка загрузки заявок:', error);
        list.innerHTML = '<div class="error-state">❌ Ошибка загрузки</div>';
    }
}
