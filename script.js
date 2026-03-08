// Данные
let users = JSON.parse(localStorage.getItem('users')) || [];
let complaints = JSON.parse(localStorage.getItem('complaints')) || [];
let applications = JSON.parse(localStorage.getItem('applications')) || [];
let currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;

// ВСЕ OWNER
const OWNERS = ['milfa', 'milk123', 'Xchik_'];

// Загрузка
document.addEventListener('DOMContentLoaded', function() {
    console.log('Страница загружена');
    updateAuth();
    loadLists();
    checkAdminLink();
    
    // Показываем правила по умолчанию
    showSection('rules');
});

// Копирование IP
function copyIP() {
    navigator.clipboard.writeText('Moongrief.aurorix.pro');
    alert('IP скопирован в буфер обмена!');
}

// Показать секцию (правила/жалобы/заявки)
function showSection(sectionId) {
    // Скрываем все секции
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active-section');
    });
    
    // Показываем нужную секцию
    document.getElementById(sectionId).classList.add('active-section');
    
    // Обновляем активный класс в навигации
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    event.target.classList.add('active');
}

// Авторизация
function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    if (!username || !password) {
        alert('Введите ник и пароль!');
        return;
    }
    
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
        currentUserSpan.textContent = '👤 ' + currentUser.username;
    } else {
        userInfo.style.display = 'none';
        loginForm.style.display = 'flex';
    }
}

// Регистрация
function showRegister() {
    document.getElementById('registerModal').style.display = 'block';
}

function closeModal() {
    document.getElementById('registerModal').style.display = 'none';
}

function register(event) {
    event.preventDefault();
    
    const username = document.getElementById('regUsername').value;
    const password = document.getElementById('regPassword').value;
    const confirm = document.getElementById('regConfirmPassword').value;
    
    if (!username || !password) {
        alert('Заполните все поля!');
        return;
    }
    
    if (password !== confirm) {
        alert('Пароли не совпадают!');
        return;
    }
    
    if (users.find(u => u.username === username)) {
        alert('Пользователь уже существует!');
        return;
    }
    
    users.push({
        username: username,
        password: password
    });
    
    localStorage.setItem('users', JSON.stringify(users));
    alert('Регистрация успешна! Теперь можно войти.');
    closeModal();
}

// Проверка доступа к админке (теперь все OWNER)
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

// Отправка жалобы
document.getElementById('complaintForm')?.addEventListener('submit', function(e) {
    e.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите в систему!');
        return;
    }
    
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
    
    complaints.push(complaint);
    localStorage.setItem('complaints', JSON.stringify(complaints));
    
    alert('Жалоба отправлена!');
    this.reset();
    loadLists();
});

// Отправка анкеты
document.getElementById('helperForm')?.addEventListener('submit', function(e) {
    e.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите в систему!');
        return;
    }
    
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
    
    applications.push(application);
    localStorage.setItem('applications', JSON.stringify(applications));
    
    alert('Анкета отправлена!');
    this.reset();
    loadLists();
});

// Загрузка списков
function loadLists() {
    loadComplaints();
    loadApplications();
}

function loadComplaints() {
    const list = document.getElementById('complaintsList');
    if (!list) return;
    
    complaints = JSON.parse(localStorage.getItem('complaints')) || [];
    
    if (complaints.length === 0) {
        list.innerHTML = '<p style="color: #666; text-align: center;">Пока нет жалоб</p>';
        return;
    }
    
    list.innerHTML = '';
    complaints.sort((a, b) => new Date(b.date) - new Date(a.date)).forEach(c => {
        list.innerHTML += `
            <div class="request-card">
                <div class="request-header">
                    <span>${c.title}</span>
                    <span class="request-status status-${c.status}">${getStatus(c.status)}</span>
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
}

function loadApplications() {
    const list = document.getElementById('applicationsList');
    if (!list) return;
    
    applications = JSON.parse(localStorage.getItem('applications')) || [];
    
    if (applications.length === 0) {
        list.innerHTML = '<p style="color: #666; text-align: center;">Пока нет заявок</p>';
        return;
    }
    
    list.innerHTML = '';
    applications.sort((a, b) => new Date(b.date) - new Date(a.date)).forEach(a => {
        list.innerHTML += `
            <div class="request-card">
                <div class="request-header">
                    <span>Анкета от ${a.author}</span>
                    <span class="request-status status-${a.status}">${getStatus(a.status)}</span>
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
}

function getStatus(status) {
    const statuses = {
        'new': '🆕 Новая',
        'pending': '⏳ В обработке',
        'resolved': '✅ Решена'
    };
    return statuses[status] || status;
}
