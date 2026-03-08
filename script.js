// Данные
let users = JSON.parse(localStorage.getItem('users')) || [];
let complaints = JSON.parse(localStorage.getItem('complaints')) || [];
let applications = JSON.parse(localStorage.getItem('applications')) || [];
let currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;

// ВСЕ OWNER (вшиты в код)
const OWNERS = ['milfa', 'milk123', 'Xchik_'];

// Загрузка - сразу добавляем владельцев в систему
document.addEventListener('DOMContentLoaded', function() {
    console.log('Страница загружена');
    
    // Добавляем владельцев в систему, если их нет
    addOwnersToSystem();
    
    // Добавляем тестовые данные для демонстрации
    addTestData();
    
    updateAuth();
    loadLists();
    checkAdminLink();
    
    // Показываем правила по умолчанию
    showSection('rules');
});

// Функция добавления владельцев в систему
function addOwnersToSystem() {
    // Загружаем пользователей
    users = JSON.parse(localStorage.getItem('users')) || [];
    let added = false;
    
    // Для каждого владельца проверяем, есть ли он в системе
    OWNERS.forEach(owner => {
        const exists = users.find(u => u.username === owner);
        if (!exists) {
            // Если владельца нет, добавляем его с паролем по умолчанию
            users.push({
                username: owner,
                password: owner + '123' // пароль: ник + 123 (например milfa123)
            });
            added = true;
        }
    });
    
    if (added) {
        localStorage.setItem('users', JSON.stringify(users));
        console.log('Владельцы добавлены в систему');
    }
}

// Функция добавления тестовых данных
function addTestData() {
    // Загружаем текущие данные
    complaints = JSON.parse(localStorage.getItem('complaints')) || [];
    applications = JSON.parse(localStorage.getItem('applications')) || [];
    
    // Если нет ни одной жалобы, добавляем тестовую
    if (complaints.length === 0) {
        const testComplaint = {
            id: Date.now() - 1000000,
            title: "Тестовая жалоба",
            against: "TestPlayer",
            description: "Это тестовая жалоба для проверки работы админ панели",
            author: "milfa",
            date: new Date().toISOString(),
            status: 'new',
            response: null
        };
        complaints.push(testComplaint);
        localStorage.setItem('complaints', JSON.stringify(complaints));
        console.log('Добавлена тестовая жалоба');
    }
    
    // Если нет ни одной заявки, добавляем тестовую
    if (applications.length === 0) {
        const testApplication = {
            id: Date.now() - 500000,
            nickname: "TestPlayer",
            name: "Тест Тестович",
            age: "16",
            timezone: "UTC+3",
            experience: "Был хелпером на другом сервере",
            reason: "Хочу помогать игрокам",
            additional: "Есть микрофон, могу играть каждый день",
            author: "milk123",
            date: new Date().toISOString(),
            status: 'new',
            response: null
        };
        applications.push(testApplication);
        localStorage.setItem('applications', JSON.stringify(applications));
        console.log('Добавлена тестовая заявка');
    }
}

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
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    
    if (!username || !password) {
        alert('Введите ник и пароль!');
        return;
    }
    
    // Обновляем users из localStorage
    users = JSON.parse(localStorage.getItem('users')) || [];
    
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
        
        // Проверяем, является ли пользователь OWNER
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

// Регистрация
function showRegister() {
    document.getElementById('registerModal').style.display = 'block';
}

function closeModal() {
    document.getElementById('registerModal').style.display = 'none';
}

function register(event) {
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
    
    // Обновляем users из localStorage
    users = JSON.parse(localStorage.getItem('users')) || [];
    
    if (users.find(u => u.username === username)) {
        alert('Пользователь уже существует!');
        return;
    }
    
    // Добавляем нового пользователя
    const newUser = {
        username: username,
        password: password
    };
    
    users.push(newUser);
    localStorage.setItem('users', JSON.stringify(users));
    
    // Сразу входим после регистрации
    currentUser = newUser;
    localStorage.setItem('currentUser', JSON.stringify(currentUser));
    
    alert('Регистрация успешна! Добро пожаловать, ' + username + '!');
    closeModal();
    updateAuth();
    checkAdminLink();
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
function submitComplaint(event) {
    event.preventDefault();
    
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
    
    // Загружаем текущие жалобы
    complaints = JSON.parse(localStorage.getItem('complaints')) || [];
    
    // Добавляем новую жалобу
    complaints.push(complaint);
    
    // Сохраняем
    localStorage.setItem('complaints', JSON.stringify(complaints));
    
    console.log('Жалоба отправлена:', complaint);
    console.log('Все жалобы:', complaints);
    
    alert('Жалоба отправлена!');
    document.getElementById('complaintForm').reset();
    loadLists();
}

// Отправка анкеты
function submitApplication(event) {
    event.preventDefault();
    
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
    
    // Загружаем текущие заявки
    applications = JSON.parse(localStorage.getItem('applications')) || [];
    
    // Добавляем новую заявку
    applications.push(application);
    
    // Сохраняем
    localStorage.setItem('applications', JSON.stringify(applications));
    
    console.log('Анкета отправлена:', application);
    console.log('Все анкеты:', applications);
    
    alert('Анкета отправлена!');
    document.getElementById('helperForm').reset();
    loadLists();
}

// Загрузка списков
function loadLists() {
    loadComplaints();
    loadApplications();
}

function loadComplaints() {
    const list = document.getElementById('complaintsList');
    if (!list) return;
    
    complaints = JSON.parse(localStorage.getItem('complaints')) || [];
    console.log('Загрузка жалоб:', complaints);
    
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
    console.log('Загрузка анкет:', applications);
    
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
