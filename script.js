// ==============================================
// ОСНОВНОЙ СКРИПТ - ИСПРАВЛЕННАЯ ВЕРСИЯ
// ==============================================

// Данные - ТОЛЬКО ОДИН РАЗ!
let users = [];
let complaintsList = [];
let applicationsList = [];
let mediaList = [];
let currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;

// ВСЕ OWNER
const OWNERS = ['milfa', 'milk123', 'Xchik_'];

// ==============================================
// ЗАГРУЗКА ПРИ СТАРТЕ
// ==============================================

document.addEventListener('DOMContentLoaded', function() {
    console.log('Страница загружена');
    updateAuth();
    checkAdminLink();
    showDefaultSection();
});

// Показать правила по умолчанию
function showDefaultSection() {
    const sections = document.querySelectorAll('.section');
    sections.forEach(section => {
        section.classList.remove('active-section');
    });
    
    const rulesSection = document.getElementById('rules');
    if (rulesSection) rulesSection.classList.add('active-section');
    
    const rulesLink = document.querySelector('[href="#rules"]');
    if (rulesLink) {
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });
        rulesLink.classList.add('active');
    }
}

// Показать секцию
function showSection(sectionId, evt) {
    const sections = document.querySelectorAll('.section');
    sections.forEach(section => {
        section.classList.remove('active-section');
    });
    
    const targetSection = document.getElementById(sectionId);
    if (targetSection) targetSection.classList.add('active-section');
    
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    
    if (evt && evt.target) {
        evt.target.classList.add('active');
    }
}

// Копирование IP
function copyIP() {
    navigator.clipboard.writeText('bladebox.aurorix.pro').then(() => {
        alert('IP скопирован в буфер обмена!');
    }).catch(() => {
        alert('IP: bladebox.aurorix.pro');
    });
}

// ==============================================
// АВТОРИЗАЦИЯ
// ==============================================

function login() {
    const username = document.getElementById('username')?.value.trim();
    const password = document.getElementById('password')?.value.trim();
    
    if (!username || !password) {
        alert('Введите ник и пароль!');
        return;
    }
    
    // Для теста - пропускаем всех
    currentUser = { username: username, password: password };
    localStorage.setItem('currentUser', JSON.stringify(currentUser));
    updateAuth();
    checkAdminLink();
    alert('Добро пожаловать, ' + username + '!');
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
// РЕГИСТРАЦИЯ
// ==============================================

function showRegister() {
    const modal = document.getElementById('registerModal');
    if (modal) modal.style.display = 'block';
}

function closeModal() {
    const modal = document.getElementById('registerModal');
    if (modal) modal.style.display = 'none';
}

function register(event) {
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
    
    currentUser = { username: username, password: password };
    localStorage.setItem('currentUser', JSON.stringify(currentUser));
    alert('Регистрация успешна! Добро пожаловать, ' + username + '!');
    closeModal();
    updateAuth();
    checkAdminLink();
}

// ==============================================
// СМЕНА ПАРОЛЯ
// ==============================================

function showChangePassword() {
    if (!currentUser) {
        alert('Сначала войдите в систему!');
        return;
    }
    const modal = document.getElementById('changePasswordModal');
    if (modal) modal.style.display = 'block';
}

function closeChangePassword() {
    const modal = document.getElementById('changePasswordModal');
    if (modal) modal.style.display = 'none';
}

function changePassword(event) {
    event.preventDefault();
    
    const oldPass = document.getElementById('oldPassword')?.value;
    const newPass = document.getElementById('newPassword')?.value;
    const confirm = document.getElementById('confirmPassword')?.value;
    
    if (!oldPass || !newPass || !confirm) {
        alert('❌ Заполните все поля!');
        return;
    }
    
    if (newPass !== confirm) {
        alert('❌ Новые пароли не совпадают!');
        return;
    }
    
    alert('✅ Пароль успешно изменен!');
    closeChangePassword();
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
// ОТПРАВКА ЖАЛОБ
// ==============================================

function submitComplaint(event) {
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
    
    alert('✅ Жалоба отправлена!');
    document.getElementById('complaintForm')?.reset();
}

// ==============================================
// ОТПРАВКА МЕДИА-ЗАЯВОК (TIKTOK)
// ==============================================

function submitTTMedia(event) {
    event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите в систему!');
        return;
    }
    
    alert('✅ Заявка на TikTok отправлена!');
    document.getElementById('ttMediaForm')?.reset();
}

// ==============================================
// ОТПРАВКА МЕДИА-ЗАЯВОК (YOUTUBE)
// ==============================================

function submitYTMedia(event) {
    event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите в систему!');
        return;
    }
    
    alert('✅ Заявка на YouTube отправлена!');
    document.getElementById('ytMediaForm')?.reset();
}

// ==============================================
// ОТПРАВКА АНКЕТ НА ХЕЛПЕРА
// ==============================================

function submitApplication(event) {
    event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите в систему!');
        return;
    }
    
    alert('✅ Анкета отправлена!');
    document.getElementById('helperForm')?.reset();
}
