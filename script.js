// ==============================================
// ОСНОВНОЙ СКРИПТ - ПРОСТАЯ РАБОЧАЯ ВЕРСИЯ
// ==============================================

// Данные
let users = [];
let complaints = [];
let applications = [];
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
});

// Показать секцию
function showSection(sectionId) {
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active-section');
    });
    document.getElementById(sectionId).classList.add('active-section');
    
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    event.target.classList.add('active');
}

// Копирование IP
function copyIP() {
    navigator.clipboard.writeText('bladebox.aurorix.pro');
    alert('IP скопирован!');
}

// ==============================================
// АВТОРИЗАЦИЯ
// ==============================================

function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    if (!username || !password) {
        alert('Введите ник и пароль!');
        return;
    }
    
    // Простая авторизация для теста
    if (username === 'admin' && password === 'admin') {
        currentUser = { username: 'admin', password: 'admin' };
        localStorage.setItem('currentUser', JSON.stringify(currentUser));
        updateAuth();
        checkAdminLink();
        alert('Добро пожаловать, admin!');
    } else {
        alert('Неверный ник или пароль!');
    }
}

function logout() {
    currentUser = null;
    localStorage.removeItem('currentUser');
    updateAuth();
    checkAdminLink();
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
    document.getElementById('registerModal').style.display = 'block';
}

function closeModal() {
    document.getElementById('registerModal').style.display = 'none';
}

function register(event) {
    event.preventDefault();
    alert('Регистрация временно отключена для теста');
    closeModal();
}

// ==============================================
// СМЕНА ПАРОЛЯ
// ==============================================

function showChangePassword() {
    alert('Смена пароля временно отключена');
}

function closeChangePassword() {
    document.getElementById('changePasswordModal').style.display = 'none';
}

// ==============================================
// ОТПРАВКА ЖАЛОБ
// ==============================================

function submitComplaint(event) {
    event.preventDefault();
    alert('Функция отправки жалоб временно отключена');
}

// ==============================================
// ОТПРАВКА АНКЕТ
// ==============================================

function submitApplication(event) {
    event.preventDefault();
    alert('Функция отправки анкет временно отключена');
}

// ==============================================
// ПЕРЕКЛЮЧЕНИЕ ПЛАТФОРМ (TT/YT)
// ==============================================

function switchPlatform(platform) {
    const ttForm = document.getElementById('ttForm');
    const ytForm = document.getElementById('ytForm');
    const switchTT = document.getElementById('switchTT');
    const switchYT = document.getElementById('switchYT');
    
    if (platform === 'tt') {
        ttForm.style.display = 'block';
        ytForm.style.display = 'none';
        switchTT.classList.add('active');
        switchYT.classList.remove('active');
    } else {
        ttForm.style.display = 'none';
        ytForm.style.display = 'block';
        switchTT.classList.remove('active');
        switchYT.classList.add('active');
    }
}
