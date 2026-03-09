// ==============================================
// MOONGRIEF-FORUM - ЛУННЫЙ СКРИПТ
// ==============================================

// Глобальные переменные
let currentUser = null;
let currentDevice = localStorage.getItem('deviceType') || null;

// ==============================================
// ВЫБОР УСТРОЙСТВА
// ==============================================

function selectDevice(device) {
    // Сохраняем выбор в localStorage
    localStorage.setItem('deviceType', device);
    currentDevice = device;
    
    // Скрываем экран выбора с анимацией
    const deviceChoice = document.getElementById('deviceChoice');
    deviceChoice.style.animation = 'fadeOut 0.5s ease';
    
    setTimeout(() => {
        deviceChoice.style.display = 'none';
        
        // Показываем основной сайт с анимацией
        const mainSite = document.getElementById('mainSite');
        mainSite.style.display = 'block';
        mainSite.style.animation = 'fadeIn 0.8s ease';
        
        // Применяем класс для мобильной версии если нужно
        if (device === 'mobile') {
            document.body.classList.add('mobile-view');
            showNotification('🌙 Мобильная версия активирована', 'moon');
        } else {
            document.body.classList.remove('mobile-view');
            showNotification('🌙 ПК версия активирована', 'moon');
        }
        
        // Инициализируем остальные функции
        initSections();
        checkAuth();
        loadLists();
    }, 500);
}

function showDeviceChoice() {
    // Анимация скрытия основного сайта
    const mainSite = document.getElementById('mainSite');
    mainSite.style.animation = 'fadeOut 0.5s ease';
    
    setTimeout(() => {
        mainSite.style.display = 'none';
        
        // Показываем экран выбора
        const deviceChoice = document.getElementById('deviceChoice');
        deviceChoice.style.display = 'flex';
        deviceChoice.style.animation = 'fadeIn 0.8s ease';
    }, 500);
}

// ==============================================
// УВЕДОМЛЕНИЯ
// ==============================================

function showNotification(message, type = 'info') {
    // Создаем элемент уведомления
    const notification = document.createElement('div');
    notification.className = `moon-notification ${type}`;
    notification.innerHTML = `
        <span class="notification-icon">🌙</span>
        <span class="notification-text">${message}</span>
    `;
    
    // Добавляем на страницу
    document.body.appendChild(notification);
    
    // Анимация появления
    setTimeout(() => {
        notification.classList.add('show');
    }, 100);
    
    // Автоматическое скрытие через 3 секунды
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => {
            notification.remove();
        }, 500);
    }, 3000);
}

// ==============================================
// КОПИРОВАНИЕ IP
// ==============================================

function copyIP() {
    navigator.clipboard.writeText('Moongrief.aurorix.pro').then(() => {
        showNotification('🌙 IP скопирован! Заходи на сервер!', 'success');
        
        // Эффект на кнопке
        const copyBtn = document.querySelector('.copy-btn');
        copyBtn.style.transform = 'scale(1.1)';
        setTimeout(() => {
            copyBtn.style.transform = 'scale(1)';
        }, 200);
    }).catch(() => {
        showNotification('❌ Ошибка копирования', 'error');
    });
}

// ==============================================
// НАВИГАЦИЯ ПО РАЗДЕЛАМ
// ==============================================

function showSection(sectionId, event) {
    if (event) {
        event.preventDefault();
    }
    
    // Скрываем все секции с анимацией
    const sections = document.querySelectorAll('.section');
    sections.forEach(section => {
        section.style.animation = 'fadeOut 0.3s ease';
        setTimeout(() => {
            section.classList.remove('active-section');
        }, 200);
    });
    
    // Показываем нужную секцию
    setTimeout(() => {
        const targetSection = document.getElementById(sectionId);
        targetSection.classList.add('active-section');
        targetSection.style.animation = 'fadeIn 0.5s ease';
        
        // Обновляем активную ссылку
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });
        
        if (event) {
            event.target.classList.add('active');
        } else {
            // Ищем ссылку по href
            document.querySelector(`.nav-link[href="#${sectionId}"]`).classList.add('active');
        }
        
        // Сохраняем последний раздел
        localStorage.setItem('lastSection', sectionId);
    }, 300);
}

function initSections() {
    // Проверяем, был ли сохранен последний раздел
    const lastSection = localStorage.getItem('lastSection') || 'rules';
    showSection(lastSection, null);
}

// ==============================================
// ПЕРЕКЛЮЧЕНИЕ МЕЖДУ ПЛАТФОРМАМИ (TT/YT)
// ==============================================

function switchPlatform(platform) {
    const ttForm = document.getElementById('ttForm');
    const ytForm = document.getElementById('ytForm');
    const ttBtn = document.getElementById('switchTT');
    const ytBtn = document.getElementById('switchYT');
    
    if (platform === 'tt') {
        // Анимация переключения
        ttForm.style.animation = 'fadeIn 0.5s ease';
        ytForm.style.animation = 'fadeOut 0.3s ease';
        
        setTimeout(() => {
            ttForm.classList.add('active');
            ytForm.classList.remove('active');
            ttBtn.classList.add('active');
            ytBtn.classList.remove('active');
        }, 200);
        
        showNotification('📱 Форма TikTok активирована', 'moon');
    } else {
        // Анимация переключения
        ytForm.style.animation = 'fadeIn 0.5s ease';
        ttForm.style.animation = 'fadeOut 0.3s ease';
        
        setTimeout(() => {
            ytForm.classList.add('active');
            ttForm.classList.remove('active');
            ytBtn.classList.add('active');
            ttBtn.classList.remove('active');
        }, 200);
        
        showNotification('▶️ Форма YouTube активирована', 'moon');
    }
}

// ==============================================
// МОДАЛЬНЫЕ ОКНА
// ==============================================

function showRegister() {
    const modal = document.getElementById('registerModal');
    modal.style.display = 'flex';
    modal.style.animation = 'modalFade 0.3s ease';
    
    // Фокус на первом поле
    setTimeout(() => {
        document.getElementById('regUsername').focus();
    }, 300);
}

function closeModal() {
    const modal = document.getElementById('registerModal');
    modal.style.animation = 'modalFade 0.3s ease reverse';
    
    setTimeout(() => {
        modal.style.display = 'none';
    }, 300);
}

function showChangePassword() {
    if (!currentUser) {
        showNotification('❌ Сначала войдите в систему', 'error');
        return;
    }
    
    const modal = document.getElementById('changePasswordModal');
    modal.style.display = 'flex';
    modal.style.animation = 'modalFade 0.3s ease';
}

function closeChangePassword() {
    const modal = document.getElementById('changePasswordModal');
    modal.style.animation = 'modalFade 0.3s ease reverse';
    
    setTimeout(() => {
        modal.style.display = 'none';
    }, 300);
}

// Закрытие модалок по клику вне окна
window.onclick = function(event) {
    const registerModal = document.getElementById('registerModal');
    const changeModal = document.getElementById('changePasswordModal');
    
    if (event.target === registerModal) {
        closeModal();
    }
    if (event.target === changeModal) {
        closeChangePassword();
    }
}

// ==============================================
// АВТОРИЗАЦИЯ (ЗАГЛУШКИ ДЛЯ ТЕСТА)
// ==============================================

function login() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    if (!username || !password) {
        showNotification('❌ Введите ник и пароль', 'error');
        return;
    }
    
    // Имитация входа
    showNotification(`🌙 Добро пожаловать, ${username}!`, 'success');
    
    // Показываем интерфейс пользователя
    document.getElementById('loginForm').style.display = 'none';
    document.getElementById('userInfo').style.display = 'flex';
    document.getElementById('currentUser').textContent = `🌙 ${username}`;
    
    currentUser = username;
    
    // Очищаем поля
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    
    // Проверяем админа (для теста)
    if (username === 'milfa' || username === 'milk123' || username === 'Xchik_') {
        document.getElementById('adminLink').style.display = 'inline-block';
        showNotification('👑 Права администратора активированы', 'moon');
    }
}

function register(event) {
    event.preventDefault();
    
    const username = document.getElementById('regUsername').value;
    const password = document.getElementById('regPassword').value;
    const confirm = document.getElementById('regConfirmPassword').value;
    
    if (!username || !password || !confirm) {
        showNotification('❌ Заполните все поля', 'error');
        return;
    }
    
    if (password !== confirm) {
        showNotification('❌ Пароли не совпадают', 'error');
        return;
    }
    
    if (password.length < 4) {
        showNotification('❌ Пароль должен быть минимум 4 символа', 'error');
        return;
    }
    
    showNotification(`🌙 Аккаунт ${username} создан! Теперь войдите.`, 'success');
    closeModal();
}

function logout() {
    showNotification(`🌙 До свидания, ${currentUser}!`, 'moon');
    
    document.getElementById('loginForm').style.display = 'flex';
    document.getElementById('userInfo').style.display = 'none';
    document.getElementById('adminLink').style.display = 'none';
    
    currentUser = null;
}

function changePassword(event) {
    event.preventDefault();
    
    const oldPass = document.getElementById('oldPassword').value;
    const newPass = document.getElementById('newPassword').value;
    const confirm = document.getElementById('confirmPassword').value;
    
    if (!oldPass || !newPass || !confirm) {
        showNotification('❌ Заполните все поля', 'error');
        return;
    }
    
    if (newPass !== confirm) {
        showNotification('❌ Новые пароли не совпадают', 'error');
        return;
    }
    
    showNotification('🔑 Пароль успешно изменен!', 'success');
    closeChangePassword();
}

// ==============================================
// ОТПРАВКА ФОРМ
// ==============================================

function submitComplaint(event) {
    event.preventDefault();
    
    const title = document.getElementById('complaintTitle').value;
    const against = document.getElementById('complaintAgainst').value;
    const desc = document.getElementById('complaintDesc').value;
    
    if (!title || !against || !desc) {
        showNotification('❌ Заполните все поля', 'error');
        return;
    }
    
    // Создаем карточку жалобы
    const complaintCard = document.createElement('div');
    complaintCard.className = 'complaint-card';
    complaintCard.innerHTML = `
        <div class="complaint-header">
            <span class="complaint-title">${title}</span>
            <span class="complaint-status status-new">НОВАЯ</span>
        </div>
        <div class="complaint-body">
            <p><strong>НА КОГО:</strong> ${against}</p>
            <p><strong>ОПИСАНИЕ:</strong> ${desc.substring(0, 100)}${desc.length > 100 ? '...' : ''}</p>
            <p><strong>ОТ:</strong> ${currentUser || 'Гость'}</p>
        </div>
    `;
    
    // Добавляем в список
    const complaintsList = document.getElementById('complaintsList');
    complaintsList.prepend(complaintCard);
    
    showNotification('⚠️ Жалоба отправлена! Срок рассмотрения: 24 часа', 'success');
    document.getElementById('complaintForm').reset();
}

function submitTTMedia(event) {
    event.preventDefault();
    
    const age = document.getElementById('ttAge').value;
    const name = document.getElementById('ttName').value;
    const nickname = document.getElementById('ttNickname').value;
    const subs = document.getElementById('ttSubs').value;
    const views = document.getElementById('ttViews').value;
    const link = document.getElementById('ttLink').value;
    
    if (!age || !name || !nickname || !subs || !views || !link) {
        showNotification('❌ Заполните все поля', 'error');
        return;
    }
    
    // Создаем карточку заявки
    const mediaCard = document.createElement('div');
    mediaCard.className = 'media-card';
    mediaCard.innerHTML = `
        <div class="media-header">
            <span class="media-title">📱 TIKTOK ЗАЯВКА</span>
            <span class="media-status status-new">НОВАЯ</span>
        </div>
        <div class="media-body">
            <p><strong>НИК:</strong> ${nickname}</p>
            <p><strong>ИМЯ:</strong> ${name}</p>
            <p><strong>ВОЗРАСТ:</strong> ${age}</p>
            <p><strong>ПОДПИСЧИКИ:</strong> ${subs}</p>
            <p><strong>ССЫЛКА:</strong> <a href="${link}" target="_blank">${link.substring(0, 30)}...</a></p>
        </div>
    `;
    
    // Добавляем в список
    const mediaList = document.getElementById('mediaList');
    mediaList.prepend(mediaCard);
    
    showNotification('📱 Заявка на TikTok отправлена!', 'success');
    document.getElementById('ttMediaForm').reset();
}

function submitYTMedia(event) {
    event.preventDefault();
    
    const age = document.getElementById('ytAge').value;
    const name = document.getElementById('ytName').value;
    const nickname = document.getElementById('ytNickname').value;
    const subs = document.getElementById('ytSubs').value;
    const views = document.getElementById('ytViews').value;
    const link = document.getElementById('ytLink').value;
    
    if (!age || !name || !nickname || !subs || !views || !link) {
        showNotification('❌ Заполните все поля', 'error');
        return;
    }
    
    // Создаем карточку заявки
    const mediaCard = document.createElement('div');
    mediaCard.className = 'media-card';
    mediaCard.innerHTML = `
        <div class="media-header">
            <span class="media-title">▶️ YOUTUBE ЗАЯВКА</span>
            <span class="media-status status-new">НОВАЯ</span>
        </div>
        <div class="media-body">
            <p><strong>НИК:</strong> ${nickname}</p>
            <p><strong>ИМЯ:</strong> ${name}</p>
            <p><strong>ВОЗРАСТ:</strong> ${age}</p>
            <p><strong>ПОДПИСЧИКИ:</strong> ${subs}</p>
            <p><strong>ССЫЛКА:</strong> <a href="${link}" target="_blank">${link.substring(0, 30)}...</a></p>
        </div>
    `;
    
    // Добавляем в список
    const mediaList = document.getElementById('mediaList');
    mediaList.prepend(mediaCard);
    
    showNotification('▶️ Заявка на YouTube отправлена!', 'success');
    document.getElementById('ytMediaForm').reset();
}

function submitApplication(event) {
    event.preventDefault();
    
    const nickname = document.getElementById('helperNickname').value;
    const name = document.getElementById('helperName').value;
    const age = document.getElementById('helperAge').value;
    const timezone = document.getElementById('helperTimezone').value;
    const experience = document.getElementById('helperExperience').value;
    const reason = document.getElementById('helperReason').value;
    const additional = document.getElementById('helperAdditional').value;
    
    if (!nickname || !name || !age || !timezone || !experience || !reason) {
        showNotification('❌ Заполните обязательные поля', 'error');
        return;
    }
    
    // Создаем карточку заявки
    const appCard = document.createElement('div');
    appCard.className = 'application-card';
    appCard.innerHTML = `
        <div class="application-header">
            <span class="application-title">👮 ЗАЯВКА НА ХЕЛПЕРА</span>
            <span class="application-status status-new">НОВАЯ</span>
        </div>
        <div class="application-body">
            <p><strong>НИК:</strong> ${nickname}</p>
            <p><strong>ИМЯ:</strong> ${name}</p>
            <p><strong>ВОЗРАСТ:</strong> ${age}</p>
            <p><strong>ЧАСОВОЙ ПОЯС:</strong> ${timezone}</p>
            <p><strong>МОТИВАЦИЯ:</strong> ${reason.substring(0, 100)}...</p>
        </div>
    `;
    
    // Добавляем в список
    const applicationsList = document.getElementById('applicationsList');
    applicationsList.prepend(appCard);
    
    showNotification('👮 Анкета на хелпера отправлена!', 'success');
    document.getElementById('helperForm').reset();
}

// ==============================================
// ЗАГРУЗКА СПИСКОВ (ЗАГЛУШКИ)
// ==============================================

function loadLists() {
    // Здесь будет загрузка из базы данных
    console.log('🌙 Загрузка списков MoonGrief-Forum...');
    
    // Добавляем тестовые данные
    loadTestData();
}

function loadTestData() {
    // Тестовые жалобы
    const complaintsList = document.getElementById('complaintsList');
    if (complaintsList.children.length === 0) {
        const testComplaint = document.createElement('div');
        testComplaint.className = 'complaint-card';
        testComplaint.innerHTML = `
            <div class="complaint-header">
                <span class="complaint-title">ГРИФЕР НА СПАВНЕ</span>
                <span class="complaint-status status-resolved">РЕШЕНО</span>
            </div>
            <div class="complaint-body">
                <p><strong>НА КОГО:</strong> Griefer123</p>
                <p><strong>ОПИСАНИЕ:</strong> Разрушил спавн и обворовал сундуки</p>
                <p><strong>ОТ:</strong> Player123</p>
            </div>
        `;
        complaintsList.appendChild(testComplaint);
    }
    
    // Тестовые медиа-заявки
    const mediaList = document.getElementById('mediaList');
    if (mediaList.children.length === 0) {
        const testMedia = document.createElement('div');
        testMedia.className = 'media-card';
        testMedia.innerHTML = `
            <div class="media-header">
                <span class="media-title">📱 TIKTOK ЗАЯВКА</span>
                <span class="media-status status-accepted">ПРИНЯТО</span>
            </div>
            <div class="media-body">
                <p><strong>НИК:</strong> MoonTikToker</p>
                <p><strong>ПОДПИСЧИКИ:</strong> 15,000</p>
                <p><strong>ССЫЛКА:</strong> tiktok.com/@moontiktoker</p>
            </div>
        `;
        mediaList.appendChild(testMedia);
    }
    
    // Тестовые заявки на хелпера
    const appsList = document.getElementById('applicationsList');
    if (appsList.children.length === 0) {
        const testApp = document.createElement('div');
        testApp.className = 'application-card';
        testApp.innerHTML = `
            <div class="application-header">
                <span class="application-title">👮 ЗАЯВКА НА ХЕЛПЕРА</span>
                <span class="application-status status-new">НОВАЯ</span>
            </div>
            <div class="application-body">
                <p><strong>НИК:</strong> MoonHelper</p>
                <p><strong>ВОЗРАСТ:</strong> 16</p>
                <p><strong>ОПЫТ:</strong> Был модератором на 3 серверах</p>
            </div>
        `;
        appsList.appendChild(testApp);
    }
}

// ==============================================
// ПРОВЕРКА АВТОРИЗАЦИИ
// ==============================================

function checkAuth() {
    // Здесь будет проверка через базу данных
    console.log('🌙 Проверка авторизации MoonGrief-Forum...');
    
    // Для теста скрываем админку
    document.getElementById('adminLink').style.display = 'none';
}

// ==============================================
// ДОПОЛНИТЕЛЬНЫЕ ФУНКЦИИ
// ==============================================

// Эффект параллакса для луны
document.addEventListener('mousemove', function(e) {
    const moon = document.querySelector('.logo h1');
    if (moon) {
        const x = (e.clientX / window.innerWidth - 0.5) * 20;
        const y = (e.clientY / window.innerHeight - 0.5) * 20;
        moon.style.transform = `translate(${x}px, ${y}px)`;
    }
});

// Добавление стилей для уведомлений
const style = document.createElement('style');
style.textContent = `
    .moon-notification {
        position: fixed;
        top: 20px;
        right: 20px;
        background: linear-gradient(135deg, #1a1a3a, #0f0f1f);
        border: 2px solid #7a7aff;
        border-radius: 50px;
        padding: 15px 25px;
        color: white;
        font-family: 'Press Start 2P', cursive;
        font-size: 10px;
        z-index: 10001;
        display: flex;
        align-items: center;
        gap: 15px;
        transform: translateX(120%);
        transition: transform 0.5s ease;
        box-shadow: 0 0 30px rgba(122, 122, 255, 0.5);
        backdrop-filter: blur(10px);
    }
    
    .moon-notification.show {
        transform: translateX(0);
    }
    
    .moon-notification.success {
        border-color: #4aff7a;
        box-shadow: 0 0 30px rgba(74, 255, 122, 0.5);
    }
    
    .moon-notification.error {
        border-color: #ff4a4a;
        box-shadow: 0 0 30px rgba(255, 74, 74, 0.5);
    }
    
    .moon-notification.moon {
        border-color: #7a7aff;
        box-shadow: 0 0 30px rgba(122, 122, 255, 0.5);
    }
    
    .notification-icon {
        font-size: 20px;
        animation: moonFloat 2s infinite;
    }
    
    @keyframes fadeOut {
        from { opacity: 1; transform: scale(1); }
        to { opacity: 0; transform: scale(0.9); }
    }
    
    @keyframes fadeIn {
        from { opacity: 0; transform: scale(0.9); }
        to { opacity: 1; transform: scale(1); }
    }
`;

document.head.appendChild(style);

// ==============================================
// ИНИЦИАЛИЗАЦИЯ ПРИ ЗАГРУЗКЕ
// ==============================================

document.addEventListener('DOMContentLoaded', function() {
    console.log('🌙 MoonGrief-Forum загружен!');
    
    const savedDevice = localStorage.getItem('deviceType');
    
    if (savedDevice) {
        // Если выбор уже был, применяем его
        selectDevice(savedDevice);
    } else {
        // Если нет - показываем экран выбора
        document.getElementById('deviceChoice').style.display = 'flex';
        document.getElementById('mainSite').style.display = 'none';
    }
    
    // Добавляем эффект свечения для луны
    setInterval(() => {
        const moonElements = document.querySelectorAll('.moon-glow, .logo h1, .section-title');
        moonElements.forEach(el => {
            el.style.textShadow = '0 0 ' + (20 + Math.random() * 20) + 'px #7a7aff';
        });
    }, 2000);
});
