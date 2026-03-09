// ==============================================
// MOONGRIEF-FORUM - АДМИН ПАНЕЛЬ
// ==============================================

// Глобальные переменные
let currentAdmin = null;
let currentActionId = null;
let currentActionType = null;
let currentActionElement = null;

// ==============================================
// ПРОВЕРКА ДОСТУПА
// ==============================================

function checkAdminAccess() {
    // Здесь будет проверка через Supabase
    // Для теста используем localStorage
    const admin = localStorage.getItem('adminUser');
    
    if (!admin) {
        // Перенаправляем на главную если не админ
        window.location.href = 'index.html';
        return false;
    }
    
    currentAdmin = admin;
    document.getElementById('adminName').textContent = `🌙 ${admin}`;
    return true;
}

// ==============================================
// ПОКАЗ УВЕДОМЛЕНИЙ
// ==============================================

function showAdminNotification(message, type = 'moon') {
    const notification = document.createElement('div');
    notification.className = `moon-notification ${type}`;
    notification.innerHTML = `
        <span class="notification-icon">🌙</span>
        <span class="notification-text">${message}</span>
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.classList.add('show');
    }, 100);
    
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => {
            notification.remove();
        }, 500);
    }, 3000);
}

// ==============================================
// ЗАГРУЗКА СТАТИСТИКИ
// ==============================================

function loadStats() {
    // Здесь будет загрузка из базы данных
    // Для теста используем случайные числа
    
    const complaints = Math.floor(Math.random() * 10);
    const media = Math.floor(Math.random() * 8);
    const apps = Math.floor(Math.random() * 5);
    const total = complaints + media + apps;
    
    document.getElementById('newComplaints').textContent = complaints;
    document.getElementById('newMedia').textContent = media;
    document.getElementById('newApplications').textContent = apps;
    document.getElementById('total').textContent = total;
    
    // Анимация чисел
    animateNumbers();
}

function animateNumbers() {
    const numbers = document.querySelectorAll('.stat-number');
    numbers.forEach(num => {
        num.style.transform = 'scale(1.2)';
        setTimeout(() => {
            num.style.transform = 'scale(1)';
        }, 300);
    });
}

// ==============================================
// ПЕРЕКЛЮЧЕНИЕ ВКЛАДОК
// ==============================================

function showAdminTab(tabName) {
    // Скрываем все вкладки
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
        tab.style.animation = 'fadeOut 0.3s ease';
    });
    
    // Убираем активный класс со всех кнопок
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Показываем выбранную вкладку
    setTimeout(() => {
        const activeTab = document.getElementById('admin' + tabName.charAt(0).toUpperCase() + tabName.slice(1));
        activeTab.classList.add('active');
        activeTab.style.animation = 'fadeIn 0.5s ease';
        
        // Активируем кнопку
        event.target.classList.add('active');
        
        // Загружаем данные для вкладки
        switch(tabName) {
            case 'complaints':
                loadComplaints();
                break;
            case 'media':
                loadMedia();
                break;
            case 'applications':
                loadApplications();
                break;
        }
    }, 300);
}

// ==============================================
// ЗАГРУЗКА ЖАЛОБ
// ==============================================

function loadComplaints() {
    const list = document.getElementById('complaintsList');
    list.innerHTML = '<div class="loading">🌙 ЗАГРУЗКА...</div>';
    
    // Имитация загрузки
    setTimeout(() => {
        // Тестовые данные
        const complaints = [
            {
                id: 1,
                title: 'ГРИФЕР НА СПАВНЕ',
                against: 'Griefer123',
                description: 'Разрушил спавн и обворовал сундуки. Ломал блоки и воровал вещи у игроков.',
                user: 'Player123',
                status: 'new',
                date: '2024-01-15 14:30'
            },
            {
                id: 2,
                title: 'ОСКОРБЛЕНИЯ В ЧАТЕ',
                against: 'ToxicPlayer',
                description: 'Постоянно оскорбляет игроков, использует нецензурную лексику.',
                user: 'NiceGuy',
                status: 'new',
                date: '2024-01-15 12:15'
            },
            {
                id: 3,
                title: 'ИСПОЛЬЗОВАНИЕ ЧИТОВ',
                against: 'Hacker99',
                description: 'Летает по серверу, использует x-ray, убивает игроков через стены.',
                user: 'FairPlayer',
                status: 'in-progress',
                date: '2024-01-14 22:40'
            }
        ];
        
        renderComplaints(complaints);
    }, 1000);
}

function renderComplaints(complaints) {
    const list = document.getElementById('complaintsList');
    
    if (complaints.length === 0) {
        list.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">🌙</div>
                <h3>НЕТ ЖАЛОБ</h3>
                <p>НОВЫЕ ЖАЛОБЫ ПОКА НЕ ПОСТУПАЛИ</p>
            </div>
        `;
        return;
    }
    
    let html = '';
    complaints.forEach(complaint => {
        const statusClass = complaint.status === 'new' ? 'status-new' : 'status-in-progress';
        const statusText = complaint.status === 'new' ? 'НОВАЯ' : 'В РАБОТЕ';
        
        html += `
            <div class="admin-card" data-id="${complaint.id}" data-type="complaint">
                <div class="admin-card-header">
                    <div class="admin-card-title">
                        <span class="card-icon">⚠️</span>
                        <h3>${complaint.title}</h3>
                    </div>
                    <span class="admin-status ${statusClass}">${statusText}</span>
                </div>
                
                <div class="admin-card-body">
                    <div class="admin-card-info">
                        <p><strong>НА КОГО:</strong> ${complaint.against}</p>
                        <p><strong>ОТ:</strong> ${complaint.user}</p>
                        <p><strong>ДАТА:</strong> ${complaint.date}</p>
                        <p><strong>ОПИСАНИЕ:</strong> ${complaint.description}</p>
                    </div>
                </div>
                
                <div class="admin-card-actions">
                    <button onclick="acceptItem('complaint', ${complaint.id}, this)" class="admin-action accept" title="Принять">
                        <span>✓</span>
                    </button>
                    <button onclick="rejectItem('complaint', ${complaint.id}, this)" class="admin-action reject" title="Отклонить">
                        <span>✗</span>
                    </button>
                    <button onclick="showResponseModal('complaint', ${complaint.id}, '${complaint.user}', '${complaint.title}')" class="admin-action respond" title="Ответить">
                        <span>📝</span>
                    </button>
                </div>
            </div>
        `;
    });
    
    list.innerHTML = html;
}

// ==============================================
// ЗАГРУЗКА МЕДИА-ЗАЯВОК
// ==============================================

function loadMedia() {
    const list = document.getElementById('mediaList');
    list.innerHTML = '<div class="loading">🌙 ЗАГРУЗКА...</div>';
    
    setTimeout(() => {
        const media = [
            {
                id: 1,
                platform: 'tt',
                nickname: 'MoonTikToker',
                name: 'Алексей',
                age: 16,
                subs: '15,000',
                views: '50,000+',
                link: 'tiktok.com/@moontiktoker',
                status: 'new',
                date: '2024-01-15 10:20'
            },
            {
                id: 2,
                platform: 'yt',
                nickname: 'MoonYoutuber',
                name: 'Дмитрий',
                age: 18,
                subs: '5,200',
                views: '10,000+',
                link: 'youtube.com/@moonyoutuber',
                status: 'new',
                date: '2024-01-14 18:30'
            }
        ];
        
        renderMedia(media);
    }, 1000);
}

function renderMedia(media) {
    const list = document.getElementById('mediaList');
    
    if (media.length === 0) {
        list.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">🌙</div>
                <h3>НЕТ МЕДИА-ЗАЯВОК</h3>
                <p>НОВЫЕ ЗАЯВКИ ПОКА НЕ ПОСТУПАЛИ</p>
            </div>
        `;
        return;
    }
    
    let html = '';
    media.forEach(item => {
        const platformIcon = item.platform === 'tt' ? '📱' : '▶️';
        const platformName = item.platform === 'tt' ? 'TIKTOK' : 'YOUTUBE';
        
        html += `
            <div class="admin-card" data-id="${item.id}" data-type="media">
                <div class="admin-card-header">
                    <div class="admin-card-title">
                        <span class="card-icon">${platformIcon}</span>
                        <h3>${platformName} ЗАЯВКА</h3>
                    </div>
                    <span class="admin-status status-new">НОВАЯ</span>
                </div>
                
                <div class="admin-card-body">
                    <div class="admin-card-info">
                        <p><strong>НИК:</strong> ${item.nickname}</p>
                        <p><strong>ИМЯ:</strong> ${item.name}</p>
                        <p><strong>ВОЗРАСТ:</strong> ${item.age}</p>
                        <p><strong>ПОДПИСЧИКИ:</strong> ${item.subs}</p>
                        <p><strong>ПРОСМОТРЫ:</strong> ${item.views}</p>
                        <p><strong>ССЫЛКА:</strong> <a href="https://${item.link}" target="_blank">${item.link}</a></p>
                    </div>
                </div>
                
                <div class="admin-card-actions">
                    <button onclick="acceptItem('media', ${item.id}, this)" class="admin-action accept" title="Принять">
                        <span>✓</span>
                    </button>
                    <button onclick="rejectItem('media', ${item.id}, this)" class="admin-action reject" title="Отклонить">
                        <span>✗</span>
                    </button>
                    <button onclick="showResponseModal('media', ${item.id}, '${item.nickname}', '${platformName} ЗАЯВКА')" class="admin-action respond" title="Ответить">
                        <span>📝</span>
                    </button>
                </div>
            </div>
        `;
    });
    
    list.innerHTML = html;
}

// ==============================================
// ЗАГРУЗКА АНКЕТ НА ХЕЛПЕРА
// ==============================================

function loadApplications() {
    const list = document.getElementById('applicationsList');
    list.innerHTML = '<div class="loading">🌙 ЗАГРУЗКА...</div>';
    
    setTimeout(() => {
        const apps = [
            {
                id: 1,
                nickname: 'MoonHelper',
                name: 'Иван',
                age: 16,
                timezone: 'UTC+3',
                experience: 'Был модератором на 3 серверах, знаю все правила',
                reason: 'Хочу помогать игрокам и делать сервер лучше',
                additional: 'Могу быть онлайн каждый день с 15:00 до 22:00',
                status: 'new',
                date: '2024-01-15 09:15'
            },
            {
                id: 2,
                nickname: 'StarHelper',
                name: 'Анна',
                age: 17,
                timezone: 'UTC+2',
                experience: 'Играю на сервере 2 года, знаю всех игроков',
                reason: 'Хочу стать частью команды',
                additional: 'Есть опыт работы в других проектах',
                status: 'new',
                date: '2024-01-14 20:30'
            }
        ];
        
        renderApplications(apps);
    }, 1000);
}

function renderApplications(apps) {
    const list = document.getElementById('applicationsList');
    
    if (apps.length === 0) {
        list.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">🌙</div>
                <h3>НЕТ АНКЕТ</h3>
                <p>НОВЫЕ АНКЕТЫ ПОКА НЕ ПОСТУПАЛИ</p>
            </div>
        `;
        return;
    }
    
    let html = '';
    apps.forEach(app => {
        html += `
            <div class="admin-card" data-id="${app.id}" data-type="application">
                <div class="admin-card-header">
                    <div class="admin-card-title">
                        <span class="card-icon">👮</span>
                        <h3>АНКЕТА НА ХЕЛПЕРА</h3>
                    </div>
                    <span class="admin-status status-new">НОВАЯ</span>
                </div>
                
                <div class="admin-card-body">
                    <div class="admin-card-info">
                        <p><strong>НИК:</strong> ${app.nickname}</p>
                        <p><strong>ИМЯ:</strong> ${app.name}</p>
                        <p><strong>ВОЗРАСТ:</strong> ${app.age}</p>
                        <p><strong>ЧАСОВОЙ ПОЯС:</strong> ${app.timezone}</p>
                        <p><strong>ОПЫТ:</strong> ${app.experience}</p>
                        <p><strong>МОТИВАЦИЯ:</strong> ${app.reason}</p>
                        ${app.additional ? `<p><strong>ДОПОЛНИТЕЛЬНО:</strong> ${app.additional}</p>` : ''}
                    </div>
                </div>
                
                <div class="admin-card-actions">
                    <button onclick="acceptItem('application', ${app.id}, this)" class="admin-action accept" title="Принять">
                        <span>✓</span>
                    </button>
                    <button onclick="rejectItem('application', ${app.id}, this)" class="admin-action reject" title="Отклонить">
                        <span>✗</span>
                    </button>
                    <button onclick="showResponseModal('application', ${app.id}, '${app.nickname}', 'АНКЕТА НА ХЕЛПЕРА')" class="admin-action respond" title="Ответить">
                        <span>📝</span>
                    </button>
                </div>
            </div>
        `;
    });
    
    list.innerHTML = html;
}

// ==============================================
// ДЕЙСТВИЯ С ЗАЯВКАМИ
// ==============================================

function acceptItem(type, id, btn) {
    const card = btn.closest('.admin-card');
    const statusBadge = card.querySelector('.admin-status');
    
    // Анимация
    btn.style.transform = 'scale(1.3)';
    setTimeout(() => btn.style.transform = 'scale(1)', 200);
    
    // Меняем статус
    statusBadge.textContent = 'ПРИНЯТО';
    statusBadge.className = 'admin-status status-accepted';
    
    showAdminNotification(`🌙 Заявка #${id} принята`, 'success');
    
    // Обновляем статистику
    loadStats();
}

function rejectItem(type, id, btn) {
    const card = btn.closest('.admin-card');
    const statusBadge = card.querySelector('.admin-status');
    
    // Анимация
    btn.style.transform = 'scale(1.3)';
    setTimeout(() => btn.style.transform = 'scale(1)', 200);
    
    // Меняем статус
    statusBadge.textContent = 'ОТКЛОНЕНО';
    statusBadge.className = 'admin-status status-rejected';
    
    showAdminNotification(`🌙 Заявка #${id} отклонена`, 'error');
    
    // Обновляем статистику
    loadStats();
}

// ==============================================
// МОДАЛЬНОЕ ОКНО ОТВЕТА
// ==============================================

function showResponseModal(type, id, user, topic) {
    currentActionId = id;
    currentActionType = type;
    
    document.getElementById('responseId').value = id;
    document.getElementById('responseType').value = type;
    document.getElementById('responseUser').textContent = user;
    document.getElementById('responseTopic').textContent = topic;
    document.getElementById('responseText').value = '';
    
    const modal = document.getElementById('responseModal');
    modal.style.display = 'flex';
    modal.style.animation = 'modalFade 0.3s ease';
}

function closeResponseModal() {
    const modal = document.getElementById('responseModal');
    modal.style.animation = 'modalFade 0.3s ease reverse';
    
    setTimeout(() => {
        modal.style.display = 'none';
    }, 300);
}

function sendResponse(event) {
    event.preventDefault();
    
    const id = document.getElementById('responseId').value;
    const type = document.getElementById('responseType').value;
    const response = document.getElementById('responseText').value;
    
    if (!response.trim()) {
        showAdminNotification('❌ Введите текст ответа', 'error');
        return;
    }
    
    showAdminNotification(`🌙 Ответ на заявку #${id} отправлен`, 'success');
    closeResponseModal();
}

// ==============================================
// ВЫХОД
// ==============================================

function logout() {
    localStorage.removeItem('adminUser');
    showAdminNotification('🌙 Выход из админ панели', 'moon');
    
    setTimeout(() => {
        window.location.href = 'index.html';
    }, 1000);
}

// ==============================================
// ФУНКЦИЯ ДЛЯ СМЕНЫ УСТРОЙСТВА
// ==============================================

function showDeviceChoice() {
    if (typeof window.showDeviceChoice === 'function') {
        window.showDeviceChoice();
    } else {
        // Если функция не доступна, перенаправляем на главную
        window.location.href = 'index.html';
    }
}

// ==============================================
// ИНИЦИАЛИЗАЦИЯ
// ==============================================

document.addEventListener('DOMContentLoaded', function() {
    // Проверяем доступ
    if (!checkAdminAccess()) {
        return;
    }
    
    // Загружаем статистику
    loadStats();
    
    // Загружаем жалобы
    loadComplaints();
    
    // Проверяем мобильную версию
    const deviceType = localStorage.getItem('deviceType');
    if (deviceType === 'mobile') {
        document.body.classList.add('mobile-view');
        document.getElementById('deviceSwitch').style.display = 'block';
    } else {
        document.getElementById('deviceSwitch').style.display = 'none';
    }
    
    // Добавляем стили для админ панели
    addAdminStyles();
});

// ==============================================
// ДОПОЛНИТЕЛЬНЫЕ СТИЛИ ДЛЯ АДМИНКИ
// ==============================================

function addAdminStyles() {
    const style = document.createElement('style');
    style.textContent = `
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 25px;
            margin-bottom: 40px;
        }
        
        .stat-card {
            background: rgba(15, 15, 31, 0.8);
            border: 2px solid #7a7aff;
            border-radius: 20px;
            padding: 25px;
            display: flex;
            align-items: center;
            gap: 20px;
            position: relative;
            overflow: hidden;
            transition: all 0.3s;
            backdrop-filter: blur(10px);
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 0 30px rgba(122, 122, 255, 0.5);
        }
        
        .stat-glow {
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(122, 122, 255, 0.1) 0%, transparent 70%);
            animation: statGlow 10s linear infinite;
            pointer-events: none;
        }
        
        @keyframes statGlow {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        
        .stat-icon {
            font-size: 40px;
            filter: drop-shadow(0 0 10px #7a7aff);
        }
        
        .stat-info h3 {
            color: #b0b0ff;
            font-size: 12px;
            margin-bottom: 10px;
        }
        
        .stat-number {
            color: white;
            font-size: 32px;
            font-weight: bold;
            text-shadow: 0 0 20px #7a7aff;
            transition: transform 0.3s;
        }
        
        .admin-tabs {
            display: flex;
            gap: 15px;
            margin-bottom: 30px;
            justify-content: center;
            flex-wrap: wrap;
        }
        
        .tab-btn {
            background: rgba(15, 15, 31, 0.8);
            border: 2px solid #7a7aff;
            color: #b0b0ff;
            padding: 15px 30px;
            border-radius: 50px;
            cursor: pointer;
            font-family: 'Press Start 2P', cursive;
            font-size: 12px;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .tab-btn:hover {
            background: #7a7aff;
            color: white;
            transform: translateY(-3px);
            box-shadow: 0 0 30px #7a7aff;
        }
        
        .tab-btn.active {
            background: #7a7aff;
            color: white;
            box-shadow: 0 0 30px #7a7aff;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .admin-controls {
            display: flex;
            justify-content: flex-end;
            margin-bottom: 20px;
        }
        
        .admin-refresh-btn {
            background: rgba(15, 15, 31, 0.8);
            border: 2px solid #7a7aff;
            color: #b0b0ff;
            padding: 10px 20px;
            border-radius: 30px;
            cursor: pointer;
            font-family: 'Press Start 2P', cursive;
            font-size: 10px;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .admin-refresh-btn:hover {
            background: #7a7aff;
            color: white;
            box-shadow: 0 0 20px #7a7aff;
        }
        
        .admin-card {
            background: rgba(15, 15, 31, 0.8);
            border: 2px solid #7a7aff;
            border-radius: 20px;
            padding: 25px;
            margin-bottom: 20px;
            position: relative;
            backdrop-filter: blur(10px);
            transition: all 0.3s;
        }
        
        .admin-card:hover {
            transform: translateX(10px);
            box-shadow: -10px 10px 30px rgba(122, 122, 255, 0.3);
        }
        
        .admin-card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid rgba(122, 122, 255, 0.3);
        }
        
        .admin-card-title {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .card-icon {
            font-size: 24px;
        }
        
        .admin-card-title h3 {
            color: #b0b0ff;
            font-size: 14px;
        }
        
        .admin-status {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 10px;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .status-new {
            background: #7a7aff;
            color: white;
            box-shadow: 0 0 10px #7a7aff;
        }
        
        .status-in-progress {
            background: #ffaa4a;
            color: white;
            box-shadow: 0 0 10px #ffaa4a;
        }
        
        .status-accepted {
            background: #4aff7a;
            color: white;
            box-shadow: 0 0 10px #4aff7a;
        }
        
        .status-rejected {
            background: #ff4a4a;
            color: white;
            box-shadow: 0 0 10px #ff4a4a;
        }
        
        .admin-card-body {
            margin-bottom: 20px;
        }
        
        .admin-card-info p {
            color: #e0e0ff;
            font-size: 11px;
            margin: 8px 0;
            line-height: 1.6;
        }
        
        .admin-card-info strong {
            color: #b0b0ff;
            min-width: 120px;
            display: inline-block;
        }
        
        .admin-card-info a {
            color: #7a7aff;
            text-decoration: none;
            transition: all 0.3s;
        }
        
        .admin-card-info a:hover {
            color: white;
            text-shadow: 0 0 10px #7a7aff;
        }
        
        .admin-card-actions {
            display: flex;
            gap: 15px;
            justify-content: flex-end;
            border-top: 2px solid rgba(122, 122, 255, 0.3);
            padding-top: 20px;
        }
        
        .admin-action {
            width: 45px;
            height: 45px;
            border-radius: 50%;
            border: 2px solid transparent;
            cursor: pointer;
            font-size: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s;
            background: rgba(15, 15, 31, 0.8);
        }
        
        .admin-action.accept {
            color: #4aff7a;
            border-color: #4aff7a;
        }
        
        .admin-action.accept:hover {
            background: #4aff7a;
            color: white;
            transform: scale(1.1);
            box-shadow: 0 0 20px #4aff7a;
        }
        
        .admin-action.reject {
            color: #ff4a4a;
            border-color: #ff4a4a;
        }
        
        .admin-action.reject:hover {
            background: #ff4a4a;
            color: white;
            transform: scale(1.1);
            box-shadow: 0 0 20px #ff4a4a;
        }
        
        .admin-action.respond {
            color: #7a7aff;
            border-color: #7a7aff;
        }
        
        .admin-action.respond:hover {
            background: #7a7aff;
            color: white;
            transform: scale(1.1);
            box-shadow: 0 0 20px #7a7aff;
        }
        
        .response-user, .response-topic {
            background: rgba(122, 122, 255, 0.1);
            padding: 12px 15px;
            border-radius: 10px;
            border: 1px solid #7a7aff;
            color: #b0b0ff;
            font-size: 12px;
            margin-bottom: 15px;
        }
        
        .action-group {
            display: flex;
            gap: 15px;
            margin-top: 20px;
        }
        
        .cancel-btn {
            background: #3a2a4a !important;
            border-color: #9a7aff !important;
        }
        
        .cancel-btn:hover {
            background: #6a4a9a !important;
        }
        
        .loading {
            text-align: center;
            padding: 60px;
            color: #7a7aff;
            font-size: 14px;
            animation: moonFloat 2s infinite;
        }
        
        @media (max-width: 768px) {
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .admin-card-actions {
                flex-wrap: wrap;
            }
            
            .admin-card-info strong {
                min-width: 100px;
            }
            
            .action-group {
                flex-direction: column;
            }
            
            .action-group button {
                width: 100%;
            }
        }
    `;
    
    document.head.appendChild(style);
}
