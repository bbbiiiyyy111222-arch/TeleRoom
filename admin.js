// ==============================================
// MOONGRIEF-FORUM - АДМИН ПАНЕЛЬ
// ==============================================

// Данные (общие с основным сайтом)
let users = JSON.parse(localStorage.getItem('mg_users')) || [];
let complaints = JSON.parse(localStorage.getItem('mg_complaints')) || [];
let media = JSON.parse(localStorage.getItem('mg_media')) || [];
let helpers = JSON.parse(localStorage.getItem('mg_helpers')) || [];

let currentAdmin = JSON.parse(localStorage.getItem('mg_currentUser')) || null;
let currentActionId = null;
let currentActionType = null;
let currentActionElement = null;

// Админы (OWNER)
const admins = ['milfa', 'milk123', 'Xchik_'];

// ==============================================
// ПРОВЕРКА ДОСТУПА
// ==============================================

function checkAdminAccess() {
    if (!currentAdmin || !admins.includes(currentAdmin.username)) {
        window.location.href = 'index.html';
        return false;
    }
    
    document.getElementById('adminName').textContent = `🌙 ${currentAdmin.username}`;
    document.getElementById('adminRole').textContent = 'OWNER';
    return true;
}

// ==============================================
// КОПИРОВАНИЕ IP
// ==============================================

function copyIP() {
    navigator.clipboard.writeText('Moongrief.aurorix.pro').then(() => {
        alert('📋 IP скопирован!');
    }).catch(() => {
        alert('❌ Ошибка копирования');
    });
}

// ==============================================
// СТАТИСТИКА
// ==============================================

function loadStats() {
    const newComplaints = complaints.filter(c => c.status === 'НОВАЯ').length;
    const newMedia = media.filter(m => m.status === 'НОВАЯ').length;
    const newHelpers = helpers.filter(h => h.status === 'НОВАЯ').length;
    const total = complaints.length + media.length + helpers.length;
    const newTotal = newComplaints + newMedia + newHelpers;
    
    document.getElementById('statComplaints').textContent = newComplaints;
    document.getElementById('statMedia').textContent = newMedia;
    document.getElementById('statHelpers').textContent = newHelpers;
    document.getElementById('statTotal').textContent = total;
    
    document.getElementById('totalStats').textContent = total;
    document.getElementById('newStats').textContent = newTotal;
}

// ==============================================
// ПЕРЕКЛЮЧЕНИЕ ВКЛАДОК
// ==============================================

function showAdminTab(tabName) {
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    document.getElementById(`admin${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`).classList.add('active');
    event.target.classList.add('active');
    
    switch(tabName) {
        case 'complaints': loadComplaints(); break;
        case 'media': loadMedia(); break;
        case 'applications': loadApplications(); break;
    }
}

// ==============================================
// ЗАГРУЗКА ЖАЛОБ
// ==============================================

function loadComplaints() {
    const list = document.getElementById('complaintsList');
    
    if (complaints.length === 0) {
        list.innerHTML = '<div class="empty-list">📭 Нет жалоб</div>';
        return;
    }
    
    let html = '';
    complaints.forEach(c => {
        const statusClass = c.status === 'НОВАЯ' ? 'status-new' : c.status === 'ПРИНЯТО' ? 'status-accepted' : 'status-rejected';
        
        html += `
            <div class="admin-card" data-id="${c.id}" data-type="complaint">
                <div class="admin-card-header">
                    <div class="admin-card-title">
                        <span class="card-icon">⚠️</span>
                        <h3>${c.title}</h3>
                    </div>
                    <span class="admin-status ${statusClass}">${c.status}</span>
                </div>
                
                <div class="admin-card-body">
                    <p><strong>От:</strong> ${c.user}</p>
                    <p><strong>Нарушитель:</strong> ${c.target}</p>
                    <p><strong>Описание:</strong> ${c.desc}</p>
                    <p><strong>Дата:</strong> ${c.date}</p>
                </div>
                
                <div class="admin-card-actions">
                    <button onclick="acceptItem('complaint', ${c.id}, this)" class="admin-action accept" title="Принять">✓</button>
                    <button onclick="rejectItem('complaint', ${c.id}, this)" class="admin-action reject" title="Отклонить">✗</button>
                    <button onclick="showResponseModal('complaint', ${c.id}, '${c.user}', '${c.title}')" class="admin-action respond" title="Ответить">📝</button>
                </div>
            </div>
        `;
    });
    
    list.innerHTML = html;
}

// ==============================================
// ЗАГРУЗКА МЕДИА
// ==============================================

function loadMedia() {
    const list = document.getElementById('mediaList');
    
    if (media.length === 0) {
        list.innerHTML = '<div class="empty-list">📭 Нет медиа-заявок</div>';
        return;
    }
    
    let html = '';
    media.forEach(m => {
        const platformIcon = m.type === 'tt' ? '📱' : '▶️';
        const platformName = m.type === 'tt' ? 'TIKTOK' : 'YOUTUBE';
        const statusClass = m.status === 'НОВАЯ' ? 'status-new' : m.status === 'ПРИНЯТО' ? 'status-accepted' : 'status-rejected';
        
        html += `
            <div class="admin-card" data-id="${m.id}" data-type="media">
                <div class="admin-card-header">
                    <div class="admin-card-title">
                        <span class="card-icon">${platformIcon}</span>
                        <h3>${platformName} ЗАЯВКА</h3>
                    </div>
                    <span class="admin-status ${statusClass}">${m.status}</span>
                </div>
                
                <div class="admin-card-body">
                    <p><strong>Ник:</strong> ${m.nick}</p>
                    <p><strong>Имя:</strong> ${m.name}</p>
                    <p><strong>Возраст:</strong> ${m.age}</p>
                    <p><strong>Подписчики:</strong> ${m.subs}</p>
                    <p><strong>Ссылка:</strong> <a href="${m.link}" target="_blank">${m.link}</a></p>
                    <p><strong>Дата:</strong> ${m.date}</p>
                </div>
                
                <div class="admin-card-actions">
                    <button onclick="acceptItem('media', ${m.id}, this)" class="admin-action accept" title="Принять">✓</button>
                    <button onclick="rejectItem('media', ${m.id}, this)" class="admin-action reject" title="Отклонить">✗</button>
                    <button onclick="showResponseModal('media', ${m.id}, '${m.nick}', '${platformName} ЗАЯВКА')" class="admin-action respond" title="Ответить">📝</button>
                </div>
            </div>
        `;
    });
    
    list.innerHTML = html;
}

// ==============================================
// ЗАГРУЗКА ХЕЛПЕРОВ
// ==============================================

function loadApplications() {
    const list = document.getElementById('applicationsList');
    
    if (helpers.length === 0) {
        list.innerHTML = '<div class="empty-list">📭 Нет анкет</div>';
        return;
    }
    
    let html = '';
    helpers.forEach(h => {
        const statusClass = h.status === 'НОВАЯ' ? 'status-new' : h.status === 'ПРИНЯТО' ? 'status-accepted' : 'status-rejected';
        
        html += `
            <div class="admin-card" data-id="${h.id}" data-type="helper">
                <div class="admin-card-header">
                    <div class="admin-card-title">
                        <span class="card-icon">👮</span>
                        <h3>АНКЕТА НА ХЕЛПЕРА</h3>
                    </div>
                    <span class="admin-status ${statusClass}">${h.status}</span>
                </div>
                
                <div class="admin-card-body">
                    <p><strong>Ник:</strong> ${h.nick}</p>
                    <p><strong>Имя:</strong> ${h.name}</p>
                    <p><strong>Возраст:</strong> ${h.age}</p>
                    <p><strong>Часовой пояс:</strong> ${h.tz}</p>
                    <p><strong>Опыт:</strong> ${h.exp}</p>
                    <p><strong>Мотивация:</strong> ${h.why}</p>
                    <p><strong>Дата:</strong> ${h.date}</p>
                </div>
                
                <div class="admin-card-actions">
                    <button onclick="acceptItem('helper', ${h.id}, this)" class="admin-action accept" title="Принять">✓</button>
                    <button onclick="rejectItem('helper', ${h.id}, this)" class="admin-action reject" title="Отклонить">✗</button>
                    <button onclick="showResponseModal('helper', ${h.id}, '${h.nick}', 'АНКЕТА НА ХЕЛПЕРА')" class="admin-action respond" title="Ответить">📝</button>
                </div>
            </div>
        `;
    });
    
    list.innerHTML = html;
}

// ==============================================
// ДЕЙСТВИЯ
// ==============================================

function acceptItem(type, id, btn) {
    const card = btn.closest('.admin-card');
    const statusBadge = card.querySelector('.admin-status');
    
    let array;
    switch(type) {
        case 'complaint': array = complaints; break;
        case 'media': array = media; break;
        case 'helper': array = helpers; break;
    }
    
    const item = array.find(i => i.id === id);
    if (item) {
        item.status = 'ПРИНЯТО';
        localStorage.setItem(`mg_${type === 'helper' ? 'helpers' : type + 's'}`, JSON.stringify(array));
    }
    
    statusBadge.textContent = 'ПРИНЯТО';
    statusBadge.className = 'admin-status status-accepted';
    
    showNotification('✅ Заявка принята');
    loadStats();
}

function rejectItem(type, id, btn) {
    const card = btn.closest('.admin-card');
    const statusBadge = card.querySelector('.admin-status');
    
    let array;
    switch(type) {
        case 'complaint': array = complaints; break;
        case 'media': array = media; break;
        case 'helper': array = helpers; break;
    }
    
    const item = array.find(i => i.id === id);
    if (item) {
        item.status = 'ОТКЛОНЕНО';
        localStorage.setItem(`mg_${type === 'helper' ? 'helpers' : type + 's'}`, JSON.stringify(array));
    }
    
    statusBadge.textContent = 'ОТКЛОНЕНО';
    statusBadge.className = 'admin-status status-rejected';
    
    showNotification('❌ Заявка отклонена');
    loadStats();
}

// ==============================================
// УВЕДОМЛЕНИЯ
// ==============================================

function showNotification(message) {
    const notification = document.createElement('div');
    notification.className = 'admin-notification';
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: #4a4a8a;
        color: white;
        padding: 10px 20px;
        border-radius: 5px;
        z-index: 10000;
        animation: slideIn 0.3s;
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

// ==============================================
// МОДАЛКА ОТВЕТА
// ==============================================

function showResponseModal(type, id, user, topic) {
    currentActionId = id;
    currentActionType = type;
    
    document.getElementById('responseId').value = id;
    document.getElementById('responseType').value = type;
    document.getElementById('responseUser').textContent = user;
    document.getElementById('responseTopic').textContent = topic;
    document.getElementById('responseText').value = '';
    
    document.getElementById('responseModal').style.display = 'flex';
}

function closeResponseModal() {
    document.getElementById('responseModal').style.display = 'none';
}

function sendResponse(event) {
    event.preventDefault();
    
    const response = document.getElementById('responseText').value;
    
    if (!response.trim()) {
        alert('Введите текст ответа');
        return;
    }
    
    alert('📨 Ответ отправлен');
    closeResponseModal();
}

// ==============================================
// МОДАЛКА ПОДТВЕРЖДЕНИЯ
// ==============================================

let confirmCallback = null;

function showConfirm(message, callback) {
    confirmCallback = callback;
    document.getElementById('confirmMessage').textContent = message;
    document.getElementById('confirmModal').style.display = 'flex';
}

function confirmAction() {
    if (confirmCallback) confirmCallback();
    closeConfirmModal();
}

function closeConfirmModal() {
    document.getElementById('confirmModal').style.display = 'none';
    confirmCallback = null;
}

// ==============================================
// ВЫХОД
// ==============================================

function logout() {
    showConfirm('Выйти из админ панели?', () => {
        window.location.href = 'index.html';
    });
}

// ==============================================
// ИНИЦИАЛИЗАЦИЯ
// ==============================================

document.addEventListener('DOMContentLoaded', function() {
    if (!checkAdminAccess()) return;
    
    loadStats();
    loadComplaints();
    
    // Добавляем стили
    const style = document.createElement('style');
    style.textContent = `
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: rgba(26, 26, 58, 0.8);
            border: 2px solid #4a4a8a;
            border-radius: 20px;
            padding: 20px;
            display: flex;
            align-items: center;
            gap: 15px;
            backdrop-filter: blur(5px);
        }
        
        .stat-icon {
            font-size: 32px;
        }
        
        .stat-info h3 {
            color: #8a8aff;
            font-size: 11px;
            margin-bottom: 5px;
        }
        
        .stat-number {
            color: white;
            font-size: 28px;
            font-weight: bold;
        }
        
        .admin-tabs {
            display: flex;
            gap: 15px;
            margin-bottom: 25px;
        }
        
        .tab-btn {
            flex: 1;
            background: rgba(42, 42, 74, 0.8);
            border: 2px solid #4a4a8a;
            color: #b0b0ff;
            padding: 15px;
            border-radius: 50px;
            cursor: pointer;
            font-family: 'Press Start 2P', cursive;
            font-size: 11px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            transition: all 0.3s;
        }
        
        .tab-btn:hover {
            background: #4a4a8a;
            color: white;
        }
        
        .tab-btn.active {
            background: linear-gradient(135deg, #4a4a8a, #6a6aaa);
            color: white;
            box-shadow: 0 0 25px #7a7aff;
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
            background: rgba(42, 42, 74, 0.8);
            border: 2px solid #4a4a8a;
            color: white;
            padding: 10px 20px;
            border-radius: 30px;
            cursor: pointer;
            font-family: 'Press Start 2P', cursive;
            font-size: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.3s;
        }
        
        .admin-refresh-btn:hover {
            background: #4a4a8a;
            box-shadow: 0 0 20px #7a7aff;
        }
        
        .admin-card {
            background: rgba(26, 26, 58, 0.8);
            border: 2px solid #4a4a8a;
            border-radius: 20px;
            padding: 25px;
            margin-bottom: 20px;
            backdrop-filter: blur(5px);
            transition: all 0.3s;
        }
        
        .admin-card:hover {
            transform: translateX(10px);
            box-shadow: -10px 10px 30px rgba(122, 122, 255, 0.3);
            border-color: #8a8aff;
        }
        
        .admin-card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #4a4a8a;
        }
        
        .admin-card-title {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .card-icon {
            font-size: 20px;
        }
        
        .admin-card-title h3 {
            color: #b0b0ff;
            font-size: 13px;
        }
        
        .admin-status {
            padding: 5px 15px;
            border-radius: 30px;
            font-size: 10px;
            font-weight: bold;
        }
        
        .status-new {
            background: #4a4a8a;
            color: white;
            box-shadow: 0 0 15px #4a4a8a;
        }
        
        .status-accepted {
            background: #4a9a7a;
            color: white;
            box-shadow: 0 0 15px #4a9a7a;
        }
        
        .status-rejected {
            background: #9a4a4a;
            color: white;
            box-shadow: 0 0 15px #9a4a4a;
        }
        
        .admin-card-body {
            margin-bottom: 20px;
        }
        
        .admin-card-body p {
            color: #c0c0ff;
            font-size: 11px;
            margin: 8px 0;
        }
        
        .admin-card-body strong {
            color: #b0b0ff;
            min-width: 90px;
            display: inline-block;
        }
        
        .admin-card-body a {
            color: #8a8aff;
            text-decoration: none;
        }
        
        .admin-card-body a:hover {
            text-decoration: underline;
        }
        
        .admin-card-actions {
            display: flex;
            gap: 15px;
            justify-content: flex-end;
            border-top: 2px solid #4a4a8a;
            padding-top: 20px;
        }
        
        .admin-action {
            width: 45px;
            height: 45px;
            border-radius: 50%;
            border: 2px solid;
            background: rgba(42, 42, 74, 0.8);
            cursor: pointer;
            font-size: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s;
        }
        
        .admin-action.accept {
            color: #4aff7a;
            border-color: #4aff7a;
        }
        
        .admin-action.accept:hover {
            background: #4aff7a;
            color: #1a1a3a;
            transform: scale(1.1);
            box-shadow: 0 0 20px #4aff7a;
        }
        
        .admin-action.reject {
            color: #ff4a4a;
            border-color: #ff4a4a;
        }
        
        .admin-action.reject:hover {
            background: #ff4a4a;
            color: #1a1a3a;
            transform: scale(1.1);
            box-shadow: 0 0 20px #ff4a4a;
        }
        
        .admin-action.respond {
            color: #8a8aff;
            border-color: #8a8aff;
        }
        
        .admin-action.respond:hover {
            background: #8a8aff;
            color: #1a1a3a;
            transform: scale(1.1);
            box-shadow: 0 0 20px #8a8aff;
        }
        
        .response-info {
            background: rgba(42, 42, 74, 0.8);
            padding: 12px;
            border-radius: 10px;
            color: #b0b0ff;
            border: 1px solid #4a4a8a;
        }
        
        .action-group {
            display: flex;
            gap: 15px;
            margin-top: 20px;
        }
        
        .cancel-btn {
            background: linear-gradient(135deg, #8a4a4a, #aa6a6a) !important;
        }
        
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
    `;
    
    document.head.appendChild(style);
});

// Закрытие модалок по клику вне
window.onclick = function(event) {
    const responseModal = document.getElementById('responseModal');
    const confirmModal = document.getElementById('confirmModal');
    
    if (event.target === responseModal) closeResponseModal();
    if (event.target === confirmModal) closeConfirmModal();
}

<script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>
<script src="db.js"></script>
<script src="admin.js"></script>
