// ==============================================
// MOONGRIEF-FORUM - АДМИН ПАНЕЛЬ (ИСПРАВЛЕНО)
// ==============================================

console.log('✅ admin.js загружается...');

// Глобальные функции для HTML
window.showAdminTab = showAdminTab;
window.loadComplaints = loadComplaints;
window.loadMedia = loadMedia;
window.loadApplications = loadApplications;
window.updateStatus = updateStatus;
window.copyIP = copyIP;
window.logout = logout;
window.showResponseModal = showResponseModal;
window.closeResponseModal = closeResponseModal;
window.sendResponse = sendResponse;
window.confirmAction = confirmAction;
window.closeConfirmModal = closeConfirmModal;

// Данные
let complaints = [];
let media = [];
let helpers = [];
let currentAdmin = null;
let currentActionId = null;
let currentActionType = null;
let confirmCallback = null;

// Админы
const ADMINS = ['milfa', 'milk123', 'Xchik_'];

// ==============================================
// ИНИЦИАЛИЗАЦИЯ
// ==============================================

document.addEventListener('DOMContentLoaded', async function() {
    console.log('🚀 Запуск админ панели...');
    
    // Загружаем текущего пользователя
    const savedUser = localStorage.getItem('mg_currentUser');
    if (savedUser) {
        currentAdmin = JSON.parse(savedUser);
        console.log('👤 Текущий пользователь:', currentAdmin);
    }
    
    // Проверяем доступ
    if (!currentAdmin || !ADMINS.includes(currentAdmin.username)) {
        console.log('❌ Нет доступа');
        window.location.href = 'index.html';
        return;
    }
    
    // Отображаем имя админа
    const adminNameEl = document.getElementById('adminName');
    if (adminNameEl) adminNameEl.textContent = `🌙 ${currentAdmin.username}`;
    
    // Загружаем данные
    await loadAllData();
});

// ==============================================
// ЗАГРУЗКА ДАННЫХ
// ==============================================

async function loadAllData() {
    console.log('📥 Загрузка данных...');
    
    try {
        // Жалобы
        if (window.getComplaints) {
            complaints = await window.getComplaints();
            console.log('📋 Жалоб:', complaints.length);
        }
        
        // Медиа
        if (window.getMediaApplications) {
            media = await window.getMediaApplications();
            console.log('📋 Медиа:', media.length);
        }
        
        // Хелперы
        if (window.getHelperApplications) {
            helpers = await window.getHelperApplications();
            console.log('📋 Хелперов:', helpers.length);
        }
        
        updateStats();
        renderComplaints();
        
    } catch (e) {
        console.error('❌ Ошибка загрузки:', e);
    }
}

// ==============================================
// СТАТИСТИКА
// ==============================================

function updateStats() {
    const newComplaints = complaints.filter(c => c.status === 'НОВАЯ').length;
    const newMedia = media.filter(m => m.status === 'НОВАЯ').length;
    const newHelpers = helpers.filter(h => h.status === 'НОВАЯ').length;
    const total = complaints.length + media.length + helpers.length;
    
    const elements = {
        statComplaints: newComplaints,
        statMedia: newMedia,
        statHelpers: newHelpers,
        statTotal: total,
        totalStats: total,
        newStats: newComplaints + newMedia + newHelpers
    };
    
    for (let [id, value] of Object.entries(elements)) {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    }
}

// ==============================================
// ПЕРЕКЛЮЧЕНИЕ ВКЛАДОК
// ==============================================

function showAdminTab(tabName) {
    console.log('🔄 Переключение на:', tabName);
    
    // Скрываем все вкладки
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    // Убираем активный класс с кнопок
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Показываем выбранную вкладку
    const tabId = 'admin' + tabName.charAt(0).toUpperCase() + tabName.slice(1);
    const tabEl = document.getElementById(tabId);
    if (tabEl) tabEl.classList.add('active');
    
    // Активируем кнопку
    if (event && event.target) {
        event.target.classList.add('active');
    }
    
    // Отрисовываем нужный контент
    if (tabName === 'complaints') renderComplaints();
    if (tabName === 'media') renderMedia();
    if (tabName === 'applications') renderHelpers();
}

// ==============================================
// ОТРИСОВКА ЖАЛОБ
// ==============================================

function renderComplaints() {
    const list = document.getElementById('complaintsList');
    if (!list) return;
    
    if (!complaints || complaints.length === 0) {
        list.innerHTML = '<div class="empty-list">📭 Нет жалоб</div>';
        return;
    }
    
    let html = '';
    complaints.forEach(c => {
        const statusClass = c.status === 'НОВАЯ' ? 'status-new' : 
                           c.status === 'ПРИНЯТО' ? 'status-accepted' : 'status-rejected';
        
        html += `
            <div class="admin-card" data-id="${c.id}">
                <div class="admin-card-header">
                    <div class="admin-card-title">
                        <span class="card-icon">⚠️</span>
                        <h3>${c.title || 'Жалоба'}</h3>
                    </div>
                    <span class="admin-status ${statusClass}">${c.status || 'НОВАЯ'}</span>
                </div>
                <div class="admin-card-body">
                    <p><strong>От:</strong> ${c.user_name || 'Неизвестно'}</p>
                    <p><strong>Нарушитель:</strong> ${c.target || 'Не указан'}</p>
                    <p><strong>Описание:</strong> ${c.description || 'Нет описания'}</p>
                    <p><strong>Дата:</strong> ${c.date || c.created_at || 'Неизвестно'}</p>
                </div>
                <div class="admin-card-actions">
                    <button onclick="updateStatus('complaint', ${c.id}, 'ПРИНЯТО')" class="admin-action accept">✓</button>
                    <button onclick="updateStatus('complaint', ${c.id}, 'ОТКЛОНЕНО')" class="admin-action reject">✗</button>
                </div>
            </div>
        `;
    });
    
    list.innerHTML = html;
}

// ==============================================
// ОТРИСОВКА МЕДИА
// ==============================================

function renderMedia() {
    const list = document.getElementById('mediaList');
    if (!list) return;
    
    if (!media || media.length === 0) {
        list.innerHTML = '<div class="empty-list">📭 Нет медиа-заявок</div>';
        return;
    }
    
    let html = '';
    media.forEach(m => {
        const statusClass = m.status === 'НОВАЯ' ? 'status-new' : 
                           m.status === 'ПРИНЯТО' ? 'status-accepted' : 'status-rejected';
        
        html += `
            <div class="admin-card" data-id="${m.id}">
                <div class="admin-card-header">
                    <div class="admin-card-title">
                        <span class="card-icon">📱</span>
                        <h3>${m.platform === 'tt' ? 'TIKTOK' : 'YOUTUBE'} ЗАЯВКА</h3>
                    </div>
                    <span class="admin-status ${statusClass}">${m.status || 'НОВАЯ'}</span>
                </div>
                <div class="admin-card-body">
                    <p><strong>От:</strong> ${m.user_name || 'Неизвестно'}</p>
                    <p><strong>Ник:</strong> ${m.nickname || 'Не указан'}</p>
                    <p><strong>Подписчики:</strong> ${m.subscribers || '0'}</p>
                    <p><strong>Дата:</strong> ${m.date || m.created_at || 'Неизвестно'}</p>
                </div>
                <div class="admin-card-actions">
                    <button onclick="updateStatus('media', ${m.id}, 'ПРИНЯТО')" class="admin-action accept">✓</button>
                    <button onclick="updateStatus('media', ${m.id}, 'ОТКЛОНЕНО')" class="admin-action reject">✗</button>
                </div>
            </div>
        `;
    });
    
    list.innerHTML = html;
}

// ==============================================
// ОТРИСОВКА ХЕЛПЕРОВ
// ==============================================

function renderHelpers() {
    const list = document.getElementById('applicationsList');
    if (!list) return;
    
    if (!helpers || helpers.length === 0) {
        list.innerHTML = '<div class="empty-list">📭 Нет заявок на хелпера</div>';
        return;
    }
    
    let html = '';
    helpers.forEach(h => {
        const statusClass = h.status === 'НОВАЯ' ? 'status-new' : 
                           h.status === 'ПРИНЯТО' ? 'status-accepted' : 'status-rejected';
        
        html += `
            <div class="admin-card" data-id="${h.id}">
                <div class="admin-card-header">
                    <div class="admin-card-title">
                        <span class="card-icon">👮</span>
                        <h3>АНКЕТА НА ХЕЛПЕРА</h3>
                    </div>
                    <span class="admin-status ${statusClass}">${h.status || 'НОВАЯ'}</span>
                </div>
                <div class="admin-card-body">
                    <p><strong>От:</strong> ${h.user_name || 'Неизвестно'}</p>
                    <p><strong>Ник:</strong> ${h.nickname || 'Не указан'}</p>
                    <p><strong>Возраст:</strong> ${h.age || 'Не указан'}</p>
                    <p><strong>Дата:</strong> ${h.date || h.created_at || 'Неизвестно'}</p>
                </div>
                <div class="admin-card-actions">
                    <button onclick="updateStatus('helper', ${h.id}, 'ПРИНЯТО')" class="admin-action accept">✓</button>
                    <button onclick="updateStatus('helper', ${h.id}, 'ОТКЛОНЕНО')" class="admin-action reject">✗</button>
                </div>
            </div>
        `;
    });
    
    list.innerHTML = html;
}

// ==============================================
// ОБНОВЛЕНИЕ СТАТУСА
// ==============================================

async function updateStatus(type, id, newStatus) {
    console.log(`🔄 Обновление ${type} #${id} -> ${newStatus}`);
    
    let success = false;
    
    if (type === 'complaint' && window.updateComplaintStatus) {
        success = await window.updateComplaintStatus(id, newStatus);
    }
    if (type === 'media' && window.updateMediaStatus) {
        success = await window.updateMediaStatus(id, newStatus);
    }
    if (type === 'helper' && window.updateHelperStatus) {
        success = await window.updateHelperStatus(id, newStatus);
    }
    
    if (success) {
        alert(`✅ Статус изменен на ${newStatus}`);
        await loadAllData();
    } else {
        alert('❌ Ошибка обновления');
    }
}

// ==============================================
// ЗАГРУЗКА ПО КНОПКАМ
// ==============================================

async function loadComplaints() {
    await loadAllData();
    renderComplaints();
}

async function loadMedia() {
    await loadAllData();
    renderMedia();
}

async function loadApplications() {
    await loadAllData();
    renderHelpers();
}

// ==============================================
// МОДАЛКИ
// ==============================================

function showResponseModal(type, id, user, topic) {
    currentActionId = id;
    currentActionType = type;
    
    const userEl = document.getElementById('responseUser');
    const topicEl = document.getElementById('responseTopic');
    if (userEl) userEl.textContent = user;
    if (topicEl) topicEl.textContent = topic;
    
    const modal = document.getElementById('responseModal');
    if (modal) modal.style.display = 'flex';
}

function closeResponseModal() {
    const modal = document.getElementById('responseModal');
    if (modal) modal.style.display = 'none';
}

function sendResponse(event) {
    if (event) event.preventDefault();
    
    const text = document.getElementById('responseText');
    if (text && text.value.trim()) {
        alert('📨 Ответ отправлен');
        closeResponseModal();
        text.value = '';
    } else {
        alert('Введите текст ответа');
    }
}

function showConfirm(message, callback) {
    confirmCallback = callback;
    const msgEl = document.getElementById('confirmMessage');
    if (msgEl) msgEl.textContent = message;
    
    const modal = document.getElementById('confirmModal');
    if (modal) modal.style.display = 'flex';
}

function confirmAction() {
    if (confirmCallback) confirmCallback();
    closeConfirmModal();
}

function closeConfirmModal() {
    const modal = document.getElementById('confirmModal');
    if (modal) modal.style.display = 'none';
    confirmCallback = null;
}

// ==============================================
// IP И ВЫХОД
// ==============================================

function copyIP() {
    navigator.clipboard.writeText('Moongrief.aurorix.pro');
    alert('📋 IP скопирован!');
}

function logout() {
    if (confirm('Выйти из админ панели?')) {
        window.location.href = 'index.html';
    }
}
