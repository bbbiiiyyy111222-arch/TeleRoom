// ==============================================
// АДМИН ПАНЕЛЬ MOONGRIEF - ПОЛНАЯ РАБОЧАЯ ВЕРСИЯ
// ==============================================

let complaints = [];
let applications = [];
let currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;
const OWNERS = ['milfa', 'milk123', 'Xchik_'];

// Загрузка
document.addEventListener('DOMContentLoaded', async function() {
    if (!currentUser || !OWNERS.includes(currentUser.username)) {
        alert('🌙 У вас нет доступа!');
        window.location.href = 'index.html';
        return;
    }
    
    document.getElementById('adminName').innerHTML = `🌙 ${currentUser.username} (OWNER)`;
    await loadAdminData();
    startAutoUpdate();
});

// Автообновление
let updateInterval;
function startAutoUpdate() {
    if (updateInterval) clearInterval(updateInterval);
    updateInterval = setInterval(async () => {
        await loadAdminData();
    }, 20000);
}

// Выход
function logout() {
    localStorage.removeItem('currentUser');
    window.location.href = 'index.html';
}

// Загрузка данных
async function loadAdminData() {
    await loadComplaints();
    await loadApplications();
    updateStats();
}

// Статистика
async function updateStats() {
    complaints = await window.getComplaints() || [];
    applications = await window.getApplications() || [];
    
    document.getElementById('newComplaints').innerHTML = complaints.filter(c => c.status === 'new').length;
    document.getElementById('newApplications').innerHTML = applications.filter(a => a.status === 'new').length;
    document.getElementById('total').innerHTML = complaints.length + applications.length;
}

// ==============================================
// ЗАГРУЗКА ЖАЛОБ
// ==============================================

async function loadComplaints() {
    const container = document.getElementById('adminComplaints');
    if (!container) return;
    
    complaints = await window.getComplaints() || [];
    
    if (complaints.length === 0) {
        container.innerHTML = `
            <div class="moon-empty">
                <div class="moon-empty-icon">🌙</div>
                <h3>НЕТ ЖАЛОБ</h3>
                <p>Пока никто не подавал жалоб</p>
            </div>
        `;
        return;
    }
    
    let html = '';
    complaints.sort((a, b) => new Date(b.date) - new Date(a.date)).forEach(c => {
        html += createComplaintCard(c);
    });
    
    container.innerHTML = html;
}

// ==============================================
// ЗАГРУЗКА АНКЕТ
// ==============================================

async function loadApplications() {
    const container = document.getElementById('adminApplications');
    if (!container) return;
    
    applications = await window.getApplications() || [];
    
    if (applications.length === 0) {
        container.innerHTML = `
            <div class="moon-empty">
                <div class="moon-empty-icon">🌙</div>
                <h3>НЕТ АНКЕТ</h3>
                <p>Пока никто не подавал заявки</p>
            </div>
        `;
        return;
    }
    
    let html = '';
    applications.sort((a, b) => new Date(b.date) - new Date(a.date)).forEach(a => {
        html += createApplicationCard(a);
    });
    
    container.innerHTML = html;
}

// ==============================================
// КАРТОЧКА ЖАЛОБЫ
// ==============================================

function createComplaintCard(c) {
    let statusClass = '';
    let statusText = '';
    let statusIcon = '';
    let buttons = '';
    
    switch(c.status) {
        case 'new':
            statusClass = 'status-new';
            statusText = 'НОВАЯ';
            statusIcon = '🆕';
            buttons = `
                <button onclick="acceptComplaint(${c.id})" class="moon-btn moon-btn-accept">
                    <span>✅</span> ПРИНЯТЬ
                </button>
                <button onclick="rejectComplaint(${c.id})" class="moon-btn moon-btn-reject">
                    <span>❌</span> ОТКЛОНИТЬ
                </button>
                <button onclick="openResponseModal('complaint', ${c.id})" class="moon-btn moon-btn-respond">
                    <span>📝</span> ОТВЕТИТЬ
                </button>
            `;
            break;
        case 'accepted':
            statusClass = 'status-accepted';
            statusText = 'ПРИНЯТА';
            statusIcon = '✅';
            buttons = `
                <span class="moon-badge moon-badge-accepted">✓ ПРИНЯТО</span>
                <button onclick="openResponseModal('complaint', ${c.id})" class="moon-btn moon-btn-respond small">
                    <span>📝</span> ОТВЕТИТЬ
                </button>
            `;
            break;
        case 'rejected':
            statusClass = 'status-rejected';
            statusText = 'ОТКЛОНЕНА';
            statusIcon = '❌';
            buttons = `
                <span class="moon-badge moon-badge-rejected">✗ ОТКЛОНЕНО</span>
                <button onclick="openResponseModal('complaint', ${c.id})" class="moon-btn moon-btn-respond small">
                    <span>📝</span> ОТВЕТИТЬ
                </button>
            `;
            break;
        case 'resolved':
            statusClass = 'status-resolved';
            statusText = 'ОТВЕЧЕНО';
            statusIcon = '📝';
            buttons = `
                <span class="moon-badge moon-badge-resolved">✓ ОТВЕЧЕНО</span>
                <button onclick="openResponseModal('complaint', ${c.id})" class="moon-btn moon-btn-respond small">
                    <span>📝</span> ОТВЕТИТЬ СНОВА
                </button>
            `;
            break;
    }
    
    return `
        <div class="moon-card">
            <div class="moon-card-header">
                <div class="moon-card-title">
                    <span class="moon-card-icon">⚠️</span>
                    <span>${c.title || 'Жалоба'}</span>
                </div>
                <div class="moon-status ${statusClass}">
                    <span class="moon-status-icon">${statusIcon}</span>
                    <span class="moon-status-text">${statusText}</span>
                </div>
            </div>
            
            <div class="moon-card-body">
                <div class="moon-info-row">
                    <span class="moon-info-label">👤 От:</span>
                    <span class="moon-info-value">${c.author}</span>
                </div>
                <div class="moon-info-row">
                    <span class="moon-info-label">🎯 На:</span>
                    <span class="moon-info-value">${c.against}</span>
                </div>
                <div class="moon-info-row moon-info-full">
                    <span class="moon-info-label">📝 Описание:</span>
                    <span class="moon-info-value">${c.description}</span>
                </div>
                <div class="moon-info-row">
                    <span class="moon-info-label">📅 Дата:</span>
                    <span class="moon-info-value">${new Date(c.date).toLocaleString()}</span>
                </div>
                
                ${c.response ? `
                <div class="moon-response">
                    <div class="moon-response-label">💬 Ответ:</div>
                    <div class="moon-response-text">${c.response}</div>
                </div>
                ` : ''}
            </div>
            
            <div class="moon-card-footer">
                <div class="moon-button-group">
                    ${buttons}
                </div>
            </div>
        </div>
    `;
}

// ==============================================
// КАРТОЧКА АНКЕТЫ
// ==============================================

function createApplicationCard(a) {
    let statusClass = '';
    let statusText = '';
    let statusIcon = '';
    let buttons = '';
    
    switch(a.status) {
        case 'new':
            statusClass = 'status-new';
            statusText = 'НОВАЯ';
            statusIcon = '🆕';
            buttons = `
                <button onclick="acceptApplication(${a.id})" class="moon-btn moon-btn-accept">
                    <span>✅</span> ПРИНЯТЬ
                </button>
                <button onclick="rejectApplication(${a.id})" class="moon-btn moon-btn-reject">
                    <span>❌</span> ОТКЛОНИТЬ
                </button>
                <button onclick="openResponseModal('application', ${a.id})" class="moon-btn moon-btn-respond">
                    <span>📝</span> ОТВЕТИТЬ
                </button>
            `;
            break;
        case 'accepted':
            statusClass = 'status-accepted';
            statusText = 'ПРИНЯТА';
            statusIcon = '✅';
            buttons = `
                <span class="moon-badge moon-badge-accepted">✓ ПРИНЯТО</span>
                <button onclick="openResponseModal('application', ${a.id})" class="moon-btn moon-btn-respond small">
                    <span>📝</span> ОТВЕТИТЬ
                </button>
            `;
            break;
        case 'rejected':
            statusClass = 'status-rejected';
            statusText = 'ОТКЛОНЕНА';
            statusIcon = '❌';
            buttons = `
                <span class="moon-badge moon-badge-rejected">✗ ОТКЛОНЕНО</span>
                <button onclick="openResponseModal('application', ${a.id})" class="moon-btn moon-btn-respond small">
                    <span>📝</span> ОТВЕТИТЬ
                </button>
            `;
            break;
        case 'resolved':
            statusClass = 'status-resolved';
            statusText = 'ОТВЕЧЕНО';
            statusIcon = '📝';
            buttons = `
                <span class="moon-badge moon-badge-resolved">✓ ОТВЕЧЕНО</span>
                <button onclick="openResponseModal('application', ${a.id})" class="moon-btn moon-btn-respond small">
                    <span>📝</span> ОТВЕТИТЬ СНОВА
                </button>
            `;
            break;
    }
    
    return `
        <div class="moon-card">
            <div class="moon-card-header">
                <div class="moon-card-title">
                    <span class="moon-card-icon">👮</span>
                    <span>АНКЕТА НА ХЕЛПЕРА</span>
                </div>
                <div class="moon-status ${statusClass}">
                    <span class="moon-status-icon">${statusIcon}</span>
                    <span class="moon-status-text">${statusText}</span>
                </div>
            </div>
            
            <div class="moon-card-body">
                <div class="moon-info-row">
                    <span class="moon-info-label">🎮 Ник:</span>
                    <span class="moon-info-value">${a.nickname || 'Нет'}</span>
                </div>
                <div class="moon-info-row">
                    <span class="moon-info-label">👤 Имя:</span>
                    <span class="moon-info-value">${a.name || 'Нет'}</span>
                </div>
                <div class="moon-info-row">
                    <span class="moon-info-label">📅 Возраст:</span>
                    <span class="moon-info-value">${a.age || 'Нет'}</span>
                </div>
                <div class="moon-info-row">
                    <span class="moon-info-label">🌍 Часовой пояс:</span>
                    <span class="moon-info-value">${a.timezone || 'Нет'}</span>
                </div>
                <div class="moon-info-row moon-info-full">
                    <span class="moon-info-label">💼 Опыт:</span>
                    <span class="moon-info-value">${a.experience || 'Нет'}</span>
                </div>
                <div class="moon-info-row moon-info-full">
                    <span class="moon-info-label">❓ Мотивация:</span>
                    <span class="moon-info-value">${a.reason || 'Нет'}</span>
                </div>
                ${a.additional ? `
                <div class="moon-info-row moon-info-full">
                    <span class="moon-info-label">📝 Дополнительно:</span>
                    <span class="moon-info-value">${a.additional}</span>
                </div>
                ` : ''}
                <div class="moon-info-row">
                    <span class="moon-info-label">👤 От:</span>
                    <span class="moon-info-value">${a.author || 'Нет'}</span>
                </div>
                <div class="moon-info-row">
                    <span class="moon-info-label">📅 Дата:</span>
                    <span class="moon-info-value">${new Date(a.date).toLocaleString()}</span>
                </div>
                
                ${a.response ? `
                <div class="moon-response">
                    <div class="moon-response-label">💬 Ответ:</div>
                    <div class="moon-response-text">${a.response}</div>
                </div>
                ` : ''}
            </div>
            
            <div class="moon-card-footer">
                <div class="moon-button-group">
                    ${buttons}
                </div>
            </div>
        </div>
    `;
}

// ==============================================
// ДЕЙСТВИЯ С ЖАЛОБАМИ
// ==============================================

async function acceptComplaint(id) {
    const complaint = complaints.find(c => c.id === id);
    if (!complaint) return;
    
    if (complaint.status !== 'new') {
        alert('❌ Эту жалобу уже обработали!');
        return;
    }
    
    const result = await window.updateComplaint(id, { status: 'accepted' });
    if (result) {
        await loadAdminData();
        showNotification('✅ Жалоба принята', 'success');
    }
}

async function rejectComplaint(id) {
    const complaint = complaints.find(c => c.id === id);
    if (!complaint) return;
    
    if (complaint.status !== 'new') {
        alert('❌ Эту жалобу уже обработали!');
        return;
    }
    
    const result = await window.updateComplaint(id, { status: 'rejected' });
    if (result) {
        await loadAdminData();
        showNotification('❌ Жалоба отклонена', 'error');
    }
}

// ==============================================
// ДЕЙСТВИЯ С АНКЕТАМИ
// ==============================================

async function acceptApplication(id) {
    const application = applications.find(a => a.id === id);
    if (!application) return;
    
    if (application.status !== 'new') {
        alert('❌ Эту анкету уже обработали!');
        return;
    }
    
    const result = await window.updateApplication(id, { status: 'accepted' });
    if (result) {
        await loadAdminData();
        showNotification('✅ Анкета принята', 'success');
    }
}

async function rejectApplication(id) {
    const application = applications.find(a => a.id === id);
    if (!application) return;
    
    if (application.status !== 'new') {
        alert('❌ Эту анкету уже обработали!');
        return;
    }
    
    const result = await window.updateApplication(id, { status: 'rejected' });
    if (result) {
        await loadAdminData();
        showNotification('❌ Анкета отклонена', 'error');
    }
}

// ==============================================
// МОДАЛКА ОТВЕТА
// ==============================================

function openResponseModal(type, id) {
    document.getElementById('responseModal').style.display = 'block';
    document.getElementById('responseId').value = id;
    document.getElementById('responseType').value = type;
    
    const title = type === 'complaint' ? 'ОТВЕТ НА ЖАЛОБУ' : 'ОТВЕТ НА АНКЕТУ';
    document.querySelector('#responseModal h2').innerHTML = `🌙 ${title}`;
}

function closeResponseModal() {
    document.getElementById('responseModal').style.display = 'none';
    document.getElementById('responseForm').reset();
}

async function sendResponse(event) {
    event.preventDefault();
    
    const id = Number(document.getElementById('responseId').value);
    const type = document.getElementById('responseType').value;
    const response = document.getElementById('responseText').value;
    
    if (!response) {
        showNotification('Введите ответ!', 'error');
        return;
    }
    
    let result;
    if (type === 'complaint') {
        result = await window.updateComplaint(id, { 
            response: response,
            status: 'resolved' 
        });
    } else {
        result = await window.updateApplication(id, { 
            response: response,
            status: 'resolved' 
        });
    }
    
    if (result) {
        closeResponseModal();
        await loadAdminData();
        showNotification('✅ Ответ отправлен', 'success');
    }
}

// ==============================================
// УВЕДОМЛЕНИЯ
// ==============================================

function showNotification(message, type) {
    const notification = document.createElement('div');
    notification.className = `moon-notification ${type}`;
    notification.innerHTML = `
        <span class="moon-notif-icon">${type === 'success' ? '✅' : '❌'}</span>
        <span class="moon-notif-text">${message}</span>
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.classList.add('show');
    }, 10);
    
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => {
            notification.remove();
        }, 300);
    }, 3000);
}

// ==============================================
// ПЕРЕКЛЮЧЕНИЕ ТАБОВ
// ==============================================

function showAdminTab(tabName) {
    document.querySelectorAll('.moon-tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    document.querySelectorAll('.moon-admin-content').forEach(content => {
        content.classList.remove('active');
    });
    
    event.target.classList.add('active');
    document.getElementById('admin' + tabName.charAt(0).toUpperCase() + tabName.slice(1)).classList.add('active');
}
