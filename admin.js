// ==============================================
// АДМИН ПАНЕЛЬ MOONGRIEF - КРАСИВЫЕ МАЛЕНЬКИЕ КНОПКИ
// ==============================================

let complaints = [];
let applications = [];
let currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;
const OWNERS = ['milfa', 'milk123', 'Xchik_'];

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

let updateInterval;
function startAutoUpdate() {
    if (updateInterval) clearInterval(updateInterval);
    updateInterval = setInterval(async () => {
        await loadAdminData();
    }, 20000);
}

function logout() {
    localStorage.removeItem('currentUser');
    window.location.href = 'index.html';
}

async function loadAdminData() {
    await loadComplaints();
    await loadApplications();
    updateStats();
}

async function updateStats() {
    complaints = await window.getComplaints() || [];
    applications = await window.getApplications() || [];
    
    document.getElementById('newComplaints').innerHTML = complaints.filter(c => c.status === 'new').length;
    document.getElementById('newApplications').innerHTML = applications.filter(a => a.status === 'new').length;
    document.getElementById('total').innerHTML = complaints.length + applications.length;
}

async function loadComplaints() {
    const container = document.getElementById('adminComplaints');
    if (!container) return;
    
    complaints = await window.getComplaints() || [];
    
    if (complaints.length === 0) {
        container.innerHTML = `<div class="empty-state">🌙 <h3>Нет жалоб</h3></div>`;
        return;
    }
    
    let html = '';
    complaints.sort((a, b) => new Date(b.date) - new Date(a.date)).forEach(c => {
        html += createComplaintCard(c);
    });
    
    container.innerHTML = html;
}

async function loadApplications() {
    const container = document.getElementById('adminApplications');
    if (!container) return;
    
    applications = await window.getApplications() || [];
    
    if (applications.length === 0) {
        container.innerHTML = `<div class="empty-state">🌙 <h3>Нет анкет</h3></div>`;
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
    let buttons = '';
    
    switch(c.status) {
        case 'new':
            statusClass = 'status-new';
            statusText = '🆕 НОВАЯ';
            buttons = `
                <div class="action-buttons">
                    <button onclick="acceptComplaint(${c.id})" class="mini-btn accept-btn" title="Принять">
                        <span>✅</span>
                    </button>
                    <button onclick="rejectComplaint(${c.id})" class="mini-btn reject-btn" title="Отклонить">
                        <span>❌</span>
                    </button>
                    <button onclick="openResponseModal('complaint', ${c.id})" class="mini-btn respond-btn" title="Ответить">
                        <span>📝</span>
                    </button>
                </div>
            `;
            break;
        case 'accepted':
            statusClass = 'status-accepted';
            statusText = '✅ ПРИНЯТО';
            buttons = `
                <div class="action-buttons">
                    <span class="status-badge accepted">✅ ПРИНЯТО</span>
                    <button onclick="openResponseModal('complaint', ${c.id})" class="mini-btn respond-btn" title="Ответить">
                        <span>📝</span>
                    </button>
                </div>
            `;
            break;
        case 'rejected':
            statusClass = 'status-rejected';
            statusText = '❌ ОТКЛОНЕНО';
            buttons = `
                <div class="action-buttons">
                    <span class="status-badge rejected">❌ ОТКЛОНЕНО</span>
                    <button onclick="openResponseModal('complaint', ${c.id})" class="mini-btn respond-btn" title="Ответить">
                        <span>📝</span>
                    </button>
                </div>
            `;
            break;
        case 'resolved':
            statusClass = 'status-resolved';
            statusText = '📝 ОТВЕЧЕНО';
            buttons = `
                <div class="action-buttons">
                    <span class="status-badge resolved">📝 ОТВЕЧЕНО</span>
                    <button onclick="openResponseModal('complaint', ${c.id})" class="mini-btn respond-btn" title="Ответить">
                        <span>📝</span>
                    </button>
                </div>
            `;
            break;
    }
    
    return `
        <div class="admin-card">
            <div class="card-header">
                <div class="card-title">
                    <span class="title-icon">⚠️</span>
                    <span class="title-text">${c.title || 'Жалоба'}</span>
                </div>
                <div class="card-status ${statusClass}">
                    <span class="status-icon">${statusText.split(' ')[0]}</span>
                    <span class="status-text">${statusText.split(' ')[1] || statusText}</span>
                </div>
            </div>
            
            <div class="card-body">
                <div class="info-line">
                    <span class="info-label">👤 От:</span>
                    <span class="info-value">${c.author}</span>
                </div>
                <div class="info-line">
                    <span class="info-label">🎯 На:</span>
                    <span class="info-value">${c.against}</span>
                </div>
                <div class="info-line full">
                    <span class="info-label">📝 Описание:</span>
                    <span class="info-value">${c.description}</span>
                </div>
                <div class="info-line">
                    <span class="info-label">📅 Дата:</span>
                    <span class="info-value">${new Date(c.date).toLocaleString()}</span>
                </div>
                
                ${c.response ? `
                <div class="response-block">
                    <span class="response-label">💬 Ответ:</span>
                    <span class="response-text">${c.response}</span>
                </div>
                ` : ''}
            </div>
            
            <div class="card-footer">
                ${buttons}
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
    let buttons = '';
    
    switch(a.status) {
        case 'new':
            statusClass = 'status-new';
            statusText = '🆕 НОВАЯ';
            buttons = `
                <div class="action-buttons">
                    <button onclick="acceptApplication(${a.id})" class="mini-btn accept-btn" title="Принять">
                        <span>✅</span>
                    </button>
                    <button onclick="rejectApplication(${a.id})" class="mini-btn reject-btn" title="Отклонить">
                        <span>❌</span>
                    </button>
                    <button onclick="openResponseModal('application', ${a.id})" class="mini-btn respond-btn" title="Ответить">
                        <span>📝</span>
                    </button>
                </div>
            `;
            break;
        case 'accepted':
            statusClass = 'status-accepted';
            statusText = '✅ ПРИНЯТО';
            buttons = `
                <div class="action-buttons">
                    <span class="status-badge accepted">✅ ПРИНЯТО</span>
                    <button onclick="openResponseModal('application', ${a.id})" class="mini-btn respond-btn" title="Ответить">
                        <span>📝</span>
                    </button>
                </div>
            `;
            break;
        case 'rejected':
            statusClass = 'status-rejected';
            statusText = '❌ ОТКЛОНЕНО';
            buttons = `
                <div class="action-buttons">
                    <span class="status-badge rejected">❌ ОТКЛОНЕНО</span>
                    <button onclick="openResponseModal('application', ${a.id})" class="mini-btn respond-btn" title="Ответить">
                        <span>📝</span>
                    </button>
                </div>
            `;
            break;
        case 'resolved':
            statusClass = 'status-resolved';
            statusText = '📝 ОТВЕЧЕНО';
            buttons = `
                <div class="action-buttons">
                    <span class="status-badge resolved">📝 ОТВЕЧЕНО</span>
                    <button onclick="openResponseModal('application', ${a.id})" class="mini-btn respond-btn" title="Ответить">
                        <span>📝</span>
                    </button>
                </div>
            `;
            break;
    }
    
    return `
        <div class="admin-card">
            <div class="card-header">
                <div class="card-title">
                    <span class="title-icon">👮</span>
                    <span class="title-text">АНКЕТА НА ХЕЛПЕРА</span>
                </div>
                <div class="card-status ${statusClass}">
                    <span class="status-icon">${statusText.split(' ')[0]}</span>
                    <span class="status-text">${statusText.split(' ')[1] || statusText}</span>
                </div>
            </div>
            
            <div class="card-body">
                <div class="info-line">
                    <span class="info-label">🎮 Ник:</span>
                    <span class="info-value">${a.nickname}</span>
                </div>
                <div class="info-line">
                    <span class="info-label">👤 Имя:</span>
                    <span class="info-value">${a.name}</span>
                </div>
                <div class="info-line">
                    <span class="info-label">📅 Возраст:</span>
                    <span class="info-value">${a.age}</span>
                </div>
                <div class="info-line">
                    <span class="info-label">🌍 Часовой пояс:</span>
                    <span class="info-value">${a.timezone}</span>
                </div>
                <div class="info-line full">
                    <span class="info-label">💼 Опыт:</span>
                    <span class="info-value">${a.experience}</span>
                </div>
                <div class="info-line full">
                    <span class="info-label">❓ Мотивация:</span>
                    <span class="info-value">${a.reason}</span>
                </div>
                ${a.additional ? `
                <div class="info-line full">
                    <span class="info-label">📝 Дополнительно:</span>
                    <span class="info-value">${a.additional}</span>
                </div>
                ` : ''}
                <div class="info-line">
                    <span class="info-label">👤 От:</span>
                    <span class="info-value">${a.author}</span>
                </div>
                <div class="info-line">
                    <span class="info-label">📅 Дата:</span>
                    <span class="info-value">${new Date(a.date).toLocaleString()}</span>
                </div>
                
                ${a.response ? `
                <div class="response-block">
                    <span class="response-label">💬 Ответ:</span>
                    <span class="response-text">${a.response}</span>
                </div>
                ` : ''}
            </div>
            
            <div class="card-footer">
                ${buttons}
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
    notification.className = `notification ${type}`;
    notification.innerHTML = `
        <span class="notif-icon">${type === 'success' ? '✅' : '❌'}</span>
        <span class="notif-text">${message}</span>
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
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    
    event.target.classList.add('active');
    document.getElementById('admin' + tabName.charAt(0).toUpperCase() + tabName.slice(1)).classList.add('active');
}
