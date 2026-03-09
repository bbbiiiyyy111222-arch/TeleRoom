// ==============================================
// АДМИН ПАНЕЛЬ BLADEBOX - С МЕДИА-ЗАЯВКАМИ
// ==============================================

let complaints = [];
let mediaApplications = [];
let applications = [];
let currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;
const OWNERS = ['milfa', 'milk123', 'Xchik_'];

document.addEventListener('DOMContentLoaded', async function() {
    if (!currentUser || !OWNERS.includes(currentUser.username)) {
        alert('⚔️ У вас нет доступа!');
        window.location.href = 'index.html';
        return;
    }
    
    document.getElementById('adminName').innerHTML = `⚔️ ${currentUser.username} (OWNER)`;
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
    await loadMediaApplications();
    await loadApplications();
    updateStats();
}

async function updateStats() {
    complaints = await window.getComplaints() || [];
    mediaApplications = await window.getMediaApplications() || [];
    applications = await window.getApplications() || [];
    
    document.getElementById('newComplaints').innerHTML = complaints.filter(c => c.status === 'new').length;
    document.getElementById('newApplications').innerHTML = applications.filter(a => a.status === 'new').length;
    document.getElementById('total').innerHTML = complaints.length + mediaApplications.length + applications.length;
}

async function loadComplaints() {
    const container = document.getElementById('adminComplaints');
    if (!container) return;
    
    complaints = await window.getComplaints() || [];
    
    if (complaints.length === 0) {
        container.innerHTML = `<div class="empty-state">⚔️ <h3>Нет жалоб</h3></div>`;
        return;
    }
    
    let html = '';
    complaints.sort((a, b) => new Date(b.date) - new Date(a.date)).forEach(c => {
        html += createComplaintCard(c);
    });
    
    container.innerHTML = html;
}

async function loadMediaApplications() {
    const container = document.getElementById('adminMedia');
    if (!container) return;
    
    mediaApplications = await window.getMediaApplications() || [];
    
    if (mediaApplications.length === 0) {
        container.innerHTML = `<div class="empty-state">📱 <h3>Нет медиа-заявок</h3></div>`;
        return;
    }
    
    let html = '';
    mediaApplications.sort((a, b) => new Date(b.date) - new Date(a.date)).forEach(m => {
        html += createMediaCard(m);
    });
    
    container.innerHTML = html;
}

async function loadApplications() {
    const container = document.getElementById('adminApplications');
    if (!container) return;
    
    applications = await window.getApplications() || [];
    
    if (applications.length === 0) {
        container.innerHTML = `<div class="empty-state">👮 <h3>Нет анкет</h3></div>`;
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
                <div class="action-group">
                    <button onclick="acceptComplaint(${c.id})" class="mini-btn accept-btn" title="Принять">✅</button>
                    <button onclick="rejectComplaint(${c.id})" class="mini-btn reject-btn" title="Отклонить">❌</button>
                    <button onclick="openResponseModal('complaint', ${c.id})" class="mini-btn respond-btn" title="Ответить">📝</button>
                </div>
            `;
            break;
        case 'accepted':
            statusClass = 'status-accepted';
            statusText = '✅ ПРИНЯТО';
            buttons = `
                <div class="action-group">
                    <span class="status-badge accepted">✅ Принято</span>
                    <button onclick="openResponseModal('complaint', ${c.id})" class="mini-btn respond-btn" title="Ответить">📝</button>
                </div>
            `;
            break;
        case 'rejected':
            statusClass = 'status-rejected';
            statusText = '❌ ОТКЛОНЕНО';
            buttons = `
                <div class="action-group">
                    <span class="status-badge rejected">❌ Отклонено</span>
                    <button onclick="openResponseModal('complaint', ${c.id})" class="mini-btn respond-btn" title="Ответить">📝</button>
                </div>
            `;
            break;
        case 'resolved':
            statusClass = 'status-resolved';
            statusText = '📝 ОТВЕЧЕНО';
            buttons = `
                <div class="action-group">
                    <span class="status-badge resolved">📝 Отвечено</span>
                    <button onclick="openResponseModal('complaint', ${c.id})" class="mini-btn respond-btn" title="Ответить">📝</button>
                </div>
            `;
            break;
    }
    
    return `
        <div class="card">
            <div class="card-header">
                <span class="card-title">⚠️ ${c.title || 'Жалоба'}</span>
                <span class="card-status ${statusClass}">${statusText}</span>
            </div>
            <div class="card-body">
                <p><strong>👤 От:</strong> ${c.author}</p>
                <p><strong>🎯 На:</strong> ${c.against}</p>
                <p><strong>📝 Описание:</strong> ${c.description}</p>
                <p><strong>📅 Дата:</strong> ${new Date(c.date).toLocaleString()}</p>
                ${c.response ? `<p><strong>💬 Ответ:</strong> ${c.response}</p>` : ''}
            </div>
            <div class="card-footer">
                ${buttons}
            </div>
        </div>
    `;
}

// ==============================================
// КАРТОЧКА МЕДИА-ЗАЯВКИ
// ==============================================

function createMediaCard(m) {
    let statusClass = '';
    let statusText = '';
    let buttons = '';
    const platformIcon = m.platform === 'tiktok' ? '📱' : '▶️';
    const platformName = m.platform === 'tiktok' ? 'TIKTOK' : 'YOUTUBE';
    
    switch(m.status) {
        case 'new':
            statusClass = 'status-new';
            statusText = '🆕 НОВАЯ';
            buttons = `
                <div class="action-group">
                    <button onclick="acceptMedia(${m.id})" class="mini-btn accept-btn" title="Принять">✅</button>
                    <button onclick="rejectMedia(${m.id})" class="mini-btn reject-btn" title="Отклонить">❌</button>
                    <button onclick="openResponseModal('media', ${m.id})" class="mini-btn respond-btn" title="Ответить">📝</button>
                </div>
            `;
            break;
        case 'accepted':
            statusClass = 'status-accepted';
            statusText = '✅ ПРИНЯТО';
            buttons = `
                <div class="action-group">
                    <span class="status-badge accepted">✅ Принято</span>
                    <button onclick="openResponseModal('media', ${m.id})" class="mini-btn respond-btn" title="Ответить">📝</button>
                </div>
            `;
            break;
        case 'rejected':
            statusClass = 'status-rejected';
            statusText = '❌ ОТКЛОНЕНО';
            buttons = `
                <div class="action-group">
                    <span class="status-badge rejected">❌ Отклонено</span>
                    <button onclick="openResponseModal('media', ${m.id})" class="mini-btn respond-btn" title="Ответить">📝</button>
                </div>
            `;
            break;
        case 'resolved':
            statusClass = 'status-resolved';
            statusText = '📝 ОТВЕЧЕНО';
            buttons = `
                <div class="action-group">
                    <span class="status-badge resolved">📝 Отвечено</span>
                    <button onclick="openResponseModal('media', ${m.id})" class="mini-btn respond-btn" title="Ответить">📝</button>
                </div>
            `;
            break;
    }
    
    return `
        <div class="card">
            <div class="card-header">
                <span class="card-title">${platformIcon} ЗАЯВКА НА ${platformName}</span>
                <span class="card-status ${statusClass}">${statusText}</span>
            </div>
            <div class="card-body">
                <p><strong>👤 Имя:</strong> ${m.name}</p>
                <p><strong>📅 Возраст:</strong> ${m.age}</p>
                <p><strong>🎮 Никнейм:</strong> ${m.nickname}</p>
                <p><strong>📊 Подписчики:</strong> ${m.subscribers}</p>
                <p><strong>👀 Просмотры:</strong> ${m.views}</p>
                <p><strong>🔗 Ссылка:</strong> <a href="${m.link}" target="_blank">${m.link.substring(0, 30)}...</a></p>
                <p><strong>👤 От:</strong> ${m.author}</p>
                <p><strong>📅 Дата:</strong> ${new Date(m.date).toLocaleString()}</p>
                ${m.response ? `<p><strong>💬 Ответ:</strong> ${m.response}</p>` : ''}
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
                <div class="action-group">
                    <button onclick="acceptApplication(${a.id})" class="mini-btn accept-btn" title="Принять">✅</button>
                    <button onclick="rejectApplication(${a.id})" class="mini-btn reject-btn" title="Отклонить">❌</button>
                    <button onclick="openResponseModal('application', ${a.id})" class="mini-btn respond-btn" title="Ответить">📝</button>
                </div>
            `;
            break;
        case 'accepted':
            statusClass = 'status-accepted';
            statusText = '✅ ПРИНЯТО';
            buttons = `
                <div class="action-group">
                    <span class="status-badge accepted">✅ Принято</span>
                    <button onclick="openResponseModal('application', ${a.id})" class="mini-btn respond-btn" title="Ответить">📝</button>
                </div>
            `;
            break;
        case 'rejected':
            statusClass = 'status-rejected';
            statusText = '❌ ОТКЛОНЕНО';
            buttons = `
                <div class="action-group">
                    <span class="status-badge rejected">❌ Отклонено</span>
                    <button onclick="openResponseModal('application', ${a.id})" class="mini-btn respond-btn" title="Ответить">📝</button>
                </div>
            `;
            break;
        case 'resolved':
            statusClass = 'status-resolved';
            statusText = '📝 ОТВЕЧЕНО';
            buttons = `
                <div class="action-group">
                    <span class="status-badge resolved">📝 Отвечено</span>
                    <button onclick="openResponseModal('application', ${a.id})" class="mini-btn respond-btn" title="Ответить">📝</button>
                </div>
            `;
            break;
    }
    
    return `
        <div class="card">
            <div class="card-header">
                <span class="card-title">👮 АНКЕТА НА ХЕЛПЕРА</span>
                <span class="card-status ${statusClass}">${statusText}</span>
            </div>
            <div class="card-body">
                <p><strong>🎮 Ник:</strong> ${a.nickname}</p>
                <p><strong>👤 Имя:</strong> ${a.name}</p>
                <p><strong>📅 Возраст:</strong> ${a.age}</p>
                <p><strong>🌍 Часовой пояс:</strong> ${a.timezone}</p>
                <p><strong>💼 Опыт:</strong> ${a.experience}</p>
                <p><strong>❓ Мотивация:</strong> ${a.reason}</p>
                ${a.additional ? `<p><strong>📝 Дополнительно:</strong> ${a.additional}</p>` : ''}
                <p><strong>👤 От:</strong> ${a.author}</p>
                <p><strong>📅 Дата:</strong> ${new Date(a.date).toLocaleString()}</p>
                ${a.response ? `<p><strong>💬 Ответ:</strong> ${a.response}</p>` : ''}
            </div>
            <div class="card-footer">
                ${buttons}
            </div>
        </div>
    `;
}

// ==============================================
// ДЕЙСТВИЯ
// ==============================================

async function acceptComplaint(id) {
    const result = await window.updateComplaint(id, { status: 'accepted' });
    if (result) {
        await loadAdminData();
        showNotification('✅ Жалоба принята', 'success');
    }
}

async function rejectComplaint(id) {
    const result = await window.updateComplaint(id, { status: 'rejected' });
    if (result) {
        await loadAdminData();
        showNotification('❌ Жалоба отклонена', 'error');
    }
}

async function acceptMedia(id) {
    const result = await window.updateMediaApplication(id, { status: 'accepted' });
    if (result) {
        await loadAdminData();
        showNotification('✅ Медиа-заявка принята', 'success');
    }
}

async function rejectMedia(id) {
    const result = await window.updateMediaApplication(id, { status: 'rejected' });
    if (result) {
        await loadAdminData();
        showNotification('❌ Медиа-заявка отклонена', 'error');
    }
}

async function acceptApplication(id) {
    const result = await window.updateApplication(id, { status: 'accepted' });
    if (result) {
        await loadAdminData();
        showNotification('✅ Анкета принята', 'success');
    }
}

async function rejectApplication(id) {
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
    
    let title = '';
    if (type === 'complaint') title = 'ОТВЕТ НА ЖАЛОБУ';
    else if (type === 'media') title = 'ОТВЕТ НА МЕДИА-ЗАЯВКУ';
    else title = 'ОТВЕТ НА АНКЕТУ';
    
    document.querySelector('#responseModal h2').innerHTML = `⚔️ ${title}`;
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
        result = await window.updateComplaint(id, { response, status: 'resolved' });
    } else if (type === 'media') {
        result = await window.updateMediaApplication(id, { response, status: 'resolved' });
    } else {
        result = await window.updateApplication(id, { response, status: 'resolved' });
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
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    
    event.target.classList.add('active');
    document.getElementById('admin' + tabName.charAt(0).toUpperCase() + tabName.slice(1)).classList.add('active');
}
