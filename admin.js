// ==============================================
// АДМИН ПАНЕЛЬ MOONGRIEF
// ==============================================

let complaints = [];
let applications = [];
let currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;
const OWNERS = ['milfa', 'milk123', 'Xchik_'];

document.addEventListener('DOMContentLoaded', async function() {
    if (!currentUser || !OWNERS.includes(currentUser.username)) {
        alert('🚫 Нет доступа к админ панели');
        window.location.href = 'index.html';
        return;
    }
    
    document.getElementById('adminName').textContent = '👑 ' + currentUser.username + ' (OWNER)';
    await loadAdminData();
    startAutoUpdate();
});

let updateInterval;
function startAutoUpdate() {
    if (updateInterval) clearInterval(updateInterval);
    updateInterval = setInterval(async () => {
        await loadAdminData();
    }, 15000);
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

async function loadComplaints() {
    const list = document.getElementById('adminComplaints');
    if (!list) return;
    
    complaints = await window.getComplaints() || [];
    
    if (complaints.length === 0) {
        list.innerHTML = '<p style="color: #666; text-align: center;">Нет жалоб</p>';
        return;
    }
    
    list.innerHTML = '';
    complaints.forEach(c => {
        list.innerHTML += createComplaintCard(c);
    });
}

async function loadApplications() {
    const list = document.getElementById('adminApplications');
    if (!list) return;
    
    applications = await window.getApplications() || [];
    
    if (applications.length === 0) {
        list.innerHTML = '<p style="color: #666; text-align: center;">Нет анкет</p>';
        return;
    }
    
    list.innerHTML = '';
    applications.forEach(a => {
        list.innerHTML += createApplicationCard(a);
    });
}

function updateStats() {
    document.getElementById('newComplaints').textContent = complaints.filter(c => c.status === 'new').length;
    document.getElementById('newApplications').textContent = applications.filter(a => a.status === 'new').length;
    document.getElementById('total').textContent = complaints.length + applications.length;
}

function createComplaintCard(c) {
    let statusText = {
        'new': '🆕 Новая',
        'accepted': '✅ Принята',
        'rejected': '❌ Отклонена',
        'resolved': '📝 Отвечено'
    }[c.status] || '🆕 Новая';
    
    return `
        <div class="request-card">
            <div class="request-header">
                <span>${c.title || 'Без названия'}</span>
                <span class="request-status status-${c.status || 'new'}">${statusText}</span>
            </div>
            <div class="request-details">
                <p><strong>От:</strong> ${c.author || 'Неизвестно'}</p>
                <p><strong>На:</strong> ${c.against || 'Неизвестно'}</p>
                <p><strong>Описание:</strong> ${c.description || 'Нет описания'}</p>
                <p><small>${c.date ? new Date(c.date).toLocaleString() : 'Нет даты'}</small></p>
            </div>
            ${c.response ? `<p><strong>Ответ:</strong> ${c.response}</p>` : ''}
            <div class="admin-actions">
                <button onclick="acceptComplaint(${c.id})" class="admin-btn accept-btn">✅ Принять</button>
                <button onclick="rejectComplaint(${c.id})" class="admin-btn reject-btn">❌ Отклонить</button>
                <button onclick="deleteComplaint(${c.id})" class="admin-btn delete-btn">🗑️ Удалить</button>
                <button onclick="openResponseModal('complaint', ${c.id})" class="admin-btn respond-btn">📝 Ответить</button>
            </div>
        </div>
    `;
}

function createApplicationCard(a) {
    let statusText = {
        'new': '🆕 Новая',
        'accepted': '✅ Принята',
        'rejected': '❌ Отклонена',
        'resolved': '📝 Отвечено'
    }[a.status] || '🆕 Новая';
    
    return `
        <div class="request-card">
            <div class="request-header">
                <span>Анкета от ${a.author || 'Неизвестно'}</span>
                <span class="request-status status-${a.status || 'new'}">${statusText}</span>
            </div>
            <div class="request-details">
                <p><strong>Ник:</strong> ${a.nickname || 'Нет'}</p>
                <p><strong>Имя:</strong> ${a.name || 'Нет'}</p>
                <p><strong>Возраст:</strong> ${a.age || 'Нет'}</p>
                <p><strong>Часовой пояс:</strong> ${a.timezone || 'Нет'}</p>
                <p><strong>Опыт:</strong> ${a.experience || 'Нет'}</p>
                <p><strong>Мотивация:</strong> ${a.reason || 'Нет'}</p>
                <p><small>${a.date ? new Date(a.date).toLocaleString() : 'Нет даты'}</small></p>
            </div>
            ${a.response ? `<p><strong>Ответ:</strong> ${a.response}</p>` : ''}
            <div class="admin-actions">
                <button onclick="acceptApplication(${a.id})" class="admin-btn accept-btn">✅ Принять</button>
                <button onclick="rejectApplication(${a.id})" class="admin-btn reject-btn">❌ Отклонить</button>
                <button onclick="deleteApplication(${a.id})" class="admin-btn delete-btn">🗑️ Удалить</button>
                <button onclick="openResponseModal('application', ${a.id})" class="admin-btn respond-btn">📝 Ответить</button>
            </div>
        </div>
    `;
}

async function acceptComplaint(id) {
    if (await window.updateComplaint(id, { status: 'accepted' })) {
        await loadAdminData();
    }
}

async function rejectComplaint(id) {
    if (await window.updateComplaint(id, { status: 'rejected' })) {
        await loadAdminData();
    }
}

async function deleteComplaint(id) {
    if (!confirm('Удалить жалобу?')) return;
    if (await window.deleteComplaint(id)) {
        await loadAdminData();
    }
}

async function acceptApplication(id) {
    if (await window.updateApplication(id, { status: 'accepted' })) {
        await loadAdminData();
    }
}

async function rejectApplication(id) {
    if (await window.updateApplication(id, { status: 'rejected' })) {
        await loadAdminData();
    }
}

async function deleteApplication(id) {
    if (!confirm('Удалить анкету?')) return;
    if (await window.deleteApplication(id)) {
        await loadAdminData();
    }
}

function openResponseModal(type, id) {
    document.getElementById('responseModal').style.display = 'block';
    document.getElementById('responseId').value = id;
    document.getElementById('responseType').value = type;
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
    
    if (!response) return alert('Введите ответ!');
    
    let updated = type === 'complaint' 
        ? await window.updateComplaint(id, { response, status: 'resolved' })
        : await window.updateApplication(id, { response, status: 'resolved' });
    
    if (updated) {
        closeResponseModal();
        await loadAdminData();
        alert('Ответ отправлен');
    }
}

function showAdminTab(tabName) {
    document.querySelectorAll('.admin-tab').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.admin-tab-content').forEach(content => content.classList.remove('active'));
    
    event.target.classList.add('active');
    document.getElementById('admin' + tabName.charAt(0).toUpperCase() + tabName.slice(1)).classList.add('active');
}
