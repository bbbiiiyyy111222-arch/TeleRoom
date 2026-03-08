// ==============================================
// АДМИН ПАНЕЛЬ MOONGRIEF - ПОЛНАЯ РАБОЧАЯ ВЕРСИЯ
// ==============================================

// Данные
let complaints = [];
let applications = [];
let currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;

// ВСЕ OWNER
const OWNERS = ['milfa', 'milk123', 'Xchik_'];

// Загрузка
document.addEventListener('DOMContentLoaded', async function() {
    if (!currentUser || !OWNERS.includes(currentUser.username)) {
        alert('У вас нет доступа к админ панели!');
        window.location.href = 'index.html';
        return;
    }
    
    document.getElementById('adminName').textContent = '🌙 ' + currentUser.username + ' (OWNER)';
    
    // Загружаем данные
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
    await updateStats();
}

// Обновление статистики
async function updateStats() {
    try {
        complaints = await window.getComplaints() || [];
        applications = await window.getApplications() || [];
        
        document.getElementById('newComplaints').textContent = complaints.filter(c => c.status === 'new').length;
        document.getElementById('newApplications').textContent = applications.filter(a => a.status === 'new').length;
        document.getElementById('total').textContent = complaints.length + applications.length;
    } catch (error) {
        console.error('Ошибка статистики:', error);
    }
}

// Загрузка жалоб
async function loadComplaints() {
    const list = document.getElementById('adminComplaints');
    if (!list) return;
    
    try {
        complaints = await window.getComplaints() || [];
        
        if (complaints.length === 0) {
            list.innerHTML = '<div class="empty-state">🌙 <h3>Нет жалоб</h3></div>';
            return;
        }
        
        list.innerHTML = '';
        complaints.sort((a, b) => new Date(b.date) - new Date(a.date)).forEach(c => {
            list.innerHTML += createComplaintCard(c);
        });
    } catch (error) {
        console.error('Ошибка загрузки жалоб:', error);
    }
}

// Загрузка анкет
async function loadApplications() {
    const list = document.getElementById('adminApplications');
    if (!list) return;
    
    try {
        applications = await window.getApplications() || [];
        
        if (applications.length === 0) {
            list.innerHTML = '<div class="empty-state">🌙 <h3>Нет анкет</h3></div>';
            return;
        }
        
        list.innerHTML = '';
        applications.sort((a, b) => new Date(b.date) - new Date(a.date)).forEach(a => {
            list.innerHTML += createApplicationCard(a);
        });
    } catch (error) {
        console.error('Ошибка загрузки анкет:', error);
    }
}

// Карточка жалобы
function createComplaintCard(c) {
    let statusText = '';
    let statusClass = '';
    let buttons = '';
    
    switch(c.status) {
        case 'new':
            statusText = '🆕 НОВАЯ';
            statusClass = 'status-new';
            buttons = `
                <button onclick="acceptComplaint(${c.id})" class="action-btn accept-btn">✅ ПРИНЯТЬ</button>
                <button onclick="rejectComplaint(${c.id})" class="action-btn reject-btn">❌ ОТКЛОНИТЬ</button>
                <button onclick="openResponseModal('complaint', ${c.id})" class="action-btn respond-btn">📝 ОТВЕТИТЬ</button>
            `;
            break;
        case 'accepted':
            statusText = '✅ ПРИНЯТА';
            statusClass = 'status-accepted';
            buttons = `
                <span class="status-message">✓ Принято</span>
                <button onclick="openResponseModal('complaint', ${c.id})" class="action-btn respond-btn">📝 ОТВЕТИТЬ</button>
            `;
            break;
        case 'rejected':
            statusText = '❌ ОТКЛОНЕНА';
            statusClass = 'status-rejected';
            buttons = `
                <span class="status-message">✗ Отклонено</span>
                <button onclick="openResponseModal('complaint', ${c.id})" class="action-btn respond-btn">📝 ОТВЕТИТЬ</button>
            `;
            break;
        case 'resolved':
            statusText = '📝 ОТВЕЧЕНО';
            statusClass = 'status-resolved';
            buttons = `
                <span class="status-message">✓ Ответ отправлен</span>
                <button onclick="openResponseModal('complaint', ${c.id})" class="action-btn respond-btn">📝 ОТВЕТИТЬ СНОВА</button>
            `;
            break;
        default:
            statusText = '🆕 НОВАЯ';
            statusClass = 'status-new';
            buttons = `
                <button onclick="acceptComplaint(${c.id})" class="action-btn accept-btn">✅ ПРИНЯТЬ</button>
                <button onclick="rejectComplaint(${c.id})" class="action-btn reject-btn">❌ ОТКЛОНИТЬ</button>
                <button onclick="openResponseModal('complaint', ${c.id})" class="action-btn respond-btn">📝 ОТВЕТИТЬ</button>
            `;
    }
    
    return `
        <div class="card">
            <div class="card-header">
                <span class="card-title">⚠️ ${c.title || 'Жалоба'}</span>
                <span class="status-badge ${statusClass}">${statusText}</span>
            </div>
            <div class="card-body">
                <p><strong>👤 От:</strong> ${c.author}</p>
                <p><strong>🎯 На:</strong> ${c.against}</p>
                <p><strong>📝 Описание:</strong> ${c.description}</p>
                <p><strong>📅 Дата:</strong> ${new Date(c.date).toLocaleString()}</p>
                ${c.response ? `<p><strong>💬 Ответ:</strong> ${c.response}</p>` : ''}
            </div>
            <div class="card-footer">
                <div class="button-group">
                    ${buttons}
                </div>
            </div>
        </div>
    `;
}

// Карточка анкеты
function createApplicationCard(a) {
    let statusText = '';
    let statusClass = '';
    let buttons = '';
    
    switch(a.status) {
        case 'new':
            statusText = '🆕 НОВАЯ';
            statusClass = 'status-new';
            buttons = `
                <button onclick="acceptApplication(${a.id})" class="action-btn accept-btn">✅ ПРИНЯТЬ</button>
                <button onclick="rejectApplication(${a.id})" class="action-btn reject-btn">❌ ОТКЛОНИТЬ</button>
                <button onclick="openResponseModal('application', ${a.id})" class="action-btn respond-btn">📝 ОТВЕТИТЬ</button>
            `;
            break;
        case 'accepted':
            statusText = '✅ ПРИНЯТА';
            statusClass = 'status-accepted';
            buttons = `
                <span class="status-message">✓ Принято</span>
                <button onclick="openResponseModal('application', ${a.id})" class="action-btn respond-btn">📝 ОТВЕТИТЬ</button>
            `;
            break;
        case 'rejected':
            statusText = '❌ ОТКЛОНЕНА';
            statusClass = 'status-rejected';
            buttons = `
                <span class="status-message">✗ Отклонено</span>
                <button onclick="openResponseModal('application', ${a.id})" class="action-btn respond-btn">📝 ОТВЕТИТЬ</button>
            `;
            break;
        case 'resolved':
            statusText = '📝 ОТВЕЧЕНО';
            statusClass = 'status-resolved';
            buttons = `
                <span class="status-message">✓ Ответ отправлен</span>
                <button onclick="openResponseModal('application', ${a.id})" class="action-btn respond-btn">📝 ОТВЕТИТЬ СНОВА</button>
            `;
            break;
        default:
            statusText = '🆕 НОВАЯ';
            statusClass = 'status-new';
            buttons = `
                <button onclick="acceptApplication(${a.id})" class="action-btn accept-btn">✅ ПРИНЯТЬ</button>
                <button onclick="rejectApplication(${a.id})" class="action-btn reject-btn">❌ ОТКЛОНИТЬ</button>
                <button onclick="openResponseModal('application', ${a.id})" class="action-btn respond-btn">📝 ОТВЕТИТЬ</button>
            `;
    }
    
    return `
        <div class="card">
            <div class="card-header">
                <span class="card-title">👮 АНКЕТА</span>
                <span class="status-badge ${statusClass}">${statusText}</span>
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
                <div class="button-group">
                    ${buttons}
                </div>
            </div>
        </div>
    `;
}

// Действия с жалобами
async function acceptComplaint(id) {
    try {
        const complaint = complaints.find(c => c.id === id);
        if (complaint.status !== 'new') {
            alert('❌ Эту жалобу уже обработали!');
            return;
        }
        
        const result = await window.updateComplaint(id, { status: 'accepted' });
        if (result) {
            await loadAdminData();
            alert('✅ Жалоба принята');
        }
    } catch (error) {
        alert('❌ Ошибка: ' + error.message);
    }
}

async function rejectComplaint(id) {
    try {
        const complaint = complaints.find(c => c.id === id);
        if (complaint.status !== 'new') {
            alert('❌ Эту жалобу уже обработали!');
            return;
        }
        
        const result = await window.updateComplaint(id, { status: 'rejected' });
        if (result) {
            await loadAdminData();
            alert('❌ Жалоба отклонена');
        }
    } catch (error) {
        alert('❌ Ошибка: ' + error.message);
    }
}

// Действия с анкетами
async function acceptApplication(id) {
    try {
        const application = applications.find(a => a.id === id);
        if (application.status !== 'new') {
            alert('❌ Эту анкету уже обработали!');
            return;
        }
        
        const result = await window.updateApplication(id, { status: 'accepted' });
        if (result) {
            await loadAdminData();
            alert('✅ Анкета принята');
        }
    } catch (error) {
        alert('❌ Ошибка: ' + error.message);
    }
}

async function rejectApplication(id) {
    try {
        const application = applications.find(a => a.id === id);
        if (application.status !== 'new') {
            alert('❌ Эту анкету уже обработали!');
            return;
        }
        
        const result = await window.updateApplication(id, { status: 'rejected' });
        if (result) {
            await loadAdminData();
            alert('❌ Анкета отклонена');
        }
    } catch (error) {
        alert('❌ Ошибка: ' + error.message);
    }
}

// Модалка ответа
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
    
    try {
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
            alert('✅ Ответ отправлен');
        }
    } catch (error) {
        alert('❌ Ошибка: ' + error.message);
    }
}

// Переключение табов
function showAdminTab(tabName) {
    document.querySelectorAll('.moon-tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.moon-admin-content').forEach(content => content.classList.remove('active'));
    
    event.target.classList.add('active');
    document.getElementById('admin' + tabName.charAt(0).toUpperCase() + tabName.slice(1)).classList.add('active');
}
