// ==============================================
// АДМИН ПАНЕЛЬ MOONGRIEF - ПОЛНАЯ ВЕРСИЯ
// ==============================================

// Данные
let complaints = [];
let applications = [];
let currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;

// ВСЕ OWNER
const OWNERS = ['milfa', 'milk123', 'Xchik_'];

// Проверка доступа
document.addEventListener('DOMContentLoaded', async function() {
    console.log('📱 Админ панель загружена');
    
    if (!currentUser || !OWNERS.includes(currentUser.username)) {
        alert('🚫 У вас нет доступа к админ панели!');
        window.location.href = 'index.html';
        return;
    }
    
    document.getElementById('adminName').textContent = '👑 ' + currentUser.username + ' (OWNER)';
    
    // Загружаем данные
    await loadAdminData();
    startAutoUpdate();
});

// ==============================================
// АВТООБНОВЛЕНИЕ КАЖДЫЕ 20 СЕКУНД
// ==============================================

let updateInterval;

function startAutoUpdate() {
    if (updateInterval) clearInterval(updateInterval);
    
    updateInterval = setInterval(async () => {
        console.log('🔄 Автообновление каждые 20 сек...');
        await loadAdminData();
    }, 20000);
}

window.addEventListener('beforeunload', function() {
    if (updateInterval) {
        clearInterval(updateInterval);
    }
});

// ==============================================
// ВЫХОД
// ==============================================

function logout() {
    localStorage.removeItem('currentUser');
    window.location.href = 'index.html';
}

// ==============================================
// ЗАГРУЗКА ДАННЫХ
// ==============================================

async function loadAdminData() {
    await loadComplaints();
    await loadApplications();
    await updateStats();
}

async function loadComplaints() {
    const list = document.getElementById('adminComplaints');
    if (!list) return;
    
    try {
        complaints = await window.getComplaints() || [];
        console.log('📋 Загружено жалоб:', complaints.length);
        
        if (complaints.length === 0) {
            list.innerHTML = '<div class="empty-state">📭 <h3>Нет жалоб</h3><p>Пока никто не подавал жалоб</p></div>';
            return;
        }
        
        list.innerHTML = '';
        complaints.forEach(c => {
            list.innerHTML += createComplaintCard(c);
        });
    } catch (error) {
        console.error('❌ Ошибка загрузки жалоб:', error);
        list.innerHTML = '<div class="error-state">❌ Ошибка загрузки данных</div>';
    }
}

async function loadApplications() {
    const list = document.getElementById('adminApplications');
    if (!list) return;
    
    try {
        applications = await window.getApplications() || [];
        console.log('📋 Загружено анкет:', applications.length);
        
        if (applications.length === 0) {
            list.innerHTML = '<div class="empty-state">📭 <h3>Нет анкет</h3><p>Пока никто не подавал заявки</p></div>';
            return;
        }
        
        list.innerHTML = '';
        applications.forEach(a => {
            list.innerHTML += createApplicationCard(a);
        });
    } catch (error) {
        console.error('❌ Ошибка загрузки анкет:', error);
        list.innerHTML = '<div class="error-state">❌ Ошибка загрузки данных</div>';
    }
}

async function updateStats() {
    try {
        complaints = await window.getComplaints() || [];
        applications = await window.getApplications() || [];
        
        document.getElementById('newComplaints').textContent = complaints.filter(c => c.status === 'new').length;
        document.getElementById('newApplications').textContent = applications.filter(a => a.status === 'new').length;
        document.getElementById('total').textContent = complaints.length + applications.length;
    } catch (error) {
        console.error('❌ Ошибка статистики:', error);
    }
}

// ==============================================
// КРАСИВЫЕ КАРТОЧКИ
// ==============================================

function createComplaintCard(c) {
    let statusText = '';
    let statusClass = '';
    let actionButtons = '';
    
    switch(c.status) {
        case 'new':
            statusText = '🆕 НОВАЯ';
            statusClass = 'status-new';
            actionButtons = `
                <div class="button-group">
                    <button onclick="acceptComplaint(${c.id})" class="btn-glow accept-btn">✅ ПРИНЯТЬ</button>
                    <button onclick="rejectComplaint(${c.id})" class="btn-glow reject-btn">❌ ОТКЛОНИТЬ</button>
                    <button onclick="openResponseModal('complaint', ${c.id})" class="btn-glow respond-btn">📝 ОТВЕТИТЬ</button>
                </div>
            `;
            break;
        case 'accepted':
            statusText = '✅ ПРИНЯТА';
            statusClass = 'status-accepted';
            actionButtons = `
                <div class="button-group">
                    <div class="status-message">✓ Жалоба принята</div>
                    <button onclick="openResponseModal('complaint', ${c.id})" class="btn-glow respond-btn">📝 ОТВЕТИТЬ</button>
                </div>
            `;
            break;
        case 'rejected':
            statusText = '❌ ОТКЛОНЕНА';
            statusClass = 'status-rejected';
            actionButtons = `
                <div class="button-group">
                    <div class="status-message">✗ Жалоба отклонена</div>
                    <button onclick="openResponseModal('complaint', ${c.id})" class="btn-glow respond-btn">📝 ОТВЕТИТЬ</button>
                </div>
            `;
            break;
        case 'resolved':
            statusText = '📝 ОТВЕЧЕНО';
            statusClass = 'status-resolved';
            actionButtons = `
                <div class="button-group">
                    <div class="status-message">✓ Ответ отправлен</div>
                    <button onclick="openResponseModal('complaint', ${c.id})" class="btn-glow respond-btn">📝 ОТВЕТИТЬ СНОВА</button>
                </div>
            `;
            break;
    }
    
    return `
        <div class="card animate-in">
            <div class="card-header">
                <div class="card-title">
                    <span class="card-icon">⚠️</span>
                    ${c.title || 'Жалоба'}
                </div>
                <div class="status-badge ${statusClass}">${statusText}</div>
            </div>
            
            <div class="card-content">
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">👤 Отправитель</div>
                        <div class="info-value">${c.author}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">🎯 Нарушитель</div>
                        <div class="info-value">${c.against}</div>
                    </div>
                    <div class="info-item full-width">
                        <div class="info-label">📝 Описание</div>
                        <div class="info-value description">${c.description}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">📅 Дата</div>
                        <div class="info-value">${new Date(c.date).toLocaleString()}</div>
                    </div>
                </div>
                
                ${c.response ? `
                <div class="response-section">
                    <div class="response-header">💬 Ответ администрации</div>
                    <div class="response-content">${c.response}</div>
                </div>` : ''}
            </div>
            
            <div class="card-footer">
                ${actionButtons}
            </div>
        </div>
    `;
}

function createApplicationCard(a) {
    let statusText = '';
    let statusClass = '';
    let actionButtons = '';
    
    switch(a.status) {
        case 'new':
            statusText = '🆕 НОВАЯ';
            statusClass = 'status-new';
            actionButtons = `
                <div class="button-group">
                    <button onclick="acceptApplication(${a.id})" class="btn-glow accept-btn">✅ ПРИНЯТЬ</button>
                    <button onclick="rejectApplication(${a.id})" class="btn-glow reject-btn">❌ ОТКЛОНИТЬ</button>
                    <button onclick="openResponseModal('application', ${a.id})" class="btn-glow respond-btn">📝 ОТВЕТИТЬ</button>
                </div>
            `;
            break;
        case 'accepted':
            statusText = '✅ ПРИНЯТА';
            statusClass = 'status-accepted';
            actionButtons = `
                <div class="button-group">
                    <div class="status-message">✓ Анкета принята</div>
                    <button onclick="openResponseModal('application', ${a.id})" class="btn-glow respond-btn">📝 ОТВЕТИТЬ</button>
                </div>
            `;
            break;
        case 'rejected':
            statusText = '❌ ОТКЛОНЕНА';
            statusClass = 'status-rejected';
            actionButtons = `
                <div class="button-group">
                    <div class="status-message">✗ Анкета отклонена</div>
                    <button onclick="openResponseModal('application', ${a.id})" class="btn-glow respond-btn">📝 ОТВЕТИТЬ</button>
                </div>
            `;
            break;
        case 'resolved':
            statusText = '📝 ОТВЕЧЕНО';
            statusClass = 'status-resolved';
            actionButtons = `
                <div class="button-group">
                    <div class="status-message">✓ Ответ отправлен</div>
                    <button onclick="openResponseModal('application', ${a.id})" class="btn-glow respond-btn">📝 ОТВЕТИТЬ СНОВА</button>
                </div>
            `;
            break;
    }
    
    return `
        <div class="card animate-in">
            <div class="card-header">
                <div class="card-title">
                    <span class="card-icon">👮</span>
                    АНКЕТА НА ХЕЛПЕРА
                </div>
                <div class="status-badge ${statusClass}">${statusText}</div>
            </div>
            
            <div class="card-content">
                <div class="info-grid">
                    <div class="info-item">
                        <div class="info-label">🎮 Игровой ник</div>
                        <div class="info-value">${a.nickname}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">👤 Настоящее имя</div>
                        <div class="info-value">${a.name}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">📅 Возраст</div>
                        <div class="info-value">${a.age} лет</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">🌍 Часовой пояс</div>
                        <div class="info-value">${a.timezone}</div>
                    </div>
                    <div class="info-item full-width">
                        <div class="info-label">💼 Опыт работы</div>
                        <div class="info-value description">${a.experience}</div>
                    </div>
                    <div class="info-item full-width">
                        <div class="info-label">❓ Мотивация</div>
                        <div class="info-value description">${a.reason}</div>
                    </div>
                    ${a.additional ? `
                    <div class="info-item full-width">
                        <div class="info-label">📝 Дополнительно</div>
                        <div class="info-value description">${a.additional}</div>
                    </div>` : ''}
                    <div class="info-item">
                        <div class="info-label">👤 Отправитель</div>
                        <div class="info-value">${a.author}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">📅 Дата</div>
                        <div class="info-value">${new Date(a.date).toLocaleString()}</div>
                    </div>
                </div>
                
                ${a.response ? `
                <div class="response-section">
                    <div class="response-header">💬 Ответ администрации</div>
                    <div class="response-content">${a.response}</div>
                </div>` : ''}
            </div>
            
            <div class="card-footer">
                ${actionButtons}
            </div>
        </div>
    `;
}

// ==============================================
// ДЕЙСТВИЯ (ТОЛЬКО 1 РАЗ)
// ==============================================

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
            showNotification('✅ Жалоба принята', 'success');
        }
    } catch (error) {
        showNotification('❌ Ошибка: ' + error.message, 'error');
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
            showNotification('❌ Жалоба отклонена', 'error');
        }
    } catch (error) {
        showNotification('❌ Ошибка: ' + error.message, 'error');
    }
}

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
            showNotification('✅ Анкета принята', 'success');
        }
    } catch (error) {
        showNotification('❌ Ошибка: ' + error.message, 'error');
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
            showNotification('❌ Анкета отклонена', 'error');
        }
    } catch (error) {
        showNotification('❌ Ошибка: ' + error.message, 'error');
    }
}

// ==============================================
// УВЕДОМЛЕНИЯ
// ==============================================

function showNotification(message, type) {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
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
// ОТВЕТЫ
// ==============================================

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
    
    if (!response) {
        showNotification('Введите ответ!', 'error');
        return;
    }
    
    try {
        let result;
        if (type === 'complaint') {
            result = await window.updateComplaint(id, { response, status: 'resolved' });
        } else {
            result = await window.updateApplication(id, { response, status: 'resolved' });
        }
        
        if (result) {
            closeResponseModal();
            await loadAdminData();
            showNotification('✅ Ответ отправлен', 'success');
        }
    } catch (error) {
        showNotification('❌ Ошибка: ' + error.message, 'error');
    }
}

// ==============================================
// ПЕРЕКЛЮЧЕНИЕ ТАБОВ
// ==============================================

function showAdminTab(tabName) {
    document.querySelectorAll('.admin-tab').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.admin-tab-content').forEach(content => content.classList.remove('active'));
    
    event.target.classList.add('active');
    document.getElementById('admin' + tabName.charAt(0).toUpperCase() + tabName.slice(1)).classList.add('active');
}
