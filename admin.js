// ==============================================
// АДМИН ПАНЕЛЬ MOONGRIEF - ПОЛНАЯ РАБОЧАЯ ВЕРСИЯ
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
// АВТООБНОВЛЕНИЕ КАЖДЫЕ 15 СЕКУНД
// ==============================================

let updateInterval;

function startAutoUpdate() {
    if (updateInterval) clearInterval(updateInterval);
    
    updateInterval = setInterval(async () => {
        console.log('🔄 Автообновление...');
        await loadAdminData();
    }, 15000);
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
            list.innerHTML = '<p style="color: #666; text-align: center; padding: 20px;">📭 Нет жалоб</p>';
            return;
        }
        
        list.innerHTML = '';
        complaints.forEach(c => {
            list.innerHTML += createComplaintCard(c);
        });
    } catch (error) {
        console.error('❌ Ошибка загрузки жалоб:', error);
        list.innerHTML = '<p style="color: red; text-align: center;">❌ Ошибка загрузки</p>';
    }
}

async function loadApplications() {
    const list = document.getElementById('adminApplications');
    if (!list) return;
    
    try {
        applications = await window.getApplications() || [];
        console.log('📋 Загружено анкет:', applications.length);
        
        if (applications.length === 0) {
            list.innerHTML = '<p style="color: #666; text-align: center; padding: 20px;">📭 Нет анкет</p>';
            return;
        }
        
        list.innerHTML = '';
        applications.forEach(a => {
            list.innerHTML += createApplicationCard(a);
        });
    } catch (error) {
        console.error('❌ Ошибка загрузки анкет:', error);
        list.innerHTML = '<p style="color: red; text-align: center;">❌ Ошибка загрузки</p>';
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
// СОЗДАНИЕ КАРТОЧЕК (С АНКЕТАМИ!)
// ==============================================

function createComplaintCard(c) {
    let statusText = '';
    switch(c.status) {
        case 'new': statusText = '🆕 Новая'; break;
        case 'accepted': statusText = '✅ Принята'; break;
        case 'rejected': statusText = '❌ Отклонена'; break;
        case 'resolved': statusText = '📝 Отвечено'; break;
        default: statusText = '🆕 Новая';
    }
    
    return `
        <div class="request-card">
            <div class="request-header">
                <span>${c.title || 'Жалоба'}</span>
                <span class="request-status status-${c.status || 'new'}">${statusText}</span>
            </div>
            <div class="request-details">
                <p><strong>ID:</strong> ${c.id}</p>
                <p><strong>От:</strong> ${c.author}</p>
                <p><strong>На:</strong> ${c.against}</p>
                <p><strong>Описание:</strong> ${c.description}</p>
                <p><small>${new Date(c.date).toLocaleString()}</small></p>
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
    let statusText = '';
    switch(a.status) {
        case 'new': statusText = '🆕 Новая'; break;
        case 'accepted': statusText = '✅ Принята'; break;
        case 'rejected': statusText = '❌ Отклонена'; break;
        case 'resolved': statusText = '📝 Отвечено'; break;
        default: statusText = '🆕 Новая';
    }
    
    return `
        <div class="request-card">
            <div class="request-header">
                <span>Анкета от ${a.author}</span>
                <span class="request-status status-${a.status || 'new'}">${statusText}</span>
            </div>
            <div class="request-details">
                <p><strong>ID:</strong> ${a.id}</p>
                <p><strong>Ник:</strong> ${a.nickname}</p>
                <p><strong>Имя:</strong> ${a.name}</p>
                <p><strong>Возраст:</strong> ${a.age}</p>
                <p><strong>Часовой пояс:</strong> ${a.timezone}</p>
                <p><strong>Опыт:</strong> ${a.experience}</p>
                <p><strong>Мотивация:</strong> ${a.reason}</p>
                <p><strong>Дополнительно:</strong> ${a.additional || 'Нет'}</p>
                <p><small>${new Date(a.date).toLocaleString()}</small></p>
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

// ==============================================
// ДЕЙСТВИЯ С ЖАЛОБАМИ
// ==============================================

async function acceptComplaint(id) {
    try {
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
        const result = await window.updateComplaint(id, { status: 'rejected' });
        if (result) {
            await loadAdminData();
            alert('❌ Жалоба отклонена');
        }
    } catch (error) {
        alert('❌ Ошибка: ' + error.message);
    }
}

// ==============================================
// УДАЛЕНИЕ ЖАЛОБ - ИСПРАВЛЕНО!
// ==============================================

async function deleteComplaint(id) {
    if (!confirm('❌ Удалить жалобу?')) return;
    
    try {
        console.log('🗑️ Удаляем жалобу ID:', id);
        const result = await window.deleteComplaint(id);
        
        if (result) {
            alert('✅ Жалоба удалена');
            await loadAdminData();
        } else {
            alert('❌ Ошибка при удалении');
        }
    } catch (error) {
        alert('❌ Ошибка: ' + error.message);
    }
}

// ==============================================
// ДЕЙСТВИЯ С ЗАЯВКАМИ
// ==============================================

async function acceptApplication(id) {
    try {
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
        const result = await window.updateApplication(id, { status: 'rejected' });
        if (result) {
            await loadAdminData();
            alert('❌ Анкета отклонена');
        }
    } catch (error) {
        alert('❌ Ошибка: ' + error.message);
    }
}

// ==============================================
// УДАЛЕНИЕ ЗАЯВОК - ИСПРАВЛЕНО!
// ==============================================

async function deleteApplication(id) {
    if (!confirm('❌ Удалить анкету?')) return;
    
    try {
        console.log('🗑️ Удаляем анкету ID:', id);
        const result = await window.deleteApplication(id);
        
        if (result) {
            alert('✅ Анкета удалена');
            await loadAdminData();
        } else {
            alert('❌ Ошибка при удалении');
        }
    } catch (error) {
        alert('❌ Ошибка: ' + error.message);
    }
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
    
    if (!response) return alert('Введите ответ!');
    
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
            alert('✅ Ответ отправлен');
        }
    } catch (error) {
        alert('❌ Ошибка: ' + error.message);
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
