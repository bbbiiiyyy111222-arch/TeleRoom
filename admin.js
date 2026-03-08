// ==============================================
// АДМИН ПАНЕЛЬ MOONGRIEF - ПОЛНАЯ ВЕРСИЯ
// ==============================================

// Данные
let complaints = [];
let applications = [];
let currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;

// ВСЕ OWNER
const OWNERS = ['milfa', 'milk123', 'Xchik_'];

console.log('📱 Админ панель загружается...');

// Проверка доступа
document.addEventListener('DOMContentLoaded', async function() {
    console.log('📱 DOM загружен');
    
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
        console.log('🔄 Автообновление админки...');
        await loadAdminData();
    }, 15000); // 15 секунд
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
        console.error('❌ Ошибка обновления статистики:', error);
    }
}

// ==============================================
// СОЗДАНИЕ КАРТОЧЕК
// ==============================================

function createComplaintCard(c) {
    let statusText = '';
    let statusClass = c.status || 'new';
    
    switch(c.status) {
        case 'new': statusText = '🆕 Новая'; break;
        case 'accepted': statusText = '✅ Принята'; break;
        case 'rejected': statusText = '❌ Отклонена'; break;
        case 'resolved': statusText = '📝 Отвечено'; break;
        default: statusText = '🆕 Новая'; statusClass = 'new';
    }
    
    return `
        <div class="request-card" id="complaint-${c.id}">
            <div class="request-header">
                <span>${c.title || 'Без названия'}</span>
                <span class="request-status status-${statusClass}">${statusText}</span>
            </div>
            <div class="request-details">
                <p><strong>🆔 ID:</strong> ${c.id || 'Нет'}</p>
                <p><strong>👤 От:</strong> ${c.author || 'Неизвестно'}</p>
                <p><strong>🎯 На:</strong> ${c.against || 'Неизвестно'}</p>
                <p><strong>📝 Описание:</strong> ${c.description || 'Нет описания'}</p>
                <p><small>📅 ${c.date ? new Date(c.date).toLocaleString() : 'Нет даты'}</small></p>
            </div>
            ${c.response ? `<p><strong>💬 Ответ:</strong> ${c.response}</p>` : ''}
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
    let statusClass = a.status || 'new';
    
    switch(a.status) {
        case 'new': statusText = '🆕 Новая'; break;
        case 'accepted': statusText = '✅ Принята'; break;
        case 'rejected': statusText = '❌ Отклонена'; break;
        case 'resolved': statusText = '📝 Отвечено'; break;
        default: statusText = '🆕 Новая'; statusClass = 'new';
    }
    
    return `
        <div class="request-card" id="application-${a.id}">
            <div class="request-header">
                <span>Анкета от ${a.author || 'Неизвестно'}</span>
                <span class="request-status status-${statusClass}">${statusText}</span>
            </div>
            <div class="request-details">
                <p><strong>🆔 ID:</strong> ${a.id || 'Нет'}</p>
                <p><strong>🎮 Ник:</strong> ${a.nickname || 'Нет'}</p>
                <p><strong>👤 Имя:</strong> ${a.name || 'Нет'}</p>
                <p><strong>📅 Возраст:</strong> ${a.age || 'Нет'}</p>
                <p><strong>🌍 Часовой пояс:</strong> ${a.timezone || 'Нет'}</p>
                <p><strong>💼 Опыт:</strong> ${a.experience || 'Нет'}</p>
                <p><strong>❓ Мотивация:</strong> ${a.reason || 'Нет'}</p>
                <p><strong>📝 Дополнительно:</strong> ${a.additional || 'Нет'}</p>
                <p><small>📅 ${a.date ? new Date(a.date).toLocaleString() : 'Нет даты'}</small></p>
            </div>
            ${a.response ? `<p><strong>💬 Ответ:</strong> ${a.response}</p>` : ''}
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
        console.log('✅ Принимаем жалобу:', id);
        const numericId = Number(id);
        const updated = await window.updateComplaint(numericId, { status: 'accepted' });
        if (updated) {
            await loadAdminData();
            alert('✅ Жалоба принята!');
        } else {
            alert('❌ Ошибка при принятии');
        }
    } catch (error) {
        console.error('❌ Ошибка:', error);
        alert('❌ Ошибка: ' + error.message);
    }
}

async function rejectComplaint(id) {
    try {
        console.log('❌ Отклоняем жалобу:', id);
        const numericId = Number(id);
        const updated = await window.updateComplaint(numericId, { status: 'rejected' });
        if (updated) {
            await loadAdminData();
            alert('❌ Жалоба отклонена!');
        } else {
            alert('❌ Ошибка при отклонении');
        }
    } catch (error) {
        console.error('❌ Ошибка:', error);
        alert('❌ Ошибка: ' + error.message);
    }
}

// ==============================================
// УДАЛЕНИЕ ЖАЛОБ - РАБОЧАЯ ВЕРСИЯ
// ==============================================

async function deleteComplaint(id) {
    // Простой confirm
    if (!confirm('❌ УДАЛИТЬ ЭТУ ЖАЛОБУ?')) {
        return;
    }
    
    console.log('🗑️ admin.js: Начинаем удаление жалобы');
    console.log('📦 ID:', id, 'тип:', typeof id);
    
    try {
        // Преобразуем ID в число
        const numericId = Number(id);
        console.log('🔢 Числовой ID:', numericId);
        
        // Вызываем функцию из db.js
        const result = await window.deleteComplaint(numericId);
        
        console.log('📦 Результат удаления:', result);
        
        if (result === true) {
            alert('✅ Жалоба удалена!');
            // Перезагружаем данные
            await loadAdminData();
        } else {
            alert('❌ Ошибка при удалении');
        }
    } catch (error) {
        console.error('❌ Ошибка:', error);
        alert('❌ Ошибка: ' + error.message);
    }
}

// ==============================================
// ДЕЙСТВИЯ С ЗАЯВКАМИ
// ==============================================

async function acceptApplication(id) {
    try {
        console.log('✅ Принимаем анкету:', id);
        const numericId = Number(id);
        const updated = await window.updateApplication(numericId, { status: 'accepted' });
        if (updated) {
            await loadAdminData();
            alert('✅ Анкета принята!');
        } else {
            alert('❌ Ошибка при принятии');
        }
    } catch (error) {
        console.error('❌ Ошибка:', error);
        alert('❌ Ошибка: ' + error.message);
    }
}

async function rejectApplication(id) {
    try {
        console.log('❌ Отклоняем анкету:', id);
        const numericId = Number(id);
        const updated = await window.updateApplication(numericId, { status: 'rejected' });
        if (updated) {
            await loadAdminData();
            alert('❌ Анкета отклонена!');
        } else {
            alert('❌ Ошибка при отклонении');
        }
    } catch (error) {
        console.error('❌ Ошибка:', error);
        alert('❌ Ошибка: ' + error.message);
    }
}

// ==============================================
// УДАЛЕНИЕ ЗАЯВОК - РАБОЧАЯ ВЕРСИЯ
// ==============================================

async function deleteApplication(id) {
    if (!confirm('❌ УДАЛИТЬ ЭТУ АНКЕТУ?')) {
        return;
    }
    
    console.log('🗑️ admin.js: Начинаем удаление анкеты');
    console.log('📦 ID:', id, 'тип:', typeof id);
    
    try {
        const numericId = Number(id);
        console.log('🔢 Числовой ID:', numericId);
        
        const result = await window.deleteApplication(numericId);
        
        console.log('📦 Результат удаления:', result);
        
        if (result === true) {
            alert('✅ Анкета удалена!');
            await loadAdminData();
        } else {
            alert('❌ Ошибка при удалении');
        }
    } catch (error) {
        console.error('❌ Ошибка:', error);
        alert('❌ Ошибка: ' + error.message);
    }
}

// ==============================================
// МОДАЛКА ОТВЕТА
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

// ==============================================
// ОТПРАВКА ОТВЕТА
// ==============================================

async function sendResponse(event) {
    event.preventDefault();
    
    const id = Number(document.getElementById('responseId').value);
    const type = document.getElementById('responseType').value;
    const response = document.getElementById('responseText').value;
    
    if (!response) {
        alert('Введите ответ!');
        return;
    }
    
    try {
        let updated = false;
        
        if (type === 'complaint') {
            updated = await window.updateComplaint(id, { 
                response: response,
                status: 'resolved' 
            });
        } else {
            updated = await window.updateApplication(id, { 
                response: response,
                status: 'resolved' 
            });
        }
        
        if (updated) {
            closeResponseModal();
            await loadAdminData();
            alert('✅ Ответ отправлен!');
        } else {
            alert('❌ Ошибка при отправке');
        }
    } catch (error) {
        console.error('❌ Ошибка:', error);
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
