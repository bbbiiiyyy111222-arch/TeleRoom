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
console.log('👤 Текущий пользователь:', currentUser);

// Проверка доступа
document.addEventListener('DOMContentLoaded', async function() {
    console.log('📱 DOM загружен');
    
    if (!currentUser || !OWNERS.includes(currentUser.username)) {
        alert('🚫 У вас нет доступа к админ панели!');
        window.location.href = 'index.html';
        return;
    }
    
    document.getElementById('adminName').textContent = '👑 ' + currentUser.username + ' (OWNER)';
    
    // Проверяем наличие функций из db.js
    checkDBFunctions();
    
    // Загружаем данные
    await loadAdminData();
    startAdminAutoUpdate();
});

// Проверка функций из db.js
function checkDBFunctions() {
    console.log('🔍 Проверка функций db.js:');
    console.log('  - getComplaints:', typeof window.getComplaints);
    console.log('  - getApplications:', typeof window.getApplications);
    console.log('  - updateComplaint:', typeof window.updateComplaint);
    console.log('  - deleteComplaint:', typeof window.deleteComplaint);
    
    if (typeof window.getComplaints !== 'function') {
        console.error('❌ Функции db.js не загружены!');
        alert('❌ Ошибка загрузки базы данных. Обновите страницу.');
    }
}

// ========== АВТОМАТИЧЕСКОЕ ОБНОВЛЕНИЕ ==========
let adminUpdateInterval;

function startAdminAutoUpdate() {
    if (adminUpdateInterval) clearInterval(adminUpdateInterval);
    
    adminUpdateInterval = setInterval(async () => {
        console.log('🔄 Автообновление админки...');
        await loadAdminData();
    }, 2000);
}

window.addEventListener('beforeunload', function() {
    if (adminUpdateInterval) {
        clearInterval(adminUpdateInterval);
    }
});

document.addEventListener('visibilitychange', function() {
    if (document.hidden) {
        if (adminUpdateInterval) {
            clearInterval(adminUpdateInterval);
            adminUpdateInterval = null;
        }
    } else {
        if (!adminUpdateInterval) {
            startAdminAutoUpdate();
        }
    }
});

// Выход
function logout() {
    localStorage.removeItem('currentUser');
    window.location.href = 'index.html';
}

// Загрузка данных
async function loadAdminData() {
    try {
        await loadAdminComplaints();
        await loadAdminApplications();
        await updateStats();
    } catch (error) {
        console.error('❌ Ошибка загрузки данных:', error);
    }
}

// Обновление статистики
async function updateStats() {
    try {
        if (typeof window.getComplaints !== 'function') {
            console.error('❌ getComplaints не функция');
            return;
        }
        
        complaints = await window.getComplaints() || [];
        applications = await window.getApplications() || [];
        
        document.getElementById('newComplaints').textContent = complaints.filter(c => c.status === 'new').length;
        document.getElementById('newApplications').textContent = applications.filter(a => a.status === 'new').length;
        document.getElementById('total').textContent = complaints.length + applications.length;
    } catch (error) {
        console.error('❌ Ошибка обновления статистики:', error);
    }
}

// Загрузка жалоб в админку
async function loadAdminComplaints() {
    const list = document.getElementById('adminComplaints');
    if (!list) return;
    
    try {
        if (typeof window.getComplaints !== 'function') {
            list.innerHTML = '<p style="color: red; text-align: center;">❌ Ошибка: функции базы данных не загружены</p>';
            return;
        }
        
        complaints = await window.getComplaints() || [];
        
        if (complaints.length === 0) {
            list.innerHTML = '<p style="color: #666; text-align: center; padding: 20px;">📭 Нет жалоб</p>';
            return;
        }
        
        list.innerHTML = '';
        complaints.forEach(c => {
            let statusText = '';
            let statusClass = c.status || 'new';
            
            switch(c.status) {
                case 'new':
                    statusText = '🆕 Новая';
                    break;
                case 'accepted':
                    statusText = '✅ Принята';
                    break;
                case 'rejected':
                    statusText = '❌ Отклонена';
                    break;
                case 'resolved':
                    statusText = '📝 Отвечено';
                    break;
                default:
                    statusText = '🆕 Новая';
                    statusClass = 'new';
            }
            
            list.innerHTML += `
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
        });
    } catch (error) {
        console.error('❌ Ошибка загрузки жалоб:', error);
        list.innerHTML = '<p style="color: red; text-align: center;">❌ Ошибка загрузки жалоб</p>';
    }
}

// Загрузка анкет в админку
async function loadAdminApplications() {
    const list = document.getElementById('adminApplications');
    if (!list) return;
    
    try {
        if (typeof window.getApplications !== 'function') {
            list.innerHTML = '<p style="color: red; text-align: center;">❌ Ошибка: функции базы данных не загружены</p>';
            return;
        }
        
        applications = await window.getApplications() || [];
        
        if (applications.length === 0) {
            list.innerHTML = '<p style="color: #666; text-align: center; padding: 20px;">📭 Нет анкет</p>';
            return;
        }
        
        list.innerHTML = '';
        applications.forEach(a => {
            let statusText = '';
            let statusClass = a.status || 'new';
            
            switch(a.status) {
                case 'new':
                    statusText = '🆕 Новая';
                    break;
                case 'accepted':
                    statusText = '✅ Принята';
                    break;
                case 'rejected':
                    statusText = '❌ Отклонена';
                    break;
                case 'resolved':
                    statusText = '📝 Отвечено';
                    break;
                default:
                    statusText = '🆕 Новая';
                    statusClass = 'new';
            }
            
            list.innerHTML += `
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
        });
    } catch (error) {
        console.error('❌ Ошибка загрузки анкет:', error);
        list.innerHTML = '<p style="color: red; text-align: center;">❌ Ошибка загрузки анкет</p>';
    }
}

// Функции для жалоб
async function acceptComplaint(id) {
    try {
        console.log('✅ Принимаем жалобу:', id);
        const numericId = Number(id);
        const updated = await window.updateComplaint(numericId, { status: 'accepted' });
        if (updated) {
            await loadAdminData();
            alert('✅ Жалоба принята!');
        } else {
            alert('❌ Ошибка при принятии жалобы');
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
            alert('❌ Ошибка при отклонении жалобы');
        }
    } catch (error) {
        console.error('❌ Ошибка:', error);
        alert('❌ Ошибка: ' + error.message);
    }
}

async function deleteComplaint(id) {
    if (confirm('❌ Вы уверены, что хотите удалить эту жалобу?')) {
        try {
            console.log('🗑️ Начинаем удаление жалобы ID:', id);
            
            const numericId = Number(id);
            console.log('🔢 Числовой ID:', numericId);
            
            const deleted = await window.deleteComplaint(numericId);
            console.log('📦 Результат удаления:', deleted);
            
            if (deleted !== false) {
                console.log('✅ Жалоба удалена успешно');
                await loadAdminData();
                alert('✅ Жалоба удалена!');
            } else {
                console.error('❌ Ошибка при удалении');
                alert('❌ Ошибка при удалении жалобы');
            }
        } catch (error) {
            console.error('❌ Ошибка в deleteComplaint:', error);
            alert('❌ Ошибка: ' + error.message);
        }
    }
}

// Функции для анкет
async function acceptApplication(id) {
    try {
        console.log('✅ Принимаем анкету:', id);
        const numericId = Number(id);
        const updated = await window.updateApplication(numericId, { status: 'accepted' });
        if (updated) {
            await loadAdminData();
            alert('✅ Анкета принята!');
        } else {
            alert('❌ Ошибка при принятии анкеты');
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
            alert('❌ Ошибка при отклонении анкеты');
        }
    } catch (error) {
        console.error('❌ Ошибка:', error);
        alert('❌ Ошибка: ' + error.message);
    }
}

async function deleteApplication(id) {
    if (confirm('❌ Вы уверены, что хотите удалить эту анкету?')) {
        try {
            console.log('🗑️ Начинаем удаление анкеты ID:', id);
            
            const numericId = Number(id);
            console.log('🔢 Числовой ID:', numericId);
            
            const deleted = await window.deleteApplication(numericId);
            console.log('📦 Результат удаления:', deleted);
            
            if (deleted !== false) {
                console.log('✅ Анкета удалена успешно');
                await loadAdminData();
                alert('✅ Анкета удалена!');
            } else {
                console.error('❌ Ошибка при удалении');
                alert('❌ Ошибка при удалении анкеты');
            }
        } catch (error) {
            console.error('❌ Ошибка в deleteApplication:', error);
            alert('❌ Ошибка: ' + error.message);
        }
    }
}

// Модалка ответа
function openResponseModal(type, id) {
    document.getElementById('responseModal').style.display = 'block';
    document.getElementById('responseId').value = id;
    document.getElementById('responseType').value = type;
    document.getElementById('responseTitle').textContent = type === 'complaint' ? 'Ответ на жалобу' : 'Ответ на анкету';
}

function closeResponseModal() {
    document.getElementById('responseModal').style.display = 'none';
    document.getElementById('responseForm').reset();
}

// Отправка ответа
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
            alert('❌ Ошибка при отправке ответа!');
        }
    } catch (error) {
        console.error('❌ Ошибка:', error);
        alert('❌ Ошибка: ' + error.message);
    }
}

// Переключение табов
function showAdminTab(tabName) {
    document.querySelectorAll('.admin-tab').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.admin-tab-content').forEach(content => content.classList.remove('active'));
    
    event.target.classList.add('active');
    document.getElementById('admin' + tabName.charAt(0).toUpperCase() + tabName.slice(1)).classList.add('active');
}

function getStatus(status) {
    const statuses = {
        'new': '🆕 Новая',
        'accepted': '✅ Принята',
        'rejected': '❌ Отклонена',
        'resolved': '📝 Отвечено'
    };
    return statuses[status] || '🆕 Новая';
}
