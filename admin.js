// Данные
let complaints = [];
let applications = [];
let currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;

// ВСЕ OWNER
const OWNERS = ['milfa', 'milk123', 'Xchik_'];

// Проверка доступа
document.addEventListener('DOMContentLoaded', async function() {
    console.log('Админ панель загружена');
    console.log('Текущий пользователь:', currentUser);
    
    if (!currentUser || !OWNERS.includes(currentUser.username)) {
        alert('У вас нет доступа к админ панели!');
        window.location.href = 'index.html';
        return;
    }
    
    document.getElementById('adminName').textContent = '👑 ' + currentUser.username + ' (OWNER)';
    
    // Загружаем данные
    await loadAdminData();
});

// Выход
function logout() {
    localStorage.removeItem('currentUser');
    window.location.href = 'index.html';
}

// Загрузка данных
async function loadAdminData() {
    await loadAdminComplaints();
    await loadAdminApplications();
    await updateStats();
}

// Обновление статистики
async function updateStats() {
    try {
        complaints = await getComplaints() || [];
        applications = await getApplications() || [];
        
        document.getElementById('newComplaints').textContent = complaints.filter(c => c.status === 'new').length;
        document.getElementById('newApplications').textContent = applications.filter(a => a.status === 'new').length;
        document.getElementById('total').textContent = complaints.length + applications.length;
    } catch (error) {
        console.error('Ошибка обновления статистики:', error);
    }
}

// Загрузка жалоб в админку
async function loadAdminComplaints() {
    const list = document.getElementById('adminComplaints');
    if (!list) return;
    
    try {
        complaints = await getComplaints() || [];
        console.log('Загружено жалоб:', complaints);
        
        if (complaints.length === 0) {
            list.innerHTML = '<p style="color: #666; text-align: center; padding: 20px;">Нет жалоб</p>';
            return;
        }
        
        list.innerHTML = '';
        complaints.forEach(c => {
            list.innerHTML += `
                <div class="request-card">
                    <div class="request-header">
                        <span>${c.title || 'Без названия'}</span>
                        <span class="request-status status-${c.status || 'new'}">${getStatus(c.status)}</span>
                    </div>
                    <div class="request-details">
                        <p><strong>ID:</strong> ${c.id || 'Нет'}</p>
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
        });
    } catch (error) {
        console.error('Ошибка загрузки жалоб:', error);
        list.innerHTML = '<p style="color: red; text-align: center;">Ошибка загрузки жалоб</p>';
    }
}

// Загрузка анкет в админку
async function loadAdminApplications() {
    const list = document.getElementById('adminApplications');
    if (!list) return;
    
    try {
        applications = await getApplications() || [];
        console.log('Загружено анкет:', applications);
        
        if (applications.length === 0) {
            list.innerHTML = '<p style="color: #666; text-align: center; padding: 20px;">Нет анкет</p>';
            return;
        }
        
        list.innerHTML = '';
        applications.forEach(a => {
            list.innerHTML += `
                <div class="request-card">
                    <div class="request-header">
                        <span>Анкета от ${a.author || 'Неизвестно'}</span>
                        <span class="request-status status-${a.status || 'new'}">${getStatus(a.status)}</span>
                    </div>
                    <div class="request-details">
                        <p><strong>ID:</strong> ${a.id || 'Нет'}</p>
                        <p><strong>Ник:</strong> ${a.nickname || 'Нет'}</p>
                        <p><strong>Имя:</strong> ${a.name || 'Нет'}</p>
                        <p><strong>Возраст:</strong> ${a.age || 'Нет'}</p>
                        <p><strong>Часовой пояс:</strong> ${a.timezone || 'Нет'}</p>
                        <p><strong>Опыт:</strong> ${a.experience || 'Нет'}</p>
                        <p><strong>Мотивация:</strong> ${a.reason || 'Нет'}</p>
                        <p><strong>Дополнительно:</strong> ${a.additional || 'Нет'}</p>
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
        });
    } catch (error) {
        console.error('Ошибка загрузки анкет:', error);
        list.innerHTML = '<p style="color: red; text-align: center;">Ошибка загрузки анкет</p>';
    }
}

// Функции для жалоб
async function acceptComplaint(id) {
    try {
        const updated = await updateComplaint(id, { status: 'resolved' });
        if (updated) {
            await loadAdminData();
            alert('Жалоба принята!');
        }
    } catch (error) {
        console.error('Ошибка:', error);
        alert('Ошибка при принятии жалобы');
    }
}

async function rejectComplaint(id) {
    try {
        const updated = await updateComplaint(id, { status: 'pending' });
        if (updated) {
            await loadAdminData();
            alert('Жалоба отклонена!');
        }
    } catch (error) {
        console.error('Ошибка:', error);
        alert('Ошибка при отклонении жалобы');
    }
}

async function deleteComplaint(id) {
    if (confirm('Удалить жалобу?')) {
        try {
            const deleted = await deleteComplaint(id);
            if (deleted) {
                await loadAdminData();
                alert('Жалоба удалена!');
            }
        } catch (error) {
            console.error('Ошибка:', error);
            alert('Ошибка при удалении жалобы');
        }
    }
}

// Функции для анкет
async function acceptApplication(id) {
    try {
        const updated = await updateApplication(id, { status: 'resolved' });
        if (updated) {
            await loadAdminData();
            alert('Анкета принята!');
        }
    } catch (error) {
        console.error('Ошибка:', error);
        alert('Ошибка при принятии анкеты');
    }
}

async function rejectApplication(id) {
    try {
        const updated = await updateApplication(id, { status: 'pending' });
        if (updated) {
            await loadAdminData();
            alert('Анкета отклонена!');
        }
    } catch (error) {
        console.error('Ошибка:', error);
        alert('Ошибка при отклонении анкеты');
    }
}

async function deleteApplication(id) {
    if (confirm('Удалить анкету?')) {
        try {
            const deleted = await deleteApplication(id);
            if (deleted) {
                await loadAdminData();
                alert('Анкета удалена!');
            }
        } catch (error) {
            console.error('Ошибка:', error);
            alert('Ошибка при удалении анкеты');
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
    
    const id = parseInt(document.getElementById('responseId').value);
    const type = document.getElementById('responseType').value;
    const response = document.getElementById('responseText').value;
    
    if (!response) {
        alert('Введите ответ!');
        return;
    }
    
    try {
        let updated = false;
        
        if (type === 'complaint') {
            updated = await updateComplaint(id, { 
                response: response,
                status: 'resolved' 
            });
        } else {
            updated = await updateApplication(id, { 
                response: response,
                status: 'resolved' 
            });
        }
        
        if (updated) {
            closeResponseModal();
            await loadAdminData();
            alert('Ответ отправлен!');
        } else {
            alert('Ошибка при отправке ответа!');
        }
    } catch (error) {
        console.error('Ошибка:', error);
        alert('Ошибка при отправке ответа');
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
        'pending': '⏳ В обработке',
        'resolved': '✅ Решена'
    };
    return statuses[status] || '🆕 Новая';
}
