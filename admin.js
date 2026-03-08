// Данные
let complaints = JSON.parse(localStorage.getItem('complaints')) || [];
let applications = JSON.parse(localStorage.getItem('applications')) || [];
let currentUser = JSON.parse(localStorage.getItem('currentUser')) || null;

// Владелец и админы
const OWNER = 'milfa';
const ADMINS = ['milk123', 'Xchik_'];

// Проверка доступа
document.addEventListener('DOMContentLoaded', function() {
    if (!currentUser || (currentUser.username !== OWNER && !ADMINS.includes(currentUser.username))) {
        alert('У вас нет доступа к админ панели!');
        window.location.href = 'index.html';
        return;
    }
    
    document.getElementById('adminName').textContent = '👤 ' + currentUser.username + (currentUser.username === OWNER ? ' (Owner)' : ' (Admin)');
    loadAdminData();
    updateStats();
});

// Выход
function logout() {
    localStorage.removeItem('currentUser');
    window.location.href = 'index.html';
}

// Загрузка данных
function loadAdminData() {
    loadAdminComplaints();
    loadAdminApplications();
}

// Обновление статистики
function updateStats() {
    complaints = JSON.parse(localStorage.getItem('complaints')) || [];
    applications = JSON.parse(localStorage.getItem('applications')) || [];
    
    document.getElementById('newComplaints').textContent = complaints.filter(c => c.status === 'new').length;
    document.getElementById('newApplications').textContent = applications.filter(a => a.status === 'new').length;
    document.getElementById('total').textContent = complaints.length + applications.length;
}

// Загрузка жалоб в админку
function loadAdminComplaints() {
    const list = document.getElementById('adminComplaints');
    if (!list) return;
    
    complaints = JSON.parse(localStorage.getItem('complaints')) || [];
    
    list.innerHTML = '';
    complaints.sort((a, b) => new Date(b.date) - new Date(a.date)).forEach(c => {
        list.innerHTML += `
            <div class="request-card">
                <div class="request-header">
                    <span>${c.title}</span>
                    <span class="request-status status-${c.status}">${getStatus(c.status)}</span>
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
    });
}

// Загрузка анкет в админку
function loadAdminApplications() {
    const list = document.getElementById('adminApplications');
    if (!list) return;
    
    applications = JSON.parse(localStorage.getItem('applications')) || [];
    
    list.innerHTML = '';
    applications.sort((a, b) => new Date(b.date) - new Date(a.date)).forEach(a => {
        list.innerHTML += `
            <div class="request-card">
                <div class="request-header">
                    <span>Анкета от ${a.author}</span>
                    <span class="request-status status-${a.status}">${getStatus(a.status)}</span>
                </div>
                <div class="request-details">
                    <p><strong>ID:</strong> ${a.id}</p>
                    <p><strong>Ник:</strong> ${a.nickname}</p>
                    <p><strong>Имя:</strong> ${a.name}</p>
                    <p><strong>Возраст:</strong> ${a.age}</p>
                    <p><strong>Часовой пояс:</strong> ${a.timezone}</p>
                    <p><strong>Опыт:</strong> ${a.experience}</p>
                    <p><strong>Мотивация:</strong> ${a.reason}</p>
                    <p><strong>Дополнительно:</strong> ${a.additional}</p>
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
    });
}

// Функции для жалоб
function acceptComplaint(id) {
    complaints = JSON.parse(localStorage.getItem('complaints')) || [];
    const index = complaints.findIndex(c => c.id === id);
    
    if (index !== -1) {
        complaints[index].status = 'resolved';
        localStorage.setItem('complaints', JSON.stringify(complaints));
        loadAdminData();
        updateStats();
    }
}

function rejectComplaint(id) {
    complaints = JSON.parse(localStorage.getItem('complaints')) || [];
    const index = complaints.findIndex(c => c.id === id);
    
    if (index !== -1) {
        complaints[index].status = 'pending';
        localStorage.setItem('complaints', JSON.stringify(complaints));
        loadAdminData();
        updateStats();
    }
}

function deleteComplaint(id) {
    if (confirm('Удалить жалобу?')) {
        complaints = JSON.parse(localStorage.getItem('complaints')) || [];
        complaints = complaints.filter(c => c.id !== id);
        localStorage.setItem('complaints', JSON.stringify(complaints));
        loadAdminData();
        updateStats();
    }
}

// Функции для анкет
function acceptApplication(id) {
    applications = JSON.parse(localStorage.getItem('applications')) || [];
    const index = applications.findIndex(a => a.id === id);
    
    if (index !== -1) {
        applications[index].status = 'resolved';
        localStorage.setItem('applications', JSON.stringify(applications));
        loadAdminData();
        updateStats();
    }
}

function rejectApplication(id) {
    applications = JSON.parse(localStorage.getItem('applications')) || [];
    const index = applications.findIndex(a => a.id === id);
    
    if (index !== -1) {
        applications[index].status = 'pending';
        localStorage.setItem('applications', JSON.stringify(applications));
        loadAdminData();
        updateStats();
    }
}

function deleteApplication(id) {
    if (confirm('Удалить анкету?')) {
        applications = JSON.parse(localStorage.getItem('applications')) || [];
        applications = applications.filter(a => a.id !== id);
        localStorage.setItem('applications', JSON.stringify(applications));
        loadAdminData();
        updateStats();
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
document.getElementById('responseForm')?.addEventListener('submit', function(e) {
    e.preventDefault();
    
    const id = parseInt(document.getElementById('responseId').value);
    const type = document.getElementById('responseType').value;
    const response = document.getElementById('responseText').value;
    
    if (type === 'complaint') {
        complaints = JSON.parse(localStorage.getItem('complaints')) || [];
        const index = complaints.findIndex(c => c.id === id);
        
        if (index !== -1) {
            complaints[index].response = response;
            complaints[index].status = 'resolved';
            localStorage.setItem('complaints', JSON.stringify(complaints));
        }
    } else {
        applications = JSON.parse(localStorage.getItem('applications')) || [];
        const index = applications.findIndex(a => a.id === id);
        
        if (index !== -1) {
            applications[index].response = response;
            applications[index].status = 'resolved';
            localStorage.setItem('applications', JSON.stringify(applications));
        }
    }
    
    closeResponseModal();
    loadAdminData();
    updateStats();
    alert('Ответ отправлен!');
});

// Переключение табов
function showAdminTab(tabName) {
    document.querySelectorAll('.admin-tab').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.admin-tab-content').forEach(content => content.classList.remove('active'));
    
    event.target.classList.add('active');
    document.getElementById('admin' + tabName.charAt(0).toUpperCase() + tabName.slice(1)).classList.add('active');
}

function getStatus(status) {
    const statuses = {
        'new': 'Новая',
        'pending': 'В обработке',
        'resolved': 'Решена'
    };
    return statuses[status] || status;
}
