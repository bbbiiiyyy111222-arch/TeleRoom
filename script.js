// ==============================================
// MOONGRIEF-FORUM - ПОЛНЫЙ СКРИПТ С ЗАЩИТОЙ
// ==============================================

console.log('🌙 MoonGrief-Forum загружается...');

// ==============================================
// ЗАЩИТА ОТ DDOS
// ==============================================

// Проверка на ботов
if (navigator.webdriver || !navigator.language || navigator.languages.length === 0) {
    window.location.href = 'about:blank';
}

const requestLimits = {};
const loginAttempts = {};

function checkRateLimit(userId, limit = 10, timeWindow = 60000) {
    const now = Date.now();
    if (!requestLimits[userId]) {
        requestLimits[userId] = [];
    }
    
    requestLimits[userId] = requestLimits[userId].filter(t => now - t < timeWindow);
    
    if (requestLimits[userId].length >= limit) {
        return false;
    }
    
    requestLimits[userId].push(now);
    return true;
}

// ==============================================
// ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ
// ==============================================

let currentUser = null;
let currentDevice = localStorage.getItem('mg_device') || null;
let complaintFiles = [];

// ==============================================
// ВЫБОР УСТРОЙСТВА
// ==============================================

window.selectDevice = function(device) {
    localStorage.setItem('mg_device', device);
    currentDevice = device;
    
    document.getElementById('deviceChoice').style.display = 'none';
    document.getElementById('mainSite').style.display = 'block';
    
    if (device === 'mobile') {
        document.body.classList.add('mobile-view');
        document.getElementById('deviceSwitch').style.display = 'block';
    } else {
        document.body.classList.remove('mobile-view');
        document.getElementById('deviceSwitch').style.display = 'none';
    }
    
    loadUserData();
};

window.showDeviceChoice = function() {
    document.getElementById('mainSite').style.display = 'none';
    document.getElementById('deviceChoice').style.display = 'flex';
};

// ==============================================
// КОПИРОВАНИЕ IP
// ==============================================

window.copyIP = function() {
    navigator.clipboard.writeText('Moongrief.aurorix.pro').then(() => {
        alert('📋 IP скопирован!');
    }).catch(() => {
        alert('❌ Ошибка копирования');
    });
};

// ==============================================
// НАВИГАЦИЯ
// ==============================================

window.showSection = function(sectionId) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-btn').forEach(b => {
        b.classList.remove('active');
        b.style.background = 'none';
        b.style.color = '#b0b0ff';
    });
    
    document.getElementById(sectionId).classList.add('active');
    if (event && event.target) {
        event.target.classList.add('active');
        event.target.style.background = '#4a4a8a';
        event.target.style.color = 'white';
    }
    
    if (sectionId === 'complaints' && currentUser) {
        loadPersonalComplaints();
    }
    if (sectionId === 'media' && currentUser) {
        loadPersonalMedia();
    }
    if (sectionId === 'applications' && currentUser) {
        loadPersonalHelpers();
    }
};

window.switchPlatform = function(platform) {
    const ttForm = document.getElementById('ttForm');
    const ytForm = document.getElementById('ytForm');
    const tabs = document.querySelectorAll('.tab');
    
    if (ttForm) ttForm.classList.remove('active');
    if (ytForm) ytForm.classList.remove('active');
    tabs.forEach(t => t.classList.remove('active'));
    
    if (platform === 'tt') {
        if (ttForm) ttForm.classList.add('active');
        if (tabs[0]) tabs[0].classList.add('active');
    } else {
        if (ytForm) ytForm.classList.add('active');
        if (tabs[1]) tabs[1].classList.add('active');
    }
};

// ==============================================
// АВТОРИЗАЦИЯ С ЗАЩИТОЙ
// ==============================================

window.login = async function() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    
    if (!username || !password) {
        alert('Введите ник и пароль');
        return;
    }
    
    // Защита от брутфорса
    const now = Date.now();
    if (!loginAttempts[username]) {
        loginAttempts[username] = { count: 0, lastAttempt: 0 };
    }
    
    if (now - loginAttempts[username].lastAttempt > 300000) {
        loginAttempts[username].count = 0;
    }
    
    if (loginAttempts[username].count >= 5) {
        alert('❌ Слишком много попыток. Подождите 5 минут.');
        return;
    }
    
    loginAttempts[username].count++;
    loginAttempts[username].lastAttempt = now;
    
    try {
        const { data, error } = await window.mgSupabase
            .from('users')
            .select('*')
            .eq('username', username)
            .eq('password', password);
        
        if (error) throw error;
        
        if (data && data.length > 0) {
            const user = data[0];
            
            currentUser = {
                username: user.username,
                role: user.role || (username === 'milfa' || username === 'milk123' || username === 'Xchik_' ? 'owner' : 'user')
            };
            
            localStorage.setItem('mg_currentUser', JSON.stringify(currentUser));
            
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('userInfo').style.display = 'flex';
            document.getElementById('currentUser').textContent = username;
            
            if (currentUser.role === 'owner') {
                document.getElementById('adminLink').style.display = 'inline-block';
            }
            
            alert(`🌙 Добро пожаловать, ${username}!`);
            
            document.getElementById('username').value = '';
            document.getElementById('password').value = '';
            
            // Сбрасываем счетчик при успешном входе
            loginAttempts[username].count = 0;
            
            loadPersonalComplaints();
            loadPersonalMedia();
            loadPersonalHelpers();
        } else {
            alert('❌ Неверный ник или пароль');
        }
    } catch (e) {
        console.error('Ошибка авторизации:', e);
        alert('❌ Ошибка подключения к базе данных');
    }
};

window.logout = function() {
    currentUser = null;
    localStorage.removeItem('mg_currentUser');
    
    document.getElementById('loginForm').style.display = 'flex';
    document.getElementById('userInfo').style.display = 'none';
    document.getElementById('adminLink').style.display = 'none';
    
    document.getElementById('complaintsList').innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои жалобы</div>';
    document.getElementById('mediaList').innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои анкеты</div>';
    document.getElementById('applicationsList').innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои анкеты</div>';
};

// ==============================================
// ЗАГРУЗКА ЛИЧНЫХ ЗАЯВОК
// ==============================================

async function loadPersonalComplaints() {
    const list = document.getElementById('complaintsList');
    if (!list) return;
    
    if (!currentUser) {
        list.innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои жалобы</div>';
        return;
    }
    
    try {
        const { data, error } = await window.mgSupabase
            .from('complaints')
            .select('*')
            .eq('author', currentUser.username)
            .order('id', { ascending: false });
        
        if (error) throw error;
        
        if (!data || data.length === 0) {
            list.innerHTML = '<div class="empty-list">📭 У вас пока нет жалоб</div>';
            return;
        }
        
        let html = '';
        data.forEach(c => {
            const files = c.files || [];
            const filesHtml = files.length > 0 ? 
                `<div style="display:flex; gap:5px; margin-top:5px;">
                    ${files.map((f, i) => `
                        <span onclick="viewMedia('${f.data}', '${f.type}')" style="cursor:pointer; background:#2a2a4a; padding:3px 8px; border-radius:5px;">
                            ${f.type.startsWith('video/') ? '▶️' : '📷'} Файл ${i+1}
                        </span>
                    `).join('')}
                </div>` : '';
            
            html += `
                <div class="complaint-card">
                    <div class="complaint-header">
                        <span class="complaint-title">${c.title || 'Жалоба'}</span>
                        <span class="complaint-status status-new">${c.status || 'НОВАЯ'}</span>
                    </div>
                    <div class="complaint-body">
                        <p><strong>Нарушитель:</strong> ${c.against || c.target || 'Не указан'}</p>
                        <p><strong>Описание:</strong> ${c.description || c.desc || 'Нет описания'}</p>
                        <p><strong>Дата:</strong> ${c.date || new Date().toLocaleString()}</p>
                        ${filesHtml}
                    </div>
                </div>
            `;
        });
        
        list.innerHTML = html;
    } catch (e) {
        console.error('Ошибка загрузки жалоб:', e);
        list.innerHTML = '<div class="empty-list">❌ Ошибка загрузки</div>';
    }
}

async function loadPersonalMedia() {
    const list = document.getElementById('mediaList');
    if (!list) return;
    
    if (!currentUser) {
        list.innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои анкеты</div>';
        return;
    }
    
    try {
        const { data, error } = await window.mgSupabase
            .from('media_applications')
            .select('*')
            .eq('user_name', currentUser.username)
            .order('id', { ascending: false });
        
        if (error) throw error;
        
        if (!data || data.length === 0) {
            list.innerHTML = '<div class="empty-list">📭 У вас пока нет медиа-заявок</div>';
            return;
        }
        
        let html = '';
        data.forEach(m => {
            html += `
                <div class="media-card">
                    <div class="media-header">
                        <span class="media-title">${m.platform === 'tt' ? '📱 TikTok' : '▶️ YouTube'}</span>
                        <span class="media-status status-new">${m.status || 'НОВАЯ'}</span>
                    </div>
                    <div class="media-body">
                        <p><strong>Ник:</strong> ${m.nickname || m.nick || 'Не указан'}</p>
                        <p><strong>Подписчики:</strong> ${m.subscribers || m.subs || '0'}</p>
                        <p><strong>Дата:</strong> ${m.date || new Date().toLocaleString()}</p>
                    </div>
                </div>
            `;
        });
        
        list.innerHTML = html;
    } catch (e) {
        console.error('Ошибка загрузки медиа:', e);
        list.innerHTML = '<div class="empty-list">❌ Ошибка загрузки</div>';
    }
}

async function loadPersonalHelpers() {
    const list = document.getElementById('applicationsList');
    if (!list) return;
    
    if (!currentUser) {
        list.innerHTML = '<div class="empty-list">🌙 Войдите чтобы увидеть свои анкеты</div>';
        return;
    }
    
    try {
        const { data, error } = await window.mgSupabase
            .from('helper_applications')
            .select('*')
            .eq('user_name', currentUser.username)
            .order('id', { ascending: false });
        
        if (error) throw error;
        
        if (!data || data.length === 0) {
            list.innerHTML = '<div class="empty-list">📭 У вас пока нет анкет</div>';
            return;
        }
        
        let html = '';
        data.forEach(h => {
            html += `
                <div class="application-card">
                    <div class="application-header">
                        <span class="application-title">👮 Анкета на хелпера</span>
                        <span class="application-status status-new">${h.status || 'НОВАЯ'}</span>
                    </div>
                    <div class="application-body">
                        <p><strong>Ник:</strong> ${h.nickname || h.nick || 'Не указан'}</p>
                        <p><strong>Дата:</strong> ${h.date || new Date().toLocaleString()}</p>
                    </div>
                </div>
            `;
        });
        
        list.innerHTML = html;
    } catch (e) {
        console.error('Ошибка загрузки хелперов:', e);
        list.innerHTML = '<div class="empty-list">❌ Ошибка загрузки</div>';
    }
}

// ==============================================
// ОТПРАВКА ЖАЛОБ С ФАЙЛАМИ И ЗАЩИТОЙ
// ==============================================

window.handleComplaintFiles = function(event) {
    const files = Array.from(event.target.files);
    
    files.forEach(file => {
        if (file.size > 10 * 1024 * 1024) {
            alert(`❌ Файл ${file.name} слишком большой! Максимум 10MB`);
            return;
        }
        
        if (!file.type.startsWith('image/') && !file.type.startsWith('video/')) {
            alert(`❌ Файл ${file.name} должен быть изображением или видео`);
            return;
        }
        
        const reader = new FileReader();
        reader.onload = function(e) {
            complaintFiles.push({
                name: file.name,
                type: file.type,
                data: e.target.result
            });
            updateComplaintFilesPreview();
        };
        reader.readAsDataURL(file);
    });
};

function updateComplaintFilesPreview() {
    const preview = document.getElementById('complaintFilesPreview');
    if (!preview) return;
    
    if (complaintFiles.length === 0) {
        preview.innerHTML = '';
        return;
    }
    
    let html = '';
    complaintFiles.forEach((file, index) => {
        html += `
            <div style="display:inline-block; margin:5px; background:#2a2a4a; padding:5px; border-radius:5px;">
                ${file.type.startsWith('video/') ? '▶️' : '📷'} ${file.name}
                <span onclick="removeComplaintFile(${index})" style="margin-left:5px; cursor:pointer; color:#ff6a6a;">✖</span>
            </div>
        `;
    });
    
    preview.innerHTML = html;
}

window.removeComplaintFile = function(index) {
    complaintFiles.splice(index, 1);
    updateComplaintFilesPreview();
};

window.submitComplaint = async function(event) {
    event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите');
        return;
    }
    
    // Проверка лимита
    if (!checkRateLimit(currentUser.username)) {
        alert('❌ Слишком много запросов. Подождите минуту.');
        return;
    }
    
    const title = document.getElementById('compTitle')?.value;
    const target = document.getElementById('compTarget')?.value;
    const desc = document.getElementById('compDesc')?.value;
    
    if (!title || !target || !desc) {
        alert('Заполните все поля');
        return;
    }
    
    try {
        const { error } = await window.mgSupabase
            .from('complaints')
            .insert([{
                author: currentUser.username,
                title: title,
                against: target,
                description: desc,
                files: complaintFiles,
                status: 'НОВАЯ',
                date: new Date().toLocaleString()
            }]);
        
        if (error) throw error;
        
        alert('✅ Жалоба отправлена!' + (complaintFiles.length > 0 ? ` (${complaintFiles.length} файлов)` : ''));
        
        document.getElementById('compTitle').value = '';
        document.getElementById('compTarget').value = '';
        document.getElementById('compDesc').value = '';
        complaintFiles = [];
        updateComplaintFilesPreview();
        
        loadPersonalComplaints();
    } catch (e) {
        console.error('Ошибка отправки жалобы:', e);
        alert('❌ Ошибка при отправке');
    }
};

// ==============================================
// ОТПРАВКА МЕДИА С ЗАЩИТОЙ
// ==============================================

window.submitTT = async function(event) {
    event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите');
        return;
    }
    
    if (!checkRateLimit(currentUser.username)) {
        alert('❌ Слишком много запросов. Подождите минуту.');
        return;
    }
    
    const age = document.getElementById('ttAge')?.value;
    const name = document.getElementById('ttName')?.value;
    const nick = document.getElementById('ttNick')?.value;
    const subs = document.getElementById('ttSubs')?.value;
    const link = document.getElementById('ttLink')?.value;
    
    if (!age || !name || !nick || !subs || !link) {
        alert('Заполните все поля');
        return;
    }
    
    try {
        const { error } = await window.mgSupabase
            .from('media_applications')
            .insert([{
                user_name: currentUser.username,
                platform: 'tt',
                age: parseInt(age),
                real_name: name,
                nickname: nick,
                subscribers: subs,
                link: link,
                status: 'НОВАЯ',
                date: new Date().toLocaleString()
            }]);
        
        if (error) throw error;
        
        alert('✅ Заявка на TikTok отправлена!');
        document.getElementById('ttAge').value = '';
        document.getElementById('ttName').value = '';
        document.getElementById('ttNick').value = '';
        document.getElementById('ttSubs').value = '';
        document.getElementById('ttLink').value = '';
        loadPersonalMedia();
    } catch (e) {
        console.error('Ошибка отправки:', e);
        alert('❌ Ошибка при отправке');
    }
};

window.submitYT = async function(event) {
    event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите');
        return;
    }
    
    if (!checkRateLimit(currentUser.username)) {
        alert('❌ Слишком много запросов. Подождите минуту.');
        return;
    }
    
    const age = document.getElementById('ytAge')?.value;
    const name = document.getElementById('ytName')?.value;
    const nick = document.getElementById('ytNick')?.value;
    const subs = document.getElementById('ytSubs')?.value;
    const link = document.getElementById('ytLink')?.value;
    
    if (!age || !name || !nick || !subs || !link) {
        alert('Заполните все поля');
        return;
    }
    
    try {
        const { error } = await window.mgSupabase
            .from('media_applications')
            .insert([{
                user_name: currentUser.username,
                platform: 'yt',
                age: parseInt(age),
                real_name: name,
                nickname: nick,
                subscribers: subs,
                link: link,
                status: 'НОВАЯ',
                date: new Date().toLocaleString()
            }]);
        
        if (error) throw error;
        
        alert('✅ Заявка на YouTube отправлена!');
        document.getElementById('ytAge').value = '';
        document.getElementById('ytName').value = '';
        document.getElementById('ytNick').value = '';
        document.getElementById('ytSubs').value = '';
        document.getElementById('ytLink').value = '';
        loadPersonalMedia();
    } catch (e) {
        console.error('Ошибка отправки:', e);
        alert('❌ Ошибка при отправке');
    }
};

// ==============================================
// ОТПРАВКА ХЕЛПЕРОВ С ЗАЩИТОЙ
// ==============================================

window.submitHelper = async function(event) {
    event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите');
        return;
    }
    
    if (!checkRateLimit(currentUser.username)) {
        alert('❌ Слишком много запросов. Подождите минуту.');
        return;
    }
    
    const nick = document.getElementById('helpNick')?.value;
    const name = document.getElementById('helpName')?.value;
    const age = document.getElementById('helpAge')?.value;
    const tz = document.getElementById('helpTz')?.value;
    const exp = document.getElementById('helpExp')?.value;
    const why = document.getElementById('helpWhy')?.value;
    
    if (!nick || !name || !age || !tz || !exp || !why) {
        alert('Заполните все поля');
        return;
    }
    
    try {
        const { error } = await window.mgSupabase
            .from('helper_applications')
            .insert([{
                user_name: currentUser.username,
                nickname: nick,
                real_name: name,
                age: parseInt(age),
                timezone: tz,
                experience: exp,
                motivation: why,
                status: 'НОВАЯ',
                date: new Date().toLocaleString()
            }]);
        
        if (error) throw error;
        
        alert('✅ Анкета отправлена!');
        document.getElementById('helpNick').value = '';
        document.getElementById('helpName').value = '';
        document.getElementById('helpAge').value = '';
        document.getElementById('helpTz').value = '';
        document.getElementById('helpExp').value = '';
        document.getElementById('helpWhy').value = '';
        loadPersonalHelpers();
    } catch (e) {
        console.error('Ошибка отправки:', e);
        alert('❌ Ошибка при отправке');
    }
};

// ==============================================
// ПРОСМОТР МЕДИА
// ==============================================

window.viewMedia = function(dataUrl, type) {
    const oldModal = document.getElementById('mediaViewModal');
    if (oldModal) oldModal.remove();
    
    const modal = document.createElement('div');
    modal.id = 'mediaViewModal';
    modal.style.cssText = `
        display: flex;
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.95);
        justify-content: center;
        align-items: center;
        z-index: 100000;
        cursor: pointer;
    `;
    
    modal.onclick = function() { this.remove(); };
    
    let mediaElement;
    if (type.startsWith('video/')) {
        mediaElement = document.createElement('video');
        mediaElement.src = dataUrl;
        mediaElement.controls = true;
        mediaElement.style.maxWidth = '90%';
        mediaElement.style.maxHeight = '90%';
    } else {
        mediaElement = document.createElement('img');
        mediaElement.src = dataUrl;
        mediaElement.style.maxWidth = '90%';
        mediaElement.style.maxHeight = '90%';
        mediaElement.style.border = '3px solid #4a4a8a';
        mediaElement.style.borderRadius = '10px';
    }
    
    const closeBtn = document.createElement('span');
    closeBtn.innerHTML = '✖';
    closeBtn.style.cssText = `
        position: absolute;
        top: 20px;
        right: 30px;
        color: white;
        font-size: 40px;
        cursor: pointer;
        width: 50px;
        height: 50px;
        display: flex;
        align-items: center;
        justify-content: center;
        background: rgba(74, 74, 138, 0.5);
        border-radius: 50%;
        border: 2px solid #7a7aff;
        z-index: 100001;
    `;
    
    closeBtn.onclick = function(e) {
        e.stopPropagation();
        modal.remove();
    };
    
    modal.appendChild(mediaElement);
    modal.appendChild(closeBtn);
    document.body.appendChild(modal);
};

// ==============================================
// МОДАЛКИ
// ==============================================

window.showRegister = function() {
    document.getElementById('registerModal').style.display = 'flex';
};

window.closeModal = function() {
    document.getElementById('registerModal').style.display = 'none';
};

window.showChangePassword = function() {
    if (!currentUser) {
        alert('Сначала войдите');
        return;
    }
    document.getElementById('changePassModal').style.display = 'flex';
};

window.closeChangePass = function() {
    document.getElementById('changePassModal').style.display = 'none';
};

window.register = function() {
    alert('Функция регистрации временно отключена');
    closeModal();
};

window.changePassword = function() {
    alert('Функция смены пароля временно отключена');
    closeChangePass();
};

// ==============================================
// ЗАГРУЗКА ПРИ СТАРТЕ
// ==============================================

async function loadUserData() {
    const savedUser = localStorage.getItem('mg_currentUser');
    if (savedUser) {
        currentUser = JSON.parse(savedUser);
        
        document.getElementById('loginForm').style.display = 'none';
        document.getElementById('userInfo').style.display = 'flex';
        document.getElementById('currentUser').textContent = currentUser.username;
        
        if (currentUser.role === 'owner') {
            document.getElementById('adminLink').style.display = 'inline-block';
        }
        
        loadPersonalComplaints();
        loadPersonalMedia();
        loadPersonalHelpers();
    }
}

document.addEventListener('DOMContentLoaded', function() {
    console.log('🌙 MoonGrief-Forum запущен');
    
    const savedDevice = localStorage.getItem('mg_device');
    if (savedDevice) {
        document.getElementById('deviceChoice').style.display = 'none';
        document.getElementById('mainSite').style.display = 'block';
        if (savedDevice === 'mobile') {
            document.body.classList.add('mobile-view');
            document.getElementById('deviceSwitch').style.display = 'block';
        }
        loadUserData();
    }
});
