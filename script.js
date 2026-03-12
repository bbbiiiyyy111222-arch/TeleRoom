// ==============================================
// MOONGRIEF-FORUM - ПОЛНЫЙ СКРИПТ (С ФОТО/ВИДЕО)
// ==============================================

console.log('🌙 MoonGrief-Forum загружается...');

let currentUser = null;
let currentDevice = localStorage.getItem('mg_device') || null;
let complaintFiles = []; // Для хранения файлов жалобы
let currentPhotoData = null; // Для фото в проблемах

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
    
    if (sectionId === 'problems') {
        loadProblems();
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
// АВТОРИЗАЦИЯ (ЧЕРЕЗ SUPABASE)
// ==============================================

window.login = async function() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    
    if (!username || !password) {
        alert('Введите ник и пароль');
        return;
    }
    
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
                role: user.role || 'user'
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
                `<div class="complaint-files">
                    ${files.map((f, i) => `
                        <div class="complaint-file-item ${f.type.startsWith('video/') ? 'video-preview' : ''}" 
                             onclick="viewMedia('${f.data}', '${f.type}')">
                            ${f.type.startsWith('video/') ? '▶️' : '📷'}
                        </div>
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
// ОТПРАВКА ЖАЛОБ С ФАЙЛАМИ
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
            <div class="file-preview-item" onclick="viewMedia('${file.data}', '${file.type}')">
                ${file.type.startsWith('video/') ? '▶️' : '📷'}
                <span class="file-remove" onclick="removeComplaintFile(${index}); event.stopPropagation();">✖</span>
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
    if (event) event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите');
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
// ОТПРАВКА МЕДИА
// ==============================================

window.submitTT = async function(event) {
    if (event) event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите');
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
    if (event) event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите');
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
// ОТПРАВКА ХЕЛПЕРОВ
// ==============================================

window.submitHelper = async function(event) {
    if (event) event.preventDefault();
    
    if (!currentUser) {
        alert('Сначала войдите');
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
// ФУНКЦИИ ДЛЯ ФОТО В ПРОБЛЕМАХ
// ==============================================

window.handlePhotoSelect = function(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    if (file.size > 5 * 1024 * 1024) {
        alert('❌ Файл слишком большой! Максимум 5MB');
        return;
    }
    
    if (!file.type.startsWith('image/')) {
        alert('❌ Можно загружать только изображения');
        return;
    }
    
    const reader = new FileReader();
    reader.onload = function(e) {
        currentPhotoData = e.target.result;
        
        const preview = document.getElementById('photoPreview');
        const previewImg = document.getElementById('previewImage');
        const photoName = document.getElementById('photoName');
        
        if (preview && previewImg && photoName) {
            previewImg.src = e.target.result;
            preview.style.display = 'block';
            photoName.textContent = file.name;
        }
    };
    reader.readAsDataURL(file);
};

window.removePhoto = function() {
    currentPhotoData = null;
    const preview = document.getElementById('photoPreview');
    const photoName = document.getElementById('photoName');
    const photoInput = document.getElementById('problemPhoto');
    
    if (preview) preview.style.display = 'none';
    if (photoName) photoName.textContent = '';
    if (photoInput) photoInput.value = '';
};

// ==============================================
// ПРОБЛЕМЫ
// ==============================================

window.addProblem = async function(event) {
    event.preventDefault();
    
    if (!currentUser || currentUser.role !== 'owner') {
        alert('❌ Только администратор может добавлять проблемы');
        return;
    }
    
    const title = document.getElementById('problemTitle')?.value;
    const desc = document.getElementById('problemDesc')?.value;
    const solution = document.getElementById('problemSolution')?.value;
    
    if (!title || !desc || !solution) {
        alert('❌ Заполните все поля');
        return;
    }
    
    try {
        const { error } = await window.mgSupabase
            .from('problems')
            .insert([{
                title: title,
                description: desc,
                solution: solution,
                photo: currentPhotoData,
                author: currentUser.username,
                date: new Date().toLocaleString(),
                created_at: new Date().toISOString()
            }]);
        
        if (error) throw error;
        
        alert('✅ Проблема добавлена' + (currentPhotoData ? ' с фото' : ''));
        
        document.getElementById('problemForm').reset();
        removePhoto();
        loadProblems();
    } catch (e) {
        console.error('Ошибка добавления проблемы:', e);
        alert('❌ Ошибка при добавлении. Проверьте консоль.');
    }
};

async function loadProblems() {
    const list = document.getElementById('problemsList');
    if (!list) return;
    
    try {
        const { data, error } = await window.mgSupabase
            .from('problems')
            .select('*')
            .order('created_at', { ascending: false });
        
        if (error) throw error;
        
        if (!data || data.length === 0) {
            list.innerHTML = '<div class="empty-list">📭 Список проблем пуст</div>';
            return;
        }
        
        let html = '';
        data.forEach(p => {
            html += `
                <div class="problem-card">
                    <div class="problem-header">
                        <span class="problem-title">⚠️ ${p.title}</span>
                        <span class="problem-date">${p.date}</span>
                    </div>
                    <div class="problem-body">
                        <p><strong>📝 Описание:</strong> ${p.description}</p>
                        <p><strong>✅ Решение:</strong> ${p.solution}</p>
                        ${p.photo ? `
                        <div class="problem-photo" onclick="viewMedia('${p.photo}', 'image/jpeg')">
                            <img src="${p.photo}" alt="Фото проблемы">
                        </div>
                        ` : ''}
                        <p><small>👤 Добавил: ${p.author}</small></p>
                    </div>
                </div>
            `;
        });
        
        list.innerHTML = html;
    } catch (e) {
        console.error('Ошибка загрузки проблем:', e);
        list.innerHTML = '<div class="empty-list">❌ Ошибка загрузки</div>';
    }
}

// ==============================================
// ПРОСМОТР МЕДИА
// ==============================================

window.viewMedia = function(dataUrl, type) {
    const oldModal = document.getElementById('mediaViewModal');
    if (oldModal) oldModal.remove();
    
    const modal = document.createElement('div');
    modal.id = 'mediaViewModal';
    modal.className = 'media-view-modal';
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
    closeBtn.className = 'close-media';
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
