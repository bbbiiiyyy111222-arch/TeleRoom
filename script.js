console.log('🌙 MoonGrief-Forum загружается...');

let currentUser = null;
let currentDevice = localStorage.getItem('mg_device') || null;

// ==============================================
// ВЫБОР УСТРОЙСТВА (РАБОТАЕТ НА ВСЕХ)
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
        document.getElementById('deviceSwitch').style.display = 'block';
    }
    
    loadUserData();
};

window.showDeviceChoice = function() {
    document.getElementById('mainSite').style.display = 'none';
    document.getElementById('deviceChoice').style.display = 'flex';
};

window.copyIP = function() {
    navigator.clipboard.writeText('Moongrief.aurorix.pro').then(() => alert('📋 IP скопирован!'));
};

// ==============================================
// НАВИГАЦИЯ
// ==============================================

window.showSection = function(sectionId) {
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    document.getElementById(sectionId).classList.add('active');
    event.target.classList.add('active');
};

window.switchPlatform = function(platform) {
    document.getElementById('ttForm').classList.remove('active');
    document.getElementById('ytForm').classList.remove('active');
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    if (platform === 'tt') {
        document.getElementById('ttForm').classList.add('active');
        document.querySelectorAll('.tab')[0].classList.add('active');
    } else {
        document.getElementById('ytForm').classList.add('active');
        document.querySelectorAll('.tab')[1].classList.add('active');
    }
};

// ==============================================
// АВТОРИЗАЦИЯ
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
            currentUser = {
                username: data[0].username,
                role: (username === 'milfa' || username === 'milk123' || username === 'Xchik_') ? 'owner' : 'user'
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
            html += `<div class="complaint-card"><div class="complaint-header"><span class="complaint-title">${c.title || 'Жалоба'}</span><span class="complaint-status status-new">${c.status || 'НОВАЯ'}</span></div><div class="complaint-body"><p><strong>Нарушитель:</strong> ${c.against || 'Не указан'}</p><p><strong>Описание:</strong> ${c.description || 'Нет описания'}</p><p><strong>Дата:</strong> ${c.date || new Date().toLocaleString()}</p></div></div>`;
        });
        list.innerHTML = html;
    } catch (e) {
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
            html += `<div class="media-card"><div class="media-header"><span class="media-title">${m.platform === 'tt' ? '📱 TikTok' : '▶️ YouTube'}</span><span class="media-status status-new">${m.status || 'НОВАЯ'}</span></div><div class="media-body"><p><strong>Ник:</strong> ${m.nickname || 'Не указан'}</p><p><strong>Подписчики:</strong> ${m.subscribers || '0'}</p><p><strong>Дата:</strong> ${m.date || new Date().toLocaleString()}</p></div></div>`;
        });
        list.innerHTML = html;
    } catch (e) {
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
            html += `<div class="application-card"><div class="application-header"><span class="application-title">👮 Анкета на хелпера</span><span class="application-status status-new">${h.status || 'НОВАЯ'}</span></div><div class="application-body"><p><strong>Ник:</strong> ${h.nickname || 'Не указан'}</p><p><strong>Дата:</strong> ${h.date || new Date().toLocaleString()}</p></div></div>`;
        });
        list.innerHTML = html;
    } catch (e) {
        list.innerHTML = '<div class="empty-list">❌ Ошибка загрузки</div>';
    }
}

// ==============================================
// ОТПРАВКА ФОРМ
// ==============================================

window.submitComplaint = async function(event) {
    event.preventDefault();
    if (!currentUser) { alert('Сначала войдите'); return; }
    
    const title = document.getElementById('compTitle')?.value;
    const target = document.getElementById('compTarget')?.value;
    const desc = document.getElementById('compDesc')?.value;
    if (!title || !target || !desc) { alert('Заполните все поля'); return; }
    
    try {
        const { error } = await window.mgSupabase.from('complaints').insert([{ author: currentUser.username, title: title, against: target, description: desc, status: 'НОВАЯ', date: new Date().toLocaleString() }]);
        if (error) throw error;
        alert('✅ Жалоба отправлена!');
        document.getElementById('compTitle').value = '';
        document.getElementById('compTarget').value = '';
        document.getElementById('compDesc').value = '';
        loadPersonalComplaints();
    } catch (e) { alert('❌ Ошибка при отправке'); }
};

window.submitTT = async function(event) {
    event.preventDefault();
    if (!currentUser) { alert('Сначала войдите'); return; }
    
    const age = document.getElementById('ttAge')?.value;
    const name = document.getElementById('ttName')?.value;
    const nick = document.getElementById('ttNick')?.value;
    const subs = document.getElementById('ttSubs')?.value;
    const link = document.getElementById('ttLink')?.value;
    if (!age || !name || !nick || !subs || !link) { alert('Заполните все поля'); return; }
    
    try {
        const { error } = await window.mgSupabase.from('media_applications').insert([{ user_name: currentUser.username, platform: 'tt', age: parseInt(age), real_name: name, nickname: nick, subscribers: subs, link: link, status: 'НОВАЯ', date: new Date().toLocaleString() }]);
        if (error) throw error;
        alert('✅ Заявка на TikTok отправлена!');
        document.getElementById('ttAge').value = '';
        document.getElementById('ttName').value = '';
        document.getElementById('ttNick').value = '';
        document.getElementById('ttSubs').value = '';
        document.getElementById('ttLink').value = '';
        loadPersonalMedia();
    } catch (e) { alert('❌ Ошибка при отправке'); }
};

window.submitYT = async function(event) {
    event.preventDefault();
    if (!currentUser) { alert('Сначала войдите'); return; }
    
    const age = document.getElementById('ytAge')?.value;
    const name = document.getElementById('ytName')?.value;
    const nick = document.getElementById('ytNick')?.value;
    const subs = document.getElementById('ytSubs')?.value;
    const link = document.getElementById('ytLink')?.value;
    if (!age || !name || !nick || !subs || !link) { alert('Заполните все поля'); return; }
    
    try {
        const { error } = await window.mgSupabase.from('media_applications').insert([{ user_name: currentUser.username, platform: 'yt', age: parseInt(age), real_name: name, nickname: nick, subscribers: subs, link: link, status: 'НОВАЯ', date: new Date().toLocaleString() }]);
        if (error) throw error;
        alert('✅ Заявка на YouTube отправлена!');
        document.getElementById('ytAge').value = '';
        document.getElementById('ytName').value = '';
        document.getElementById('ytNick').value = '';
        document.getElementById('ytSubs').value = '';
        document.getElementById('ytLink').value = '';
        loadPersonalMedia();
    } catch (e) { alert('❌ Ошибка при отправке'); }
};

window.submitHelper = async function(event) {
    event.preventDefault();
    if (!currentUser) { alert('Сначала войдите'); return; }
    
    const nick = document.getElementById('helpNick')?.value;
    const name = document.getElementById('helpName')?.value;
    const age = document.getElementById('helpAge')?.value;
    const tz = document.getElementById('helpTz')?.value;
    const exp = document.getElementById('helpExp')?.value;
    const why = document.getElementById('helpWhy')?.value;
    if (!nick || !name || !age || !tz || !exp || !why) { alert('Заполните все поля'); return; }
    
    try {
        const { error } = await window.mgSupabase.from('helper_applications').insert([{ user_name: currentUser.username, nickname: nick, real_name: name, age: parseInt(age), timezone: tz, experience: exp, motivation: why, status: 'НОВАЯ', date: new Date().toLocaleString() }]);
        if (error) throw error;
        alert('✅ Анкета отправлена!');
        document.getElementById('helpNick').value = '';
        document.getElementById('helpName').value = '';
        document.getElementById('helpAge').value = '';
        document.getElementById('helpTz').value = '';
        document.getElementById('helpExp').value = '';
        document.getElementById('helpWhy').value = '';
        loadPersonalHelpers();
    } catch (e) { alert('❌ Ошибка при отправке'); }
};

// ==============================================
// МОДАЛКИ
// ==============================================

window.showRegister = function() { document.getElementById('registerModal').style.display = 'flex'; };
window.closeModal = function() { document.getElementById('registerModal').style.display = 'none'; };
window.showChangePassword = function() { if (!currentUser) { alert('Сначала войдите'); return; } document.getElementById('changePassModal').style.display = 'flex'; };
window.closeChangePass = function() { document.getElementById('changePassModal').style.display = 'none'; };
window.register = function() { alert('Функция регистрации временно отключена'); closeModal(); };
window.changePassword = function() { alert('Функция смены пароля временно отключена'); closeChangePass(); };

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
        if (currentUser.role === 'owner') { document.getElementById('adminLink').style.display = 'inline-block'; }
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
        if (savedDevice === 'mobile') { document.body.classList.add('mobile-view'); }
        document.getElementById('deviceSwitch').style.display = 'block';
        loadUserData();
    }
});
