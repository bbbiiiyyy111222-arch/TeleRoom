// ==============================================
// MOONGRIEF-FORUM - БАЗА ДАННЫХ (ФИНАЛ)
// ==============================================

console.log('✅ db.js загружается...');

const SUPABASE_URL = 'https://opeypwayctnnyrfkhajf.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9wZXlwd2F5Y3RubnlyZmtoYWpmIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzI5MzU4ODQsImV4cCI6MjA4ODUxMTg4NH0._Y1R1NNCVMyVgyeN7O7a24n4BGwc44c6vO1Q6MAf74A';

if (!window.mgSupabase) {
    window.mgSupabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);
    console.log('✅ Создан клиент Supabase');
}

// ==============================================
// ПОЛЬЗОВАТЕЛИ
// ==============================================

window.checkUser = async function(username, password) {
    try {
        console.log(`🔍 Проверка: ${username}`);
        
        const { data, error } = await window.mgSupabase
            .from('users')
            .select('*')
            .eq('username', username);
        
        if (error) throw error;
        
        if (!data || data.length === 0) {
            console.log('❌ Пользователь не найден');
            return null;
        }
        
        const user = data[0];
        
        if (user.password === password) {
            console.log('✅ Пароль верный');
            
            let role = 'user';
            if (username === 'milfa' || username === 'milk123' || username === 'Xchik_') {
                role = 'owner';
            }
            
            return {
                username: user.username,
                password: user.password,
                role: role
            };
        } else {
            console.log('❌ Неверный пароль');
            return null;
        }
    } catch (e) {
        console.error('Ошибка:', e);
        return null;
    }
};

// ==============================================
// ЖАЛОБЫ - ТОЧНО ПО ТВОЕЙ ТАБЛИЦЕ
// ==============================================

window.saveComplaint = async function(complaint) {
    try {
        console.log('💾 Сохраняем жалобу:', complaint);
        
        const { data, error } = await window.mgSupabase
            .from('complaints')
            .insert([{
                user_name: complaint.user,
                title: complaint.title,
                against: complaint.target,  // target -> against
                description: complaint.desc,
                status: 'НОВАЯ',
                date: new Date().toLocaleString('ru-RU')
            }])
            .select();
        
        if (error) {
            console.error('❌ Ошибка:', error);
            alert('Ошибка: ' + error.message);
            return false;
        }
        
        console.log('✅ Жалоба сохранена:', data);
        alert('✅ Жалоба отправлена!');
        return true;
    } catch (e) {
        console.error('❌ Ошибка:', e);
        alert('Ошибка: ' + e.message);
        return false;
    }
};

window.getComplaints = async function() {
    try {
        const { data, error } = await window.mgSupabase
            .from('complaints')
            .select('*')
            .order('id', { ascending: false });
        
        if (error) throw error;
        return data || [];
    } catch (e) {
        console.error('Ошибка загрузки жалоб:', e);
        return [];
    }
};

window.getUserComplaints = async function(username) {
    try {
        const { data, error } = await window.mgSupabase
            .from('complaints')
            .select('*')
            .eq('user_name', username)
            .order('id', { ascending: false });
        
        if (error) throw error;
        return data || [];
    } catch (e) {
        console.error('Ошибка загрузки жалоб пользователя:', e);
        return [];
    }
};

window.updateComplaintStatus = async function(id, status) {
    try {
        const { error } = await window.mgSupabase
            .from('complaints')
            .update({ status: status })
            .eq('id', id);
        
        if (error) throw error;
        alert('✅ Статус обновлен');
        return true;
    } catch (e) {
        console.error('Ошибка обновления статуса:', e);
        alert('❌ Ошибка обновления');
        return false;
    }
};

// ==============================================
// МЕДИА-ЗАЯВКИ
// ==============================================

window.saveMediaApplication = async function(mediaApp) {
    try {
        console.log('💾 Сохраняем медиа:', mediaApp);
        
        const { data, error } = await window.mgSupabase
            .from('media_applications')
            .insert([{
                user_name: mediaApp.user,
                platform: mediaApp.type,
                age: mediaApp.age,
                real_name: mediaApp.name,
                nickname: mediaApp.nick,
                subscribers: mediaApp.subs,
                link: mediaApp.link,
                status: 'НОВАЯ',
                date: new Date().toLocaleString('ru-RU')
            }])
            .select();
        
        if (error) {
            console.error('❌ Ошибка:', error);
            alert('Ошибка: ' + error.message);
            return false;
        }
        
        console.log('✅ Медиа сохранено:', data);
        alert('✅ Заявка отправлена!');
        return true;
    } catch (e) {
        console.error('❌ Ошибка:', e);
        alert('Ошибка: ' + e.message);
        return false;
    }
};

window.getMediaApplications = async function() {
    try {
        const { data, error } = await window.mgSupabase
            .from('media_applications')
            .select('*')
            .order('id', { ascending: false });
        
        if (error) throw error;
        return data || [];
    } catch (e) {
        console.error('Ошибка загрузки медиа:', e);
        return [];
    }
};

window.getUserMediaApplications = async function(username) {
    try {
        const { data, error } = await window.mgSupabase
            .from('media_applications')
            .select('*')
            .eq('user_name', username)
            .order('id', { ascending: false });
        
        if (error) throw error;
        return data || [];
    } catch (e) {
        console.error('Ошибка загрузки медиа пользователя:', e);
        return [];
    }
};

window.updateMediaStatus = async function(id, status) {
    try {
        const { error } = await window.mgSupabase
            .from('media_applications')
            .update({ status: status })
            .eq('id', id);
        
        if (error) throw error;
        alert('✅ Статус обновлен');
        return true;
    } catch (e) {
        console.error('Ошибка обновления статуса медиа:', e);
        alert('❌ Ошибка обновления');
        return false;
    }
};

// ==============================================
// ХЕЛПЕРЫ
// ==============================================

window.saveHelperApplication = async function(helperApp) {
    try {
        console.log('💾 Сохраняем хелпера:', helperApp);
        
        const { data, error } = await window.mgSupabase
            .from('helper_applications')
            .insert([{
                user_name: helperApp.user,
                nickname: helperApp.nick,
                real_name: helperApp.name,
                age: helperApp.age,
                timezone: helperApp.tz,
                experience: helperApp.exp,
                motivation: helperApp.why,
                status: 'НОВАЯ',
                date: new Date().toLocaleString('ru-RU')
            }])
            .select();
        
        if (error) {
            console.error('❌ Ошибка:', error);
            alert('Ошибка: ' + error.message);
            return false;
        }
        
        console.log('✅ Хелпер сохранен:', data);
        alert('✅ Анкета отправлена!');
        return true;
    } catch (e) {
        console.error('❌ Ошибка:', e);
        alert('Ошибка: ' + e.message);
        return false;
    }
};

window.getHelperApplications = async function() {
    try {
        const { data, error } = await window.mgSupabase
            .from('helper_applications')
            .select('*')
            .order('id', { ascending: false });
        
        if (error) throw error;
        return data || [];
    } catch (e) {
        console.error('Ошибка загрузки хелперов:', e);
        return [];
    }
};

window.getUserHelperApplications = async function(username) {
    try {
        const { data, error } = await window.mgSupabase
            .from('helper_applications')
            .select('*')
            .eq('user_name', username)
            .order('id', { ascending: false });
        
        if (error) throw error;
        return data || [];
    } catch (e) {
        console.error('Ошибка загрузки хелперов пользователя:', e);
        return [];
    }
};

window.updateHelperStatus = async function(id, status) {
    try {
        const { error } = await window.mgSupabase
            .from('helper_applications')
            .update({ status: status })
            .eq('id', id);
        
        if (error) throw error;
        alert('✅ Статус обновлен');
        return true;
    } catch (e) {
        console.error('Ошибка обновления статуса хелпера:', e);
        alert('❌ Ошибка обновления');
        return false;
    }
};

console.log('✅ db.js готов к работе');
