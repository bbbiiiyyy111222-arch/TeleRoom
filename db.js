// ==============================================
// MOONGRIEF-FORUM - БАЗА ДАННЫХ (С ЗАГОЛОВКАМИ)
// ==============================================

console.log('✅ db.js загружается...');

const SUPABASE_URL = 'https://opeypwayctnnyrfkhajf.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9wZXlwd2F5Y3RubnlyZmtoYWpmIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzI5MzU4ODQsImV4cCI6MjA4ODUxMTg4NH0._Y1R1NNCVMyVgyeN7O7a24n4BGwc44c6vO1Q6MAf74A';

// Создаем клиент с дополнительными опциями
if (!window.mgSupabase) {
    window.mgSupabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY, {
        auth: {
            persistSession: false,
            autoRefreshToken: false,
            detectSessionInUrl: false
        },
        global: {
            headers: {
                'X-Client-Info': 'moongrief-forum'
            }
        }
    });
    console.log('✅ Клиент Supabase создан');
}

// ==============================================
// ВСПОМОГАТЕЛЬНАЯ ФУНКЦИЯ ДЛЯ ПРОВЕРКИ
// ==============================================

async function testConnection() {
    try {
        const { error } = await window.mgSupabase
            .from('users')
            .select('count', { count: 'exact', head: true });
        
        if (error) {
            console.log('⚠️ Ошибка подключения:', error.message);
            return false;
        }
        console.log('✅ Подключение к Supabase работает');
        return true;
    } catch (e) {
        console.log('❌ Ошибка подключения:', e.message);
        return false;
    }
}

// Вызываем проверку
testConnection();

// ==============================================
// ПОЛЬЗОВАТЕЛИ
// ==============================================

window.checkUser = async function(username, password) {
    try {
        console.log(`🔍 Проверка пользователя: ${username}`);
        
        const { data, error } = await window.mgSupabase
            .from('users')
            .select('*')
            .eq('username', username);
        
        if (error) {
            console.error('Ошибка запроса:', error);
            return null;
        }
        
        if (!data || data.length === 0) {
            console.log('❌ Пользователь не найден');
            return null;
        }
        
        const user = data[0];
        console.log('👤 Найден пользователь:', user.username);
        
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
        console.error('Ошибка checkUser:', e);
        return null;
    }
};

// ==============================================
// ЖАЛОБЫ
// ==============================================

window.saveComplaint = async function(complaint) {
    try {
        console.log('💾 Сохраняем жалобу:', complaint);
        
        const { data, error } = await window.mgSupabase
            .from('complaints')
            .insert([{
                author: complaint.user,
                title: complaint.title,
                against: complaint.target,
                description: complaint.desc,
                status: 'НОВАЯ',
                date: new Date().toISOString()
            }])
            .select();
        
        if (error) {
            console.error('❌ Ошибка:', error);
            return false;
        }
        
        console.log('✅ Жалоба сохранена:', data);
        return true;
    } catch (e) {
        console.error('❌ Ошибка:', e);
        return false;
    }
};

window.getComplaints = async function() {
    try {
        const { data, error } = await window.mgSupabase
            .from('complaints')
            .select('*')
            .order('id', { ascending: false });
        
        if (error) {
            console.error('Ошибка загрузки жалоб:', error);
            return [];
        }
        
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
            .eq('author', username)
            .order('id', { ascending: false });
        
        if (error) {
            console.error('Ошибка загрузки жалоб пользователя:', error);
            return [];
        }
        
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
        
        if (error) {
            console.error('Ошибка обновления:', error);
            return false;
        }
        
        return true;
    } catch (e) {
        console.error('Ошибка обновления:', e);
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
                age: parseInt(mediaApp.age) || 0,
                real_name: mediaApp.name,
                nickname: mediaApp.nick,
                subscribers: mediaApp.subs,
                link: mediaApp.link,
                status: 'НОВАЯ',
                date: new Date().toLocaleString('ru-RU'),
                created_at: new Date().toISOString()
            }])
            .select();
        
        if (error) {
            console.error('❌ Ошибка:', error);
            return false;
        }
        
        console.log('✅ Медиа сохранено:', data);
        return true;
    } catch (e) {
        console.error('❌ Ошибка:', e);
        return false;
    }
};

window.getMediaApplications = async function() {
    try {
        const { data, error } = await window.mgSupabase
            .from('media_applications')
            .select('*')
            .order('id', { ascending: false });
        
        if (error) {
            console.error('Ошибка загрузки медиа:', error);
            return [];
        }
        
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
        
        if (error) {
            console.error('Ошибка загрузки медиа пользователя:', error);
            return [];
        }
        
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
        
        if (error) {
            console.error('Ошибка обновления:', error);
            return false;
        }
        
        return true;
    } catch (e) {
        console.error('Ошибка обновления:', e);
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
                age: parseInt(helperApp.age) || 0,
                timezone: helperApp.tz,
                experience: helperApp.exp,
                motivation: helperApp.why,
                status: 'НОВАЯ',
                date: new Date().toLocaleString('ru-RU'),
                created_at: new Date().toISOString()
            }])
            .select();
        
        if (error) {
            console.error('❌ Ошибка:', error);
            return false;
        }
        
        console.log('✅ Хелпер сохранен:', data);
        return true;
    } catch (e) {
        console.error('❌ Ошибка:', e);
        return false;
    }
};

window.getHelperApplications = async function() {
    try {
        const { data, error } = await window.mgSupabase
            .from('helper_applications')
            .select('*')
            .order('id', { ascending: false });
        
        if (error) {
            console.error('Ошибка загрузки хелперов:', error);
            return [];
        }
        
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
        
        if (error) {
            console.error('Ошибка загрузки хелперов пользователя:', error);
            return [];
        }
        
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
        
        if (error) {
            console.error('Ошибка обновления:', error);
            return false;
        }
        
        return true;
    } catch (e) {
        console.error('Ошибка обновления:', e);
        return false;
    }
};

// ==============================================
// СТАТИСТИКА
// ==============================================

window.getStats = async function() {
    try {
        const complaints = await window.getComplaints();
        const media = await window.getMediaApplications();
        const helpers = await window.getHelperApplications();
        
        return {
            total: complaints.length + media.length + helpers.length,
            new: complaints.filter(c => c.status === 'НОВАЯ').length + 
                 media.filter(m => m.status === 'НОВАЯ').length + 
                 helpers.filter(h => h.status === 'НОВАЯ').length,
            complaints: complaints.length,
            media: media.length,
            helpers: helpers.length,
            newComplaints: complaints.filter(c => c.status === 'НОВАЯ').length,
            newMedia: media.filter(m => m.status === 'НОВАЯ').length,
            newHelpers: helpers.filter(h => h.status === 'НОВАЯ').length
        };
    } catch (e) {
        console.error('Ошибка статистики:', e);
        return {
            total: 0, new: 0,
            complaints: 0, media: 0, helpers: 0,
            newComplaints: 0, newMedia: 0, newHelpers: 0
        };
    }
};

console.log('✅ db.js готов к работе!');
