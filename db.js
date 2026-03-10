// ==============================================
// MOONGRIEF-FORUM - БАЗА ДАННЫХ
// ==============================================

console.log('✅ db.js загружается...');

const SUPABASE_URL = 'https://opeypwayctnnyrfkhajf.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9wZXlwd2F5Y3RubnlyZmtoYWpmIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzI5MzU4ODQsImV4cCI6MjA4ODUxMTg4NH0._Y1R1NNCVMyVgyeN7O7a24n4BGwc44c6vO1Q6MAf74A';

const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);

// ==============================================
// ПОЛЬЗОВАТЕЛИ
// ==============================================

window.getUsers = async function() {
    try {
        const { data, error } = await supabase
            .from('users')
            .select('*');
        
        if (error) throw error;
        return data || [];
    } catch (e) {
        console.error('Ошибка загрузки пользователей:', e);
        return [];
    }
};

window.checkUser = async function(username, password) {
    try {
        console.log(`🔍 Проверка пользователя: ${username}`);
        
        const { data, error } = await supabase
            .from('users')
            .select('*')
            .eq('username', username);
        
        if (error) throw error;
        
        if (!data || data.length === 0) {
            console.log('❌ Пользователь не найден');
            return null;
        }
        
        const user = data[0];
        console.log('👤 Найден пользователь:', user);
        
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
        console.error('Ошибка проверки пользователя:', e);
        return null;
    }
};

// ==============================================
// ЖАЛОБЫ
// ==============================================

window.saveComplaint = async function(complaint) {
    try {
        console.log('💾 Сохраняем жалобу:', complaint);
        
        const { data, error } = await supabase
            .from('complaints')
            .insert([{
                user_name: complaint.user,
                title: complaint.title,
                target: complaint.target,
                description: complaint.desc,
                status: 'НОВАЯ',
                date: new Date().toLocaleString('ru-RU'),
                created_at: new Date().toISOString()
            }])
            .select();
        
        if (error) throw error;
        
        console.log('✅ Жалоба сохранена:', data);
        return true;
    } catch (e) {
        console.error('❌ Ошибка сохранения жалобы:', e);
        return false;
    }
};

window.getComplaints = async function() {
    try {
        const { data, error } = await supabase
            .from('complaints')
            .select('*')
            .order('created_at', { ascending: false });
        
        if (error) throw error;
        
        console.log('📋 Загружено жалоб:', data?.length || 0);
        return data || [];
    } catch (e) {
        console.error('Ошибка загрузки жалоб:', e);
        return [];
    }
};

window.getUserComplaints = async function(username) {
    try {
        const { data, error } = await supabase
            .from('complaints')
            .select('*')
            .eq('user_name', username)
            .order('created_at', { ascending: false });
        
        if (error) throw error;
        return data || [];
    } catch (e) {
        console.error('Ошибка загрузки жалоб пользователя:', e);
        return [];
    }
};

window.updateComplaintStatus = async function(id, status) {
    try {
        const { error } = await supabase
            .from('complaints')
            .update({ status: status })
            .eq('id', id);
        
        if (error) throw error;
        return true;
    } catch (e) {
        console.error('Ошибка обновления статуса:', e);
        return false;
    }
};

// ==============================================
// МЕДИА-ЗАЯВКИ
// ==============================================

window.saveMediaApplication = async function(mediaApp) {
    try {
        console.log('💾 Сохраняем медиа-заявку:', mediaApp);
        
        const { data, error } = await supabase
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
                date: new Date().toLocaleString('ru-RU'),
                created_at: new Date().toISOString()
            }])
            .select();
        
        if (error) throw error;
        
        console.log('✅ Медиа-заявка сохранена:', data);
        return true;
    } catch (e) {
        console.error('❌ Ошибка сохранения медиа-заявки:', e);
        return false;
    }
};

window.getMediaApplications = async function() {
    try {
        const { data, error } = await supabase
            .from('media_applications')
            .select('*')
            .order('created_at', { ascending: false });
        
        if (error) throw error;
        
        console.log('📋 Загружено медиа-заявок:', data?.length || 0);
        return data || [];
    } catch (e) {
        console.error('Ошибка загрузки медиа-заявок:', e);
        return [];
    }
};

window.getUserMediaApplications = async function(username) {
    try {
        const { data, error } = await supabase
            .from('media_applications')
            .select('*')
            .eq('user_name', username)
            .order('created_at', { ascending: false });
        
        if (error) throw error;
        return data || [];
    } catch (e) {
        console.error('Ошибка загрузки медиа-заявок пользователя:', e);
        return [];
    }
};

window.updateMediaStatus = async function(id, status) {
    try {
        const { error } = await supabase
            .from('media_applications')
            .update({ status: status })
            .eq('id', id);
        
        if (error) throw error;
        return true;
    } catch (e) {
        console.error('Ошибка обновления статуса медиа-заявки:', e);
        return false;
    }
};

// ==============================================
// ХЕЛПЕРЫ
// ==============================================

window.saveHelperApplication = async function(helperApp) {
    try {
        console.log('💾 Сохраняем заявку на хелпера:', helperApp);
        
        const { data, error } = await supabase
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
                date: new Date().toLocaleString('ru-RU'),
                created_at: new Date().toISOString()
            }])
            .select();
        
        if (error) throw error;
        
        console.log('✅ Заявка на хелпера сохранена:', data);
        return true;
    } catch (e) {
        console.error('❌ Ошибка сохранения заявки на хелпера:', e);
        return false;
    }
};

window.getHelperApplications = async function() {
    try {
        const { data, error } = await supabase
            .from('helper_applications')
            .select('*')
            .order('created_at', { ascending: false });
        
        if (error) throw error;
        
        console.log('📋 Загружено заявок на хелпера:', data?.length || 0);
        return data || [];
    } catch (e) {
        console.error('Ошибка загрузки заявок на хелпера:', e);
        return [];
    }
};

window.getUserHelperApplications = async function(username) {
    try {
        const { data, error } = await supabase
            .from('helper_applications')
            .select('*')
            .eq('user_name', username)
            .order('created_at', { ascending: false });
        
        if (error) throw error;
        return data || [];
    } catch (e) {
        console.error('Ошибка загрузки заявок пользователя на хелпера:', e);
        return [];
    }
};

window.updateHelperStatus = async function(id, status) {
    try {
        const { error } = await supabase
            .from('helper_applications')
            .update({ status: status })
            .eq('id', id);
        
        if (error) throw error;
        return true;
    } catch (e) {
        console.error('Ошибка обновления статуса заявки на хелпера:', e);
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
            total: 0, new: 0, complaints: 0, media: 0, helpers: 0,
            newComplaints: 0, newMedia: 0, newHelpers: 0
        };
    }
};

// ==============================================
// ТЕСТ ПОДКЛЮЧЕНИЯ
// ==============================================

(async function testConnection() {
    console.log('🔄 Проверка подключения к Supabase...');
    
    const tables = ['users', 'complaints', 'media_applications', 'helper_applications'];
    
    for (const table of tables) {
        const { data, error } = await supabase
            .from(table)
            .select('count', { count: 'exact', head: true });
        
        if (error) {
            console.log(`❌ ${table}: ${error.message}`);
        } else {
            console.log(`✅ ${table}: доступна`);
        }
    }
    
    // Показываем пользователей
    const { data: users } = await supabase
        .from('users')
        .select('username, password');
    
    console.log('👥 Пользователи в базе:');
    users?.forEach(u => console.log(`   ${u.username}: ${u.password}`));
    
    console.log('✅ База данных готова к работе');
})();
