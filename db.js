// ==============================================
// MOONGRIEF-FORUM - БАЗА ДАННЫХ
// ==============================================

console.log('✅ db.js загружается...');

const SUPABASE_URL = 'https://opeypwayctnnyrfkhajf.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9wZXlwd2F5Y3RubnlyZmtoYWpmIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzI5MzU4ODQsImV4cCI6MjA4ODUxMTg4NH0._Y1R1NNCVMyVgyeN7O7a24n4BGwc44c6vO1Q6MAf74A';

if (!window.mgSupabase) {
    window.mgSupabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);
}

// ==============================================
// ПОЛЬЗОВАТЕЛИ - ИСПРАВЛЕНО (СВОИ ПАРОЛИ)
// ==============================================

window.checkUser = async function(username, password) {
    try {
        console.log(`🔍 Проверка: ${username} / ${password}`);
        
        const { data, error } = await window.mgSupabase
            .from('users')
            .select('*')
            .eq('username', username);
        
        if (error || !data || data.length === 0) {
            console.log('❌ Пользователь не найден');
            return null;
        }
        
        const user = data[0];
        console.log('👤 Найден:', user.username, 'пароль в БД:', user.password);
        
        // Сравниваем с введенным паролем
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
// ЖАЛОБЫ - ИСПРАВЛЕНО (БЕЗ created_at)
// ==============================================

window.saveComplaint = async function(complaint) {
    try {
        const { error } = await window.mgSupabase
            .from('complaints')
            .insert([{
                user_name: complaint.user,
                title: complaint.title,
                target: complaint.target,
                description: complaint.desc,
                status: 'НОВАЯ',
                date: new Date().toLocaleString('ru-RU')
            }]);
        
        if (error) throw error;
        console.log('✅ Жалоба сохранена');
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
            .select('*');
        
        if (error) throw error;
        return data || [];
    } catch (e) {
        console.error('Ошибка загрузки жалоб:', e);
        return [];
    }
};

// ==============================================
// МЕДИА-ЗАЯВКИ - ИСПРАВЛЕНО
// ==============================================

window.saveMediaApplication = async function(mediaApp) {
    try {
        const { error } = await window.mgSupabase
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
            }]);
        
        if (error) throw error;
        console.log('✅ Медиа-заявка сохранена');
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
            .select('*');
        
        if (error) throw error;
        return data || [];
    } catch (e) {
        console.error('Ошибка загрузки медиа-заявок:', e);
        return [];
    }
};

// ==============================================
// ХЕЛПЕРЫ - ИСПРАВЛЕНО
// ==============================================

window.saveHelperApplication = async function(helperApp) {
    try {
        const { error } = await window.mgSupabase
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
            }]);
        
        if (error) throw error;
        console.log('✅ Заявка на хелпера сохранена');
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
            .select('*');
        
        if (error) throw error;
        return data || [];
    } catch (e) {
        console.error('Ошибка загрузки заявок на хелпера:', e);
        return [];
    }
};
