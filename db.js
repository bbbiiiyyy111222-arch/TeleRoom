// ==============================================
// MOONGRIEF-FORUM - БАЗА ДАННЫХ
// ==============================================

console.log('✅ db.js загружается...');

const SUPABASE_URL = 'https://opeypwayctnnyrfkhajf.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9wZXlwd2F5Y3RubnlyZmtoYWpmIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzI5MzU4ODQsImV4cCI6MjA4ODUxMTg4NH0._Y1R1NNCVMyVgyeN7O7a24n4BGwc44c6vO1Q6MAf74A';

const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);

// ==============================================
// ПОЛЬЗОВАТЕЛИ - СВОИ ПАРОЛИ
// ==============================================

window.getUsers = async function() {
    const { data, error } = await supabase
        .from('users')
        .select('*');
    if (error) console.error(error);
    return data || [];
};

window.checkUser = async function(username, password) {
    console.log(`🔍 Проверка: ${username} / ${password}`);
    
    // Ищем пользователя по username
    const { data, error } = await supabase
        .from('users')
        .select('*')
        .eq('username', username);
    
    if (error) {
        console.error('Ошибка:', error);
        return null;
    }
    
    if (!data || data.length === 0) {
        console.log('❌ Пользователь не найден');
        return null;
    }
    
    const user = data[0];
    console.log('👤 Найден:', user);
    
    // Сравниваем пароль
    if (user.password === password) {
        console.log('✅ Пароль верный');
        
        // Определяем роль
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
};

// ==============================================
// ЖАЛОБЫ
// ==============================================

window.saveComplaint = async function(complaint) {
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
    
    if (error) {
        console.error('❌ Ошибка:', error);
        return false;
    }
    
    console.log('✅ Сохранено:', data);
    return true;
};

window.getComplaints = async function() {
    const { data, error } = await supabase
        .from('complaints')
        .select('*')
        .order('created_at', { ascending: false });
    
    if (error) console.error(error);
    return data || [];
};

window.getUserComplaints = async function(username) {
    const { data, error } = await supabase
        .from('complaints')
        .select('*')
        .eq('user_name', username)
        .order('created_at', { ascending: false });
    
    return data || [];
};

window.updateComplaintStatus = async function(id, status) {
    const { error } = await supabase
        .from('complaints')
        .update({ status: status })
        .eq('id', id);
    
    return !error;
};

// ==============================================
// МЕДИА-ЗАЯВКИ
// ==============================================

window.saveMediaApplication = async function(mediaApp) {
    const { error } = await supabase
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
        }]);
    
    if (error) console.error(error);
    return !error;
};

window.getMediaApplications = async function() {
    const { data, error } = await supabase
        .from('media_applications')
        .select('*')
        .order('created_at', { ascending: false });
    
    return data || [];
};

window.updateMediaStatus = async function(id, status) {
    const { error } = await supabase
        .from('media_applications')
        .update({ status: status })
        .eq('id', id);
    
    return !error;
};

// ==============================================
// ХЕЛПЕРЫ
// ==============================================

window.saveHelperApplication = async function(helperApp) {
    const { error } = await supabase
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
        }]);
    
    if (error) console.error(error);
    return !error;
};

window.getHelperApplications = async function() {
    const { data, error } = await supabase
        .from('helper_applications')
        .select('*')
        .order('created_at', { ascending: false });
    
    return data || [];
};

window.updateHelperStatus = async function(id, status) {
    const { error } = await supabase
        .from('helper_applications')
        .update({ status: status })
        .eq('id', id);
    
    return !error;
};

// ==============================================
// ТЕСТ
// ==============================================

(async function() {
    console.log('🔄 Проверка подключения...');
    
    // Проверяем таблицы
    const tables = ['users', 'complaints', 'media_applications', 'helper_applications'];
    for (const table of tables) {
        const { error } = await supabase
            .from(table)
            .select('count', { count: 'exact', head: true });
        
        console.log(error ? `❌ ${table}` : `✅ ${table}`);
    }
    
    // Показываем пользователей
    const { data: users } = await supabase.from('users').select('username, password');
    console.log('👥 Пользователи в базе:');
    users.forEach(u => console.log(`   ${u.username}: ${u.password}`));
    
    console.log('✅ База готова!');
})();
