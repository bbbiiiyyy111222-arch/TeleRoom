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
        if (password !== 'admin123') {
            return null;
        }
        
        const { data, error } = await supabase
            .from('users')
            .select('*')
            .eq('name', username);
        
        if (error) throw error;
        
        if (data && data.length > 0) {
            const user = data[0];
            let role = 'user';
            if (username === 'milfa' || username === 'milk123' || username === 'Xchik_') {
                role = 'owner';
            }
            
            return {
                username: user.name,
                password: 'admin123',
                role: role
            };
        }
        return null;
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
        console.log('✅ Жалоба сохранена');
        return true;
    } catch (e) {
        console.error('Ошибка сохранения жалобы:', e);
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
        console.error('Ошибка обновления статуса жалобы:', e);
        return false;
    }
};

// ==============================================
// МЕДИА-ЗАЯВКИ (TIKTOK/YOUTUBE)
// ==============================================

window.saveMediaApplication = async function(mediaApp) {
    try {
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
        console.log('✅ Медиа-заявка сохранена');
        return true;
    } catch (e) {
        console.error('Ошибка сохранения медиа-заявки:', e);
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
// ЗАЯВКИ НА ХЕЛПЕРА
// ==============================================

window.saveHelperApplication = async function(helperApp) {
    try {
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
        console.log('✅ Заявка на хелпера сохранена');
        return true;
    } catch (e) {
        console.error('Ошибка сохранения заявки на хелпера:', e);
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
        
        const newComplaints = complaints.filter(c => c.status === 'НОВАЯ').length;
        const newMedia = media.filter(m => m.status === 'НОВАЯ').length;
        const newHelpers = helpers.filter(h => h.status === 'НОВАЯ').length;
        
        return {
            total: complaints.length + media.length + helpers.length,
            new: newComplaints + newMedia + newHelpers,
            complaints: complaints.length,
            media: media.length,
            helpers: helpers.length,
            newComplaints,
            newMedia,
            newHelpers
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

// ==============================================
// ПРОВЕРКА
// ==============================================

(async function() {
    console.log('✅ База данных готова к работе');
    console.log('📊 Таблицы: users, complaints, media_applications, helper_applications');
})();
