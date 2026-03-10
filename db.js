// ==============================================
// MOONGRIEF-FORUM - БАЗА ДАННЫХ
// ==============================================

console.log('✅ db.js загружается...');

// Supabase подключение
const SUPABASE_URL = 'https://opeypwayctnnyrfkhajf.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9wZXlwd2F5Y3RubnlyZmtoYWpmIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzI5MzU4ODQsImV4cCI6MjA4ODUxMTg4NH0._Y1R1NNCVMyVgyeN7O7a24n4BGwc44c6vO1Q6MAf74A';

// Создаем клиент
const moonGriefSupabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);

// ==============================================
// ПОЛЬЗОВАТЕЛИ - ПАРОЛЬ admin123 ДЛЯ ВСЕХ
// ==============================================

window.getUsers = async function() {
    try {
        const { data, error } = await moonGriefSupabase
            .from('users')
            .select('*');
        
        if (error) {
            console.error('Ошибка загрузки пользователей:', error);
            return [];
        }
        return data || [];
    } catch (e) {
        console.error('Исключение при загрузке пользователей:', e);
        return [];
    }
};

// Проверка при входе - пароль ВСЕГДА admin123
window.checkUser = async function(username, password) {
    try {
        console.log('🔍 Проверка пользователя:', username, 'пароль:', password);
        
        // Проверяем что пароль равен admin123
        if (password !== 'admin123') {
            console.log('❌ Неверный пароль (должен быть admin123)');
            return null;
        }
        
        // Ищем пользователя по имени
        const { data, error } = await moonGriefSupabase
            .from('users')
            .select('*')
            .eq('name', username);
        
        if (error) {
            console.error('Ошибка проверки пользователя:', error);
            return null;
        }
        
        if (data && data.length > 0) {
            const user = data[0];
            
            // Определяем роль (админы)
            let role = 'user';
            if (username === 'milfa' || username === 'milk123' || username === 'Xchik_') {
                role = 'owner';
            }
            
            console.log('✅ Пользователь найден:', user.name, 'роль:', role);
            
            return {
                username: user.name,
                password: 'admin123',
                role: role,
                email: user.email,
                phone: user.phone
            };
        }
        
        console.log('❌ Пользователь не найден');
        return null;
    } catch (e) {
        console.error('Исключение при проверке пользователя:', e);
        return null;
    }
};

// ==============================================
// ЖАЛОБЫ - ИСПРАВЛЕНО
// ==============================================

// Сохранить жалобу
window.saveComplaint = async function(complaint) {
    try {
        console.log('💾 Сохраняем жалобу:', complaint);
        
        const { data, error } = await moonGriefSupabase
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
            console.error('❌ Ошибка сохранения жалобы:', error);
            return false;
        }
        
        console.log('✅ Жалоба сохранена:', data);
        return true;
    } catch (e) {
        console.error('❌ Исключение при сохранении жалобы:', e);
        return false;
    }
};

// Получить все жалобы (для админки)
window.getComplaints = async function() {
    try {
        const { data, error } = await moonGriefSupabase
            .from('complaints')
            .select('*')
            .order('created_at', { ascending: false });
        
        if (error) {
            console.error('Ошибка загрузки жалоб:', error);
            return [];
        }
        
        console.log('📋 Загружено жалоб:', data?.length || 0);
        return data || [];
    } catch (e) {
        console.error('Исключение при загрузке жалоб:', e);
        return [];
    }
};

// Получить жалобы конкретного пользователя
window.getUserComplaints = async function(username) {
    try {
        const { data, error } = await moonGriefSupabase
            .from('complaints')
            .select('*')
            .eq('user_name', username)
            .order('created_at', { ascending: false });
        
        if (error) {
            console.error('Ошибка загрузки жалоб пользователя:', error);
            return [];
        }
        
        return data || [];
    } catch (e) {
        console.error('Исключение при загрузке жалоб пользователя:', e);
        return [];
    }
};

// ==============================================
// МЕДИА-ЗАЯВКИ - ИСПРАВЛЕНО
// ==============================================

// Сохранить медиа-заявку
window.saveMediaApplication = async function(mediaApp) {
    try {
        console.log('💾 Сохраняем медиа-заявку:', mediaApp);
        
        const { data, error } = await moonGriefSupabase
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
        
        if (error) {
            console.error('❌ Ошибка сохранения медиа-заявки:', error);
            return false;
        }
        
        console.log('✅ Медиа-заявка сохранена:', data);
        return true;
    } catch (e) {
        console.error('❌ Исключение при сохранении медиа-заявки:', e);
        return false;
    }
};

// Получить все медиа-заявки (для админки)
window.getMediaApplications = async function() {
    try {
        const { data, error } = await moonGriefSupabase
            .from('media_applications')
            .select('*')
            .order('created_at', { ascending: false });
        
        if (error) {
            console.error('Ошибка загрузки медиа-заявок:', error);
            return [];
        }
        
        console.log('📋 Загружено медиа-заявок:', data?.length || 0);
        return data || [];
    } catch (e) {
        console.error('Исключение при загрузке медиа-заявок:', e);
        return [];
    }
};

// Получить медиа-заявки конкретного пользователя
window.getUserMediaApplications = async function(username) {
    try {
        const { data, error } = await moonGriefSupabase
            .from('media_applications')
            .select('*')
            .eq('user_name', username)
            .order('created_at', { ascending: false });
        
        if (error) {
            console.error('Ошибка загрузки медиа-заявок пользователя:', error);
            return [];
        }
        
        return data || [];
    } catch (e) {
        console.error('Исключение при загрузке медиа-заявок пользователя:', e);
        return [];
    }
};

// ==============================================
// ЗАЯВКИ НА ХЕЛПЕРА - ИСПРАВЛЕНО
// ==============================================

// Сохранить заявку на хелпера
window.saveHelperApplication = async function(helperApp) {
    try {
        console.log('💾 Сохраняем заявку на хелпера:', helperApp);
        
        const { data, error } = await moonGriefSupabase
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
        
        if (error) {
            console.error('❌ Ошибка сохранения заявки на хелпера:', error);
            return false;
        }
        
        console.log('✅ Заявка на хелпера сохранена:', data);
        return true;
    } catch (e) {
        console.error('❌ Исключение при сохранении заявки на хелпера:', e);
        return false;
    }
};

// Получить все заявки на хелпера (для админки)
window.getHelperApplications = async function() {
    try {
        const { data, error } = await moonGriefSupabase
            .from('helper_applications')
            .select('*')
            .order('created_at', { ascending: false });
        
        if (error) {
            console.error('Ошибка загрузки заявок на хелпера:', error);
            return [];
        }
        
        console.log('📋 Загружено заявок на хелпера:', data?.length || 0);
        return data || [];
    } catch (e) {
        console.error('Исключение при загрузке заявок на хелпера:', e);
        return [];
    }
};

// Получить заявки на хелпера конкретного пользователя
window.getUserHelperApplications = async function(username) {
    try {
        const { data, error } = await moonGriefSupabase
            .from('helper_applications')
            .select('*')
            .eq('user_name', username)
            .order('created_at', { ascending: false });
        
        if (error) {
            console.error('Ошибка загрузки заявок пользователя на хелпера:', error);
            return [];
        }
        
        return data || [];
    } catch (e) {
        console.error('Исключение при загрузке заявок пользователя на хелпера:', e);
        return [];
    }
};

// ==============================================
// АДМИН-ФУНКЦИИ - ОБНОВЛЕНИЕ СТАТУСОВ
// ==============================================

window.updateComplaintStatus = async function(id, status) {
    try {
        const { error } = await moonGriefSupabase
            .from('complaints')
            .update({ status: status })
            .eq('id', id);
        
        if (error) {
            console.error('Ошибка обновления статуса жалобы:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение при обновлении статуса:', e);
        return false;
    }
};

window.updateMediaStatus = async function(id, status) {
    try {
        const { error } = await moonGriefSupabase
            .from('media_applications')
            .update({ status: status })
            .eq('id', id);
        
        if (error) {
            console.error('Ошибка обновления статуса медиа-заявки:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение при обновлении статуса:', e);
        return false;
    }
};

window.updateHelperStatus = async function(id, status) {
    try {
        const { error } = await moonGriefSupabase
            .from('helper_applications')
            .update({ status: status })
            .eq('id', id);
        
        if (error) {
            console.error('Ошибка обновления статуса заявки на хелпера:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение при обновлении статуса:', e);
        return false;
    }
};

// ==============================================
// СТАТИСТИКА ДЛЯ АДМИНКИ
// ==============================================

window.getStats = async function() {
    try {
        const complaints = await window.getComplaints();
        const media = await window.getMediaApplications();
        const helpers = await window.getHelperApplications();
        
        const newComplaints = complaints.filter(c => c.status === 'НОВАЯ').length;
        const newMedia = media.filter(m => m.status === 'НОВАЯ').length;
        const newHelpers = helpers.filter(h => h.status === 'НОВАЯ').length;
        
        console.log('📊 Статистика:', {
            complaints: complaints.length,
            media: media.length,
            helpers: helpers.length,
            new: newComplaints + newMedia + newHelpers
        });
        
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
// ПРОВЕРКА ПОДКЛЮЧЕНИЯ
// ==============================================

(async function testConnection() {
    try {
        console.log('🔄 Проверка подключения к Supabase...');
        
        // Проверяем таблицы
        const tables = ['users', 'complaints', 'media_applications', 'helper_applications'];
        
        for (const table of tables) {
            const { data, error } = await moonGriefSupabase
                .from(table)
                .select('count', { count: 'exact', head: true });
            
            if (error) {
                console.log(`⚠️ Таблица ${table}: ${error.message}`);
            } else {
                console.log(`✅ Таблица ${table}: доступна`);
            }
        }
        
        console.log('✅ Подключение к Supabase успешно!');
        console.log('🔑 Пароль для входа: admin123');
        console.log('👑 Админы: milfa, milk123, Xchik_');
        
    } catch (e) {
        console.error('❌ Ошибка при проверке подключения:', e);
    }
})();

console.log('✅ Все функции базы данных MoonGrief-Forum загружены');
