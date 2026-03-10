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
// ПОЛЬЗОВАТЕЛИ - ПАРОЛИ ИЗ ТАБЛИЦЫ (ПОЛЕ email)
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

// Проверка при входе - пароли из таблицы (поле email)
window.checkUser = async function(username, password) {
    try {
        console.log('🔍 Проверка пользователя:', username);
        
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
            
            // Сверяем пароль с полем email
            if (user.email === password) {
                console.log('✅ Пароль верный');
                
                // Определяем роль (админы)
                let role = 'user';
                if (username === 'milfa' || username === 'milk123' || username === 'Xchik_') {
                    role = 'owner';
                }
                
                return {
                    username: user.name,
                    password: user.email,
                    role: role,
                    email: user.email,
                    phone: user.phone
                };
            } else {
                console.log('❌ Неверный пароль');
                return null;
            }
        }
        
        console.log('❌ Пользователь не найден');
        return null;
    } catch (e) {
        console.error('Исключение при проверке пользователя:', e);
        return null;
    }
};

// Регистрация нового пользователя
window.registerUser = async function(username, password) {
    try {
        // Проверяем, существует ли уже
        const { data: existing } = await moonGriefSupabase
            .from('users')
            .select('*')
            .eq('name', username);
        
        if (existing && existing.length > 0) {
            return { success: false, message: 'Пользователь уже существует' };
        }
        
        // Создаем нового пользователя
        const { data, error } = await moonGriefSupabase
            .from('users')
            .insert([{
                name: username,
                email: password, // Пароль сохраняем в email
                phone: new Date().toISOString()
            }]);
        
        if (error) {
            console.error('Ошибка регистрации:', error);
            return { success: false, message: 'Ошибка регистрации' };
        }
        
        return { success: true, message: 'Регистрация успешна' };
    } catch (e) {
        console.error('Исключение при регистрации:', e);
        return { success: false, message: 'Ошибка' };
    }
};

// Смена пароля
window.changeUserPassword = async function(username, oldPassword, newPassword) {
    try {
        // Проверяем старый пароль
        const { data: user, error: findError } = await moonGriefSupabase
            .from('users')
            .select('*')
            .eq('name', username)
            .eq('email', oldPassword);
        
        if (findError || !user || user.length === 0) {
            return { success: false, message: 'Неверный старый пароль' };
        }
        
        // Обновляем пароль
        const { error: updateError } = await moonGriefSupabase
            .from('users')
            .update({ email: newPassword })
            .eq('name', username);
        
        if (updateError) {
            return { success: false, message: 'Ошибка при смене пароля' };
        }
        
        return { success: true, message: 'Пароль изменен' };
    } catch (e) {
        console.error('Ошибка смены пароля:', e);
        return { success: false, message: 'Ошибка' };
    }
};

// ==============================================
// ЖАЛОБЫ
// ==============================================

window.saveComplaint = async function(complaint) {
    try {
        const { data, error } = await moonGriefSupabase
            .from('complaints')
            .insert([{
                user_name: complaint.user,
                title: complaint.title,
                target: complaint.target,
                description: complaint.desc,
                status: 'НОВАЯ',
                date: new Date().toLocaleString(),
                created_at: new Date().toISOString()
            }]);
        
        if (error) {
            console.error('Ошибка сохранения жалобы:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение:', e);
        return false;
    }
};

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
        return data || [];
    } catch (e) {
        console.error('Исключение:', e);
        return [];
    }
};

// ==============================================
// МЕДИА-ЗАЯВКИ
// ==============================================

window.saveMediaApplication = async function(mediaApp) {
    try {
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
                date: new Date().toLocaleString(),
                created_at: new Date().toISOString()
            }]);
        
        if (error) {
            console.error('Ошибка сохранения медиа-заявки:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение:', e);
        return false;
    }
};

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
        return data || [];
    } catch (e) {
        console.error('Исключение:', e);
        return [];
    }
};

// ==============================================
// ЗАЯВКИ НА ХЕЛПЕРА
// ==============================================

window.saveHelperApplication = async function(helperApp) {
    try {
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
                date: new Date().toLocaleString(),
                created_at: new Date().toISOString()
            }]);
        
        if (error) {
            console.error('Ошибка сохранения анкеты:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение:', e);
        return false;
    }
};

window.getHelperApplications = async function() {
    try {
        const { data, error } = await moonGriefSupabase
            .from('helper_applications')
            .select('*')
            .order('created_at', { ascending: false });
        
        if (error) {
            console.error('Ошибка загрузки анкет:', error);
            return [];
        }
        return data || [];
    } catch (e) {
        console.error('Исключение:', e);
        return [];
    }
};

// ==============================================
// ОБНОВЛЕНИЕ СТАТУСОВ (ДЛЯ АДМИНКИ)
// ==============================================

window.updateComplaintStatus = async function(id, status) {
    try {
        const { error } = await moonGriefSupabase
            .from('complaints')
            .update({ status: status })
            .eq('id', id);
        
        return !error;
    } catch (e) {
        return false;
    }
};

window.updateMediaStatus = async function(id, status) {
    try {
        const { error } = await moonGriefSupabase
            .from('media_applications')
            .update({ status: status })
            .eq('id', id);
        
        return !error;
    } catch (e) {
        return false;
    }
};

window.updateHelperStatus = async function(id, status) {
    try {
        const { error } = await moonGriefSupabase
            .from('helper_applications')
            .update({ status: status })
            .eq('id', id);
        
        return !error;
    } catch (e) {
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
// ПРОВЕРКА ПОДКЛЮЧЕНИЯ
// ==============================================

(async function testConnection() {
    try {
        const { data, error } = await moonGriefSupabase
            .from('users')
            .select('*');
        
        if (error) {
            console.error('❌ Ошибка подключения к Supabase:', error.message);
        } else {
            console.log('✅ Подключение к Supabase успешно!');
            console.log('📊 Найдено пользователей:', data.length);
            console.log('👥 Список пользователей и их пароли (поле email):');
            data.forEach(user => {
                console.log(`   - ${user.name}: пароль "${user.email}"`);
            });
            console.log('🔑 Входите со своими паролями из таблицы!');
        }
    } catch (e) {
        console.error('❌ Исключение при подключении к Supabase:', e);
    }
})();

console.log('✅ Все функции базы данных MoonGrief-Forum загружены');
console.log('📋 Пароли берутся из поля email в таблице users');
