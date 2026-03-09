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
// ПОЛЬЗОВАТЕЛИ (по твоей структуре)
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

window.checkUser = async function(username, password) {
    try {
        // Ищем пользователя где name = username И email = password
        const { data, error } = await moonGriefSupabase
            .from('users')
            .select('*')
            .eq('name', username)
            .eq('email', password); // ВНИМАНИЕ: email это поле для пароля!
        
        if (error) {
            console.error('Ошибка проверки пользователя:', error);
            return null;
        }
        
        if (data && data.length > 0) {
            const user = data[0];
            // Определяем роль
            let role = 'user';
            if (username === 'milfa' || username === 'milk123' || username === 'Xchik_') {
                role = 'owner';
            }
            
            return {
                username: user.name,
                password: user.email, // Это "пароль"
                role: role,
                id: user.id
            };
        }
        
        return null;
    } catch (e) {
        console.error('Исключение при проверке пользователя:', e);
        return null;
    }
};

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
                phone: new Date().toISOString() // Дата регистрации
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

window.changeUserPassword = async function(username, oldPassword, newPassword) {
    try {
        // Проверяем стар��й пароль
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
        // Создаем таблицу complaints если её нет
        const { data, error } = await moonGriefSupabase
            .from('complaints')
            .insert([{
                user_name: complaint.user,
                title: complaint.title,
                target: complaint.target,
                description: complaint.desc,
                status: 'НОВАЯ',
                created_at: new Date().toISOString()
            }]);
        
        if (error) console.error('Ошибка сохранения жалобы:', error);
        return !error;
    } catch (e) {
        console.error('Исключение:', e);
        return false;
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
                created_at: new Date().toISOString()
            }]);
        
        if (error) console.error('Ошибка сохранения медиа-заявки:', error);
        return !error;
    } catch (e) {
        console.error('Исключение:', e);
        return false;
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
                created_at: new Date().toISOString()
            }]);
        
        if (error) console.error('Ошибка сохранения анкеты:', error);
        return !error;
    } catch (e) {
        console.error('Исключение:', e);
        return false;
    }
};

// ==============================================
// АДМИН-ФУНКЦИИ
// ==============================================

window.getStats = async function() {
    try {
        // Здесь нужно будет создать соответствующие таблицы
        return {
            total: 0,
            new: 0,
            complaints: 0,
            media: 0,
            helpers: 0
        };
    } catch (e) {
        return { total: 0, new: 0, complaints: 0, media: 0, helpers: 0 };
    }
};

console.log('✅ База данных MoonGrief-Forum готова');
