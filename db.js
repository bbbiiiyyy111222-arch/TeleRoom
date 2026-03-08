// Подключение к Supabase - ПРАВИЛЬНЫЕ КЛЮЧИ
const SUPABASE_URL = 'https://opeypwayctnnyrfkhajf.supabase.co';
const SUPABASE_KEY = 'sb_publishable_AzXYR-uQE2Ua9S0v6LAQBQ_Noq1h..';

console.log('🔄 Подключение к Supabase:', SUPABASE_URL);
console.log('🔑 Ключ загружен');

// Создаем клиент
const supabaseClient = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);

// Функция проверки подключения
window.testConnection = async function() {
    try {
        console.log('🔍 Проверяем подключение...');
        const { data, error } = await supabaseClient
            .from('users')
            .select('*')
            .limit(1);
        
        if (error) {
            console.error('❌ Ошибка подключения:', error);
            return false;
        } else {
            console.log('✅ Подключение работает! Данные:', data);
            return true;
        }
    } catch (e) {
        console.error('❌ Исключение при подключении:', e);
        return false;
    }
}

// Функции для работы с пользователями
window.getUsers = async function() {
    try {
        const { data, error } = await supabaseClient
            .from('users')
            .select('*');
        
        if (error) {
            console.error('Ошибка загрузки пользователей:', error);
            return [];
        }
        return data || [];
    } catch (e) {
        console.error('Исключение:', e);
        return [];
    }
}

window.saveUser = async function(username, password) {
    try {
        const { data, error } = await supabaseClient
            .from('users')
            .insert([
                { username: username, password: password }
            ]);
        
        if (error) {
            console.error('Ошибка сохранения пользователя:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение:', e);
        return false;
    }
}

window.updateUserPassword = async function(username, password) {
    try {
        const { data, error } = await supabaseClient
            .from('users')
            .update({ password: password })
            .eq('username', username);
        
        if (error) {
            console.error('Ошибка обновления пароля:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение:', e);
        return false;
    }
}

// Функции для жалоб
window.getComplaints = async function() {
    try {
        const { data, error } = await supabaseClient
            .from('complaints')
            .select('*')
            .order('date', { ascending: false });
        
        if (error) {
            console.error('Ошибка загрузки жалоб:', error);
            return [];
        }
        return data || [];
    } catch (e) {
        console.error('Исключение:', e);
        return [];
    }
}

window.saveComplaint = async function(complaint) {
    try {
        console.log('Сохраняем жалобу:', complaint);
        
        const { data, error } = await supabaseClient
            .from('complaints')
            .insert([complaint]);
        
        if (error) {
            console.error('Ошибка сохранения жалобы:', error);
            return false;
        }
        console.log('Жалоба сохранена:', data);
        return true;
    } catch (e) {
        console.error('Исключение:', e);
        return false;
    }
}

window.updateComplaint = async function(id, updates) {
    try {
        const { data, error } = await supabaseClient
            .from('complaints')
            .update(updates)
            .eq('id', id);
        
        if (error) {
            console.error('Ошибка обновления жалобы:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение:', e);
        return false;
    }
}

window.deleteComplaint = async function(id) {
    try {
        const { data, error } = await supabaseClient
            .from('complaints')
            .delete()
            .eq('id', id);
        
        if (error) {
            console.error('Ошибка удаления жалобы:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение:', e);
        return false;
    }
}

// Функции для заявок
window.getApplications = async function() {
    try {
        const { data, error } = await supabaseClient
            .from('applications')
            .select('*')
            .order('date', { ascending: false });
        
        if (error) {
            console.error('Ошибка загрузки заявок:', error);
            return [];
        }
        return data || [];
    } catch (e) {
        console.error('Исключение:', e);
        return [];
    }
}

window.saveApplication = async function(application) {
    try {
        console.log('Сохраняем заявку:', application);
        
        const { data, error } = await supabaseClient
            .from('applications')
            .insert([application]);
        
        if (error) {
            console.error('Ошибка сохранения заявки:', error);
            return false;
        }
        console.log('Заявка сохранена:', data);
        return true;
    } catch (e) {
        console.error('Исключение:', e);
        return false;
    }
}

window.updateApplication = async function(id, updates) {
    try {
        const { data, error } = await supabaseClient
            .from('applications')
            .update(updates)
            .eq('id', id);
        
        if (error) {
            console.error('Ошибка обновления заявки:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение:', e);
        return false;
    }
}

window.deleteApplication = async function(id) {
    try {
        const { data, error } = await supabaseClient
            .from('applications')
            .delete()
            .eq('id', id);
        
        if (error) {
            console.error('Ошибка удаления заявки:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение:', e);
        return false;
    }
}

// Автоматически проверим подключение
setTimeout(() => {
    window.testConnection();
}, 1000);
