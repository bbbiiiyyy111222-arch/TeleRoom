// Подключение к Supabase
const SUPABASE_URL = 'https://opeypwayctnnyrfkhajf.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9wZXlwd2F5Y3RubnlyZmtoYWpmIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzI5MzU4ODQsImV4cCI6MjA4ODUxMTg4NH0._Y1R1NNCVMyVgyeN7O7a24n4BGwc44c6vO1Q6MAf74A';

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

// Функции для жалоб - УДАЛЕНИЕ (ИСПРАВЛЕНО)
window.deleteComplaint = async function(id) {
    try {
        console.log('🗑️ Удаляем жалобу с ID:', id, 'тип:', typeof id);
        
        // Преобразуем ID в число
        const numericId = Number(id);
        console.log('🔢 Числовой ID:', numericId);
        
        const { data, error } = await supabaseClient
            .from('complaints')
            .delete()
            .eq('id', numericId);
        
        if (error) {
            console.error('❌ Ошибка удаления жалобы:', error);
            return false;
        }
        
        console.log('✅ Жалоба удалена, ответ:', data);
        return true; // Всегда возвращаем true при успехе
    } catch (e) {
        console.error('❌ Исключение при удалении:', e);
        return false;
    }
}

// Функции для заявок - УДАЛЕНИЕ (ИСПРАВЛЕНО)
window.deleteApplication = async function(id) {
    try {
        console.log('🗑️ Удаляем заявку с ID:', id, 'тип:', typeof id);
        
        // Преобразуем ID в число
        const numericId = Number(id);
        console.log('🔢 Числовой ID:', numericId);
        
        const { data, error } = await supabaseClient
            .from('applications')
            .delete()
            .eq('id', numericId);
        
        if (error) {
            console.error('❌ Ошибка удаления заявки:', error);
            return false;
        }
        
        console.log('✅ Заявка удалена, ответ:', data);
        return true; // Всегда возвращаем true при успехе
    } catch (e) {
        console.error('❌ Исключение при удалении:', e);
        return false;
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
        console.log('Обновляем жалобу:', id, updates);
        
        const { data, error } = await supabaseClient
            .from('complaints')
            .update(updates)
            .eq('id', id);
        
        if (error) {
            console.error('Ошибка обновления жалобы:', error);
            return false;
        }
        console.log('Жалоба обновлена:', data);
        return true;
    } catch (e) {
        console.error('Исключение:', e);
        return false;
    }
}

window.deleteComplaint = async function(id) {
    try {
        console.log('🗑️ Удаляем жалобу с ID:', id, 'тип:', typeof id);
        
        // Преобразуем ID в число
        const numericId = Number(id);
        console.log('🔢 Числовой ID:', numericId);
        
        const { data, error } = await supabaseClient
            .from('complaints')
            .delete()
            .eq('id', numericId);
        
        if (error) {
            console.error('❌ Ошибка удаления жалобы:', error);
            alert('Ошибка: ' + error.message);
            return false;
        }
        console.log('✅ Жалоба удалена, ответ:', data);
        return true;
    } catch (e) {
        console.error('❌ Исключение при удалении:', e);
        alert('Исключение: ' + e.message);
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
        console.log('Обновляем заявку:', id, updates);
        
        const { data, error } = await supabaseClient
            .from('applications')
            .update(updates)
            .eq('id', id);
        
        if (error) {
            console.error('Ошибка обновления заявки:', error);
            return false;
        }
        console.log('Заявка обновлена:', data);
        return true;
    } catch (e) {
        console.error('Исключение:', e);
        return false;
    }
}

window.deleteApplication = async function(id) {
    try {
        console.log('🗑️ Удаляем заявку с ID:', id, 'тип:', typeof id);
        
        // Преобразуем ID в число
        const numericId = Number(id);
        console.log('🔢 Числовой ID:', numericId);
        
        const { data, error } = await supabaseClient
            .from('applications')
            .delete()
            .eq('id', numericId);
        
        if (error) {
            console.error('❌ Ошибка удаления заявки:', error);
            alert('Ошибка: ' + error.message);
            return false;
        }
        console.log('✅ Заявка удалена, ответ:', data);
        return true;
    } catch (e) {
        console.error('❌ Исключение при удалении:', e);
        alert('Исключение: ' + e.message);
        return false;
    }
}

// Проверяем подключение
setTimeout(() => {
    window.testConnection();
}, 1000);
