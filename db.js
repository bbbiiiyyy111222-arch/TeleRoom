// ==============================================
// БАЗА ДАННЫХ MOONGRIEF - ПОЛНАЯ ВЕРСИЯ
// ==============================================

const SUPABASE_URL = 'https://opeypwayctnnyrfkhajf.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9wZXlwd2F5Y3RubnlyZmtoYWpmIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzI5MzU4ODQsImV4cCI6MjA4ODUxMTg4NH0._Y1R1NNCVMyVgyeN7O7a24n4BGwc44c6vO1Q6MAf74A';

console.log('🔄 Подключение к Supabase');

const supabaseClient = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);

// ==============================================
// ПОЛЬЗОВАТЕЛИ
// ==============================================

window.getUsers = async function() {
    try {
        const { data, error } = await supabaseClient
            .from('users')
            .select('*');
        if (error) throw error;
        return data || [];
    } catch (e) {
        console.error('Ошибка загрузки пользователей:', e);
        return [];
    }
}

window.saveUser = async function(username, password) {
    try {
        const { error } = await supabaseClient
            .from('users')
            .insert([{ username, password }]);
        if (error) throw error;
        return true;
    } catch (e) {
        console.error('Ошибка сохранения пользователя:', e);
        return false;
    }
}

window.updateUserPassword = async function(username, password) {
    try {
        const { error } = await supabaseClient
            .from('users')
            .update({ password })
            .eq('username', username);
        if (error) throw error;
        return true;
    } catch (e) {
        console.error('Ошибка обновления пароля:', e);
        return false;
    }
}

window.changePassword = async function(username, oldPassword, newPassword) {
    try {
        const { data: user, error: findError } = await supabaseClient
            .from('users')
            .select('*')
            .eq('username', username)
            .eq('password', oldPassword)
            .single();
        
        if (findError || !user) {
            return { success: false, message: 'Неверный старый пароль' };
        }
        
        const { error: updateError } = await supabaseClient
            .from('users')
            .update({ password: newPassword })
            .eq('username', username);
        
        if (updateError) throw updateError;
        
        return { success: true, message: 'Пароль изменен' };
    } catch (e) {
        console.error('Ошибка смены пароля:', e);
        return { success: false, message: 'Ошибка при смене пароля' };
    }
}

// ==============================================
// ЖАЛОБЫ
// ==============================================

window.getComplaints = async function() {
    try {
        const { data, error } = await supabaseClient
            .from('complaints')
            .select('*')
            .order('date', { ascending: false });
        if (error) throw error;
        return data || [];
    } catch (e) {
        console.error('Ошибка загрузки жалоб:', e);
        return [];
    }
}

window.saveComplaint = async function(complaint) {
    try {
        const { error } = await supabaseClient
            .from('complaints')
            .insert([complaint]);
        if (error) throw error;
        return true;
    } catch (e) {
        console.error('Ошибка сохранения жалобы:', e);
        return false;
    }
}

window.updateComplaint = async function(id, updates) {
    try {
        const { error } = await supabaseClient
            .from('complaints')
            .update(updates)
            .eq('id', id);
        if (error) throw error;
        return true;
    } catch (e) {
        console.error('Ошибка обновления жалобы:', e);
        return false;
    }
}

// ==============================================
// УДАЛЕНИЕ ЖАЛОБ - РАБОЧАЯ ВЕРСИЯ
// ==============================================

window.deleteComplaint = async function(id) {
    console.log('🗑️ db.js: Удаление жалобы ID:', id);
    
    try {
        const { error } = await supabaseClient
            .from('complaints')
            .delete()
            .eq('id', id);
        
        if (error) {
            console.error('❌ db.js: Ошибка:', error);
            return false;
        }
        
        console.log('✅ db.js: Жалоба удалена');
        return true;
    } catch (e) {
        console.error('❌ db.js: Исключение:', e);
        return false;
    }
}

// ==============================================
// ЗАЯВКИ
// ==============================================

window.getApplications = async function() {
    try {
        const { data, error } = await supabaseClient
            .from('applications')
            .select('*')
            .order('date', { ascending: false });
        if (error) throw error;
        return data || [];
    } catch (e) {
        console.error('Ошибка загрузки заявок:', e);
        return [];
    }
}

window.saveApplication = async function(application) {
    try {
        const { error } = await supabaseClient
            .from('applications')
            .insert([application]);
        if (error) throw error;
        return true;
    } catch (e) {
        console.error('Ошибка сохранения заявки:', e);
        return false;
    }
}

window.updateApplication = async function(id, updates) {
    try {
        const { error } = await supabaseClient
            .from('applications')
            .update(updates)
            .eq('id', id);
        if (error) throw error;
        return true;
    } catch (e) {
        console.error('Ошибка обновления заявки:', e);
        return false;
    }
}

// ==============================================
// УДАЛЕНИЕ ЗАЯВОК - РАБОЧАЯ ВЕРСИЯ
// ==============================================

window.deleteApplication = async function(id) {
    console.log('🗑️ db.js: Удаление заявки ID:', id);
    
    try {
        const { error } = await supabaseClient
            .from('applications')
            .delete()
            .eq('id', id);
        
        if (error) {
            console.error('❌ db.js: Ошибка:', error);
            return false;
        }
        
        console.log('✅ db.js: Заявка удалена');
        return true;
    } catch (e) {
        console.error('❌ db.js: Исключение:', e);
        return false;
    }
}

console.log('✅ db.js загружен');
