// Подключение к Supabase
const SUPABASE_URL = 'https://opeypwavctnnryrfkhajf.supabase.co';
const SUPABASE_KEY = 'sb_publishable_AzXYR-uQE2Ua9S0v6LAQBQ_Noq1h..';

// Создаем клиент с другим именем
const supabaseClient = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);

// Функции для работы с пользователями
async function getUsers() {
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

async function saveUser(username, password) {
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

async function updateUserPassword(username, password) {
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
async function getComplaints() {
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

async function saveComplaint(complaint) {
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

async function updateComplaint(id, updates) {
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

async function deleteComplaint(id) {
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
async function getApplications() {
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

async function saveApplication(application) {
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

async function updateApplication(id, updates) {
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

async function deleteApplication(id) {
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
