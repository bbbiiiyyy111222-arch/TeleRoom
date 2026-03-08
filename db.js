// Подключение к Supabase
const SUPABASE_URL = 'https://opeypwavctnnryrfkhajf.supabase.co';
const SUPABASE_KEY = 'sb_publishable_AzXYR-uQE2Ua9S0v6LAQBQ_Noq1h..';

// Создаем клиент
const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);

// Функции для работы с пользователями
async function getUsers() {
    const { data, error } = await supabase
        .from('users')
        .select('*');
    
    if (error) {
        console.error('Ошибка загрузки пользователей:', error);
        return [];
    }
    return data || [];
}

async function saveUser(username, password) {
    const { data, error } = await supabase
        .from('users')
        .insert([
            { username: username, password: password }
        ]);
    
    if (error) {
        console.error('Ошибка сохранения пользователя:', error);
        return false;
    }
    return true;
}

async function updateUserPassword(username, password) {
    const { data, error } = await supabase
        .from('users')
        .update({ password: password })
        .eq('username', username);
    
    if (error) {
        console.error('Ошибка обновления пароля:', error);
        return false;
    }
    return true;
}

async function getUserByUsername(username) {
    const { data, error } = await supabase
        .from('users')
        .select('*')
        .eq('username', username)
        .single();
    
    if (error) {
        console.error('Ошибка загрузки пользователя:', error);
        return null;
    }
    return data;
}

// Функции для жалоб
async function getComplaints() {
    const { data, error } = await supabase
        .from('complaints')
        .select('*')
        .order('date', { ascending: false });
    
    if (error) {
        console.error('Ошибка загрузки жалоб:', error);
        return [];
    }
    return data || [];
}

async function saveComplaint(complaint) {
    const { data, error } = await supabase
        .from('complaints')
        .insert([complaint]);
    
    if (error) {
        console.error('Ошибка сохранения жалобы:', error);
        return false;
    }
    return true;
}

async function updateComplaint(id, updates) {
    const { data, error } = await supabase
        .from('complaints')
        .update(updates)
        .eq('id', id);
    
    if (error) {
        console.error('Ошибка обновления жалобы:', error);
        return false;
    }
    return true;
}

async function deleteComplaint(id) {
    const { data, error } = await supabase
        .from('complaints')
        .delete()
        .eq('id', id);
    
    if (error) {
        console.error('Ошибка удаления жалобы:', error);
        return false;
    }
    return true;
}

// Функции для заявок
async function getApplications() {
    const { data, error } = await supabase
        .from('applications')
        .select('*')
        .order('date', { ascending: false });
    
    if (error) {
        console.error('Ошибка загрузки заявок:', error);
        return [];
    }
    return data || [];
}

async function saveApplication(application) {
    const { data, error } = await supabase
        .from('applications')
        .insert([application]);
    
    if (error) {
        console.error('Ошибка сохранения заявки:', error);
        return false;
    }
    return true;
}

async function updateApplication(id, updates) {
    const { data, error } = await supabase
        .from('applications')
        .update(updates)
        .eq('id', id);
    
    if (error) {
        console.error('Ошибка обновления заявки:', error);
        return false;
    }
    return true;
}

async function deleteApplication(id) {
    const { data, error } = await supabase
        .from('applications')
        .delete()
        .eq('id', id);
    
    if (error) {
        console.error('Ошибка удаления заявки:', error);
        return false;
    }
    return true;
}
