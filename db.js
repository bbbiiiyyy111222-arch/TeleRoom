// ==============================================
// БАЗА ДАННЫХ BLADEBOX - ПОЛНАЯ РАБОЧАЯ ВЕРСИЯ
// ==============================================

// Supabase подключение - ВСТАВЬТЕ СВОИ ДАННЫЕ!
const SUPABASE_URL = 'https://ваш-проект.supabase.co';
const SUPABASE_KEY = 'ваш-ключ';

// Создаем клиент
const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);

console.log('✅ db.js загружен');

// ==============================================
// ПОЛЬЗОВАТЕЛИ
// ==============================================

window.getUsers = async function() {
    try {
        const { data, error } = await supabase
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

window.saveUser = async function(username, password) {
    try {
        const { data, error } = await supabase
            .from('users')
            .insert([{ username, password }]);
        
        if (error) {
            console.error('Ошибка сохранения пользователя:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение при сохранении пользователя:', e);
        return false;
    }
};

window.updateUserPassword = async function(username, password) {
    try {
        const { data, error } = await supabase
            .from('users')
            .update({ password })
            .eq('username', username);
        
        if (error) {
            console.error('Ошибка обновления пароля:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение при обновлении пароля:', e);
        return false;
    }
};

window.changePassword = async function(username, oldPassword, newPassword) {
    try {
        // Сначала проверяем старый пароль
        const { data: user, error: findError } = await supabase
            .from('users')
            .select('*')
            .eq('username', username)
            .eq('password', oldPassword)
            .single();
        
        if (findError || !user) {
            return { success: false, message: 'Неверный старый пароль' };
        }
        
        // Обновляем пароль
        const { error: updateError } = await supabase
            .from('users')
            .update({ password: newPassword })
            .eq('username', username);
        
        if (updateError) throw updateError;
        
        return { success: true, message: 'Пароль изменен' };
    } catch (e) {
        console.error('Ошибка смены пароля:', e);
        return { success: false, message: 'Ошибка при смене пароля' };
    }
};

// ==============================================
// ЖАЛОБЫ
// ==============================================

window.getComplaints = async function() {
    try {
        const { data, error } = await supabase
            .from('complaints')
            .select('*')
            .order('date', { ascending: false });
        
        if (error) {
            console.error('Ошибка загрузки жалоб:', error);
            return [];
        }
        return data || [];
    } catch (e) {
        console.error('Исключение при загрузке жалоб:', e);
        return [];
    }
};

window.saveComplaint = async function(complaint) {
    try {
        const { data, error } = await supabase
            .from('complaints')
            .insert([complaint]);
        
        if (error) {
            console.error('Ошибка сохранения жалобы:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение при сохранении жалобы:', e);
        return false;
    }
};

window.updateComplaint = async function(id, updates) {
    try {
        const { data, error } = await supabase
            .from('complaints')
            .update(updates)
            .eq('id', id);
        
        if (error) {
            console.error('Ошибка обновления жалобы:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение при обновлении жалобы:', e);
        return false;
    }
};

window.deleteComplaint = async function(id) {
    try {
        const { data, error } = await supabase
            .from('complaints')
            .delete()
            .eq('id', id);
        
        if (error) {
            console.error('Ошибка удаления жалобы:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение при удалении жалобы:', e);
        return false;
    }
};

// ==============================================
// МЕДИА-ЗАЯВКИ (TIKTOK И YOUTUBE)
// ==============================================

window.getMediaApplications = async function() {
    try {
        const { data, error } = await supabase
            .from('media_applications')
            .select('*')
            .order('date', { ascending: false });
        
        if (error) {
            console.error('Ошибка загрузки медиа-заявок:', error);
            return [];
        }
        return data || [];
    } catch (e) {
        console.error('Исключение при загрузке медиа-заявок:', e);
        return [];
    }
};

window.saveMediaApplication = async function(mediaApp) {
    try {
        const { data, error } = await supabase
            .from('media_applications')
            .insert([mediaApp]);
        
        if (error) {
            console.error('Ошибка сохранения медиа-заявки:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение при сохранении медиа-заявки:', e);
        return false;
    }
};

window.updateMediaApplication = async function(id, updates) {
    try {
        const { data, error } = await supabase
            .from('media_applications')
            .update(updates)
            .eq('id', id);
        
        if (error) {
            console.error('Ошибка обновления медиа-заявки:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение при обновлении медиа-заявки:', e);
        return false;
    }
};

window.deleteMediaApplication = async function(id) {
    try {
        const { data, error } = await supabase
            .from('media_applications')
            .delete()
            .eq('id', id);
        
        if (error) {
            console.error('Ошибка удаления медиа-заявки:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение при удалении медиа-заявки:', e);
        return false;
    }
};

// ==============================================
// ЗАЯВКИ НА ХЕЛПЕРА
// ==============================================

window.getApplications = async function() {
    try {
        const { data, error } = await supabase
            .from('applications')
            .select('*')
            .order('date', { ascending: false });
        
        if (error) {
            console.error('Ошибка загрузки заявок:', error);
            return [];
        }
        return data || [];
    } catch (e) {
        console.error('Исключение при загрузке заявок:', e);
        return [];
    }
};

window.saveApplication = async function(application) {
    try {
        const { data, error } = await supabase
            .from('applications')
            .insert([application]);
        
        if (error) {
            console.error('Ошибка сохранения заявки:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение при сохранении заявки:', e);
        return false;
    }
};

window.updateApplication = async function(id, updates) {
    try {
        const { data, error } = await supabase
            .from('applications')
            .update(updates)
            .eq('id', id);
        
        if (error) {
            console.error('Ошибка обновления заявки:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение при обновлении заявки:', e);
        return false;
    }
};

window.deleteApplication = async function(id) {
    try {
        const { data, error } = await supabase
            .from('applications')
            .delete()
            .eq('id', id);
        
        if (error) {
            console.error('Ошибка удаления заявки:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение при удалении заявки:', e);
        return false;
    }
};

console.log('✅ Все функции базы данных загружены');
