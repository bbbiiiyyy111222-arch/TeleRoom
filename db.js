// ==============================================
// MOONGRIEF-FORUM - БАЗА ДАННЫХ
// ==============================================

console.log('✅ db.js загружается...');

// Supabase подключение - ТВОИ РЕАЛЬНЫЕ ДАННЫЕ!
const SUPABASE_URL = 'https://opeypwayctnnyrfkhajf.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9wZXlwd2F5Y3RubnlyZmtoYWpmIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzI5MzU4ODQsImV4cCI6MjA4ODUxMTg4NH0._Y1R1NNCVMyVgyeN7O7a24n4BGwc44c6vO1Q6MAf74A';

// Создаем клиент
const moonGriefSupabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);

// ==============================================
// ПОЛЬЗОВАТЕЛИ
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

window.saveUser = async function(username, password, role = 'user') {
    try {
        // Проверяем админов
        const admins = ['milfa', 'milk123', 'Xchik_'];
        const userRole = admins.includes(username) ? 'owner' : role;
        
        const { data, error } = await moonGriefSupabase
            .from('users')
            .insert([{ 
                username, 
                password,
                role: userRole,
                created_at: new Date().toISOString()
            }]);
        
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
        const { data, error } = await moonGriefSupabase
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
        // Сначала проверяем стар��й пароль
        const { data: user, error: findError } = await moonGriefSupabase
            .from('users')
            .select('*')
            .eq('username', username)
            .eq('password', oldPassword)
            .single();
        
        if (findError || !user) {
            return { success: false, message: 'Неверный старый пароль' };
        }
        
        // Обновляем пароль
        const { error: updateError } = await moonGriefSupabase
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
        const { data, error } = await moonGriefSupabase
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
        const { data, error } = await moonGriefSupabase
            .from('complaints')
            .insert([{
                user: complaint.user,
                title: complaint.title,
                target: complaint.target,
                desc: complaint.desc,
                status: 'НОВАЯ',
                date: new Date().toLocaleString()
            }]);
        
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

window.updateComplaintStatus = async function(id, status) {
    try {
        const { data, error } = await moonGriefSupabase
            .from('complaints')
            .update({ status: status })
            .eq('id', id);
        
        if (error) {
            console.error('Ошибка обновления статуса жалобы:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение при обновлении статуса жалобы:', e);
        return false;
    }
};

window.deleteComplaint = async function(id) {
    try {
        const { data, error } = await moonGriefSupabase
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
        const { data, error } = await moonGriefSupabase
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
        const { data, error } = await moonGriefSupabase
            .from('media_applications')
            .insert([{
                user: mediaApp.user,
                type: mediaApp.type,
                age: mediaApp.age,
                name: mediaApp.name,
                nick: mediaApp.nick,
                subs: mediaApp.subs,
                link: mediaApp.link,
                status: 'НОВАЯ',
                date: new Date().toLocaleString()
            }]);
        
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

window.updateMediaStatus = async function(id, status) {
    try {
        const { data, error } = await moonGriefSupabase
            .from('media_applications')
            .update({ status: status })
            .eq('id', id);
        
        if (error) {
            console.error('Ошибка обновления статуса медиа-заявки:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение при обновлении статуса медиа-заявки:', e);
        return false;
    }
};

window.deleteMediaApplication = async function(id) {
    try {
        const { data, error } = await moonGriefSupabase
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

window.getHelperApplications = async function() {
    try {
        const { data, error } = await moonGriefSupabase
            .from('helper_applications')
            .select('*')
            .order('date', { ascending: false });
        
        if (error) {
            console.error('Ошибка загрузки заявок на хелпера:', error);
            return [];
        }
        return data || [];
    } catch (e) {
        console.error('Исключение при загрузке заявок на хелпера:', e);
        return [];
    }
};

window.saveHelperApplication = async function(helperApp) {
    try {
        const { data, error } = await moonGriefSupabase
            .from('helper_applications')
            .insert([{
                user: helperApp.user,
                nick: helperApp.nick,
                name: helperApp.name,
                age: helperApp.age,
                tz: helperApp.tz,
                exp: helperApp.exp,
                why: helperApp.why,
                status: 'НОВАЯ',
                date: new Date().toLocaleString()
            }]);
        
        if (error) {
            console.error('Ошибка сохранения заявки на хелпера:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение при сохранении заявки на хелпера:', e);
        return false;
    }
};

window.updateHelperStatus = async function(id, status) {
    try {
        const { data, error } = await moonGriefSupabase
            .from('helper_applications')
            .update({ status: status })
            .eq('id', id);
        
        if (error) {
            console.error('Ошибка обновления статуса заявки на хелпера:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение при обновлении статуса заявки на хелпера:', e);
        return false;
    }
};

window.deleteHelperApplication = async function(id) {
    try {
        const { data, error } = await moonGriefSupabase
            .from('helper_applications')
            .delete()
            .eq('id', id);
        
        if (error) {
            console.error('Ошибка удаления заявки на хелпера:', error);
            return false;
        }
        return true;
    } catch (e) {
        console.error('Исключение при удалении заявки на хелпера:', e);
        return false;
    }
};

// ==============================================
// АДМИН-ФУНКЦИИ
// ==============================================

window.getAllApplications = async function() {
    try {
        const [complaints, media, helpers] = await Promise.all([
            window.getComplaints(),
            window.getMediaApplications(),
            window.getHelperApplications()
        ]);
        
        return {
            complaints,
            media,
            helpers
        };
    } catch (e) {
        console.error('Ошибка загрузки всех заявок:', e);
        return { complaints: [], media: [], helpers: [] };
    }
};

window.getStats = async function() {
    try {
        const { complaints, media, helpers } = await window.getAllApplications();
        
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
        console.error('Ошибка получения статистики:', e);
        return { total: 0, new: 0, complaints: 0, media: 0, helpers: 0, newComplaints: 0, newMedia: 0, newHelpers: 0 };
    }
};

// ==============================================
// ПРОВЕРКА ПОДКЛЮЧЕНИЯ
// ==============================================

(async function testConnection() {
    try {
        const { data, error } = await moonGriefSupabase
            .from('users')
            .select('count', { count: 'exact', head: true });
        
        if (error) {
            console.error('❌ Ошибка подключения к Supabase:', error.message);
        } else {
            console.log('✅ Подключение к Supabase успешно!');
        }
    } catch (e) {
        console.error('❌ Исключение при подключении к Supabase:', e);
    }
})();

console.log('✅ Все функции базы данных MoonGrief-Forum загружены');
