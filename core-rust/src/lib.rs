use jni::objects::JString;
use jni::sys::jboolean;
use jni::JNIEnv;
use std::collections::HashSet;
use std::sync::Mutex;

// Создаем глобальную потокобезопасную структуру для хранения черного списка доменов
lazy_static::lazy_static! {
    static ref BLOCKED_DOMAINS: Mutex<HashSet<String>> = {
        let mut set = HashSet::new();
        // Черный список 18+ доменов
        set.insert("example-adult-site.com".to_string());
        set.insert("bad-content-domain.net".to_string());
        set.insert("pornhub.com".to_string());
        set.insert("xhamster.com".to_string());
        set.insert("toppornsites.com".to_string());
        set.insert("theporndude.com".to_string());
        set.insert("tiava.com".to_string());
        set.insert("meendo.net".to_string());
        set.insert("island-of-pleasure.site".to_string());
        set.insert("semrush.com".to_string());
        set.insert("epornreview.com".to_string());
        set.insert("nutaku.net".to_string());
        set.insert("pornlist18.com".to_string());
        set.insert("cherry.ai".to_string());
        Mutex::new(set)
    };
}

/// Функция проверки домена: возвращает true, если домен заблокирован (18+)
pub fn is_domain_blocked(domain: &str) -> bool {
    let clean_domain = domain.trim().to_lowercase();
    let list = BLOCKED_DOMAINS.lock().unwrap();
    
    // Безопасная проверка: точное совпадение или принадлежность поддомену
    list.iter().any(|bad_domain| {
        clean_domain == *bad_domain || clean_domain.ends_with(&format!(".{}", bad_domain))
    })
}

// ВНИМАНИЕ: Имя функции должно в точности соответствовать пакету com.filter 
// и классу VpnFilterService, где объявлена external fun checkDomainNative
#[no_mangle]
pub extern "system" fn Java_com_filter_VpnFilterService_checkDomainNative(
    mut env: JNIEnv,
    _class: jni::objects::JClass,
    domain_jstring: JString,
) -> jboolean {
    // Получаем строку домена из Kotlin
    let domain: String = match env.get_string(&domain_jstring) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };

    // Проверяем через нашу функцию фильтрации
    if is_domain_blocked(&domain) {
        1 // true (заблокировано)
    } else {
        0 // false (разрешено)
    }
}