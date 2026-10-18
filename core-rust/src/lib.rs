use jni::objects::JString;
use jni::sys::jboolean;
use jni::JNIEnv;
use std::collections::HashSet;
use std::sync::Mutex;

lazy_static::lazy_static! {
    static ref BLOCKED_DOMAINS: Mutex<HashSet<String>> = {
        let mut set = HashSet::new();
        // Чистый список строго запрещенных 18+ доменов
        set.insert("pornhub.com".to_string());
        set.insert("xhamster.com".to_string());
        set.insert("toppornsites.com".to_string());
        set.insert("theporndude.com".to_string());
        set.insert("tiava.com".to_string());
        set.insert("meendo.net".to_string());
        set.insert("island-of-pleasure.site".to_string());
        set.insert("epornreview.com".to_string());
        set.insert("nutaku.net".to_string());
        set.insert("pornlist18.com".to_string());
        Mutex::new(set)
    };
}

pub fn is_domain_blocked(domain: &str) -> bool {
    // Убираем пробелы, переводим в нижний регистр и удаляем точку на конце, если она есть (например, "youtube.com.")
    let clean_domain = domain.trim().to_lowercase();
    let clean_domain = clean_domain.strip_suffix('.').unwrap_or(&clean_domain);
    
    let list = BLOCKED_DOMAINS.lock().unwrap();
    
    // Проверяем точное совпадение или принадлежность поддомену
    list.iter().any(|bad_domain| {
        clean_domain == *bad_domain || clean_domain.ends_with(&format!(".{}", bad_domain))
    })
}

#[no_mangle]
pub extern "system" fn Java_com_filter_VpnFilterService_checkDomainNative(
    mut env: JNIEnv,
    _class: jni::objects::JClass,
    domain_jstring: JString,
) -> jboolean {
    let domain: String = match env.get_string(&domain_jstring) {
        Ok(s) => s.into(),
        Err(_) => return 0, // При ошибке чтения строки НЕ блокируем (безопасно пропускаем)
    };

    if is_domain_blocked(&domain) {
        1 // true (заблокировано)
    } else {
        0 // false (разрешено, YouTube и всё остальное летит дальше)
    }
}