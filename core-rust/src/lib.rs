use jni::objects::{JObject, JString};
use jni::sys::jboolean;
use jni::JNIEnv;
use std::collections::HashSet;

lazy_static::lazy_static! {
    static ref BLOCKED_DOMAINS: HashSet<&'static str> = {
        [
            "pornhub.com",
            "xhamster.com",
            "toppornsites.com",
            "theporndude.com",
            "tiava.com",
            "meendo.net",
            "island-of-pleasure.site",
            "epornreview.com",
            "nutaku.net",
            "pornlist18.com",
        ]
        .into_iter()
        .collect()
    };
}

pub fn is_domain_blocked(domain: &str) -> bool {
    let lowered = domain.trim().to_lowercase();
    let mut current: &str = lowered.strip_suffix('.').unwrap_or(&lowered);

    // Проверяем сам домен и все его родительские домены:
    // a.b.pornhub.com -> b.pornhub.com -> pornhub.com
    loop {
        if BLOCKED_DOMAINS.contains(current) {
            return true;
        }
        match current.find('.') {
            Some(i) => current = &current[i + 1..],
            None => return false,
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_filter_VpnFilterService_checkDomainNative(
    mut env: JNIEnv,
    _this: JObject,
    domain_jstring: JString,
) -> jboolean {
    let domain: String = match env.get_string(&domain_jstring) {
        Ok(s) => s.into(),
        Err(_) => return 0, // при ошибке не блокируем
    };

    if is_domain_blocked(&domain) { 1 } else { 0 }
}