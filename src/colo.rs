use std::collections::HashMap;
use std::sync::OnceLock;

/// Cloudflare `colo` code → country mapping, embedded at compile time.
///
/// The dataset is a flat object keyed by the three-letter Cloudflare
/// datacenter code (the same value parsed from `/cdn-cgi/trace`) with the
/// human-readable country as the value. It covers the common edge locations;
/// unknown or future codes simply resolve to `None` rather than erroring.
const COLO_DB: &str = include_str!("colo_db.json");

fn database() -> &'static HashMap<&'static str, &'static str> {
    static DB: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    DB.get_or_init(|| {
        serde_json::from_str::<HashMap<&'static str, &'static str>>(COLO_DB).unwrap_or_default()
    })
}

/// Resolve a Cloudflare `colo` code to its country name.
///
/// The lookup is case-insensitive and returns `None` when the code is unknown
/// or the embedded dataset failed to parse.
pub fn lookup_country(code: &str) -> Option<&'static str> {
    let normalized = code.trim().to_ascii_uppercase();
    database().get(normalized.as_str()).copied()
}

#[cfg(test)]
mod tests {
    use super::lookup_country;

    #[test]
    fn known_code_resolves_to_country() {
        assert_eq!(lookup_country("fra"), Some("Germany"));
        assert_eq!(lookup_country("FRA"), Some("Germany"));
        assert_eq!(lookup_country("AMS"), Some("Netherlands"));
    }

    #[test]
    fn unknown_code_resolves_to_none() {
        assert_eq!(lookup_country("ZZZ"), None);
        assert_eq!(lookup_country(""), None);
    }
}
