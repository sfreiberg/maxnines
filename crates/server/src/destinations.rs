//! Whether a saved secret would still go where it went. A password, key or header
//! is kept when its box is left empty, but never for somewhere new: anyone who can
//! edit a check or a channel could otherwise point it at a server of their own and
//! read the secret there.

use url::Url;

/// Whether two targets, as typed, reach the same place: the same scheme, host and
/// port for web addresses, and otherwise the same text, whatever its case.
pub fn same_place(saved: &str, new: &str) -> bool {
    let (saved, new) = (saved.trim(), new.trim());
    match (Url::parse(saved), Url::parse(new)) {
        (Ok(saved), Ok(new)) if saved.has_host() && new.has_host() => {
            saved.origin() == new.origin()
        }
        _ => saved.eq_ignore_ascii_case(new),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_same_server_is_the_same_place() {
        for (saved, new) in [
            (
                "https://hooks.example.com/a",
                "https://hooks.example.com/b?c=d",
            ),
            (
                "https://hooks.example.com/a",
                "https://HOOKS.example.com:443/a",
            ),
            ("db.example.com:5432", "DB.example.com:5432"),
            ("db.example.com", " db.example.com "),
        ] {
            assert!(same_place(saved, new), "{saved} {new}");
        }
        for (saved, new) in [
            ("https://hooks.example.com/a", "https://hooks.example.net/a"),
            ("https://hooks.example.com/a", "http://hooks.example.com/a"),
            (
                "https://hooks.example.com/a",
                "https://hooks.example.com:8443/a",
            ),
            (
                "https://hooks.example.com",
                "https://hooks.example.com.evil.example",
            ),
            ("db.example.com:5432", "db.example.com:5433"),
            ("db.example.com", "evil.example"),
        ] {
            assert!(!same_place(saved, new), "{saved} {new}");
        }
    }
}
