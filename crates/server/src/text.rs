//! Text that can be left out. Left out is `None`, kept as NULL, and never an empty
//! string: whatever arrives blank, from a form or the API, is taken as none where it
//! comes in, so nothing further on has to wonder which of the two it's looking at.

use serde::{Deserialize, Deserializer};

/// `text`, unless it's empty or only spaces, which is none.
pub fn non_blank(text: &str) -> Option<String> {
    (!text.trim().is_empty()).then(|| text.to_string())
}

/// `text` trimmed, unless that leaves nothing, which is none.
pub fn trimmed(text: &str) -> Option<String> {
    non_blank(text.trim())
}

/// For serde: text that can be left out, sent as null, or sent blank, which are all
/// none. Use it with `#[serde(default, deserialize_with = "crate::text::optional")]`.
pub fn optional<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    let text = Option::<String>::deserialize(deserializer)?;
    Ok(text.as_deref().and_then(non_blank))
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct Input {
        #[serde(default, deserialize_with = "optional")]
        filter: Option<String>,
    }

    fn filter(json: &str) -> Option<String> {
        serde_json::from_str::<Input>(json).unwrap().filter
    }

    #[test]
    fn left_out_null_and_blank_are_all_none() {
        assert_eq!(filter("{}"), None);
        assert_eq!(filter(r#"{"filter": null}"#), None);
        assert_eq!(filter(r#"{"filter": ""}"#), None);
        assert_eq!(filter(r#"{"filter": "  "}"#), None);
        assert_eq!(
            filter(r#"{"filter": " os=linux"}"#),
            Some(" os=linux".to_string())
        );
    }

    #[test]
    fn typed_text_is_none_when_blank() {
        assert_eq!(non_blank(""), None);
        assert_eq!(non_blank(" "), None);
        assert_eq!(non_blank(" a "), Some(" a ".to_string()));
        assert_eq!(trimmed(" a "), Some("a".to_string()));
        assert_eq!(trimmed("\t"), None);
    }
}
