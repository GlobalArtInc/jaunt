use std::collections::BTreeMap;
use std::fmt;

pub const MAX_LABELS: usize = 16;
const MAX_KEY_LEN: usize = 63;
const MAX_VALUE_LEN: usize = 63;
const RESERVED_KEYS: [&str; 1] = ["name"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LabelError {
    #[error("at most {MAX_LABELS} labels are allowed")]
    TooMany,
    #[error("a label key must match [a-z][a-z0-9_.-]{{0,62}}")]
    InvalidKey,
    #[error(
        "the label key `name` is reserved: policy selectors match it against the resource name"
    )]
    ReservedKey,
    #[error("a label value must match [A-Za-z0-9._-]{{0,63}}")]
    InvalidValue,
    #[error("labels must be written as key=value pairs separated by commas")]
    Malformed,
    #[error("a label key appears more than once")]
    DuplicateKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Labels(BTreeMap<String, String>);

impl Labels {
    pub fn new(map: BTreeMap<String, String>) -> Result<Labels, LabelError> {
        if map.keys().any(|key| RESERVED_KEYS.contains(&key.as_str())) {
            return Err(LabelError::ReservedKey);
        }
        Labels::stored(map)
    }

    pub(crate) fn stored(map: BTreeMap<String, String>) -> Result<Labels, LabelError> {
        if map.len() > MAX_LABELS {
            return Err(LabelError::TooMany);
        }
        for (key, value) in &map {
            if !is_valid_key(key) {
                return Err(LabelError::InvalidKey);
            }
            if !is_valid_value(value) {
                return Err(LabelError::InvalidValue);
            }
        }
        Ok(Labels(map))
    }

    pub fn parse_assignments(text: &str) -> Result<Labels, LabelError> {
        let mut map = BTreeMap::new();
        if !text.is_empty() {
            for pair in text.split(',') {
                let (key, value) = pair.split_once('=').ok_or(LabelError::Malformed)?;
                if map.insert(key.to_owned(), value.to_owned()).is_some() {
                    return Err(LabelError::DuplicateKey);
                }
                if map.len() > MAX_LABELS {
                    return Err(LabelError::TooMany);
                }
            }
        }
        Labels::new(map)
    }

    pub fn as_map(&self) -> &BTreeMap<String, String> {
        &self.0
    }

    pub fn into_map(self) -> BTreeMap<String, String> {
        self.0
    }
}

impl fmt::Display for Labels {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (key, value) in &self.0 {
            if !first {
                f.write_str(",")?;
            }
            first = false;
            write!(f, "{key}={value}")?;
        }
        Ok(())
    }
}

fn is_valid_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    bytes.len() <= MAX_KEY_LEN
        && bytes.first().is_some_and(u8::is_ascii_lowercase)
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
}

fn is_valid_value(value: &str) -> bool {
    value.len() <= MAX_VALUE_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{LabelError, Labels};

    fn one(key: &str, value: &str) -> BTreeMap<String, String> {
        BTreeMap::from([(key.to_owned(), value.to_owned())])
    }

    #[test]
    fn keys_and_values_follow_their_patterns() {
        let long_key = format!("k{}", "a".repeat(62));
        let too_long_key = format!("k{}", "a".repeat(63));
        let long_value = "V".repeat(63);
        let too_long_value = "V".repeat(64);
        let keys = [
            ("env", true),
            ("a", true),
            ("k8s.io-team_1", true),
            (long_key.as_str(), true),
            (too_long_key.as_str(), false),
            ("", false),
            ("1env", false),
            ("Env", false),
            ("en v", false),
            ("env=", false),
        ];
        for (key, ok) in keys {
            assert_eq!(Labels::new(one(key, "x")).is_ok(), ok, "{key:?}");
        }
        let values = [
            ("prod", true),
            ("", true),
            ("A-b_c.9", true),
            (long_value.as_str(), true),
            (too_long_value.as_str(), false),
            ("a b", false),
            ("a,b", false),
            ("é", false),
        ];
        for (value, ok) in values {
            assert_eq!(Labels::new(one("env", value)).is_ok(), ok, "{value:?}");
        }
    }

    #[test]
    fn the_name_key_is_rejected_on_input_and_still_read_from_storage() {
        assert_eq!(
            Labels::new(one("name", "web-1")),
            Err(LabelError::ReservedKey)
        );
        assert!(Labels::new(one("names", "x")).is_ok());
        assert!(Labels::new(one("hostname", "x")).is_ok());
        let stored = Labels::stored(one("name", "web-1")).expect("stored labels stay readable");
        assert_eq!(
            stored.as_map().get("name").map(String::as_str),
            Some("web-1")
        );
        assert_eq!(
            Labels::stored(one("Name", "x")),
            Err(LabelError::InvalidKey)
        );
        assert!(
            LabelError::ReservedKey
                .to_string()
                .contains("`name` is reserved"),
            "{}",
            LabelError::ReservedKey
        );
    }

    #[test]
    fn at_most_sixteen_labels_are_accepted() {
        let many = |count: usize| {
            (0..count)
                .map(|n| (format!("k{n}"), "v".to_owned()))
                .collect()
        };
        assert!(Labels::new(many(16)).is_ok());
        assert_eq!(Labels::new(many(17)), Err(LabelError::TooMany));
    }

    #[test]
    fn assignments_parse_into_sorted_labels_and_render_back() {
        let labels = Labels::parse_assignments("role=db,env=prod").unwrap();
        assert_eq!(labels.to_string(), "env=prod,role=db");
        assert!(Labels::parse_assignments("").unwrap().as_map().is_empty());
        for (text, error) in [
            ("env", LabelError::Malformed),
            ("env=prod,", LabelError::Malformed),
            ("env=a,env=b", LabelError::DuplicateKey),
            ("Env=a", LabelError::InvalidKey),
            ("env=a,name=web-1", LabelError::ReservedKey),
            ("env=a b", LabelError::InvalidValue),
        ] {
            assert_eq!(Labels::parse_assignments(text), Err(error), "{text:?}");
        }
        let seventeen: Vec<String> = (0..17).map(|n| format!("k{n}=v")).collect();
        assert_eq!(
            Labels::parse_assignments(&seventeen.join(",")),
            Err(LabelError::TooMany)
        );
    }
}
