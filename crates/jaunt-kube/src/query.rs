use crate::escape::{Plus, percent_decode};

pub const MAX_QUERY_PARAMETERS: usize = 1000;

const NAME_FIELD: &str = "metadata.name";

pub(crate) struct Query<'a> {
    raw: &'a str,
}

impl<'a> Query<'a> {
    pub(crate) fn parse(raw: Option<&'a str>) -> Option<Self> {
        let raw = raw.unwrap_or("");
        if raw.split('&').count() > MAX_QUERY_PARAMETERS {
            return None;
        }
        Some(Self { raw })
    }

    pub(crate) fn first(&self, key: &str) -> Option<Vec<u8>> {
        self.raw
            .split('&')
            .filter(|pair| !pair.is_empty() && !pair.contains(';'))
            .find_map(|pair| {
                let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
                let decoded_key = percent_decode(raw_key.as_bytes(), Plus::Space)?;
                let decoded_value = percent_decode(raw_value.as_bytes(), Plus::Space)?;
                (decoded_key == key.as_bytes()).then_some(decoded_value)
            })
    }

    pub(crate) fn is_watch(&self) -> bool {
        self.flag("watch")
    }

    pub(crate) fn flag(&self, key: &str) -> bool {
        self.first(key)
            .is_some_and(|value| value != b"0" && !folds_to_false(&value))
    }

    pub(crate) fn name_from_field_selector(&self) -> Option<String> {
        let selector = String::from_utf8(self.first("fieldSelector")?).ok()?;
        exact_match(&selector, NAME_FIELD)
    }
}

pub fn query_flag(query: Option<&str>, key: &str) -> bool {
    Query::parse(query).is_some_and(|query| query.flag(key))
}

fn folds_to_false(value: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(value) else {
        return false;
    };
    let mut folded = text.chars().map(|ch| match ch {
        '\u{017f}' => 's',
        other => other.to_ascii_lowercase(),
    });
    "false"
        .chars()
        .all(|expected| folded.next() == Some(expected))
        && folded.next().is_none()
}

fn exact_match(selector: &str, field: &str) -> Option<String> {
    let mut terms = split_terms(selector);
    terms.sort_unstable();
    let mut found = None;
    for term in terms.into_iter().filter(|term| !term.is_empty()) {
        let (lhs, operator, rhs) = split_term(term)?;
        let value = unescape_value(rhs)?;
        if found.is_none() && operator != "!=" && lhs == field {
            found = Some(value);
        }
    }
    found
}

fn split_terms(selector: &str) -> Vec<&str> {
    if selector.is_empty() {
        return Vec::new();
    }
    let mut terms = Vec::new();
    let mut start = 0;
    let mut escaped = false;
    for (index, ch) in selector.char_indices() {
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == ',' {
            terms.push(selector.get(start..index).unwrap_or(""));
            start = index + 1;
        }
    }
    terms.push(selector.get(start..).unwrap_or(""));
    terms
}

fn split_term(term: &str) -> Option<(&str, &'static str, &str)> {
    term.char_indices().find_map(|(index, _)| {
        let remaining = term.get(index..)?;
        ["!=", "==", "="].into_iter().find_map(|operator| {
            remaining
                .strip_prefix(operator)
                .map(|rhs| (term.get(..index).unwrap_or(""), operator, rhs))
        })
    })
}

fn unescape_value(value: &str) -> Option<String> {
    let mut out = String::with_capacity(value.len());
    let mut escaped = false;
    for ch in value.chars() {
        if escaped {
            if !matches!(ch, '\\' | ',' | '=') {
                return None;
            }
            out.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            ',' | '=' => return None,
            other => out.push(other),
        }
    }
    (!escaped).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(raw: &str) -> Query<'_> {
        Query::parse(Some(raw)).unwrap()
    }

    #[test]
    fn watch_follows_the_first_decodable_value() {
        for (raw, watch) in [
            ("", false),
            ("watch=true", true),
            ("watch=1", true),
            ("watch", true),
            ("watch=", true),
            ("watch=0", false),
            ("watch=false", false),
            ("watch=FALSE", false),
            ("watch=fal%C5%BFe", false),
            ("watch=no", true),
            ("w%61tch=true", true),
            ("watch=false&watch=true", false),
            ("watch=%zz&watch=0", false),
            ("watch=true;x=1", false),
            ("watch=+", true),
            ("watchx=true", false),
        ] {
            assert_eq!(query(raw).is_watch(), watch, "query {raw:?}");
        }
    }

    #[test]
    fn name_comes_from_an_exact_metadata_name_term() {
        for (selector, name) in [
            ("metadata.name=web", Some("web")),
            ("metadata.name==web", Some("web")),
            ("metadata.name!=web", None),
            ("status.phase=Running,metadata.name=web", Some("web")),
            ("metadata.name=b,metadata.name=a", Some("a")),
            ("metadata.name=a\\,b", Some("a,b")),
            ("metadata.name=a=b", None),
            ("metadata.name=a\\x", None),
            ("metadata.name=a\\", None),
            ("bogus,metadata.name=web", None),
            ("", None),
            (",metadata.name=web", Some("web")),
        ] {
            assert_eq!(
                exact_match(selector, NAME_FIELD).as_deref(),
                name,
                "selector {selector:?}"
            );
        }
    }

    #[test]
    fn a_flag_follows_the_first_value_like_the_api_server() {
        for (raw, set) in [
            (None, false),
            (Some(""), false),
            (Some("follow=true"), true),
            (Some("follow=f"), true),
            (Some("follow=no"), true),
            (Some("follow"), true),
            (Some("follow="), true),
            (Some("follow=1"), true),
            (Some("follow=0"), false),
            (Some("follow=false"), false),
            (Some("follow=fAlSe"), false),
            (Some("follow=fal%C5%BFe"), false),
            (Some("follow=false&follow=true"), false),
            (Some("follow=true&follow=false"), true),
            (Some("container=c&follow=true"), true),
            (Some("follow=true;x=1"), false),
            (Some("followx=true"), false),
        ] {
            assert_eq!(query_flag(raw, "follow"), set, "{raw:?}");
        }
        let over_limit = vec!["follow=true"; MAX_QUERY_PARAMETERS + 1].join("&");
        assert!(!query_flag(Some(&over_limit), "follow"));
    }

    #[test]
    fn too_many_parameters_are_refused() {
        let at_limit = vec!["a=1"; MAX_QUERY_PARAMETERS].join("&");
        let over_limit = vec!["a=1"; MAX_QUERY_PARAMETERS + 1].join("&");
        assert!(Query::parse(Some(&at_limit)).is_some());
        assert!(Query::parse(Some(&over_limit)).is_none());
    }
}
