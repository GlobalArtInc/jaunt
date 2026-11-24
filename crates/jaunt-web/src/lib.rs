#[derive(Clone, Copy)]
pub struct Asset {
    pub path: &'static str,
    pub content_type: &'static str,
    pub bytes: &'static [u8],
    pub etag: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/assets_table.rs"));

pub const ENTRY_PATH: &str = "index.html";

pub fn assets() -> &'static [Asset] {
    TABLE
}

pub fn find(path: &str) -> Option<&'static Asset> {
    TABLE.iter().find(|asset| asset.path == path)
}

pub fn entry() -> Option<&'static Asset> {
    find(ENTRY_PATH)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{ENTRY_PATH, assets, entry, find};

    fn text_of(path: &str) -> &'static str {
        std::str::from_utf8(find(path).unwrap().bytes).unwrap()
    }

    #[test]
    fn the_entry_page_and_the_placeholder_app_are_embedded_with_their_types() {
        let entry = entry().unwrap();
        assert_eq!(entry.path, ENTRY_PATH);
        assert_eq!(entry.content_type, "text/html; charset=utf-8");
        assert_eq!(
            find("assets/app.js").unwrap().content_type,
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            find("assets/app.css").unwrap().content_type,
            "text/css; charset=utf-8"
        );
        assert!(!find("assets/app.js").unwrap().bytes.is_empty());
    }

    #[test]
    fn table_paths_are_unique_relative_and_made_of_safe_characters() {
        let mut seen = HashSet::new();
        for asset in assets() {
            assert!(seen.insert(asset.path), "{}", asset.path);
            assert!(!asset.path.starts_with('/'), "{}", asset.path);
            for segment in asset.path.split('/') {
                assert!(!segment.is_empty() && segment != "." && segment != "..");
                assert!(
                    segment
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric()
                            || matches!(byte, b'.' | b'_' | b'-'))
                );
            }
        }
    }

    #[test]
    fn every_etag_is_a_quoted_strong_tag_that_differs_between_files() {
        let tags: HashSet<&str> = assets().iter().map(|asset| asset.etag).collect();
        assert_eq!(tags.len(), assets().len());
        for tag in tags {
            assert!(
                tag.starts_with('"') && tag.ends_with('"') && tag.len() > 2,
                "{tag}"
            );
        }
    }

    #[test]
    fn lookups_are_exact_and_never_resolve_relative_segments() {
        for path in [
            "",
            "/index.html",
            "assets/",
            "assets/../index.html",
            "Assets/app.js",
        ] {
            assert!(find(path).is_none(), "{path:?}");
        }
    }

    #[test]
    fn the_placeholder_page_has_no_inline_script_or_style() {
        let page = text_of(ENTRY_PATH);
        for (start, _) in page.match_indices("<script") {
            let tag = &page[start..start + page[start..].find('>').unwrap()];
            assert!(tag.contains(" src=\"/assets/"), "{tag}");
        }
        assert!(!page.contains("<style") && !page.contains(" style="));
        assert!(!page.contains("javascript:"));
    }
}
