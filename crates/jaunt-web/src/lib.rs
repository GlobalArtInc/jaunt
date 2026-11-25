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
    fn the_entry_page_the_module_entry_and_the_stylesheet_are_embedded_with_their_types() {
        let entry = entry().unwrap();
        assert_eq!(entry.path, ENTRY_PATH);
        assert_eq!(entry.content_type, "text/html; charset=utf-8");
        for path in ["assets/app.js", "assets/js/app.js", "assets/theme-init.js"] {
            let asset = find(path).unwrap();
            assert_eq!(
                asset.content_type, "text/javascript; charset=utf-8",
                "{path}"
            );
            assert!(!asset.bytes.is_empty(), "{path}");
        }
        let css = find("assets/app.css").unwrap();
        assert_eq!(css.content_type, "text/css; charset=utf-8");
        assert!(!css.bytes.is_empty());
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
    fn the_entry_page_has_no_inline_script_or_style() {
        let page = text_of(ENTRY_PATH);
        for (start, _) in page.match_indices("<script") {
            let tag = &page[start..start + page[start..].find('>').unwrap()];
            assert!(tag.contains(" src=\"/assets/"), "{tag}");
        }
        assert!(!page.contains("<style") && !page.contains(" style="));
        assert!(!page.contains("javascript:"));
    }

    fn quoted_paths(source: &str) -> Vec<String> {
        let mut found = Vec::new();
        for marker in ["from \"", "src=\"", "href=\""] {
            for (start, _) in source.match_indices(marker) {
                let rest = &source[start + marker.len()..];
                if let Some(end) = rest.find('"') {
                    found.push(rest[..end].to_owned());
                }
            }
        }
        found
    }

    fn resolve(base: &str, reference: &str) -> Option<String> {
        if let Some(absolute) = reference.strip_prefix('/') {
            return Some(absolute.to_owned());
        }
        if !reference.starts_with("./") && !reference.starts_with("../") {
            return None;
        }
        let mut segments: Vec<&str> = base.split('/').collect();
        segments.pop();
        for part in reference.split('/') {
            match part {
                "." => {}
                ".." => {
                    segments.pop()?;
                }
                other => segments.push(other),
            }
        }
        Some(segments.join("/"))
    }

    #[test]
    fn every_asset_the_page_or_a_module_refers_to_is_embedded() {
        let mut checked = 0;
        for asset in assets() {
            if !(asset.path.ends_with(".js") || asset.path.ends_with(".html")) {
                continue;
            }
            for reference in quoted_paths(text_of(asset.path)) {
                if reference.starts_with('#') || reference.starts_with("http") {
                    continue;
                }
                let Some(target) = resolve(asset.path, &reference) else {
                    continue;
                };
                if !(target.ends_with(".js") || target.ends_with(".css")) {
                    continue;
                }
                assert!(
                    find(&target).is_some(),
                    "{} refers to {reference}, which is not embedded",
                    asset.path
                );
                checked += 1;
            }
        }
        assert!(checked >= 20, "{checked}");
    }

    #[test]
    fn no_asset_can_turn_data_into_markup_or_code() {
        let forbidden = [
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "eval(",
            "new Function(",
            "javascript:",
            "@import",
            "http://",
            "https://",
        ];
        for asset in assets() {
            let source = text_of(asset.path);
            for needle in forbidden {
                assert!(!source.contains(needle), "{} contains {needle}", asset.path);
            }
            assert!(!source.contains(" style=\""), "{}", asset.path);
        }
    }
}
