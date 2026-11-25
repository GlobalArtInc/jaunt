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
    fn the_brand_files_are_embedded_with_their_types_and_etags() {
        for (path, content_type) in [
            ("assets/brand/favicon.svg", "image/svg+xml"),
            ("assets/brand/favicon.ico", "image/x-icon"),
            ("assets/brand/apple-touch-icon.png", "image/png"),
        ] {
            let asset = find(path).unwrap();
            assert_eq!(asset.content_type, content_type, "{path}");
            assert!(!asset.bytes.is_empty(), "{path}");
            assert!(asset.etag.len() > 2, "{path}");
        }
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

    const VENDORED: &[(&str, &str)] = &[
        (
            "assets/vendor/xterm/xterm.js",
            "1f991ac3b4b283ebf96e60ae23a00a52765dd3a2e46fa6fdda9f1aab032f7495",
        ),
        (
            "assets/vendor/xterm/xterm.css",
            "ba8e6985669488981ccf40c0cefe3aba80722cb6c92de7ad628b0bd717faf2b6",
        ),
        (
            "assets/vendor/xterm/LICENSE.txt",
            "b569f629d00f2626a8100df2a1798210535621e42164dfd426a6fe5aac7b0ccd",
        ),
        (
            "assets/vendor/xterm/NOTICE.txt",
            "d1101d6a2e3714b6e14eeec3fe0d688a4d3f374e99c8c71172cc409ef99348e4",
        ),
        (
            "assets/vendor/xterm/README.txt",
            "eb2cc407a421a77c50d791ea738a93423b6627673fff36e3c9622a96e69d4933",
        ),
        (
            "assets/vendor/xterm-addon-canvas/addon-canvas.js",
            "7b3e904d5bec98b54d26674994cf994396c4af0971010ffd0d4983229b65d933",
        ),
        (
            "assets/vendor/xterm-addon-canvas/LICENSE.txt",
            "689ceb10716bd7a87a804c14951d7c2b818cbd60aab83d540902470ce3b13444",
        ),
        (
            "assets/vendor/xterm-addon-canvas/NOTICE.txt",
            "9871afac62c1841e6614ea413f03c09291e69a995434061530a6756ff5b6a51c",
        ),
        (
            "assets/vendor/xterm-addon-canvas/README.txt",
            "6f30f7538c794b154b863f96a784296813f1844a3ee1b7b6f2b5088b0b37ae1e",
        ),
    ];

    const SVG_NAMESPACE_ATTRIBUTE: &str = " xmlns=\"http://www.w3.org/2000/svg\"";

    const VENDOR_PREFIX: &str = "assets/vendor/";
    const ADDRESS_NEEDLES: &[&str] = &["http://", "https://"];

    fn sha256_of(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        use sha2::{Digest, Sha256};

        Sha256::digest(bytes)
            .iter()
            .fold(String::new(), |mut hex, byte| {
                let _ = write!(hex, "{byte:02x}");
                hex
            })
    }

    fn is_pinned_vendored(path: &str, bytes: &[u8]) -> bool {
        VENDORED
            .iter()
            .any(|(pinned, hash)| *pinned == path && *hash == sha256_of(bytes))
    }

    #[test]
    fn every_vendored_file_is_pinned_by_hash_and_nothing_else_lives_in_the_vendor_directory() {
        let embedded: HashSet<&str> = assets()
            .iter()
            .map(|asset| asset.path)
            .filter(|path| path.starts_with(VENDOR_PREFIX))
            .collect();
        let pinned: HashSet<&str> = VENDORED.iter().map(|(path, _)| *path).collect();
        assert_eq!(embedded, pinned);
        for asset in assets()
            .iter()
            .filter(|asset| embedded.contains(asset.path))
        {
            assert!(
                is_pinned_vendored(asset.path, asset.bytes),
                "{} does not match its pinned hash",
                asset.path
            );
        }
    }

    #[test]
    fn each_vendored_directory_has_a_license_a_notice_and_a_readme_naming_the_version_and_hashes() {
        let directories: HashSet<&str> = VENDORED
            .iter()
            .filter_map(|(path, _)| path.rsplit_once('/').map(|(directory, _)| directory))
            .collect();
        assert!(!directories.is_empty());
        for directory in directories {
            for name in ["LICENSE.txt", "NOTICE.txt", "README.txt"] {
                assert!(
                    find(&format!("{directory}/{name}")).is_some(),
                    "{directory}/{name}"
                );
            }
            let readme = text_of(&format!("{directory}/README.txt"));
            assert!(readme.contains("Version:") && readme.contains("sha512-"));
            for (path, hash) in VENDORED.iter().filter(|(path, _)| {
                path.starts_with(&format!("{directory}/"))
                    && !path.ends_with("README.txt")
                    && !path.ends_with("NOTICE.txt")
            }) {
                assert!(
                    readme.contains(hash),
                    "{directory} README misses the hash of {path}"
                );
            }
        }
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
            let Ok(text) = std::str::from_utf8(asset.bytes) else {
                assert!(
                    asset.path.ends_with(".png") || asset.path.ends_with(".ico"),
                    "{} is not text",
                    asset.path
                );
                continue;
            };
            let source = &if asset.path.ends_with(".svg") {
                text.replace(SVG_NAMESPACE_ATTRIBUTE, "")
            } else {
                text.to_owned()
            };
            let pinned = is_pinned_vendored(asset.path, asset.bytes);
            for needle in forbidden {
                if pinned && ADDRESS_NEEDLES.contains(&needle) {
                    continue;
                }
                assert!(!source.contains(needle), "{} contains {needle}", asset.path);
            }
            assert!(!source.contains(" style=\""), "{}", asset.path);
        }
    }

    #[test]
    fn the_address_exemption_covers_only_pinned_documentation_and_stylesheet_comments_not_scripts()
    {
        for (path, _) in VENDORED {
            if path.ends_with(".js") {
                let source = text_of(path);
                for needle in ADDRESS_NEEDLES {
                    assert!(!source.contains(needle), "{path} contains {needle}");
                }
            }
        }
    }
}
