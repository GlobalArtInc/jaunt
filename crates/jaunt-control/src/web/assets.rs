use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::Response;
use jaunt_web::Asset;

use crate::http::{empty_response, server_error};

const FILE_DIRECTORY: &str = "assets";
const FAVICON_PATH: &str = "/favicon.ico";
const FAVICON_KEY: &str = "assets/brand/favicon.ico";
const INDEX_CACHE_CONTROL: &str = "no-cache";
const FILE_CACHE_CONTROL: &str = "no-cache";

pub(crate) async fn serve(method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let path = uri.path();
    if is_reserved(path) {
        return empty_response(StatusCode::NOT_FOUND);
    }
    if method != Method::GET && method != Method::HEAD {
        let mut response = empty_response(StatusCode::METHOD_NOT_ALLOWED);
        response
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return response;
    }
    let head = method == Method::HEAD;
    if path == FAVICON_PATH {
        return match jaunt_web::find(FAVICON_KEY) {
            Some(asset) => respond(asset, FILE_CACHE_CONTROL, &headers, head),
            None => {
                tracing::error!(target: "jaunt::control", "the embedded favicon is missing");
                server_error()
            }
        };
    }
    let Some(key) = table_key(path) else {
        return empty_response(StatusCode::NOT_FOUND);
    };
    if is_file_path(key) {
        return match jaunt_web::find(key).filter(|_| !path.ends_with('/')) {
            Some(asset) => respond(asset, FILE_CACHE_CONTROL, &headers, head),
            None => empty_response(StatusCode::NOT_FOUND),
        };
    }
    match jaunt_web::entry() {
        Some(entry) => respond(entry, INDEX_CACHE_CONTROL, &headers, head),
        None => {
            tracing::error!(target: "jaunt::control", "the embedded entry page is missing");
            server_error()
        }
    }
}

fn is_file_path(key: &str) -> bool {
    key.strip_prefix(FILE_DIRECTORY)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

fn is_reserved(path: &str) -> bool {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    let (first, rest) = match trimmed.split_once('/') {
        Some((first, rest)) => (first, Some(rest)),
        None => (trimmed, None),
    };
    first.eq_ignore_ascii_case("v1")
        || first.eq_ignore_ascii_case("static")
        || (first.eq_ignore_ascii_case("login") && rest.is_some())
}

fn table_key(path: &str) -> Option<&str> {
    let relative = path.strip_prefix('/')?;
    if relative.is_empty() {
        return Some(relative);
    }
    let trimmed = relative.strip_suffix('/').unwrap_or(relative);
    let safe = trimmed.split('/').all(|segment| {
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'~')
            })
    });
    safe.then_some(trimmed)
}

fn etag_matches(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get_all(header::IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|line| line.split(','))
        .map(str::trim)
        .any(|candidate| {
            candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
        })
}

fn respond(
    asset: &Asset,
    cache_control: &'static str,
    headers: &HeaderMap,
    head: bool,
) -> Response {
    let (Ok(content_type), Ok(etag)) = (
        HeaderValue::try_from(asset.content_type),
        HeaderValue::try_from(asset.etag),
    ) else {
        tracing::error!(target: "jaunt::control", "an embedded asset has an invalid header value");
        return server_error();
    };
    let mut response = if etag_matches(headers, asset.etag) {
        empty_response(StatusCode::NOT_MODIFIED)
    } else {
        let mut response = if head {
            Response::new(Body::empty())
        } else {
            Response::new(Body::from(asset.bytes))
        };
        let response_headers = response.headers_mut();
        response_headers.insert(header::CONTENT_TYPE, content_type);
        response_headers.insert(header::CONTENT_LENGTH, HeaderValue::from(asset.bytes.len()));
        response
    };
    let response_headers = response.headers_mut();
    response_headers.insert(header::ETAG, etag);
    response_headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control),
    );
    response
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header};

    use super::{etag_matches, is_file_path, is_reserved, table_key};

    #[test]
    fn clean_paths_map_to_table_keys_and_everything_else_is_refused() {
        for (path, key) in [
            ("/", ""),
            ("/assets/app.js", "assets/app.js"),
            ("/nodes", "nodes"),
            ("/nodes/web-01/", "nodes/web-01"),
            ("/a_b/c~d/e.f", "a_b/c~d/e.f"),
        ] {
            assert_eq!(table_key(path), Some(key), "{path}");
        }
        for path in [
            "",
            "assets/app.js",
            "//",
            "//evil",
            "/a//b",
            "/assets/../x",
            "/assets/./app.js",
            "/..",
            "/.",
            "/%2e%2e/x",
            "/assets/%2E%2E/x",
            "/assets/..%2fx",
            "/assets/a%2fb",
            "/assets/a%5cb",
            "/assets/a\\b",
            "/assets/a\0b",
            "/assets/a%00b",
            "/a b",
            "/caf\u{e9}",
            "/a;b",
            "/a:b",
        ] {
            assert_eq!(table_key(path), None, "{path:?}");
        }
    }

    #[test]
    fn the_api_the_device_pages_and_their_case_variants_are_never_the_spa() {
        for path in [
            "/v1",
            "/v1/",
            "/v1/web/session",
            "/V1/web/session",
            "/V1",
            "/static",
            "/static/login.css",
            "/STATIC/x",
            "/Static",
            "/login/",
            "/login/device",
            "/Login/Device",
            "/LOGIN/x",
        ] {
            assert!(is_reserved(path), "{path}");
        }
        for path in [
            "/",
            "/login",
            "/Login",
            "/nodes",
            "/v1x",
            "/staticfiles",
            "/loginx/y",
            "/assets/app.js",
        ] {
            assert!(!is_reserved(path), "{path}");
        }
    }

    #[test]
    fn everything_at_or_under_the_assets_directory_is_a_file_lookup() {
        for key in ["assets", "assets/app.js", "assets/missing", "assets/a/b"] {
            assert!(is_file_path(key), "{key}");
        }
        for key in ["", "index.html", "assetsx", "nodes/assets", "Assets/app.js"] {
            assert!(!is_file_path(key), "{key}");
        }
    }

    #[test]
    fn a_conditional_request_matches_strong_weak_listed_and_star_validators() {
        let etag = "\"abc-1\"";
        let with = |lines: &[&str]| {
            let mut headers = HeaderMap::new();
            for line in lines {
                headers.append(header::IF_NONE_MATCH, HeaderValue::from_str(line).unwrap());
            }
            etag_matches(&headers, etag)
        };

        assert!(with(&["\"abc-1\""]));
        assert!(with(&["W/\"abc-1\""]));
        assert!(with(&["\"zzz\", \"abc-1\""]));
        assert!(with(&["\"zzz\"", "\"abc-1\""]));
        assert!(with(&["*"]));
        assert!(!with(&[]));
        assert!(!with(&["\"abc-2\""]));
        assert!(!with(&["abc-1"]));
        assert!(!with(&[""]));
    }
}
