use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;

use crate::control::Control;

pub(crate) const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; \
style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; \
frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

pub(crate) const RECORDING_CONTENT_SECURITY_POLICY: &str = "default-src 'none'; sandbox";

const STRICT_TRANSPORT_SECURITY: &str = "max-age=31536000";

pub(crate) struct SecurityHeaders {
    transport_security: Option<HeaderValue>,
}

impl SecurityHeaders {
    pub(crate) fn new(public_origin: &str) -> SecurityHeaders {
        SecurityHeaders {
            transport_security: public_origin
                .starts_with("https://")
                .then(|| HeaderValue::from_static(STRICT_TRANSPORT_SECURITY)),
        }
    }

    pub(crate) fn apply(&self, headers: &mut HeaderMap) {
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CONTENT_SECURITY_POLICY),
        );
        headers.insert(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        );
        headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
        headers.insert(
            header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin"),
        );
        headers.insert(
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        );
        if let Some(value) = &self.transport_security {
            headers.insert(header::STRICT_TRANSPORT_SECURITY, value.clone());
        }
    }
}

impl SecurityHeaders {
    pub(crate) fn apply_sandboxed(&self, headers: &mut HeaderMap) {
        self.apply(headers);
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(RECORDING_CONTENT_SECURITY_POLICY),
        );
    }
}

pub(crate) async fn apply_sandboxed_to_response(
    State(control): State<Control>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    control.web.headers.apply_sandboxed(response.headers_mut());
    response
}

pub(crate) async fn apply_to_response(
    State(control): State<Control>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    control.web.headers.apply(response.headers_mut());
    response
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderMap;

    use super::{CONTENT_SECURITY_POLICY, RECORDING_CONTENT_SECURITY_POLICY, SecurityHeaders};

    fn applied(origin: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        SecurityHeaders::new(origin).apply(&mut headers);
        headers
    }

    #[test]
    fn every_response_gets_the_strict_policy_and_the_framing_and_sniffing_guards() {
        let headers = applied("https://jaunt.example");

        assert_eq!(
            headers["content-security-policy"],
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
             connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; \
             form-action 'self'"
        );
        assert!(!CONTENT_SECURITY_POLICY.contains("unsafe"));
        assert_eq!(headers["x-content-type-options"], "nosniff");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(headers["referrer-policy"], "strict-origin");
        assert_eq!(headers["cross-origin-opener-policy"], "same-origin");
    }

    #[test]
    fn transport_security_is_sent_only_for_an_https_origin() {
        assert_eq!(
            applied("https://jaunt.example")["strict-transport-security"],
            "max-age=31536000"
        );
        for origin in ["http://jaunt.example", "http://127.0.0.1:8443", ""] {
            assert!(
                applied(origin).get("strict-transport-security").is_none(),
                "{origin}"
            );
        }
    }

    #[test]
    fn values_set_earlier_are_replaced_not_kept() {
        let mut headers = HeaderMap::new();
        headers.insert("content-security-policy", "default-src *".parse().unwrap());
        headers.insert("referrer-policy", "no-referrer".parse().unwrap());

        SecurityHeaders::new("https://jaunt.example").apply(&mut headers);

        assert_eq!(headers["content-security-policy"], CONTENT_SECURITY_POLICY);
        assert_eq!(headers["referrer-policy"], "strict-origin");
    }

    #[test]
    fn sandboxed_responses_keep_every_guard_and_replace_only_the_policy() {
        let mut headers = HeaderMap::new();
        SecurityHeaders::new("https://jaunt.example").apply_sandboxed(&mut headers);

        assert_eq!(
            headers["content-security-policy"],
            RECORDING_CONTENT_SECURITY_POLICY
        );
        assert_eq!(
            RECORDING_CONTENT_SECURITY_POLICY,
            "default-src 'none'; sandbox"
        );
        assert_eq!(headers["x-content-type-options"], "nosniff");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(headers["cross-origin-opener-policy"], "same-origin");
    }
}
