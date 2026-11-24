use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::Response;

use crate::device::page::escape;

fn document(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>{}</title><link rel=\"stylesheet\" href=\"/assets/app.css\"></head>\
<body><main>{body}</main></body></html>",
        escape(title)
    )
}

fn respond(status: StatusCode, html: String) -> Response {
    let mut response = Response::new(Body::from(html));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}

fn notice(status: StatusCode, heading: &str, message: &str) -> Response {
    let body = format!(
        "<h1>{}</h1><p>{}</p><p><a href=\"/\">Back to Jaunt</a></p>",
        escape(heading),
        escape(message)
    );
    respond(status, document(heading, &body))
}

pub(crate) fn signed_in(return_to: &str) -> Option<Response> {
    let refresh = HeaderValue::try_from(format!("0; url={return_to}")).ok()?;
    let body = format!(
        "<h1>Signed in</h1><p>You are being taken back to Jaunt. \
If nothing happens, use the link below.</p><p><a href=\"{}\">Continue</a></p>",
        escape(return_to)
    );
    let mut response = respond(StatusCode::OK, document("Signed in", &body));
    response
        .headers_mut()
        .insert(HeaderName::from_static("refresh"), refresh);
    Some(response)
}

pub(crate) fn sign_in_failed() -> Response {
    notice(
        StatusCode::BAD_REQUEST,
        "Sign-in failed",
        "The sign-in could not be completed. Start again from the Jaunt page.",
    )
}

pub(crate) fn busy() -> Response {
    notice(
        StatusCode::SERVICE_UNAVAILABLE,
        "Busy",
        "The service is busy. Try again in a moment.",
    )
}

pub(crate) fn server_error() -> Response {
    notice(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Something went wrong",
        "The request could not be completed. Try again later.",
    )
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::signed_in;

    #[tokio::test]
    async fn the_signed_in_page_answers_200_with_a_refresh_header_and_an_escaped_link() {
        let response = signed_in("/nodes?a=1&b=\"2\"").unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get("location").is_none());
        assert_eq!(response.headers()["refresh"], "0; url=/nodes?a=1&b=\"2\"");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            html.contains("<a href=\"/nodes?a=1&amp;b=&quot;2&quot;\">Continue</a>"),
            "{html}"
        );
        assert!(!html.contains("<script"));
    }

    #[test]
    fn a_return_path_that_cannot_be_a_header_is_not_shown() {
        assert!(signed_in("/a\r\nSet-Cookie: x=1").is_none());
    }
}
