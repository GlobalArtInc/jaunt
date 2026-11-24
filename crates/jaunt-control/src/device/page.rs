use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::Response;

const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; form-action 'self'; style-src 'self'; \
base-uri 'none'; frame-ancestors 'none'";
const STYLESHEET: &str = include_str!("login.css");

pub(crate) struct RequestFacts<'a> {
    pub(crate) label: Option<&'a str>,
    pub(crate) ip: &'a str,
    pub(crate) requested_at: i64,
}

pub(crate) fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

pub(crate) fn format_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let seconds_of_day = secs.rem_euclid(86_400);
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    let hour = seconds_of_day / 3_600;
    let minute = seconds_of_day % 3_600 / 60;
    let second = seconds_of_day % 60;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

fn document(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>{}</title><link rel=\"stylesheet\" href=\"/static/login.css\"></head>\
<body><main>{body}</main></body></html>",
        escape(title)
    )
}

fn respond(status: StatusCode, html: String) -> Response {
    let mut response = Response::new(Body::from(html));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin"),
    );
    response
}

fn facts_list(facts: &RequestFacts<'_>, extra: &str) -> String {
    format!(
        "<dl>{extra}<dt>Client label (unverified, supplied by the requester)</dt><dd>{}</dd><dt>Requested from</dt><dd>{}</dd>\
<dt>Requested at</dt><dd>{}</dd></dl>",
        escape(facts.label.unwrap_or("not given")),
        escape(facts.ip),
        escape(&format_utc(facts.requested_at)),
    )
}

fn action_form(action: &str, login_id: &str, token: &str, button: &str, class: &str) -> String {
    format!(
        "<form method=\"post\" action=\"{}\"><input type=\"hidden\" name=\"login_id\" value=\"{}\">\
<input type=\"hidden\" name=\"token\" value=\"{}\"><button type=\"submit\" class=\"{}\">{}</button></form>",
        escape(action),
        escape(login_id),
        escape(token),
        escape(class),
        escape(button),
    )
}

pub(crate) fn entry(code_rejected: bool) -> Response {
    let error = if code_rejected {
        "<p class=\"error\" role=\"alert\">The code was not recognised or has expired. \
Check the code in your terminal and try again.</p>"
    } else {
        ""
    };
    let body = format!(
        "<h1>Sign in from your terminal</h1><p>Enter the code shown in your terminal.</p>{error}\
<form method=\"post\" action=\"/login/device\"><label for=\"user_code\">Code</label>\
<input id=\"user_code\" name=\"user_code\" type=\"text\" autocomplete=\"off\" \
autocapitalize=\"characters\" spellcheck=\"false\" maxlength=\"16\" required>\
<button type=\"submit\" class=\"primary\">Continue</button></form>"
    );
    respond(StatusCode::OK, document("Sign in to Jaunt", &body))
}

pub(crate) fn confirmation(
    facts: &RequestFacts<'_>,
    code: &str,
    login_id: &str,
    token: &str,
) -> Response {
    let code_row = format!("<dt>Code</dt><dd class=\"code\">{}</dd>", escape(code));
    let body = format!(
        "<h1>Confirm this sign-in request</h1>\
<p>A terminal asked to sign in to Jaunt. Continue only if you started this request.</p>{}\
<p>The code above must match the code shown in your terminal.</p>{}",
        facts_list(facts, &code_row),
        action_form(
            "/login/device/continue",
            login_id,
            token,
            "Continue to sign in",
            "primary"
        ),
    );
    respond(StatusCode::OK, document("Confirm sign-in request", &body))
}

pub(crate) fn continue_page(authorize_url: &str) -> Option<Response> {
    let navigable = authorize_url.starts_with("https://") || authorize_url.starts_with("http://");
    if !navigable || !authorize_url.is_ascii() || authorize_url.chars().any(char::is_control) {
        return None;
    }
    let refresh = HeaderValue::try_from(format!("0; url={authorize_url}")).ok()?;
    let body = format!(
        "<h1>Continue to sign in</h1><p>You are being taken to your identity provider. \
If nothing happens, use the link below.</p>\
<p><a class=\"button primary\" href=\"{}\">Continue to sign in</a></p>",
        escape(authorize_url)
    );
    let mut response = respond(StatusCode::OK, document("Continue to sign in", &body));
    response
        .headers_mut()
        .insert(HeaderName::from_static("refresh"), refresh);
    Some(response)
}

pub(crate) fn approval(
    facts: &RequestFacts<'_>,
    email: &str,
    login_id: &str,
    token: &str,
) -> Response {
    let identity_row = format!("<dt>Signed in as</dt><dd>{}</dd>", escape(email));
    let body = format!(
        "<h1>Approve sign-in for the Jaunt CLI?</h1>\
<p>Approve only if you started this request in a terminal.</p>{}<div class=\"actions\">{}{}</div>",
        facts_list(facts, &identity_row),
        action_form(
            "/login/device/approve",
            login_id,
            token,
            "Approve",
            "primary"
        ),
        action_form("/login/device/deny", login_id, token, "Deny", "secondary"),
    );
    respond(StatusCode::OK, document("Approve sign-in", &body))
}

fn notice(status: StatusCode, heading: &str, message: &str) -> Response {
    let body = format!("<h1>{}</h1><p>{}</p>", escape(heading), escape(message));
    respond(status, document(heading, &body))
}

pub(crate) fn approved() -> Response {
    notice(
        StatusCode::OK,
        "Approved",
        "You can return to your terminal.",
    )
}

pub(crate) fn denied() -> Response {
    notice(StatusCode::OK, "Denied", "Request denied.")
}

pub(crate) fn invalid_request(status: StatusCode) -> Response {
    notice(
        status,
        "Request not valid",
        "This request is no longer valid. Start again from your terminal.",
    )
}

pub(crate) fn forbidden() -> Response {
    notice(
        StatusCode::FORBIDDEN,
        "Request refused",
        "This request did not come from the sign-in page.",
    )
}

pub(crate) fn too_many_attempts(retry_after_secs: i64) -> Response {
    let mut response = notice(
        StatusCode::TOO_MANY_REQUESTS,
        "Too many attempts",
        "Too many codes were entered incorrectly. Try again later.",
    );
    if let Ok(value) = HeaderValue::try_from(retry_after_secs.max(1).to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
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

pub(crate) fn sign_in_failed() -> Response {
    notice(
        StatusCode::BAD_REQUEST,
        "Sign-in failed",
        "The sign-in could not be completed. You can close this tab and start again from the terminal.",
    )
}

pub(crate) fn stylesheet() -> Response {
    let mut response = Response::new(Body::from(STYLESHEET));
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/css"));
    response
}

#[cfg(test)]
mod tests {
    use super::{CONTENT_SECURITY_POLICY, RequestFacts, continue_page, escape, format_utc};

    const HOSTILE_URL: &str = "https://idp.example/authorize?a=1&b=\"><script>x</script>'";

    #[test]
    fn the_continue_page_answers_200_with_a_refresh_header_and_no_redirect() {
        let response = continue_page(HOSTILE_URL).unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert!(response.headers().get("location").is_none());
        assert_eq!(
            response.headers().get("refresh").unwrap().to_str().unwrap(),
            format!("0; url={HOSTILE_URL}")
        );
        assert_eq!(
            response.headers().get("content-security-policy").unwrap(),
            CONTENT_SECURITY_POLICY
        );
    }

    #[tokio::test]
    async fn the_continue_page_holds_the_url_only_inside_a_quoted_escaped_href() {
        let response = continue_page(HOSTILE_URL).unwrap();

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains(
            "href=\"https://idp.example/authorize?a=1&amp;b=&quot;&gt;&lt;script&gt;x&lt;/script&gt;&#39;\">Continue to sign in</a>"
        ));
        assert_eq!(html.matches("idp.example").count(), 1);
        assert!(!html.contains("<script"));
    }

    #[test]
    fn urls_that_could_break_out_of_a_header_or_an_attribute_are_refused() {
        for url in [
            "https://idp.example/a\r\nX-Injected: 1",
            "https://idp.example/a\nb",
            "https://idp.example/a\0b",
            "https://idp.example/a\u{7f}b",
            "https://idp.example/a\u{85}b",
            "https://idp.example/\u{e9}",
            "javascript:alert(1)",
            "data:text/html,x",
            "//idp.example/a",
            "/relative",
            "",
        ] {
            assert!(continue_page(url).is_none(), "{url:?}");
        }
        assert!(continue_page("http://127.0.0.1:9/authorize?x=1").is_some());
    }

    #[test]
    fn the_escaper_neutralises_every_html_metacharacter() {
        assert_eq!(escape("<>&\"'"), "&lt;&gt;&amp;&quot;&#39;");
        assert_eq!(
            escape("<script>alert('x')</script>"),
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"
        );
        assert_eq!(escape("&amp;"), "&amp;amp;");
        assert_eq!(escape("plain text 123"), "plain text 123");
        assert_eq!(escape(""), "");
    }

    #[test]
    fn times_are_formatted_in_utc_across_leap_days_and_the_epoch() {
        for (secs, text) in [
            (0, "1970-01-01 00:00:00 UTC"),
            (-1, "1969-12-31 23:59:59 UTC"),
            (951_782_400, "2000-02-29 00:00:00 UTC"),
            (1_700_000_000, "2023-11-14 22:13:20 UTC"),
            (4_102_444_799, "2099-12-31 23:59:59 UTC"),
            (4_102_444_800, "2100-01-01 00:00:00 UTC"),
        ] {
            assert_eq!(format_utc(secs), text);
        }
    }

    #[test]
    fn dynamic_values_never_reach_the_markup_unescaped() {
        let facts = RequestFacts {
            label: Some("<b>\"x\"</b>"),
            ip: "<ip>",
            requested_at: 0,
        };
        let html = super::facts_list(&facts, "");
        assert!(!html.contains("<b>") && !html.contains("<ip>"));
        assert!(html.contains("&lt;b&gt;&quot;x&quot;&lt;/b&gt;"));
        assert!(html.contains("&lt;ip&gt;"));
    }
}
