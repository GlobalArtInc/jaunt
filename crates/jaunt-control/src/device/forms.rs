use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::http::{HeaderMap, StatusCode, header};

use crate::finish::canonical_login_id;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FormFailure {
    TooLarge,
    Malformed,
}

pub(crate) struct Form {
    fields: HashMap<String, String>,
}

impl Form {
    pub(crate) fn parse(
        headers: &HeaderMap,
        body: Result<Bytes, BytesRejection>,
    ) -> Result<Form, FormFailure> {
        let bytes = match body {
            Ok(bytes) => bytes,
            Err(rejection) if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE => {
                return Err(FormFailure::TooLarge);
            }
            Err(_) => return Err(FormFailure::Malformed),
        };
        if !is_form_content_type(headers) {
            return Err(FormFailure::Malformed);
        }
        let mut fields = HashMap::new();
        for (name, value) in form_urlencoded::parse(&bytes) {
            if fields
                .insert(name.into_owned(), value.into_owned())
                .is_some()
            {
                return Err(FormFailure::Malformed);
            }
        }
        Ok(Form { fields })
    }

    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }

    pub(crate) fn flow(&self) -> Option<FlowFields> {
        let login_id = canonical_login_id(self.get("login_id")?)?;
        let token = self.get("token").filter(|token| !token.is_empty())?;
        Some(FlowFields {
            login_id,
            token: token.to_owned(),
        })
    }
}

pub(crate) struct FlowFields {
    pub(crate) login_id: String,
    pub(crate) token: String,
}

fn is_form_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value
            .to_str()
            .ok()
            .and_then(|text| text.split(';').next())
            .is_some_and(|essence| {
                essence
                    .trim()
                    .eq_ignore_ascii_case("application/x-www-form-urlencoded")
            }),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Bytes;
    use axum::http::{HeaderMap, HeaderValue, header};

    use super::{Form, FormFailure};

    const LOGIN_ID: &str = "0b7a0a2e-6a53-4c4e-9a3e-6d3a3f1b2c4d";

    fn parse(content_type: Option<&str>, body: &str) -> Result<Form, FormFailure> {
        let mut headers = HeaderMap::new();
        if let Some(content_type) = content_type {
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(content_type).unwrap(),
            );
        }
        Form::parse(&headers, Ok(Bytes::from(body.to_owned())))
    }

    #[test]
    fn fields_are_decoded_and_duplicates_or_wrong_content_types_are_refused() {
        let form = parse(
            Some("application/x-www-form-urlencoded; charset=UTF-8"),
            "user_code=ab+cd%2D12&other=",
        )
        .unwrap();
        assert_eq!(form.get("user_code"), Some("ab cd-12"));
        assert_eq!(form.get("other"), Some(""));
        assert_eq!(form.get("missing"), None);

        for (content_type, body) in [
            (Some("application/x-www-form-urlencoded"), "a=1&a=2"),
            (Some("application/json"), "a=1"),
            (Some("text/plain"), "a=1"),
            (None, "a=1"),
        ] {
            assert_eq!(
                parse(content_type, body).err(),
                Some(FormFailure::Malformed),
                "{content_type:?} {body}"
            );
        }
    }

    #[test]
    fn the_flow_fields_need_a_canonical_login_id_and_a_token() {
        let content_type = Some("application/x-www-form-urlencoded");
        let good = parse(content_type, &format!("login_id={LOGIN_ID}&token=abc")).unwrap();
        let flow = good.flow().unwrap();
        assert_eq!(flow.login_id, LOGIN_ID);
        assert_eq!(flow.token, "abc");

        let upper = LOGIN_ID.to_uppercase();
        for body in [
            format!("login_id={LOGIN_ID}"),
            format!("login_id={LOGIN_ID}&token="),
            "login_id=nope&token=abc".to_owned(),
            format!("login_id={upper}&token=abc"),
            "token=abc".to_owned(),
        ] {
            assert!(
                parse(content_type, &body).unwrap().flow().is_none(),
                "{body}"
            );
        }
    }
}
