use std::fmt;

use zeroize::Zeroizing;

pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: impl Into<Zeroizing<String>>) -> Secret {
        Secret(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::Secret;

    #[test]
    fn debug_output_hides_the_value_and_expose_returns_it() {
        let secret = Secret::new("hunter2".to_owned());
        assert_eq!(secret.expose(), "hunter2");
        assert!(!format!("{secret:?}").contains("hunter2"));
    }
}
