use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CaKind {
    User,
    Host,
    Internal,
}

impl CaKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            CaKind::User => "user",
            CaKind::Host => "host",
            CaKind::Internal => "internal",
        }
    }
}

impl fmt::Display for CaKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
