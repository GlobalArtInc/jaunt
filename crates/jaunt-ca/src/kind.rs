use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CaKind {
    User,
    Host,
    Internal,
    UserX509,
    DbClient,
}

impl CaKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            CaKind::User => "user",
            CaKind::Host => "host",
            CaKind::Internal => "internal",
            CaKind::UserX509 => "user-x509",
            CaKind::DbClient => "db-client",
        }
    }

    pub const fn is_x509_client(self) -> bool {
        matches!(self, CaKind::UserX509 | CaKind::DbClient)
    }
}

impl fmt::Display for CaKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
