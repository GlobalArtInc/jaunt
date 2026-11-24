use jaunt_policy::Identity;
use jaunt_store::User;

pub(crate) fn policy_identity(user: &User) -> Identity {
    Identity {
        email: user.email.clone(),
        username: user.username.clone(),
        groups: user.groups.clone(),
    }
}

#[cfg(test)]
mod tests {
    use jaunt_policy::Identity;
    use jaunt_store::User;

    use super::policy_identity;

    fn stored(username: &str) -> User {
        User {
            id: "user-id".to_owned(),
            issuer: "https://idp.example".to_owned(),
            subject: "subject-1".to_owned(),
            email: "ada@example.com".to_owned(),
            username: username.to_owned(),
            display_name: Some("Ada".to_owned()),
            groups: vec!["ops".to_owned(), "dev".to_owned()],
            created_at: 1,
            updated_at: 2,
        }
    }

    #[test]
    fn the_identity_carries_the_stored_email_username_and_groups() {
        assert_eq!(
            policy_identity(&stored("ada")),
            Identity {
                email: "ada@example.com".to_owned(),
                username: "ada".to_owned(),
                groups: vec!["ops".to_owned(), "dev".to_owned()],
            }
        );
    }

    #[test]
    fn an_empty_username_stays_empty_and_is_never_derived_from_the_email() {
        assert_eq!(policy_identity(&stored("")).username, "");
    }
}
