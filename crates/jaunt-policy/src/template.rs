use std::borrow::Cow;

use crate::model::Identity;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Trait {
    Username,
    Email,
    Groups,
}

impl Trait {
    const ALL: [Trait; 3] = [Trait::Username, Trait::Email, Trait::Groups];

    fn placeholder(self) -> &'static str {
        match self {
            Trait::Username => "{username}",
            Trait::Email => "{email}",
            Trait::Groups => "{groups}",
        }
    }

    fn values(self, identity: &Identity) -> &[String] {
        match self {
            Trait::Username => std::slice::from_ref(&identity.username),
            Trait::Email => std::slice::from_ref(&identity.email),
            Trait::Groups => &identity.groups,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Target {
    pub(crate) literal: fn(&str) -> bool,
    pub(crate) prefix: fn(&str) -> bool,
    pub(crate) substituted: fn(&str) -> bool,
}

#[derive(Debug, Clone)]
pub(crate) enum ValueSpec {
    Literal(String),
    Template { prefix: String, source: Trait },
}

pub(crate) enum Parsed {
    Valid(ValueSpec),
    MalformedTemplate,
    InvalidLiteral,
    InvalidPrefix,
}

impl ValueSpec {
    pub(crate) fn parse(text: &str, target: Target) -> Parsed {
        let Some(open) = text.find(['{', '}']) else {
            return if (target.literal)(text) {
                Parsed::Valid(ValueSpec::Literal(text.to_owned()))
            } else {
                Parsed::InvalidLiteral
            };
        };
        let (prefix, placeholder) = text.split_at(open);
        let Some(source) = Trait::ALL
            .into_iter()
            .find(|candidate| candidate.placeholder() == placeholder)
        else {
            return Parsed::MalformedTemplate;
        };
        if !(target.prefix)(prefix) {
            return Parsed::InvalidPrefix;
        }
        Parsed::Valid(ValueSpec::Template {
            prefix: prefix.to_owned(),
            source,
        })
    }

    pub(crate) fn email() -> Self {
        ValueSpec::Template {
            prefix: String::new(),
            source: Trait::Email,
        }
    }

    pub(crate) fn drops_invalid(&self, identity: &Identity, target: Target) -> bool {
        match self {
            ValueSpec::Literal(_) => false,
            ValueSpec::Template { prefix, source } => source
                .values(identity)
                .iter()
                .filter(|value| !value.is_empty())
                .any(|value| !(target.substituted)(&format!("{prefix}{value}"))),
        }
    }

    pub(crate) fn as_literal(&self) -> Option<&str> {
        match self {
            ValueSpec::Literal(value) => Some(value),
            ValueSpec::Template { .. } => None,
        }
    }

    pub(crate) fn as_written(&self) -> String {
        match self {
            ValueSpec::Literal(value) => value.clone(),
            ValueSpec::Template { prefix, source } => {
                format!("{prefix}{}", source.placeholder())
            }
        }
    }

    pub(crate) fn resolve<'a>(
        &'a self,
        identity: &'a Identity,
        target: Target,
    ) -> impl Iterator<Item = Cow<'a, str>> + 'a {
        let (literal, prefix, values): (Option<&str>, &str, &[String]) = match self {
            ValueSpec::Literal(value) => (Some(value.as_str()), "", &[]),
            ValueSpec::Template { prefix, source } => {
                (None, prefix.as_str(), source.values(identity))
            }
        };
        let literal = literal
            .filter(|value| (target.literal)(value))
            .map(Cow::Borrowed);
        let substituted = values
            .iter()
            .filter(|value| !value.is_empty())
            .map(move |value| format!("{prefix}{value}"))
            .filter(move |value| (target.substituted)(value))
            .map(Cow::Owned);
        literal.into_iter().chain(substituted)
    }
}

pub(crate) const TRAIT_FORMS: &str =
    "a trait must be {username}, {email} or {groups}, alone or after a literal prefix";
