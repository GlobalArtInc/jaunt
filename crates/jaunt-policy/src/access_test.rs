use std::fmt;

use serde::Deserialize;

use crate::model::{Identity, NodeInfo};
use crate::policy::PolicySet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum Expect {
    Allow,
    Deny,
}

impl fmt::Display for Expect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Expect::Allow => "allow",
            Expect::Deny => "deny",
        })
    }
}

impl Expect {
    fn from_allowed(allowed: bool) -> Self {
        if allowed { Expect::Allow } else { Expect::Deny }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessTest {
    pub source: String,
    pub user: String,
    pub groups: Vec<String>,
    pub username: String,
    pub node: NodeInfo,
    pub login: String,
    pub expect: Expect,
}

impl AccessTest {
    pub fn identity(&self) -> Identity {
        Identity {
            email: self.user.clone(),
            username: self.username.clone(),
            groups: self.groups.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessTestResult {
    pub index: usize,
    pub passed: bool,
    pub description: String,
}

pub fn run_access_tests(set: &PolicySet) -> Vec<AccessTestResult> {
    set.tests()
        .iter()
        .enumerate()
        .map(|(index, case)| {
            let decision = set.authorize_ssh(&case.identity(), &case.node, &case.login);
            let actual = Expect::from_allowed(decision.allowed);
            let passed = actual == case.expect;
            let outcome = if passed { "passed" } else { "FAILED" };
            let description = format!(
                "{outcome}: {} user={:?} login={:?} node={:?} labels={:?} expected {} got {}",
                case.source,
                case.user,
                case.login,
                case.node.name,
                case.node.labels,
                case.expect,
                actual
            );
            AccessTestResult {
                index,
                passed,
                description,
            }
        })
        .collect()
}
