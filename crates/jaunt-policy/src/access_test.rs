use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;

use crate::model::{Identity, NodeInfo, ResourceInfo};
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
pub enum AccessTarget {
    Ssh {
        node: NodeInfo,
        login: String,
    },
    Kubernetes {
        cluster: ResourceInfo,
        user: Option<String>,
        groups: Option<BTreeSet<String>>,
    },
    Database {
        server: ResourceInfo,
        user: String,
        name: String,
    },
    Tcp {
        service: ResourceInfo,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessTest {
    pub source: String,
    pub user: String,
    pub groups: Vec<String>,
    pub username: String,
    pub target: AccessTarget,
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

struct Evaluation {
    actual: Expect,
    target: String,
    mismatch: Option<String>,
}

fn evaluate(set: &PolicySet, case: &AccessTest) -> Evaluation {
    let identity = case.identity();
    match &case.target {
        AccessTarget::Ssh { node, login } => Evaluation {
            actual: Expect::from_allowed(set.authorize_ssh(&identity, node, login).allowed),
            target: format!(
                "login={login:?} node={:?} labels={:?}",
                node.name, node.labels
            ),
            mismatch: None,
        },
        AccessTarget::Kubernetes {
            cluster,
            user,
            groups,
        } => {
            let decision = set.authorize_kube(&identity, cluster);
            let allowed = decision.allowed
                && user
                    .as_ref()
                    .is_none_or(|user| decision.users.contains(user));
            let actual_groups: BTreeSet<String> = decision.groups.into_iter().collect();
            let mismatch = groups
                .as_ref()
                .filter(|expected| **expected != actual_groups)
                .map(|expected| format!("groups expected {expected:?} got {actual_groups:?}"));
            Evaluation {
                actual: Expect::from_allowed(allowed),
                target: format!(
                    "kubernetes user={user:?} cluster={:?} labels={:?}",
                    cluster.name, cluster.labels
                ),
                mismatch,
            }
        }
        AccessTarget::Database { server, user, name } => Evaluation {
            actual: Expect::from_allowed(set.authorize_db(&identity, server, user, name).allowed),
            target: format!(
                "database user={user:?} name={name:?} server={:?} labels={:?}",
                server.name, server.labels
            ),
            mismatch: None,
        },
        AccessTarget::Tcp { service } => Evaluation {
            actual: Expect::from_allowed(set.authorize_tcp(&identity, service).allowed),
            target: format!("tcp service={:?} labels={:?}", service.name, service.labels),
            mismatch: None,
        },
    }
}

pub fn run_access_tests(set: &PolicySet) -> Vec<AccessTestResult> {
    set.tests()
        .iter()
        .enumerate()
        .map(|(index, case)| {
            let evaluation = evaluate(set, case);
            let passed = evaluation.actual == case.expect && evaluation.mismatch.is_none();
            let outcome = if passed { "passed" } else { "FAILED" };
            let mut description = format!(
                "{outcome}: {} user={:?} {} expected {} got {}",
                case.source, case.user, evaluation.target, case.expect, evaluation.actual
            );
            if let Some(mismatch) = evaluation.mismatch {
                description.push_str("; ");
                description.push_str(&mismatch);
            }
            AccessTestResult {
                index,
                passed,
                description,
            }
        })
        .collect()
}
