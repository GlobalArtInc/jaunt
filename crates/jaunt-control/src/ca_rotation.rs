use std::fmt;

use jaunt_ca::{CaKind, TrustSet, fingerprint_hex};
use jaunt_store::{NodeHostCertificate, NodeTrustServed, Store, StoreError, UnexpiredGroup};

pub const TRUST_FRESHNESS_SECS: i64 = 20 * 60;
pub const MAX_LISTED_NODES: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationKind {
    User,
    Host,
}

impl RotationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            RotationKind::User => "user",
            RotationKind::Host => "host",
        }
    }

    pub const fn ca_kind(self) -> CaKind {
        match self {
            RotationKind::User => CaKind::User,
            RotationKind::Host => CaKind::Host,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationStep {
    Promote,
    Retire,
}

impl RotationStep {
    pub const fn as_str(self) -> &'static str {
        match self {
            RotationStep::Promote => "promote",
            RotationStep::Retire => "retire",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotKeys {
    pub active: String,
    pub next: Option<String>,
    pub previous: Vec<String>,
    pub trust_id: String,
}

impl SlotKeys {
    pub fn of(trust: &TrustSet) -> SlotKeys {
        SlotKeys {
            active: fingerprint_hex(trust.active()),
            next: trust.next().map(fingerprint_hex),
            previous: trust.previous().map(fingerprint_hex).collect(),
            trust_id: trust.set_id(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counters {
    pub keys: SlotKeys,
    pub nodes: Vec<NodeTrustServed>,
    pub signers: Vec<UnexpiredGroup>,
    pub host_trusts: Vec<UnexpiredGroup>,
    pub node_host: Vec<NodeHostCertificate>,
}

impl Counters {
    pub fn new(keys: SlotKeys) -> Counters {
        Counters {
            keys,
            nodes: Vec::new(),
            signers: Vec::new(),
            host_trusts: Vec::new(),
            node_host: Vec::new(),
        }
    }
}

pub async fn gather(
    store: &Store,
    kind: RotationKind,
    trust: &TrustSet,
    now: i64,
) -> Result<Counters, StoreError> {
    let source = store.ca_counters();
    let mut counters = Counters::new(SlotKeys::of(trust));
    match kind {
        RotationKind::User => {
            counters.nodes = source.node_trust().await?;
            counters.signers = source.certificates_by_signer(now).await?;
        }
        RotationKind::Host => {
            counters.host_trusts = source.certificates_by_host_trust(now).await?;
            counters.node_host = source.latest_node_host_certificates().await?;
        }
    }
    Ok(counters)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Unexpired {
    pub count: i64,
    pub nearest_valid_before: Option<i64>,
    pub farthest_valid_before: Option<i64>,
}

impl Unexpired {
    fn add(&mut self, group: &UnexpiredGroup) {
        self.count = self.count.saturating_add(group.count);
        self.nearest_valid_before = Some(
            self.nearest_valid_before
                .map_or(group.nearest_valid_before, |nearest| {
                    nearest.min(group.nearest_valid_before)
                }),
        );
        self.farthest_valid_before = Some(
            self.farthest_valid_before
                .map_or(group.farthest_valid_before, |farthest| {
                    farthest.max(group.farthest_valid_before)
                }),
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Summary {
    pub nodes_current: usize,
    pub nodes_behind: Vec<String>,
    pub nodes_offline: Vec<String>,
    pub old_certificates: Unexpired,
    pub old_host_trust: Unexpired,
    pub nodes_on_old_host_key: Vec<String>,
}

pub fn summarize(kind: RotationKind, counters: &Counters, now: i64) -> Summary {
    let keys = &counters.keys;
    let old_signer = |id: &Option<String>| match id {
        None => true,
        Some(fingerprint) => keys.previous.contains(fingerprint),
    };
    let mut summary = Summary::default();
    match kind {
        RotationKind::User => {
            for node in &counters.nodes {
                let fresh = node
                    .served_at
                    .is_some_and(|at| now.saturating_sub(at) <= TRUST_FRESHNESS_SECS);
                if !fresh {
                    summary.nodes_offline.push(node.name.clone());
                } else if node.trust_id.as_deref() == Some(keys.trust_id.as_str()) {
                    summary.nodes_current += 1;
                } else {
                    summary.nodes_behind.push(node.name.clone());
                }
            }
            for group in &counters.signers {
                if group.farthest_valid_before > now && old_signer(&group.id) {
                    summary.old_certificates.add(group);
                }
            }
        }
        RotationKind::Host => {
            for group in &counters.host_trusts {
                let current = group.id.as_deref() == Some(keys.trust_id.as_str());
                if group.farthest_valid_before > now && !current {
                    summary.old_host_trust.add(group);
                }
            }
            for certificate in &counters.node_host {
                let blocking =
                    certificate.not_after > now && old_signer(&certificate.ca_fingerprint);
                if blocking && !summary.nodes_on_old_host_key.contains(&certificate.name) {
                    summary.nodes_on_old_host_key.push(certificate.name.clone());
                }
            }
        }
    }
    summary
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReason {
    NodesBehind(Vec<String>),
    OldCertificates(Unexpired),
    OldHostTrust(Unexpired),
    NodesOnOldHostKey(Vec<String>),
}

impl fmt::Display for BlockReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockReason::NodesBehind(names) => {
                write!(f, "{} behind ({})", nodes(names.len()), listed(names))
            }
            BlockReason::OldCertificates(unexpired) => write!(
                f,
                "{} signed by a previous key or before rotation tracking",
                certificates(unexpired.count)
            ),
            BlockReason::OldHostTrust(unexpired) => write!(
                f,
                "{} issued before the current host keys were published",
                certificates(unexpired.count)
            ),
            BlockReason::NodesOnOldHostKey(names) => write!(
                f,
                "{} on a previous host key ({})",
                nodes(names.len()),
                listed(names)
            ),
        }
    }
}

fn nodes(count: usize) -> String {
    if count == 1 {
        "1 node".to_owned()
    } else {
        format!("{count} nodes")
    }
}

fn certificates(count: i64) -> String {
    if count == 1 {
        "1 unexpired user certificate".to_owned()
    } else {
        format!("{count} unexpired user certificates")
    }
}

fn listed(names: &[String]) -> String {
    let mut shown: Vec<String> = names
        .iter()
        .take(MAX_LISTED_NODES)
        .map(|name| printable(name))
        .collect();
    if names.len() > MAX_LISTED_NODES {
        shown.push("…".to_owned());
    }
    shown.join(", ")
}

fn printable(text: &str) -> String {
    text.chars()
        .map(|ch| {
            if (' '..='~').contains(&ch) {
                ch.to_string()
            } else {
                ch.escape_default().to_string()
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allowed,
    Blocked(Vec<BlockReason>),
}

impl Verdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Verdict::Allowed)
    }

    pub fn line(&self, step: RotationStep) -> String {
        match self {
            Verdict::Allowed => format!("{}: ready", step.as_str()),
            Verdict::Blocked(reasons) => {
                let reasons: Vec<String> = reasons.iter().map(ToString::to_string).collect();
                format!("{}: blocked: {}", step.as_str(), reasons.join("; "))
            }
        }
    }
}

pub fn verdict(kind: RotationKind, step: RotationStep, counters: &Counters, now: i64) -> Verdict {
    let summary = summarize(kind, counters, now);
    let reason = match (kind, step) {
        (RotationKind::User, RotationStep::Promote) => (!summary.nodes_behind.is_empty())
            .then(|| BlockReason::NodesBehind(summary.nodes_behind.clone())),
        (RotationKind::User, RotationStep::Retire) => (summary.old_certificates.count > 0)
            .then_some(BlockReason::OldCertificates(summary.old_certificates)),
        (RotationKind::Host, RotationStep::Promote) => (summary.old_host_trust.count > 0)
            .then_some(BlockReason::OldHostTrust(summary.old_host_trust)),
        (RotationKind::Host, RotationStep::Retire) => (!summary.nodes_on_old_host_key.is_empty())
            .then(|| BlockReason::NodesOnOldHostKey(summary.nodes_on_old_host_key.clone())),
    };
    match reason {
        Some(reason) => Verdict::Blocked(vec![reason]),
        None => Verdict::Allowed,
    }
}

#[cfg(test)]
mod tests {
    use jaunt_store::{NodeHostCertificate, NodeTrustServed, UnexpiredGroup};

    use super::{
        BlockReason, Counters, MAX_LISTED_NODES, RotationKind, RotationStep, SlotKeys,
        TRUST_FRESHNESS_SECS, Unexpired, Verdict, summarize, verdict,
    };

    const NOW: i64 = 1_700_000_000;
    const ACTIVE: &str = "aa";
    const NEXT: &str = "bb";
    const PREVIOUS: &str = "cc";
    const RETIRED: &str = "dd";
    const CURRENT: &str = "trust-now";

    fn counters() -> Counters {
        Counters::new(SlotKeys {
            active: ACTIVE.to_owned(),
            next: Some(NEXT.to_owned()),
            previous: vec![PREVIOUS.to_owned()],
            trust_id: CURRENT.to_owned(),
        })
    }

    fn node(trust_id: Option<&str>, served_at: Option<i64>) -> NodeTrustServed {
        NodeTrustServed {
            node_id: "n1".to_owned(),
            name: "web-01".to_owned(),
            trust_id: trust_id.map(str::to_owned),
            served_at,
        }
    }

    fn group(id: Option<&str>, farthest: i64) -> UnexpiredGroup {
        UnexpiredGroup {
            id: id.map(str::to_owned),
            count: 2,
            nearest_valid_before: farthest - 10,
            farthest_valid_before: farthest,
        }
    }

    fn single(id: Option<&str>, valid_before: i64) -> UnexpiredGroup {
        UnexpiredGroup {
            id: id.map(str::to_owned),
            count: 1,
            nearest_valid_before: valid_before,
            farthest_valid_before: valid_before,
        }
    }

    fn host_certificate(signer: Option<&str>, not_after: i64) -> NodeHostCertificate {
        NodeHostCertificate {
            node_id: "n2".to_owned(),
            name: "db-01".to_owned(),
            ca_fingerprint: signer.map(str::to_owned),
            not_after,
        }
    }

    fn with_node(node: NodeTrustServed) -> Counters {
        let mut counters = counters();
        counters.nodes = vec![node];
        counters
    }

    fn with_signer(group: UnexpiredGroup) -> Counters {
        let mut counters = counters();
        counters.signers = vec![group];
        counters
    }

    fn with_host_trust(group: UnexpiredGroup) -> Counters {
        let mut counters = counters();
        counters.host_trusts = vec![group];
        counters
    }

    fn with_node_host(certificate: NodeHostCertificate) -> Counters {
        let mut counters = counters();
        counters.node_host = vec![certificate];
        counters
    }

    #[test]
    fn every_rule_of_the_verdict_table_decides_its_own_row() {
        use RotationKind::{Host, User};
        use RotationStep::{Promote, Retire};

        let behind = || Verdict::Blocked(vec![BlockReason::NodesBehind(vec!["web-01".to_owned()])]);
        let old = |farthest| Unexpired {
            count: 2,
            nearest_valid_before: Some(farthest - 10),
            farthest_valid_before: Some(farthest),
        };
        let old_signer =
            |farthest| Verdict::Blocked(vec![BlockReason::OldCertificates(old(farthest))]);
        let old_trust = |farthest| Verdict::Blocked(vec![BlockReason::OldHostTrust(old(farthest))]);
        let one = |valid_before| Unexpired {
            count: 1,
            nearest_valid_before: Some(valid_before),
            farthest_valid_before: Some(valid_before),
        };
        let old_host = || {
            Verdict::Blocked(vec![BlockReason::NodesOnOldHostKey(vec![
                "db-01".to_owned(),
            ])])
        };
        let fresh = NOW - 60;
        let rows: Vec<(&str, RotationKind, RotationStep, Counters, Verdict)> = vec![
            ("no nodes", User, Promote, counters(), Verdict::Allowed),
            (
                "node has the current set",
                User,
                Promote,
                with_node(node(Some(CURRENT), Some(fresh))),
                Verdict::Allowed,
            ),
            (
                "node has an older set",
                User,
                Promote,
                with_node(node(Some("old"), Some(fresh))),
                behind(),
            ),
            (
                "node served without an id",
                User,
                Promote,
                with_node(node(None, Some(fresh))),
                behind(),
            ),
            (
                "served exactly at the freshness edge",
                User,
                Promote,
                with_node(node(Some("old"), Some(NOW - TRUST_FRESHNESS_SECS))),
                behind(),
            ),
            (
                "served just past the freshness edge",
                User,
                Promote,
                with_node(node(Some("old"), Some(NOW - TRUST_FRESHNESS_SECS - 1))),
                Verdict::Allowed,
            ),
            (
                "never served counts as offline",
                User,
                Promote,
                with_node(node(None, None)),
                Verdict::Allowed,
            ),
            (
                "served ahead of the clock",
                User,
                Promote,
                with_node(node(Some("old"), Some(NOW + 30))),
                behind(),
            ),
            (
                "no certificates",
                User,
                Retire,
                counters(),
                Verdict::Allowed,
            ),
            (
                "unattributed certificates are old",
                User,
                Retire,
                with_signer(group(None, NOW + 60)),
                old_signer(NOW + 60),
            ),
            (
                "certificates on the previous key",
                User,
                Retire,
                with_signer(group(Some(PREVIOUS), NOW + 60)),
                old_signer(NOW + 60),
            ),
            (
                "certificates on the active key",
                User,
                Retire,
                with_signer(group(Some(ACTIVE), NOW + 60)),
                Verdict::Allowed,
            ),
            (
                "certificates on an already retired key",
                User,
                Retire,
                with_signer(group(Some(RETIRED), NOW + 60)),
                Verdict::Allowed,
            ),
            (
                "previous key, valid_before equals now",
                User,
                Retire,
                with_signer(group(Some(PREVIOUS), NOW)),
                Verdict::Allowed,
            ),
            (
                "previous key, valid_before one second ahead",
                User,
                Retire,
                with_signer(group(Some(PREVIOUS), NOW + 1)),
                old_signer(NOW + 1),
            ),
            (
                "a single certificate on the previous key",
                User,
                Retire,
                with_signer(single(Some(PREVIOUS), NOW + 1)),
                Verdict::Blocked(vec![BlockReason::OldCertificates(one(NOW + 1))]),
            ),
            (
                "user certificates with the current host set",
                Host,
                Promote,
                with_host_trust(group(Some(CURRENT), NOW + 60)),
                Verdict::Allowed,
            ),
            (
                "user certificates with an older host set",
                Host,
                Promote,
                with_host_trust(group(Some("old"), NOW + 60)),
                old_trust(NOW + 60),
            ),
            (
                "user certificates without a host set",
                Host,
                Promote,
                with_host_trust(group(None, NOW + 60)),
                old_trust(NOW + 60),
            ),
            (
                "older host set, valid_before equals now",
                Host,
                Promote,
                with_host_trust(group(Some("old"), NOW)),
                Verdict::Allowed,
            ),
            (
                "older host set, valid_before one second ahead",
                Host,
                Promote,
                with_host_trust(group(Some("old"), NOW + 1)),
                old_trust(NOW + 1),
            ),
            (
                "a single certificate with an older host set",
                Host,
                Promote,
                with_host_trust(single(None, NOW + 1)),
                Verdict::Blocked(vec![BlockReason::OldHostTrust(one(NOW + 1))]),
            ),
            (
                "node host certificate on the previous key",
                Host,
                Retire,
                with_node_host(host_certificate(Some(PREVIOUS), NOW + 60)),
                old_host(),
            ),
            (
                "node host certificate without a signer",
                Host,
                Retire,
                with_node_host(host_certificate(None, NOW + 60)),
                old_host(),
            ),
            (
                "node host certificate on the active key",
                Host,
                Retire,
                with_node_host(host_certificate(Some(ACTIVE), NOW + 60)),
                Verdict::Allowed,
            ),
            (
                "node host certificate on a retired key",
                Host,
                Retire,
                with_node_host(host_certificate(Some(RETIRED), NOW + 60)),
                Verdict::Allowed,
            ),
            (
                "node host certificate expiring now",
                Host,
                Retire,
                with_node_host(host_certificate(Some(PREVIOUS), NOW)),
                Verdict::Allowed,
            ),
            (
                "node host certificate one second ahead",
                Host,
                Retire,
                with_node_host(host_certificate(Some(PREVIOUS), NOW + 1)),
                old_host(),
            ),
            (
                "user data does not gate the host slot",
                Host,
                Promote,
                with_node(node(Some("old"), Some(fresh))),
                Verdict::Allowed,
            ),
            (
                "host data does not gate the user slot",
                User,
                Retire,
                with_node_host(host_certificate(None, NOW + 60)),
                Verdict::Allowed,
            ),
        ];
        for (name, kind, step, counters, expected) in rows {
            assert_eq!(verdict(kind, step, &counters, NOW), expected, "{name}");
        }
    }

    #[test]
    fn the_summary_counts_nodes_and_merges_old_certificate_groups() {
        let mut counters = counters();
        counters.nodes = vec![
            node(Some(CURRENT), Some(NOW)),
            node(Some("old"), Some(NOW)),
            node(None, None),
        ];
        counters.signers = vec![
            group(None, NOW + 100),
            group(Some(PREVIOUS), NOW + 40),
            group(Some(ACTIVE), NOW + 500),
        ];

        let summary = summarize(RotationKind::User, &counters, NOW);

        assert_eq!(summary.nodes_current, 1);
        assert_eq!(summary.nodes_behind, ["web-01"]);
        assert_eq!(summary.nodes_offline, ["web-01"]);
        assert_eq!(
            summary.old_certificates,
            Unexpired {
                count: 4,
                nearest_valid_before: Some(NOW + 30),
                farthest_valid_before: Some(NOW + 100),
            }
        );
    }

    #[test]
    fn verdict_lines_match_between_status_and_refusals() {
        assert_eq!(
            Verdict::Allowed.line(RotationStep::Promote),
            "promote: ready"
        );
        let names: Vec<String> = (1..=MAX_LISTED_NODES + 5)
            .map(|index| format!("n{index:02}"))
            .collect();
        let line =
            Verdict::Blocked(vec![BlockReason::NodesBehind(names)]).line(RotationStep::Promote);
        assert!(
            line.starts_with("promote: blocked: 25 nodes behind (n01, n02, "),
            "{line}"
        );
        assert!(line.ends_with("n20, …)"), "{line}");
        assert!(!line.contains("n21"));
        let one = Verdict::Blocked(vec![BlockReason::OldCertificates(Unexpired {
            count: 1,
            nearest_valid_before: Some(NOW),
            farthest_valid_before: Some(NOW),
        })]);
        assert_eq!(
            one.line(RotationStep::Retire),
            "retire: blocked: 1 unexpired user certificate signed by a previous key or before \
             rotation tracking"
        );
        let escaped = BlockReason::NodesOnOldHostKey(vec!["web\n01\u{1b}".to_owned()]).to_string();
        assert_eq!(escaped, "1 node on a previous host key (web\\n01\\u{1b})");
    }
}
