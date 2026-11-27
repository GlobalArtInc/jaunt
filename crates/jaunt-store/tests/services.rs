use jaunt_store::{
    AnnounceOutcome, Announced, AnnouncedService, Announcement, Labels, MAX_SERVICE_HISTORY,
    Service, ServiceApproval, ServiceApproveOutcome, ServiceChange, ServiceDecisionOutcome,
    ServiceKind, ServiceQuery, ServiceState, Store,
};
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use tempfile::TempDir;

const RAW_NODE: &str = "INSERT INTO nodes (id, name, labels, hostname, tls_public_key, \
    ssh_host_public_key, tls_spki_sha256, ssh_host_key_fingerprint, state, approved_by, \
    created_at) VALUES (?, ?, '{}', 'h', 't', 's', 'f', 'f', ?, 'cli:root', 1)";

struct Fixture {
    store: Store,
    pool: SqlitePool,
    _dir: TempDir,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("jaunt.db");
    let store = Store::open(&path).await.unwrap();
    store.migrate().await.unwrap();
    let pool = SqlitePool::connect_with(SqliteConnectOptions::new().filename(&path))
        .await
        .unwrap();
    for (id, state) in [("n1", "active"), ("n2", "active"), ("gone", "removed")] {
        sqlx::query(RAW_NODE)
            .bind(id)
            .bind(format!("node-{id}"))
            .bind(state)
            .execute(&pool)
            .await
            .unwrap();
    }
    Fixture {
        store,
        pool,
        _dir: dir,
    }
}

fn labels(pairs: &[(&str, &str)]) -> Labels {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn item(name: &str, env: &str, settings: &str) -> AnnouncedService {
    AnnouncedService {
        kind: ServiceKind::Tcp,
        name: name.to_owned(),
        labels: labels(&[("env", env)]),
        settings: settings.to_owned(),
        address_hint: Some("10.0.0.5:3000".to_owned()),
    }
}

impl Fixture {
    async fn announce_as(&self, node_id: &str, items: &[AnnouncedService], now: i64) -> Announced {
        self.announce_with(node_id, true, items, now).await
    }

    async fn announce_with(
        &self,
        node_id: &str,
        ssh_enabled: bool,
        items: &[AnnouncedService],
        now: i64,
    ) -> Announced {
        match self
            .store
            .services()
            .announce(&Announcement {
                node_id,
                ssh_enabled,
                services: items,
                now,
            })
            .await
            .unwrap()
        {
            AnnounceOutcome::Applied(announced) => announced,
            AnnounceOutcome::NodeNotActive => panic!("the node is not active"),
            AnnounceOutcome::TooMany => panic!("the announcement was refused as too many"),
        }
    }

    async fn approve(&self, id: &str, labels_override: Option<&Labels>) -> ServiceApproveOutcome {
        self.store
            .services()
            .approve(&ServiceApproval {
                id,
                approver: "web:admin",
                labels_override,
                now: 50,
            })
            .await
            .unwrap()
    }

    async fn all(&self) -> Vec<Service> {
        let mut services = Vec::new();
        for state in [
            ServiceState::Pending,
            ServiceState::Approved,
            ServiceState::Removed,
        ] {
            let page = self
                .store
                .services()
                .page(&ServiceQuery {
                    state: Some(state),
                    node_id: None,
                    after: None,
                    limit: 200,
                })
                .await
                .unwrap();
            services.extend(page.services);
        }
        services.sort_by_key(|service| (service.node_id.clone(), service.revision));
        services
    }
}

fn requested(announced: &Announced) -> Vec<&Service> {
    announced
        .changes
        .iter()
        .filter_map(|change| match change {
            ServiceChange::Requested(service) => Some(service),
            _ => None,
        })
        .collect()
}

#[tokio::test]
async fn a_new_service_is_pending_and_the_same_set_again_changes_nothing() {
    let f = fixture().await;
    let first = f
        .announce_as("n1", &[item("grafana", "prod", "{}")], 10)
        .await;
    let created = requested(&first);
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].state, ServiceState::Pending);
    assert_eq!(created[0].revision, 1);
    assert!(created[0].announced && created[0].approved_by.is_none());
    assert_eq!(first.ssh_changed, None);

    let again = f
        .announce_as("n1", &[item("grafana", "prod", "{}")], 20)
        .await;
    assert_eq!(again, Announced::default());
    let stored = f.all().await;
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].id, created[0].id);
    assert_eq!(stored[0].last_seen_at, 20);
    assert!(f.store.services().offered().await.unwrap().is_empty());
}

#[tokio::test]
async fn changed_labels_open_a_new_revision_while_the_approved_one_stays_in_effect() {
    let f = fixture().await;
    let first = f
        .announce_as("n1", &[item("grafana", "prod", "{}")], 10)
        .await;
    let pending_id = requested(&first)[0].id.clone();
    let ServiceApproveOutcome::Approved(approved) = f.approve(&pending_id, None).await else {
        panic!("approval refused");
    };
    assert_eq!(approved.service.state, ServiceState::Approved);
    assert_eq!(approved.service.approved_by.as_deref(), Some("web:admin"));

    let changed = f
        .announce_as("n1", &[item("grafana", "dev", "{}")], 20)
        .await;
    let revision = requested(&changed);
    assert_eq!(revision.len(), 1);
    assert_eq!(revision[0].revision, 2);
    assert_eq!(revision[0].labels, labels(&[("env", "dev")]));
    let offered = f.store.services().offered().await.unwrap();
    assert_eq!(offered.len(), 1);
    assert_eq!(offered[0].id, pending_id);
    assert_eq!(offered[0].labels, labels(&[("env", "prod")]));

    let back = f
        .announce_as("n1", &[item("grafana", "prod", "{}")], 30)
        .await;
    assert!(matches!(back.changes.as_slice(),
        [ServiceChange::Superseded(old)] if old.id == revision[0].id));
    assert_eq!(f.store.services().get(&revision[0].id).await.unwrap(), None);
    assert_eq!(
        f.store.services().offered().await.unwrap()[0].id,
        pending_id
    );
}

#[tokio::test]
async fn settings_and_address_are_recorded_without_a_new_approval() {
    let f = fixture().await;
    let first = f
        .announce_as("n1", &[item("grafana", "prod", "{\"a\":1}")], 10)
        .await;
    let id = requested(&first)[0].id.clone();
    f.approve(&id, None).await;
    let mut moved = item("grafana", "prod", "{\"a\":2}");
    moved.address_hint = Some("10.0.0.6:3000".to_owned());

    let announced = f.announce_as("n1", &[moved], 20).await;

    assert_eq!(announced, Announced::default());
    let offered = f.store.services().offered().await.unwrap();
    assert_eq!(offered.len(), 1);
    assert_eq!(offered[0].id, id);
    assert_eq!(offered[0].settings, "{\"a\":2}");
    assert_eq!(offered[0].address_hint.as_deref(), Some("10.0.0.6:3000"));
    assert_eq!(offered[0].state, ServiceState::Approved);
}

#[tokio::test]
async fn a_service_left_out_is_withdrawn_and_comes_back_without_approval() {
    let f = fixture().await;
    let first = f
        .announce_as("n1", &[item("grafana", "prod", "{}")], 10)
        .await;
    let id = requested(&first)[0].id.clone();
    f.approve(&id, None).await;

    let gone = f.announce_as("n1", &[], 20).await;
    assert!(matches!(gone.changes.as_slice(),
        [ServiceChange::Withdrawn(service)] if service.id == id && !service.announced
            && service.state == ServiceState::Approved));
    assert!(f.store.services().offered().await.unwrap().is_empty());
    assert_eq!(f.announce_as("n1", &[], 25).await, Announced::default());

    let back = f
        .announce_as("n1", &[item("grafana", "prod", "{}")], 30)
        .await;
    assert!(matches!(back.changes.as_slice(),
        [ServiceChange::Reannounced(service)] if service.id == id && service.announced));
    assert_eq!(f.store.services().offered().await.unwrap().len(), 1);
}

#[tokio::test]
async fn an_override_is_kept_and_the_agent_proposal_does_not_reopen_it() {
    let f = fixture().await;
    let first = f
        .announce_as("n1", &[item("grafana", "prod", "{}")], 10)
        .await;
    let id = requested(&first)[0].id.clone();
    let chosen = labels(&[("env", "staging")]);
    let ServiceApproveOutcome::Approved(approved) = f.approve(&id, Some(&chosen)).await else {
        panic!("approval refused");
    };
    assert_eq!(approved.service.labels, chosen);
    assert_eq!(
        approved.service.announced_labels,
        labels(&[("env", "prod")])
    );

    let again = f
        .announce_as("n1", &[item("grafana", "prod", "{}")], 20)
        .await;

    assert_eq!(again, Announced::default());
    assert_eq!(
        f.store.services().offered().await.unwrap()[0].labels,
        chosen
    );
}

#[tokio::test]
async fn an_approved_pair_belongs_to_one_active_node() {
    let f = fixture().await;
    let one = f
        .announce_as("n1", &[item("grafana", "prod", "{}")], 10)
        .await;
    let two = f
        .announce_as("n2", &[item("grafana", "prod", "{}")], 10)
        .await;
    let first = requested(&one)[0].id.clone();
    let second = requested(&two)[0].id.clone();
    assert!(matches!(
        f.approve(&first, None).await,
        ServiceApproveOutcome::Approved(_)
    ));

    assert_eq!(
        f.approve(&second, None).await,
        ServiceApproveOutcome::NameTaken {
            node_id: "n1".to_owned(),
            node_name: "node-n1".to_owned(),
        }
    );
    assert_eq!(
        f.store
            .services()
            .get(&second)
            .await
            .unwrap()
            .unwrap()
            .state,
        ServiceState::Pending
    );
    let mut other_kind = item("grafana", "prod", "{}");
    other_kind.kind = ServiceKind::Kubernetes;
    let kube = f
        .announce_as("n2", &[item("grafana", "prod", "{}"), other_kind], 20)
        .await;
    assert!(matches!(
        f.approve(&requested(&kube)[0].id, None).await,
        ServiceApproveOutcome::Approved(_)
    ));

    sqlx::query("UPDATE nodes SET state = 'removed' WHERE id = 'n1'")
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(matches!(
        f.approve(&second, None).await,
        ServiceApproveOutcome::Approved(_)
    ));
    assert_eq!(
        f.approve(&first, None).await,
        ServiceApproveOutcome::NotPending(ServiceState::Approved)
    );
}

#[tokio::test]
async fn reject_takes_only_pending_and_remove_only_approved() {
    let f = fixture().await;
    let announced = f
        .announce_as(
            "n1",
            &[item("a", "prod", "{}"), item("b", "prod", "{}")],
            10,
        )
        .await;
    let ids: Vec<String> = requested(&announced)
        .iter()
        .map(|service| service.id.clone())
        .collect();
    let services = f.store.services();
    f.approve(&ids[1], None).await;

    assert_eq!(
        services.remove(&ids[0]).await.unwrap(),
        ServiceDecisionOutcome::WrongState(ServiceState::Pending)
    );
    assert!(matches!(services.reject(&ids[0]).await.unwrap(),
        ServiceDecisionOutcome::Done(service) if service.state == ServiceState::Removed));
    assert_eq!(
        services.reject(&ids[1]).await.unwrap(),
        ServiceDecisionOutcome::WrongState(ServiceState::Approved)
    );
    assert!(matches!(services.remove(&ids[1]).await.unwrap(),
        ServiceDecisionOutcome::Done(service) if service.state == ServiceState::Removed));
    assert_eq!(
        services.remove("missing").await.unwrap(),
        ServiceDecisionOutcome::NotFound
    );
    assert!(services.offered().await.unwrap().is_empty());
    assert_eq!(
        f.approve(&ids[0], None).await,
        ServiceApproveOutcome::NotPending(ServiceState::Removed)
    );

    let again = f
        .announce_as(
            "n1",
            &[item("a", "prod", "{}"), item("b", "prod", "{}")],
            20,
        )
        .await;
    let revisions: Vec<i64> = requested(&again)
        .iter()
        .map(|service| service.revision)
        .collect();
    assert_eq!(revisions, [2, 2]);
}

#[tokio::test]
async fn a_removed_node_cannot_announce_and_the_ssh_flag_is_stored() {
    let f = fixture().await;
    let refused = f
        .store
        .services()
        .announce(&Announcement {
            node_id: "gone",
            ssh_enabled: true,
            services: &[item("a", "prod", "{}")],
            now: 10,
        })
        .await
        .unwrap();
    assert_eq!(refused, AnnounceOutcome::NodeNotActive);
    assert!(f.all().await.is_empty());

    assert!(
        f.store
            .nodes()
            .get("n1")
            .await
            .unwrap()
            .unwrap()
            .ssh_enabled
    );
    let off = f.announce_with("n1", false, &[], 10).await;
    assert_eq!(off.ssh_changed, Some(false));
    assert!(
        !f.store
            .nodes()
            .get("n1")
            .await
            .unwrap()
            .unwrap()
            .ssh_enabled
    );
    assert_eq!(
        f.announce_with("n1", false, &[], 11).await.ssh_changed,
        None
    );
    assert_eq!(
        f.announce_with("n1", true, &[], 12).await.ssh_changed,
        Some(true)
    );
}

#[tokio::test]
async fn rows_grow_only_by_an_admin_decision_while_the_content_stays_the_same() {
    let f = fixture().await;
    let same = [item("grafana", "prod", "{}")];
    let first = f.announce_as("n1", &same, 10).await;
    for now in 11..16 {
        assert_eq!(f.announce_as("n1", &same, now).await, Announced::default());
    }
    assert_eq!(f.all().await.len(), 1);

    let mut rejected = requested(&first)[0].id.clone();
    for (round, now) in (20..23).enumerate() {
        f.store.services().reject(&rejected).await.unwrap();
        let again = f.announce_as("n1", &same, now).await;
        rejected = requested(&again)[0].id.clone();
        for repeat in 1..4 {
            assert_eq!(
                f.announce_as("n1", &same, now + repeat * 100).await,
                Announced::default()
            );
        }
        assert_eq!(f.all().await.len(), round + 2);
    }
}

#[tokio::test]
async fn label_flips_keep_one_pending_row_and_never_touch_the_approved_one() {
    let f = fixture().await;
    let first = f
        .announce_as("n1", &[item("grafana", "prod", "{}")], 10)
        .await;
    let approved_id = requested(&first)[0].id.clone();
    f.approve(&approved_id, None).await;
    let mut superseded = Vec::new();
    let mut current = String::new();
    for flip in 0..200_i64 {
        let env = if flip % 2 == 0 { "dev" } else { "stage" };
        let announced = f
            .announce_as("n1", &[item("grafana", env, "{}")], 20 + flip)
            .await;
        let created = requested(&announced);
        assert_eq!(created.len(), 1, "{flip}");
        if !current.is_empty() {
            superseded.push(current.clone());
        }
        current = created[0].id.clone();
        let offered = f.store.services().offered().await.unwrap();
        assert_eq!(offered.len(), 1, "{flip}");
        assert_eq!(offered[0].id, approved_id, "{flip}");
        assert_eq!(offered[0].labels, labels(&[("env", "prod")]), "{flip}");
    }

    let rows = f.all().await;
    let count = |state: ServiceState| rows.iter().filter(|row| row.state == state).count();
    assert_eq!(count(ServiceState::Approved), 1);
    assert_eq!(count(ServiceState::Pending), 1);
    assert!(count(ServiceState::Removed) <= usize::try_from(MAX_SERVICE_HISTORY).unwrap());
    assert_eq!(rows.len(), 2);
    let approved = f.store.services().get(&approved_id).await.unwrap().unwrap();
    assert_eq!(approved.state, ServiceState::Approved);
    assert_eq!(approved.labels, labels(&[("env", "prod")]));

    assert_eq!(
        f.approve(&superseded[0], None).await,
        ServiceApproveOutcome::NotFound
    );
    assert_eq!(
        f.approve(superseded.last().unwrap(), None).await,
        ServiceApproveOutcome::NotFound
    );
    let ServiceApproveOutcome::Approved(approved) = f.approve(&current, None).await else {
        panic!("the current pending revision was not approved");
    };
    assert_eq!(approved.service.labels, labels(&[("env", "stage")]));
    assert_eq!(approved.replaced.map(|old| old.id), Some(approved_id));
}

#[tokio::test]
async fn at_most_eight_history_rows_are_kept_per_service_and_the_oldest_go_first() {
    let f = fixture().await;
    let same = [item("grafana", "prod", "{}")];
    let mut pending = requested(&f.announce_as("n1", &same, 10).await)[0]
        .id
        .clone();
    for round in 0..12_i64 {
        f.store.services().reject(&pending).await.unwrap();
        pending = requested(&f.announce_as("n1", &same, 20 + round).await)[0]
            .id
            .clone();
    }
    let ServiceApproveOutcome::Approved(_) = f.approve(&pending, None).await else {
        panic!("approval refused");
    };
    for round in 0..3_i64 {
        let changed = f
            .announce_as("n1", &[item("grafana", "dev", "{}")], 40 + round * 2)
            .await;
        let next = requested(&changed)[0].id.clone();
        f.approve(&next, None).await;
        f.announce_as("n1", &[item("grafana", "dev", "{}")], 41 + round * 2)
            .await;
        let back = f
            .announce_as("n1", &[item("grafana", "prod", "{}")], 41 + round * 2)
            .await;
        f.approve(&requested(&back)[0].id, None).await;
    }

    let rows = f.all().await;
    let history: Vec<i64> = rows
        .iter()
        .filter(|row| row.state == ServiceState::Removed)
        .map(|row| row.revision)
        .collect();
    let newest = rows.iter().map(|row| row.revision).max().unwrap();
    assert_eq!(history.len(), 8, "{history:?}");
    assert_eq!(history, ((newest - 8)..newest).collect::<Vec<_>>());
    assert_eq!(
        rows.iter()
            .filter(|row| row.state == ServiceState::Approved)
            .count(),
        1
    );
}

fn many(prefix: &str, count: usize) -> Vec<AnnouncedService> {
    (0..count)
        .map(|index| item(&format!("{prefix}{index}"), "prod", "{}"))
        .collect()
}

fn ids_in(rows: &[Service], state: ServiceState) -> Vec<String> {
    let mut ids: Vec<String> = rows
        .iter()
        .filter(|row| row.state == state)
        .map(|row| row.id.clone())
        .collect();
    ids.sort();
    ids
}

#[tokio::test]
async fn pending_rows_leave_with_the_set_so_new_names_cannot_pile_up() {
    let f = fixture().await;
    let mut previous: Vec<String> = Vec::new();
    for (round, prefix) in ["a", "b", "c"].into_iter().enumerate() {
        let announced = f
            .announce_as("n1", &many(prefix, 64), 10 + round as i64)
            .await;
        let withdrawn = announced
            .changes
            .iter()
            .filter(|change| matches!(change, ServiceChange::Withdrawn(_)))
            .count();
        assert_eq!(withdrawn, previous.len(), "{prefix}");
        for gone in &previous {
            assert_eq!(
                f.store.services().get(gone).await.unwrap(),
                None,
                "{prefix}"
            );
        }
        previous = requested(&announced)
            .iter()
            .map(|service| service.id.clone())
            .collect();
        assert_eq!(previous.len(), 64);
        assert_eq!(f.all().await.len(), 64, "{prefix}");
    }
    for now in 20..25 {
        assert_eq!(
            f.announce_as("n1", &many("c", 64), now).await,
            Announced::default()
        );
    }
    assert_eq!(f.all().await.len(), 64);
}

#[tokio::test]
async fn the_live_cap_refuses_a_whole_announcement_above_one_hundred_twenty_eight() {
    let f = fixture().await;
    let first = f.announce_as("n1", &many("a", 64), 10).await;
    for service in requested(&first) {
        assert!(matches!(
            f.approve(&service.id, None).await,
            ServiceApproveOutcome::Approved(_)
        ));
    }
    let second = f.announce_as("n1", &many("b", 64), 11).await;
    assert_eq!(f.all().await.len(), 128);
    f.approve(&requested(&second)[0].id, None).await;

    let at_cap = f.announce_as("n1", &many("c", 63), 12).await;
    assert_eq!(requested(&at_cap).len(), 63);
    let before = f.all().await;
    assert_eq!(ids_in(&before, ServiceState::Approved).len(), 65);
    assert_eq!(ids_in(&before, ServiceState::Pending).len(), 63);

    let refused = f
        .store
        .services()
        .announce(&Announcement {
            node_id: "n1",
            ssh_enabled: false,
            services: &many("d", 64),
            now: 13,
        })
        .await
        .unwrap();
    assert_eq!(refused, AnnounceOutcome::TooMany);
    let after = f.all().await;
    assert_eq!(after, before);
    assert!(
        f.store
            .nodes()
            .get("n1")
            .await
            .unwrap()
            .unwrap()
            .ssh_enabled
    );
}
