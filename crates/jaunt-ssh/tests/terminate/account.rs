use std::sync::{Arc, Mutex};

use jaunt_proto::BoxFuture;
use jaunt_ssh::{AccountKeeper, AccountStep, EndReason};

use crate::sshd::SshdStats;
use crate::support::{Fixture, LOGIN, Options, SESSION_ID};

struct FixedKeeper {
    step: AccountStep,
    calls: Mutex<Vec<(String, String)>>,
}

impl FixedKeeper {
    fn new(step: AccountStep) -> Arc<Self> {
        Arc::new(Self {
            step,
            calls: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<(String, String)> {
        self.calls.lock().unwrap().clone()
    }
}

impl AccountKeeper for FixedKeeper {
    fn ensure<'a>(&'a self, login: &'a str, session_id: &'a str) -> BoxFuture<'a, AccountStep> {
        self.calls
            .lock()
            .unwrap()
            .push((login.to_owned(), session_id.to_owned()));
        Box::pin(async move { self.step })
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_account_step_runs_after_authorize_and_maps_each_answer_to_an_end_reason() {
    for (step, reason) in [
        (AccountStep::NoAccount, EndReason::NoAccount),
        (AccountStep::Refused, EndReason::AccountRefused),
        (AccountStep::Failed, EndReason::AccountFailed),
    ] {
        let keeper = FixedKeeper::new(step);
        let fixture = Fixture::new(Options {
            keeper: Some(Arc::clone(&keeper) as Arc<dyn AccountKeeper>),
            ..Options::default()
        })
        .await;
        let mut client = fixture.connect().await;
        assert!(
            !client.authenticate(LOGIN, fixture.cert.clone()).await,
            "{step:?}"
        );
        let outcome = client.finish().await;
        assert!(outcome.authorized, "{step:?}");
        assert_eq!(outcome.reason, reason, "{step:?}");
        assert_eq!(
            keeper.calls(),
            vec![(LOGIN.to_owned(), SESSION_ID.to_owned())]
        );
        assert_eq!(fixture.authority.requests().len(), 1);
        assert_eq!(fixture.authority.ends().len(), 1);
        assert_eq!(SshdStats::count(&fixture.sshd.stats.connections), 0);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_keeper_that_continues_leads_to_the_inner_login() {
    let keeper = FixedKeeper::new(AccountStep::Continue);
    let fixture = Fixture::new(Options {
        keeper: Some(Arc::clone(&keeper) as Arc<dyn AccountKeeper>),
        ..Options::default()
    })
    .await;
    let client = fixture.login().await;
    assert_eq!(keeper.calls().len(), 1);
    assert_eq!(SshdStats::count(&fixture.sshd.stats.logins), 1);
    let outcome = client.finish().await;
    assert!(outcome.authorized);
    assert_eq!(outcome.reason, EndReason::ClientClosed);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_denied_session_never_reaches_the_keeper() {
    let keeper = FixedKeeper::new(AccountStep::Continue);
    let fixture = Fixture::new(Options {
        decision: crate::support::Decision::Deny,
        keeper: Some(Arc::clone(&keeper) as Arc<dyn AccountKeeper>),
        ..Options::default()
    })
    .await;
    let mut client = fixture.connect().await;
    assert!(!client.authenticate(LOGIN, fixture.cert.clone()).await);
    assert_eq!(client.finish().await.reason, EndReason::Denied);
    assert!(keeper.calls().is_empty());
}
