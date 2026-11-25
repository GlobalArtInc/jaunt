use jaunt_store::SessionState;

use crate::stand::Stand;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_certificate_minted_with_the_ca_key_for_a_victims_serial_is_refused_at_the_gate() {
    let stand = Stand::start(&["web-01"]).await;
    let victim = stand.identity().await;
    let (_outer, inner) = stand.session(&victim, "web-01").await;
    assert_eq!(inner.echo().await, b"ok\n");
    let session_id = stand.nodes[0].log.last_authorized();
    assert_eq!(stand.stored(&session_id).await.state, SessionState::Active);
    let sessions = stand.sessions_of_user().await.len();

    let forged = stand.forged_for(&victim);
    assert_eq!(forged.serial, victim.serial);
    let outer = stand.connect(&forged).await;

    assert!(outer.forward("web-01").await.is_err());
    assert_eq!(stand.sessions_of_user().await.len(), sessions);
    assert_eq!(stand.nodes[0].log.last_authorized(), session_id);
    stand.stop().await;
}
