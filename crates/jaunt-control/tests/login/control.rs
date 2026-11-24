use jaunt_ca::CaKind;
use jaunt_control::ControlError;

use crate::support::{Harness, Options};

#[tokio::test(flavor = "multi_thread")]
async fn only_a_user_authority_can_sign_user_certificates() {
    let refused = Harness::try_with(Options {
        authority: CaKind::Host,
        ..Options::default()
    })
    .await;
    assert!(matches!(refused, Err(ControlError::NotUserAuthority)));

    let accepted = Harness::try_with(Options::default()).await;
    assert!(accepted.is_ok());
}
