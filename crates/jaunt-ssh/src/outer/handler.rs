use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use russh::keys::Certificate;
use russh::server::{
    self, Auth, ChannelOpenHandle, Msg, PublicKeyOffer, Response, Session, VerifiedPublicKey,
};
use russh::{Channel, ChannelId, ChannelOpenFailure, Pty};
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use super::forward::{self, Cause, Opening};
use super::{AuthDenial, Connection, ForwardRefusal, OuterEvent, Phase, RouteTarget, StreamEnd};
use crate::cert::{UserIdentity, verify_user_certificate};
use crate::intake::{ChannelGrant, ChannelIntake, IntakeError};
use crate::limits::OpenRate;
use crate::target::parse_node_target;

const MAX_LOGGED_LOGIN: usize = 64;
const MAX_KEY_OFFERS: usize = 32;

struct ForwardLink {
    intake: ChannelIntake,
    token: CancellationToken,
    cause: Arc<Cause>,
}

pub(super) struct OuterHandler {
    connection: Arc<Connection>,
    window: u32,
    pre_auth: Option<OwnedSemaphorePermit>,
    identity: Option<UserIdentity>,
    login: String,
    failures: usize,
    offers: usize,
    forwards: HashMap<ChannelId, ForwardLink>,
    opens: OpenRate,
    tracker: TaskTracker,
}

impl OuterHandler {
    pub(super) fn new(
        connection: Arc<Connection>,
        window: u32,
        pre_auth: OwnedSemaphorePermit,
        tracker: TaskTracker,
    ) -> Self {
        let opens = OpenRate::new(connection.hop.limits.opens_per_minute);
        Self {
            connection,
            window,
            pre_auth: Some(pre_auth),
            identity: None,
            login: String::new(),
            failures: 0,
            offers: 0,
            forwards: HashMap::new(),
            opens,
            tracker,
        }
    }

    fn attempts_left(&self) -> bool {
        self.failures < self.connection.hop.limits.max_auth_attempts
    }

    fn refuse_attempt(&self) -> Auth {
        if !self.attempts_left() {
            self.connection.set_phase(Phase::Exhausted);
        }
        Auth::reject()
    }

    fn deny(&mut self, user: &str, reason: AuthDenial) -> Auth {
        if self.attempts_left() {
            self.failures = self.failures.saturating_add(1);
            self.connection.denied.store(true, Ordering::SeqCst);
            self.connection.hop.emit(OuterEvent::AuthDenied {
                reason,
                login: logged_login(user),
            });
        }
        self.refuse_attempt()
    }

    fn refuse_request(
        &self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        session.channel_failure(channel)
    }
}

fn logged_login(user: &str) -> String {
    user.chars()
        .take(MAX_LOGGED_LOGIN)
        .map(|c| if unsafe_in_logs(c) { '?' } else { c })
        .collect()
}

fn unsafe_in_logs(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

impl server::Handler for OuterHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::reject())
    }

    async fn auth_password(&mut self, user: &str, _password: &str) -> Result<Auth, Self::Error> {
        Ok(self.deny(user, AuthDenial::Password))
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        _response: Option<Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        Ok(self.deny(user, AuthDenial::KeyboardInteractive))
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        _offer: PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        self.offers = self.offers.saturating_add(1);
        if self.offers > MAX_KEY_OFFERS {
            self.connection.set_phase(Phase::Exhausted);
            return Ok(Auth::reject());
        }
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        _key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(self.deny(user, AuthDenial::PlainKey))
    }

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &Certificate,
    ) -> Result<Auth, Self::Error> {
        if !self.attempts_left() {
            return Ok(self.refuse_attempt());
        }
        let cas = self.connection.hop.cas.current();
        match verify_user_certificate(certificate, &cas, self.connection.unix_now()) {
            Ok(identity) => {
                self.identity = Some(identity);
                self.login = logged_login(user);
                Ok(Auth::Accept)
            }
            Err(rejection) => Ok(self.deny(user, AuthDenial::Certificate(rejection))),
        }
    }

    async fn auth_succeeded(&mut self, _session: &mut Session) -> Result<(), Self::Error> {
        self.pre_auth = None;
        if let Some(identity) = &self.identity {
            self.connection.hop.emit(OuterEvent::AuthAccepted {
                user_id: identity.user_id.clone(),
                serial: identity.serial,
                login: self.login.clone(),
            });
            self.connection
                .set_phase(Phase::Authenticated(identity.clone()));
        }
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.connection.hop.emit(OuterEvent::SessionRefused);
        reply
            .reject(ChannelOpenFailure::Other {
                code: 1,
                reason: self.connection.hop.session_refusal.to_string(),
            })
            .await;
        Ok(())
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(identity) = self.identity.clone() else {
            reply
                .reject(ChannelOpenFailure::AdministrativelyProhibited)
                .await;
            return Ok(());
        };
        self.forwards.retain(|_, link| !link.token.is_cancelled());
        let within_rate = self.opens.admit(Instant::now());
        let hop = &self.connection.hop;
        let Some(node) = parse_node_target(host_to_connect, port_to_connect, &hop.suffix) else {
            hop.refuse(reply, None, ForwardRefusal::BadTarget).await;
            return Ok(());
        };
        if !within_rate || self.forwards.len() >= hop.limits.max_forwards {
            hop.refuse(reply, Some(node), ForwardRefusal::Limit).await;
            return Ok(());
        }
        let target = RouteTarget {
            identity,
            node,
            client_addr: self.connection.client_addr,
        };
        let id = channel.id();
        let (read_half, output) = channel.split();
        drop(read_half);
        let (intake, reader) =
            ChannelIntake::new(self.window, ChannelGrant::new(session.handle(), id));
        let token = self.connection.token.child_token();
        let cause = Arc::new(Cause::default());
        self.forwards.insert(
            id,
            ForwardLink {
                intake,
                token: token.clone(),
                cause: Arc::clone(&cause),
            },
        );
        self.tracker.spawn(forward::open(Opening {
            connection: Arc::clone(&self.connection),
            target,
            reply,
            reader,
            output,
            token,
            cause,
        }));
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        match self
            .forwards
            .get(&channel)
            .map(|link| link.intake.push_data(data))
        {
            Some(Err(IntakeError::WindowOverrun | IntakeError::DataAfterEof)) => {
                Err(self.connection.violated())
            }
            Some(Ok(()) | Err(IntakeError::SessionGone)) | None => Ok(()),
        }
    }

    async fn extended_data(
        &mut self,
        channel: ChannelId,
        _code: u32,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        match self
            .forwards
            .get(&channel)
            .map(|link| link.intake.consume_extended(data.len()))
        {
            Some(Err(IntakeError::WindowOverrun | IntakeError::DataAfterEof)) => {
                Err(self.connection.violated())
            }
            Some(Ok(()) | Err(IntakeError::SessionGone)) | None => Ok(()),
        }
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(link) = self.forwards.get(&channel) {
            link.intake.push_eof();
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(link) = self.forwards.remove(&channel) {
            link.cause.set(StreamEnd::ClientGone);
            link.intake.push_close();
            link.token.cancel();
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse_request(channel, session)
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        _x11_auth_protocol: &str,
        _x11_auth_cookie: &str,
        _x11_screen_number: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse_request(channel, session)
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        _variable_name: &str,
        _variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse_request(channel, session)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse_request(channel, session)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse_request(channel, session)
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse_request(channel, session)
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.refuse_request(channel, session)
    }

    async fn agent_request(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::logged_login;

    #[test]
    fn logged_logins_are_short_and_printable() {
        let long = "a".repeat(100);
        assert_eq!(logged_login("jaunt"), "jaunt");
        assert_eq!(logged_login(&long).chars().count(), 64);
        assert_eq!(logged_login("ja\nun\u{1b}t"), "ja?un?t");
        assert_eq!(
            logged_login("a\u{2028}b\u{2029}c\u{202e}d\u{2066}e\u{200f}f\u{061c}g"),
            "a?b?c?d?e?f?g"
        );
        assert_eq!(logged_login("ä\u{200d}ö"), "ä\u{200d}ö");
        assert_eq!(logged_login("ü".repeat(70).as_str()).chars().count(), 64);
    }
}
