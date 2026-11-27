use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rcgen::string::Ia5String;
use rcgen::{ExtendedKeyUsagePurpose, SanType};
use uuid::Uuid;

use super::root::{self, RootProfile};
use super::{
    IssuedCertificate, Leaf, LeafIssuer, MAX_COMMON_NAME_LEN, SubjectPublicKey, random_serial,
};
use crate::cert::{validate_email, window, window_backdated};
use crate::error::CaError;
use crate::kind::CaKind;
use crate::signer::Signer;

pub const CLIENT_ROOT_VALIDITY: Duration = Duration::from_secs(5 * 365 * 24 * 60 * 60);
pub const MAX_USER_X509_VALIDITY: Duration = Duration::from_secs(24 * 60 * 60);
pub const DB_CLIENT_VALIDITY: Duration = Duration::from_secs(5 * 60);
pub const DB_CLIENT_BACKDATE: Duration = Duration::from_secs(60);

const USER_URN_PREFIX: &str = "urn:jaunt:user:";
const MAX_DATABASE_ROLE_LEN: usize = 63;

static USER_X509_ROOT: RootProfile = RootProfile {
    kind: CaKind::UserX509,
    common_name: "Jaunt User X.509 CA",
    validity: CLIENT_ROOT_VALIDITY,
};

static DB_CLIENT_ROOT: RootProfile = RootProfile {
    kind: CaKind::DbClient,
    common_name: "Jaunt Database Client CA",
    validity: CLIENT_ROOT_VALIDITY,
};

#[derive(Clone, Debug)]
pub struct UserX509Params {
    pub subject_public_key: SubjectPublicKey,
    pub user_id: Uuid,
    pub email: String,
    pub serial: u64,
    pub valid_before: SystemTime,
}

#[derive(Clone, Debug)]
pub struct DbClientParams {
    pub subject_public_key: SubjectPublicKey,
    pub role: String,
}

pub struct ClientCa {
    issuer: LeafIssuer,
}

impl ClientCa {
    pub fn new(signer: Arc<dyn Signer>, root_der: Vec<u8>) -> Result<Self, CaError> {
        let kind = signer.kind();
        root_profile(kind)?;
        Ok(Self {
            issuer: LeafIssuer::new(signer, root_der, kind)?,
        })
    }

    pub fn create_root(signer: &dyn Signer, now: SystemTime) -> Result<IssuedCertificate, CaError> {
        root::create(signer, now, root_profile(signer.kind())?)
    }

    pub fn kind(&self) -> CaKind {
        self.issuer.kind()
    }

    pub fn root_der(&self) -> &[u8] {
        self.issuer.root_der()
    }

    pub fn root_sha256_hex(&self) -> String {
        self.issuer.root_sha256_hex()
    }

    pub fn root_not_before(&self) -> SystemTime {
        self.issuer.root_not_before()
    }

    pub fn root_not_after(&self) -> SystemTime {
        self.issuer.root_not_after()
    }

    pub fn issue_user_certificate(
        &self,
        params: UserX509Params,
        now: SystemTime,
    ) -> Result<IssuedCertificate, CaError> {
        self.require(CaKind::UserX509)?;
        validate_email(&params.email)?;
        if params.user_id.is_nil() {
            return Err(CaError::InvalidUserId);
        }
        if params.serial == 0 {
            return Err(CaError::InvalidSerial);
        }
        let validity = remaining(now, params.valid_before)?;
        let window = window(now, validity, MAX_USER_X509_VALIDITY)?;
        self.issuer.check_window(now, &window)?;
        let uri = Ia5String::try_from(user_urn(params.user_id)).map_err(CaError::X509)?;
        let user_id = params.user_id.hyphenated().to_string();
        let common_name = if params.email.len() > MAX_COMMON_NAME_LEN {
            &user_id
        } else {
            &params.email
        };
        self.issuer.issue(Leaf {
            subject: &params.subject_public_key,
            window: &window,
            common_name: Some(common_name),
            usage: ExtendedKeyUsagePurpose::ClientAuth,
            names: vec![SanType::URI(uri)],
            serial: u128::from(params.serial),
        })
    }

    pub fn issue_db_client_certificate(
        &self,
        params: DbClientParams,
        now: SystemTime,
    ) -> Result<IssuedCertificate, CaError> {
        self.require(CaKind::DbClient)?;
        validate_database_role(&params.role)?;
        let window = window_backdated(
            now,
            DB_CLIENT_VALIDITY,
            DB_CLIENT_VALIDITY,
            DB_CLIENT_BACKDATE,
        )?;
        self.issuer.check_window(now, &window)?;
        self.issuer.issue(Leaf {
            subject: &params.subject_public_key,
            window: &window,
            common_name: Some(&params.role),
            usage: ExtendedKeyUsagePurpose::ClientAuth,
            names: Vec::new(),
            serial: random_serial()?,
        })
    }

    #[cfg(test)]
    pub(super) fn issue_raw(
        &self,
        subject: &SubjectPublicKey,
        window: &crate::cert::Window,
        common_name: &str,
        usage: ExtendedKeyUsagePurpose,
    ) -> Result<IssuedCertificate, CaError> {
        self.issuer.issue(Leaf {
            subject,
            window,
            common_name: Some(common_name),
            usage,
            names: Vec::new(),
            serial: random_serial()?,
        })
    }

    fn require(&self, expected: CaKind) -> Result<(), CaError> {
        if self.issuer.kind() == expected {
            Ok(())
        } else {
            Err(CaError::WrongAuthorityKind { expected })
        }
    }
}

impl fmt::Debug for ClientCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientCa")
            .field("kind", &self.issuer.kind())
            .field("root_sha256", &format_args!("{}", self.root_sha256_hex()))
            .finish_non_exhaustive()
    }
}

fn root_profile(kind: CaKind) -> Result<&'static RootProfile, CaError> {
    match kind {
        CaKind::UserX509 => Ok(&USER_X509_ROOT),
        CaKind::DbClient => Ok(&DB_CLIENT_ROOT),
        CaKind::User | CaKind::Host | CaKind::Internal => Err(CaError::NotAClientAuthority(kind)),
    }
}

fn remaining(now: SystemTime, valid_before: SystemTime) -> Result<Duration, CaError> {
    let seconds = |at: SystemTime| {
        at.duration_since(UNIX_EPOCH)
            .map(|since| since.as_secs())
            .map_err(|_| CaError::InvalidTime)
    };
    let (now, valid_before) = (seconds(now)?, seconds(valid_before)?);
    Ok(Duration::from_secs(valid_before.saturating_sub(now)))
}

fn user_urn(user_id: Uuid) -> String {
    format!("{USER_URN_PREFIX}{}", user_id.hyphenated())
}

fn validate_database_role(role: &str) -> Result<(), CaError> {
    let acceptable = !role.is_empty()
        && role.len() <= MAX_DATABASE_ROLE_LEN
        && role.bytes().all(|byte| (0x21..=0x7e).contains(&byte));
    if acceptable {
        Ok(())
    } else {
        Err(CaError::InvalidDatabaseRole)
    }
}
