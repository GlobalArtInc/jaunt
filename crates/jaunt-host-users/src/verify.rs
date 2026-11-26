use crate::config::HostUsersConfig;
use crate::names::Name;
use crate::rules::Candidate;
use crate::system::{FileFacts, FileKind, GroupEntry, PasswdEntry};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    login: Name,
    uid: u32,
    gid: u32,
    home: String,
}

impl Verified {
    pub fn login(&self) -> &Name {
        &self.login
    }

    pub fn uid(&self) -> u32 {
        self.uid
    }

    pub fn gid(&self) -> u32 {
        self.gid
    }

    pub fn home(&self) -> &str {
        &self.home
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VerifyProblem {
    #[error("the account database has no entry for the new account")]
    AccountMissing,
    #[error("the account entry carries another name")]
    Name,
    #[error("the uid is 0 or outside host_users.uid_min..=uid_max")]
    Uid,
    #[error("the primary gid is 0 or outside host_users.uid_min..=uid_max")]
    Gid,
    #[error("the home directory in the account entry is not home_base/<login>")]
    Home,
    #[error("the login shell is not host_users.shell")]
    Shell,
    #[error("the group database has no entry for the new group")]
    GroupMissing,
    #[error("the new group is not named after the login")]
    GroupName,
    #[error("the new group does not carry the primary gid")]
    GroupGid,
    #[error("the home directory does not exist")]
    HomeMissing,
    #[error("the home directory is not a real directory")]
    HomeNotDirectory,
    #[error("the home directory belongs to another uid")]
    HomeOwner,
}

pub fn verify_created(
    config: &HostUsersConfig,
    candidate: &Candidate,
    passwd: Option<&PasswdEntry>,
    group: Option<&GroupEntry>,
    home: Option<&FileFacts>,
) -> Result<Verified, VerifyProblem> {
    let login = candidate.login();
    let ids = config.uid_min()..=config.uid_max();
    let expected_home = config.home_of(login);
    let passwd = passwd.ok_or(VerifyProblem::AccountMissing)?;
    if passwd.name != *login {
        return Err(VerifyProblem::Name);
    }
    if passwd.uid == 0 || !ids.contains(&passwd.uid) {
        return Err(VerifyProblem::Uid);
    }
    if passwd.gid == 0 || !ids.contains(&passwd.gid) {
        return Err(VerifyProblem::Gid);
    }
    if passwd.home != expected_home || passwd.home != candidate.home() {
        return Err(VerifyProblem::Home);
    }
    if passwd.shell != config.shell() {
        return Err(VerifyProblem::Shell);
    }
    let group = group.ok_or(VerifyProblem::GroupMissing)?;
    if group.name != *login {
        return Err(VerifyProblem::GroupName);
    }
    if group.gid != passwd.gid {
        return Err(VerifyProblem::GroupGid);
    }
    let home = home.ok_or(VerifyProblem::HomeMissing)?;
    if home.kind != FileKind::Directory {
        return Err(VerifyProblem::HomeNotDirectory);
    }
    if home.uid != passwd.uid {
        return Err(VerifyProblem::HomeOwner);
    }
    Ok(Verified {
        login: login.clone(),
        uid: passwd.uid,
        gid: passwd.gid,
        home: passwd.home.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::{VerifyProblem, verify_created};
    use crate::system::{FileKind, GroupEntry, PasswdEntry};
    use crate::testing::{candidate, created_entries, enabled_config, name};

    #[test]
    fn only_an_account_that_matches_the_request_and_the_rules_is_verified() {
        let config = enabled_config("  uid_min: 30000\n  uid_max: 30999\n");
        let alice = candidate(&config, "alice");
        let (passwd, group, home) = created_entries(&config, &alice, 30_001);
        let verified =
            verify_created(&config, &alice, Some(&passwd), Some(&group), Some(&home)).unwrap();
        assert_eq!(verified.login(), &name("alice"));
        assert_eq!((verified.uid(), verified.gid()), (30_001, 30_001));
        assert_eq!(verified.home(), "/home/alice");
        for uid in [30_000, 30_999] {
            let (passwd, group, home) = created_entries(&config, &alice, uid);
            assert!(
                verify_created(&config, &alice, Some(&passwd), Some(&group), Some(&home)).is_ok(),
                "{uid}"
            );
        }

        let with_passwd = |change: fn(&mut PasswdEntry)| {
            let mut passwd = passwd.clone();
            change(&mut passwd);
            passwd
        };
        let with_group = |change: fn(&mut GroupEntry)| {
            let mut group = group.clone();
            change(&mut group);
            group
        };
        let cases = [
            (
                "uid 0",
                with_passwd(|entry| entry.uid = 0),
                group.clone(),
                home,
                VerifyProblem::Uid,
            ),
            (
                "uid below",
                with_passwd(|entry| entry.uid = 29_999),
                group.clone(),
                home,
                VerifyProblem::Uid,
            ),
            (
                "uid above",
                with_passwd(|entry| entry.uid = 31_000),
                group.clone(),
                home,
                VerifyProblem::Uid,
            ),
            (
                "gid 0",
                with_passwd(|entry| entry.gid = 0),
                group.clone(),
                home,
                VerifyProblem::Gid,
            ),
            (
                "gid outside",
                with_passwd(|entry| entry.gid = 100),
                group.clone(),
                home,
                VerifyProblem::Gid,
            ),
            (
                "other name",
                with_passwd(|entry| entry.name = crate::testing::name("alicia")),
                group.clone(),
                home,
                VerifyProblem::Name,
            ),
            (
                "other home",
                with_passwd(|entry| entry.home = "/home/other".to_owned()),
                group.clone(),
                home,
                VerifyProblem::Home,
            ),
            (
                "other shell",
                with_passwd(|entry| entry.shell = "/bin/sh".to_owned()),
                group.clone(),
                home,
                VerifyProblem::Shell,
            ),
            (
                "foreign gid",
                passwd.clone(),
                with_group(|entry| entry.gid = 30_500),
                home,
                VerifyProblem::GroupGid,
            ),
            (
                "foreign group name",
                passwd.clone(),
                with_group(|entry| entry.name = crate::testing::name("staff2")),
                home,
                VerifyProblem::GroupName,
            ),
            (
                "home symlink",
                passwd.clone(),
                group.clone(),
                crate::system::FileFacts {
                    kind: FileKind::Symlink,
                    ..home
                },
                VerifyProblem::HomeNotDirectory,
            ),
            (
                "home file",
                passwd.clone(),
                group.clone(),
                crate::system::FileFacts {
                    kind: FileKind::Regular,
                    ..home
                },
                VerifyProblem::HomeNotDirectory,
            ),
            (
                "home owner",
                passwd.clone(),
                group.clone(),
                crate::system::FileFacts { uid: 0, ..home },
                VerifyProblem::HomeOwner,
            ),
        ];
        for (label, passwd, group, home, problem) in cases {
            let result = verify_created(&config, &alice, Some(&passwd), Some(&group), Some(&home));
            assert_eq!(result, Err(problem), "{label}");
        }
        for (label, result, problem) in [
            (
                "no account",
                verify_created(&config, &alice, None, Some(&group), Some(&home)),
                VerifyProblem::AccountMissing,
            ),
            (
                "no group",
                verify_created(&config, &alice, Some(&passwd), None, Some(&home)),
                VerifyProblem::GroupMissing,
            ),
            (
                "no home",
                verify_created(&config, &alice, Some(&passwd), Some(&group), None),
                VerifyProblem::HomeMissing,
            ),
        ] {
            assert_eq!(result, Err(problem), "{label}");
        }
    }
}
