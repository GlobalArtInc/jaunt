use std::fmt::Write;
use std::fs;

use jaunt_policy::{AdminPermission, Identity, NodeInfo, PolicySet, load_dir};

const V1_SET: &str = "\
apiVersion: jaunt/v1
kind: Role
metadata: { name: operators }
spec:
  members: { users: [alice@example.com], groups: [infra-admins] }
  ssh: { nodes: { env: [staging, prod], team: ['*'] }, logins: [deploy, '{username}'], portForwarding: true }
  admin: [nodes.approve, sessions.read]
---
apiVersion: jaunt/v1
kind: Role
metadata: { name: web }
spec:
  members: { groups: [web] }
  ssh: { nodes: { env: [prod, staging] }, logins: [deploy], recordInput: true }
---
apiVersion: jaunt/v1
kind: Role
metadata: { name: break-glass }
spec:
  members: { users: [carol@example.com] }
  ssh: { nodes: { env: ['*'] }, logins: [root, '{username}'] }
---
apiVersion: jaunt/v1
kind: Role
metadata: { name: dev }
spec:
  members: { groups: [dev] }
  ssh: { nodes: { env: [dev] }, logins: ['{username}', app] }
---
apiVersion: jaunt/v1
kind: Role
metadata: { name: orphan }
spec:
  ssh: { nodes: { env: ['*'] }, logins: [root] }
---
apiVersion: jaunt/v1
kind: Role
metadata: { name: auditors }
spec:
  members: { groups: [audit] }
  admin: [audit.read]
---
apiVersion: jaunt/v1
kind: Role
metadata: { name: dup }
spec:
  members: { groups: [dup] }
  ssh: { nodes: { env: [dev] }, logins: [app, '{username}'], portForwarding: true }
---
apiVersion: jaunt/v1
kind: Role
metadata: { name: self-service }
spec:
  members: { groups: [self] }
  ssh: { nodes: { env: [qa] }, logins: ['{username}'] }
";

const GOLDEN: &str = r#"admin alice@example.com ["nodes.approve", "sessions.read"]
ssh alice@example.com web-1 route=1 logins=["alice", "deploy"] allow=["deploy:operators:10", "alice:operators:10"]
ssh alice@example.com web-2 route=0 logins=[] allow=[]
ssh alice@example.com stage-1 route=1 logins=["alice", "deploy"] allow=["deploy:operators:10", "alice:operators:10"]
ssh alice@example.com dev-1 route=0 logins=[] allow=[]
ssh alice@example.com bare-1 route=0 logins=[] allow=[]
ssh alice@example.com named-1 route=1 logins=["alice", "deploy"] allow=["deploy:operators:10", "alice:operators:10"]
ssh alice@example.com qa-1 route=0 logins=[] allow=[]
admin bob@example.com []
ssh bob@example.com web-1 route=1 logins=["deploy"] allow=["deploy:web:01"]
ssh bob@example.com web-2 route=1 logins=["deploy"] allow=["deploy:web:01"]
ssh bob@example.com stage-1 route=1 logins=["deploy"] allow=["deploy:web:01"]
ssh bob@example.com dev-1 route=1 logins=["app", "bob"] allow=["app:dev:00", "bob:dev:00"]
ssh bob@example.com bare-1 route=0 logins=[] allow=[]
ssh bob@example.com named-1 route=1 logins=["deploy"] allow=["deploy:web:01"]
ssh bob@example.com qa-1 route=0 logins=[] allow=[]
admin carol@example.com []
ssh carol@example.com web-1 route=1 logins=["root"] allow=["root:break-glass:00"]
ssh carol@example.com web-2 route=1 logins=["root"] allow=["root:break-glass:00"]
ssh carol@example.com stage-1 route=1 logins=["root"] allow=["root:break-glass:00"]
ssh carol@example.com dev-1 route=1 logins=["root"] allow=["root:break-glass:00"]
ssh carol@example.com bare-1 route=0 logins=[] allow=[]
ssh carol@example.com named-1 route=1 logins=["root"] allow=["root:break-glass:00"]
ssh carol@example.com qa-1 route=1 logins=["root"] allow=["root:break-glass:00"]
admin dave@example.com ["nodes.approve", "sessions.read"]
ssh dave@example.com web-1 route=1 logins=["deploy"] allow=["deploy:operators:10"]
ssh dave@example.com web-2 route=0 logins=[] allow=[]
ssh dave@example.com stage-1 route=1 logins=["deploy"] allow=["deploy:operators:10"]
ssh dave@example.com dev-1 route=0 logins=[] allow=[]
ssh dave@example.com bare-1 route=0 logins=[] allow=[]
ssh dave@example.com named-1 route=1 logins=["deploy"] allow=["deploy:operators:10"]
ssh dave@example.com qa-1 route=0 logins=[] allow=[]
admin erin@example.com ["audit.read"]
ssh erin@example.com web-1 route=0 logins=[] allow=[]
ssh erin@example.com web-2 route=0 logins=[] allow=[]
ssh erin@example.com stage-1 route=0 logins=[] allow=[]
ssh erin@example.com dev-1 route=1 logins=["app"] allow=["app:dev:00"]
ssh erin@example.com bare-1 route=0 logins=[] allow=[]
ssh erin@example.com named-1 route=0 logins=[] allow=[]
ssh erin@example.com qa-1 route=0 logins=[] allow=[]
admin mallory@example.com []
ssh mallory@example.com web-1 route=0 logins=[] allow=[]
ssh mallory@example.com web-2 route=0 logins=[] allow=[]
ssh mallory@example.com stage-1 route=0 logins=[] allow=[]
ssh mallory@example.com dev-1 route=0 logins=[] allow=[]
ssh mallory@example.com bare-1 route=0 logins=[] allow=[]
ssh mallory@example.com named-1 route=0 logins=[] allow=[]
ssh mallory@example.com qa-1 route=0 logins=[] allow=[]
admin frank@example.com ["nodes.approve", "sessions.read"]
ssh frank@example.com web-1 route=1 logins=["deploy", "frank"] allow=["deploy:operators+web:11", "frank:operators:10"]
ssh frank@example.com web-2 route=1 logins=["deploy"] allow=["deploy:web:01"]
ssh frank@example.com stage-1 route=1 logins=["deploy", "frank"] allow=["deploy:operators+web:11", "frank:operators:10"]
ssh frank@example.com dev-1 route=0 logins=[] allow=[]
ssh frank@example.com bare-1 route=0 logins=[] allow=[]
ssh frank@example.com named-1 route=1 logins=["deploy", "frank"] allow=["deploy:operators+web:11", "frank:operators:10"]
ssh frank@example.com qa-1 route=0 logins=[] allow=[]
admin grace@example.com ["nodes.approve", "sessions.read"]
ssh grace@example.com web-1 route=1 logins=["deploy"] allow=["deploy:operators:10"]
ssh grace@example.com web-2 route=0 logins=[] allow=[]
ssh grace@example.com stage-1 route=1 logins=["deploy"] allow=["deploy:operators:10"]
ssh grace@example.com dev-1 route=1 logins=["app"] allow=["app:dev:00"]
ssh grace@example.com bare-1 route=0 logins=[] allow=[]
ssh grace@example.com named-1 route=1 logins=["deploy"] allow=["deploy:operators:10"]
ssh grace@example.com qa-1 route=0 logins=[] allow=[]
admin heidi@example.com []
ssh heidi@example.com web-1 route=0 logins=[] allow=[]
ssh heidi@example.com web-2 route=0 logins=[] allow=[]
ssh heidi@example.com stage-1 route=0 logins=[] allow=[]
ssh heidi@example.com dev-1 route=1 logins=["app", "heidi"] allow=["app:dev+dup:10", "heidi:dev+dup:10"]
ssh heidi@example.com bare-1 route=0 logins=[] allow=[]
ssh heidi@example.com named-1 route=0 logins=[] allow=[]
ssh heidi@example.com qa-1 route=0 logins=[] allow=[]
admin ivan@example.com []
ssh ivan@example.com web-1 route=0 logins=[] allow=[]
ssh ivan@example.com web-2 route=0 logins=[] allow=[]
ssh ivan@example.com stage-1 route=0 logins=[] allow=[]
ssh ivan@example.com dev-1 route=0 logins=[] allow=[]
ssh ivan@example.com bare-1 route=0 logins=[] allow=[]
ssh ivan@example.com named-1 route=0 logins=[] allow=[]
ssh ivan@example.com qa-1 route=0 logins=[] allow=[]
admin judy@example.com []
ssh judy@example.com web-1 route=0 logins=[] allow=[]
ssh judy@example.com web-2 route=0 logins=[] allow=[]
ssh judy@example.com stage-1 route=0 logins=[] allow=[]
ssh judy@example.com dev-1 route=0 logins=[] allow=[]
ssh judy@example.com bare-1 route=0 logins=[] allow=[]
ssh judy@example.com named-1 route=0 logins=[] allow=[]
ssh judy@example.com qa-1 route=1 logins=["judy"] allow=["judy:self-service:00"]
reach web-1 break-glass:carol@example.com::root,{username}:00: operators:alice@example.com:infra-admins:deploy,{username}:10:nodes.approve,sessions.read orphan:::root:00: web::web:deploy:01:
reach web-2 break-glass:carol@example.com::root,{username}:00: orphan:::root:00: web::web:deploy:01:
reach stage-1 break-glass:carol@example.com::root,{username}:00: operators:alice@example.com:infra-admins:deploy,{username}:10:nodes.approve,sessions.read orphan:::root:00: web::web:deploy:01:
reach dev-1 break-glass:carol@example.com::root,{username}:00: dev::dev:{username},app:00: dup::dup:app,{username}:10: orphan:::root:00:
reach bare-1 
reach named-1 break-glass:carol@example.com::root,{username}:00: operators:alice@example.com:infra-admins:deploy,{username}:10:nodes.approve,sessions.read orphan:::root:00: web::web:deploy:01:
reach qa-1 break-glass:carol@example.com::root,{username}:00: orphan:::root:00: self-service::self:{username}:00:
"#;

fn identities() -> Vec<Identity> {
    [
        ("alice@example.com", "alice", &[][..]),
        ("bob@example.com", "bob", &["web", "dev"][..]),
        ("carol@example.com", "root", &[][..]),
        ("dave@example.com", "Dave", &["infra-admins"][..]),
        ("erin@example.com", "", &["dev", "audit"][..]),
        (
            "mallory@example.com",
            "mallory",
            &["Web", "infra-admin"][..],
        ),
        ("frank@example.com", "frank", &["infra-admins", "web"][..]),
        ("grace@example.com", "root", &["dev", "infra-admins"][..]),
        ("heidi@example.com", "heidi", &["dev", "dup"][..]),
        ("ivan@example.com", "Ivan", &["self"][..]),
        ("judy@example.com", "judy", &["self"][..]),
    ]
    .into_iter()
    .map(|(email, username, groups)| Identity {
        email: email.to_owned(),
        username: username.to_owned(),
        groups: groups.iter().map(|group| (*group).to_owned()).collect(),
    })
    .collect()
}

fn nodes() -> Vec<NodeInfo> {
    [
        ("web-1", &[("env", "prod"), ("team", "web")][..]),
        ("web-2", &[("env", "prod")][..]),
        ("stage-1", &[("env", "staging"), ("team", "core")][..]),
        ("dev-1", &[("env", "dev"), ("team", "")][..]),
        ("bare-1", &[][..]),
        (
            "named-1",
            &[("env", "prod"), ("name", "web-1"), ("team", "x")][..],
        ),
        ("qa-1", &[("env", "qa"), ("team", "qa")][..]),
    ]
    .into_iter()
    .map(|(name, labels)| NodeInfo {
        name: name.to_owned(),
        labels: labels
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect(),
    })
    .collect()
}

const LOGINS: [&str; 17] = [
    "deploy",
    "root",
    "app",
    "alice",
    "bob",
    "Dave",
    "dave",
    "mallory",
    "frank",
    "grace",
    "heidi",
    "Ivan",
    "ivan",
    "judy",
    "",
    "a b",
    "{username}",
];

fn render(set: &PolicySet) -> String {
    let mut out = String::new();
    for who in identities() {
        let admin: Vec<&str> = AdminPermission::ALL
            .into_iter()
            .filter(|permission| set.admin_can(&who, *permission))
            .map(|permission| permission.as_str())
            .collect();
        writeln!(out, "admin {} {admin:?}", who.email).unwrap();
        for target in nodes() {
            let mut allowed = Vec::new();
            for login in LOGINS {
                let decision = set.authorize_ssh(&who, &target, login);
                if decision.allowed {
                    allowed.push(format!(
                        "{login}:{}:{}{}",
                        decision.roles.join("+"),
                        u8::from(decision.port_forwarding),
                        u8::from(decision.record_input)
                    ));
                } else {
                    assert_eq!(decision, Default::default(), "{login:?}");
                }
            }
            writeln!(
                out,
                "ssh {} {} route={} logins={:?} allow={allowed:?}",
                who.email,
                target.name,
                u8::from(set.route(&who, &target)),
                set.ssh_logins(&who, &target),
            )
            .unwrap();
        }
    }
    for target in nodes() {
        let reaching: Vec<String> = set
            .roles_reaching(&target)
            .into_iter()
            .map(|access| {
                let admin: Vec<&str> = access.admin.iter().map(AdminPermission::as_str).collect();
                format!(
                    "{}:{}:{}:{}:{}{}:{}",
                    access.role,
                    access.users.join(","),
                    access.groups.join(","),
                    access.logins.join(","),
                    u8::from(access.port_forwarding),
                    u8::from(access.record_input),
                    admin.join(",")
                )
            })
            .collect();
        writeln!(out, "reach {} {}", target.name, reaching.join(" ")).unwrap();
    }
    out
}

#[test]
fn v1_sets_without_new_fields_keep_their_decisions() {
    let dir = tempfile::tempdir().expect("create temp dir");
    fs::write(dir.path().join("roles.yaml"), V1_SET).expect("write policy file");
    let set = load_dir(dir.path()).expect("policy set must load");
    let actual = render(&set);
    assert_eq!(actual, GOLDEN, "\n{actual}");
}
