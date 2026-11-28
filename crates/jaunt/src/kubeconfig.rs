use std::collections::HashSet;
use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use serde_saphyr::{Options, SerializerOptions};

pub const MARKER_NAME: &str = "jaunt";
pub const EXEC_API_VERSION: &str = "client.authentication.k8s.io/v1";
const MARKER_PROFILE: &str = "profile";
const API_VERSION: &str = "v1";
const KIND: &str = "Config";
const CLUSTERS: &str = "clusters";
const CONTEXTS: &str = "contexts";
const USERS: &str = "users";
const CURRENT_CONTEXT: &str = "current-context";
const LISTS: [(&str, &str); 3] = [
    (CLUSTERS, "cluster"),
    (CONTEXTS, "context"),
    (USERS, "user"),
];

#[derive(Debug, Clone, PartialEq)]
pub enum Yaml {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(f64),
    Str(String),
    Seq(Vec<Yaml>),
    Map(Vec<(Yaml, Yaml)>),
}

impl Yaml {
    pub fn text(value: &str) -> Yaml {
        Yaml::Str(value.to_owned())
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Yaml::Str(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_seq(&self) -> Option<&[Yaml]> {
        match self {
            Yaml::Seq(items) => Some(items),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&Yaml> {
        match self {
            Yaml::Map(entries) => entries
                .iter()
                .find(|(found, _)| found.as_str() == Some(key))
                .map(|(_, value)| value),
            _ => None,
        }
    }

    fn get_mut(&mut self, key: &str) -> Option<&mut Yaml> {
        match self {
            Yaml::Map(entries) => entries
                .iter_mut()
                .find(|(found, _)| found.as_str() == Some(key))
                .map(|(_, value)| value),
            _ => None,
        }
    }

    fn string_at(&self, path: &[&str]) -> Option<&str> {
        path.iter()
            .try_fold(self, |node, key| node.get(key))
            .and_then(Yaml::as_str)
    }
}

fn map(entries: Vec<(&str, Yaml)>) -> Yaml {
    Yaml::Map(
        entries
            .into_iter()
            .map(|(key, value)| (Yaml::text(key), value))
            .collect(),
    )
}

fn set_key(entries: &mut Vec<(Yaml, Yaml)>, key: &str, value: Yaml) {
    match entries
        .iter_mut()
        .find(|(found, _)| found.as_str() == Some(key))
    {
        Some((_, slot)) => *slot = value,
        None => entries.push((Yaml::text(key), value)),
    }
}

impl Serialize for Yaml {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Yaml::Null => serializer.serialize_unit(),
            Yaml::Bool(value) => serializer.serialize_bool(*value),
            Yaml::Int(value) => serializer.serialize_i64(*value),
            Yaml::UInt(value) => serializer.serialize_u64(*value),
            Yaml::Float(value) => serializer.serialize_f64(*value),
            Yaml::Str(value) => serializer.serialize_str(value),
            Yaml::Seq(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
            Yaml::Map(entries) => {
                let mut map = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    map.serialize_entry(key, value)?;
                }
                map.end()
            }
        }
    }
}

struct YamlVisitor;

impl<'de> Visitor<'de> for YamlVisitor {
    type Value = Yaml;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a YAML value that kubectl can read")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Yaml, E> {
        Ok(Yaml::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Yaml, E> {
        Ok(Yaml::Int(value))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Yaml, E> {
        Ok(i64::try_from(value).map_or(Yaml::UInt(value), Yaml::Int))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Yaml, E> {
        if value.is_finite() {
            Ok(Yaml::Float(value))
        } else {
            Err(E::custom("a number that is not finite"))
        }
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Yaml, E> {
        Ok(Yaml::text(value))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Yaml, E> {
        Ok(Yaml::Str(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Yaml, E> {
        Ok(Yaml::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Yaml, E> {
        Ok(Yaml::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Yaml, D::Error> {
        Yaml::deserialize(deserializer)
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(self, deserializer: D) -> Result<Yaml, D::Error> {
        Yaml::deserialize(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Yaml, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = access.next_element()? {
            items.push(item);
        }
        Ok(Yaml::Seq(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Yaml, A::Error> {
        let mut entries: Vec<(Yaml, Yaml)> = Vec::new();
        while let Some(entry) = access.next_entry::<Yaml, Yaml>()? {
            entries.push(entry);
        }
        Ok(Yaml::Map(entries))
    }
}

impl<'de> Deserialize<'de> for Yaml {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Yaml, D::Error> {
        deserializer.deserialize_any(YamlVisitor)
    }
}

fn read_options() -> Options {
    let mut options = Options::default();
    options.with_snippet = false;
    options.reject_unsupported_tags = true;
    options.legacy_octal_numbers = true;
    options
}

fn write_options() -> SerializerOptions {
    let mut options = SerializerOptions::default();
    options.prefer_block_scalars = false;
    options
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KubeconfigError {
    #[error("it is not UTF-8 text")]
    NotUtf8,
    #[error("it is not valid YAML (line {line}, column {column})")]
    Syntax { line: u64, column: u64 },
    #[error("its top level is not a mapping")]
    NotAMapping,
    #[error(
        "it has no `apiVersion`; kubectl accepts that, but jaunt edits only files that say `apiVersion: v1` and `kind: Config`; write a complete copy with `kubectl --kubeconfig FILE config view --raw > NEWFILE` and use that"
    )]
    MissingApiVersion,
    #[error(
        "it has no `kind`; kubectl accepts that, but jaunt edits only files that say `apiVersion: v1` and `kind: Config`; write a complete copy with `kubectl --kubeconfig FILE config view --raw > NEWFILE` and use that"
    )]
    MissingKind,
    #[error("its `apiVersion` is not `v1`")]
    ApiVersion,
    #[error("its `kind` is not `Config`")]
    Kind,
    #[error("its `{list}` is not a list of entries that each have a name")]
    Malformed { list: &'static str },
    #[error(
        "an entry in `{list}` has the name {shown}, which YAML reads as a boolean or a number rather than text; put the name in quotes"
    )]
    NameNotText { list: &'static str, shown: String },
    #[error("its `current-context` is not text; put the name in quotes")]
    CurrentContext,
    #[error("it has a mapping key that is empty, a list or a mapping, which kubectl cannot read")]
    KeyNotText,
    #[error(
        "it repeats a mapping key (kubectl reads `1` and \"1\", or `yes` and `true`, as the same key)"
    )]
    RepeatedKey,
    #[error("the updated file cannot be written as YAML")]
    Render,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConflictError {
    #[error(
        "a context named `{name}` already exists and was not added by jaunt for this profile; choose another name with --context NAME"
    )]
    Context { name: String },
    #[error(
        "a {kind} entry named `{name}` already exists and was not added by jaunt for this profile; rename or remove it first"
    )]
    Entry { kind: &'static str, name: String },
    #[error("the {kind} entry `{name}` appears more than once; remove the extra entries first")]
    Repeated { kind: &'static str, name: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Kubeconfig {
    root: Vec<(Yaml, Yaml)>,
}

pub fn parse_yaml(text: &str) -> Result<Yaml, KubeconfigError> {
    serde_saphyr::from_str_with_options(text, read_options()).map_err(|err| {
        let (line, column) = err
            .location()
            .map_or((0, 0), |location| (location.line(), location.column()));
        KubeconfigError::Syntax { line, column }
    })
}

fn skeleton() -> Vec<(Yaml, Yaml)> {
    [
        ("apiVersion", Yaml::text(API_VERSION)),
        (CLUSTERS, Yaml::Seq(Vec::new())),
        (CONTEXTS, Yaml::Seq(Vec::new())),
        (CURRENT_CONTEXT, Yaml::text("")),
        ("kind", Yaml::text(KIND)),
        ("preferences", Yaml::Map(Vec::new())),
        (USERS, Yaml::Seq(Vec::new())),
    ]
    .into_iter()
    .map(|(key, value)| (Yaml::text(key), value))
    .collect()
}

fn key_text(key: &Yaml) -> Option<String> {
    match key {
        Yaml::Str(text) => Some(text.clone()),
        Yaml::Bool(value) => Some(value.to_string()),
        Yaml::Int(value) => Some(value.to_string()),
        Yaml::UInt(value) => Some(value.to_string()),
        Yaml::Float(value) => Some(value.to_string()),
        Yaml::Null | Yaml::Seq(_) | Yaml::Map(_) => None,
    }
}

fn check_keys(value: &Yaml) -> Result<(), KubeconfigError> {
    match value {
        Yaml::Map(entries) => {
            let mut seen = HashSet::with_capacity(entries.len());
            for (key, inner) in entries {
                let text = key_text(key).ok_or(KubeconfigError::KeyNotText)?;
                if !seen.insert(text) {
                    return Err(KubeconfigError::RepeatedKey);
                }
                check_keys(inner)?;
            }
            Ok(())
        }
        Yaml::Seq(items) => items.iter().try_for_each(check_keys),
        _ => Ok(()),
    }
}

fn check_name(list: &'static str, item: &Yaml) -> Result<(), KubeconfigError> {
    match item.get("name") {
        Some(Yaml::Str(_)) => Ok(()),
        Some(scalar @ (Yaml::Bool(_) | Yaml::Int(_) | Yaml::UInt(_) | Yaml::Float(_))) => {
            Err(KubeconfigError::NameNotText {
                list,
                shown: key_text(scalar).unwrap_or_default(),
            })
        }
        _ => Err(KubeconfigError::Malformed { list }),
    }
}

fn check_lists(root: &Yaml) -> Result<(), KubeconfigError> {
    for (list, _) in LISTS {
        match root.get(list) {
            None | Some(Yaml::Null) => {}
            Some(Yaml::Seq(items)) => {
                for item in items {
                    check_name(list, item)?;
                }
            }
            Some(_) => return Err(KubeconfigError::Malformed { list }),
        }
    }
    match root.get(CURRENT_CONTEXT) {
        None | Some(Yaml::Null | Yaml::Str(_)) => Ok(()),
        Some(_) => Err(KubeconfigError::CurrentContext),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginEntries {
    pub profile: String,
    pub cluster_entry: String,
    pub user_entry: String,
    pub context: String,
    pub server: String,
    pub certificate_authority_data: String,
    pub command: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginChanges {
    pub current_context_set: bool,
    pub current_context_missing: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurrentContextRule {
    SetWhenMissing,
    Keep,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Removal {
    pub contexts: Vec<String>,
    pub clusters: Vec<String>,
    pub users: Vec<String>,
    pub kept: Vec<KeptEntry>,
    pub current_context_removed: Option<String>,
}

impl Removal {
    pub fn is_empty(&self) -> bool {
        self.contexts.is_empty() && self.clusters.is_empty() && self.users.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeptEntry {
    pub kind: &'static str,
    pub name: String,
    pub used_by: String,
}

fn marker(profile: &str) -> Yaml {
    map(vec![
        (
            "extension",
            map(vec![(MARKER_PROFILE, Yaml::text(profile))]),
        ),
        ("name", Yaml::text(MARKER_NAME)),
    ])
}

pub fn is_marked(entry: &Yaml, inner: &str, profile: &str) -> bool {
    entry
        .get(inner)
        .and_then(|inner| inner.get("extensions"))
        .and_then(Yaml::as_seq)
        .is_some_and(|extensions| {
            extensions.iter().any(|extension| {
                extension.string_at(&["name"]) == Some(MARKER_NAME)
                    && extension.string_at(&["extension", MARKER_PROFILE]) == Some(profile)
            })
        })
}

fn entry_name(entry: &Yaml) -> Option<&str> {
    entry.string_at(&["name"])
}

fn exec_value(entries: &LoginEntries) -> Yaml {
    map(vec![
        ("apiVersion", Yaml::text(EXEC_API_VERSION)),
        (
            "args",
            Yaml::Seq(entries.args.iter().map(|arg| Yaml::text(arg)).collect()),
        ),
        ("command", Yaml::text(&entries.command)),
        ("interactiveMode", Yaml::text("IfAvailable")),
        ("provideClusterInfo", Yaml::Bool(false)),
    ])
}

struct Slot {
    list: &'static str,
    inner: &'static str,
    name: String,
    fields: Vec<(&'static str, Yaml)>,
}

impl Slot {
    fn new_entry(&self, profile: &str) -> Yaml {
        let mut inner: Vec<(&str, Yaml)> = self
            .fields
            .iter()
            .map(|(key, value)| (*key, value.clone()))
            .collect();
        inner.push(("extensions", Yaml::Seq(vec![marker(profile)])));
        inner.sort_by(|left, right| left.0.cmp(right.0));
        let mut entry = vec![(self.inner, map(inner)), ("name", Yaml::text(&self.name))];
        entry.sort_by(|left, right| left.0.cmp(right.0));
        map(entry)
    }

    fn conflict(&self) -> ConflictError {
        if self.list == CONTEXTS {
            ConflictError::Context {
                name: self.name.clone(),
            }
        } else {
            ConflictError::Entry {
                kind: self.inner,
                name: self.name.clone(),
            }
        }
    }
}

impl Kubeconfig {
    pub fn parse(contents: Option<&[u8]>) -> Result<Kubeconfig, KubeconfigError> {
        let Some(bytes) = contents else {
            return Ok(Kubeconfig { root: skeleton() });
        };
        let text = std::str::from_utf8(bytes).map_err(|_| KubeconfigError::NotUtf8)?;
        let root = match parse_yaml(text)? {
            Yaml::Null => return Ok(Kubeconfig { root: skeleton() }),
            root @ Yaml::Map(_) => root,
            _ => return Err(KubeconfigError::NotAMapping),
        };
        check_keys(&root)?;
        match root.get("apiVersion") {
            None | Some(Yaml::Null) => return Err(KubeconfigError::MissingApiVersion),
            Some(found) if found.as_str() != Some(API_VERSION) => {
                return Err(KubeconfigError::ApiVersion);
            }
            Some(_) => {}
        }
        match root.get("kind") {
            None | Some(Yaml::Null) => return Err(KubeconfigError::MissingKind),
            Some(found) if found.as_str() != Some(KIND) => return Err(KubeconfigError::Kind),
            Some(_) => {}
        }
        check_lists(&root)?;
        match root {
            Yaml::Map(root) => Ok(Kubeconfig { root }),
            _ => Err(KubeconfigError::NotAMapping),
        }
    }

    pub fn render(&self) -> Result<Vec<u8>, KubeconfigError> {
        let root = Yaml::Map(self.root.clone());
        let text = serde_saphyr::to_string_with_options(&root, write_options())
            .map_err(|_| KubeconfigError::Render)?;
        if parse_yaml(&text).ok().as_ref() != Some(&root) {
            return Err(KubeconfigError::Render);
        }
        Ok(text.into_bytes())
    }

    pub fn value(&self) -> Yaml {
        Yaml::Map(self.root.clone())
    }

    fn list(&self, key: &str) -> &[Yaml] {
        self.root
            .iter()
            .find(|(found, _)| found.as_str() == Some(key))
            .and_then(|(_, value)| value.as_seq())
            .unwrap_or_default()
    }

    fn set_list(&mut self, key: &str, items: Vec<Yaml>) {
        set_key(&mut self.root, key, Yaml::Seq(items));
    }

    pub fn current_context(&self) -> Option<&str> {
        self.root
            .iter()
            .find(|(found, _)| found.as_str() == Some(CURRENT_CONTEXT))
            .and_then(|(_, value)| value.as_str())
            .filter(|name| !name.is_empty())
    }

    pub fn merge_login(
        &mut self,
        entries: &LoginEntries,
        rule: CurrentContextRule,
    ) -> Result<LoginChanges, ConflictError> {
        let slots = [
            Slot {
                list: CLUSTERS,
                inner: "cluster",
                name: entries.cluster_entry.clone(),
                fields: vec![
                    (
                        "certificate-authority-data",
                        Yaml::text(&entries.certificate_authority_data),
                    ),
                    ("server", Yaml::text(&entries.server)),
                ],
            },
            Slot {
                list: USERS,
                inner: "user",
                name: entries.user_entry.clone(),
                fields: vec![("exec", exec_value(entries))],
            },
            Slot {
                list: CONTEXTS,
                inner: "context",
                name: entries.context.clone(),
                fields: vec![
                    ("cluster", Yaml::text(&entries.cluster_entry)),
                    ("user", Yaml::text(&entries.user_entry)),
                ],
            },
        ];
        let mut found = Vec::with_capacity(slots.len());
        for slot in &slots {
            let matching: Vec<usize> = self
                .list(slot.list)
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry_name(entry) == Some(slot.name.as_str()))
                .map(|(index, _)| index)
                .collect();
            match matching.as_slice() {
                [] => found.push(None),
                [index] => {
                    if !is_marked(&self.list(slot.list)[*index], slot.inner, &entries.profile) {
                        return Err(slot.conflict());
                    }
                    found.push(Some(*index));
                }
                _ => {
                    return Err(ConflictError::Repeated {
                        kind: slot.inner,
                        name: slot.name.clone(),
                    });
                }
            }
        }
        for (slot, index) in slots.iter().zip(found) {
            let mut list = self.list(slot.list).to_vec();
            match index.and_then(|index| list.get_mut(index)) {
                Some(entry) => {
                    if let Some(Yaml::Map(inner)) = entry.get_mut(slot.inner) {
                        for (key, value) in &slot.fields {
                            set_key(inner, key, value.clone());
                        }
                    }
                }
                None => list.push(slot.new_entry(&entries.profile)),
            }
            self.set_list(slot.list, list);
        }
        let current_context_set =
            rule == CurrentContextRule::SetWhenMissing && self.current_context().is_none();
        if current_context_set {
            set_key(
                &mut self.root,
                CURRENT_CONTEXT,
                Yaml::text(&entries.context),
            );
        }
        Ok(LoginChanges {
            current_context_set,
            current_context_missing: self.current_context().is_none(),
        })
    }

    pub fn remove_profile(&mut self, profile: &str, cluster_entry: Option<&str>) -> Removal {
        let mut removal = Removal::default();
        let (gone, kept): (Vec<Yaml>, Vec<Yaml>) =
            self.list(CONTEXTS).iter().cloned().partition(|context| {
                is_marked(context, "context", profile)
                    && cluster_entry.is_none_or(|wanted| {
                        context.string_at(&["context", "cluster"]) == Some(wanted)
                    })
            });
        let references: Vec<(&str, Option<&str>, Option<&str>)> = kept
            .iter()
            .map(|context| {
                (
                    entry_name(context).unwrap_or_default(),
                    context.string_at(&["context", "cluster"]),
                    context.string_at(&["context", "user"]),
                )
            })
            .collect();
        let cluster_user = |name: &str| {
            references
                .iter()
                .find(|(_, cluster, _)| *cluster == Some(name))
                .map(|(context, _, _)| (*context).to_owned())
        };
        let user_user = |name: &str| {
            references
                .iter()
                .find(|(_, _, user)| *user == Some(name))
                .map(|(context, _, _)| (*context).to_owned())
        };
        let removable_cluster = |entry: &Yaml| {
            is_marked(entry, "cluster", profile)
                && cluster_entry.is_none_or(|wanted| entry_name(entry) == Some(wanted))
        };
        let removable_user = |entry: &Yaml| is_marked(entry, "user", profile);
        let clusters = prune(
            self.list(CLUSTERS),
            "cluster",
            &removable_cluster,
            &cluster_user,
        );
        let users = prune(self.list(USERS), "user", &removable_user, &user_user);
        removal.contexts = gone
            .iter()
            .filter_map(entry_name)
            .map(str::to_owned)
            .collect();
        removal.clusters = clusters.removed;
        removal.users = users.removed;
        removal.kept = [clusters.kept_entries, users.kept_entries].concat();
        removal.current_context_removed = self
            .current_context()
            .filter(|current| removal.contexts.iter().any(|gone| gone == current))
            .map(str::to_owned);
        if !removal.contexts.is_empty() {
            self.set_list(CONTEXTS, kept);
        }
        if !removal.clusters.is_empty() {
            self.set_list(CLUSTERS, clusters.remaining);
        }
        if !removal.users.is_empty() {
            self.set_list(USERS, users.remaining);
        }
        removal
    }
}

struct Pruned {
    remaining: Vec<Yaml>,
    removed: Vec<String>,
    kept_entries: Vec<KeptEntry>,
}

fn prune(
    entries: &[Yaml],
    kind: &'static str,
    removable: &dyn Fn(&Yaml) -> bool,
    used_by: &dyn Fn(&str) -> Option<String>,
) -> Pruned {
    let mut pruned = Pruned {
        remaining: Vec::with_capacity(entries.len()),
        removed: Vec::new(),
        kept_entries: Vec::new(),
    };
    for entry in entries {
        let name = entry_name(entry).unwrap_or_default().to_owned();
        if !removable(entry) {
            pruned.remaining.push(entry.clone());
            continue;
        }
        match used_by(&name) {
            Some(context) => {
                pruned.kept_entries.push(KeptEntry {
                    kind,
                    name,
                    used_by: context,
                });
                pruned.remaining.push(entry.clone());
            }
            None => pruned.removed.push(name),
        }
    }
    pruned
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{
        ConflictError, CurrentContextRule, KeptEntry, Kubeconfig, KubeconfigError, LoginEntries,
        Yaml, is_marked, parse_yaml,
    };

    const RICH: &str = r#"# kept by kubectl users
apiVersion: v1
kind: Config
preferences:
  colors: true
current-context: work
clusters:
- name: work
  cluster:
    server: https://k8s.example.test:6443
    certificate-authority-data: Q0E=
    extensions:
    - name: client.authentication.k8s.io/exec
      extension:
        audience: work
- name: legacy
  cluster: {server: "http://localhost:8080", proxy-url: "socks5://localhost:1080"}
contexts:
- name: work
  context:
    cluster: work
    user: alice
    namespace: team
- name: legacy
  context: {cluster: legacy, user: token-user}
users:
- name: alice
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: aws
      args: [eks, get-token, --cluster-name, work]
      env:
      - name: AWS_PROFILE
        value: "yes"
      interactiveMode: Never
- name: token-user
  user:
    token: c2VjcmV0LXRva2Vu
- name: cert-user
  user:
    client-certificate-data: Q0VSVA==
    client-key-data: S0VZ
unknown-top-level:
  nested: [1, 2.5, true, null, "0755", on, 'it''s']
  multi: "line one\nline two"
"#;

    fn entries(profile: &str, cluster: &str) -> LoginEntries {
        let cluster_entry = format!("jaunt-{profile}-{cluster}");
        LoginEntries {
            profile: profile.to_owned(),
            context: cluster_entry.clone(),
            user_entry: format!("jaunt-{profile}"),
            cluster_entry,
            server: format!("https://{cluster}.kube.example.test"),
            certificate_authority_data: "Uk9PVFM=".to_owned(),
            command: "/usr/local/bin/jaunt".to_owned(),
            args: vec![
                "kube".to_owned(),
                "credentials".to_owned(),
                "--profile".to_owned(),
                profile.to_owned(),
            ],
        }
    }

    fn logged_in(base: Option<&str>, logins: &[(&str, &str)]) -> Kubeconfig {
        let mut config = Kubeconfig::parse(base.map(str::as_bytes)).unwrap();
        for (profile, cluster) in logins {
            config
                .merge_login(
                    &entries(profile, cluster),
                    CurrentContextRule::SetWhenMissing,
                )
                .unwrap();
        }
        config
    }

    fn reparsed(config: &Kubeconfig) -> Yaml {
        let rendered = config.render().unwrap();
        parse_yaml(std::str::from_utf8(&rendered).unwrap()).unwrap()
    }

    fn list<'a>(value: &'a Yaml, key: &str) -> &'a [Yaml] {
        value.get(key).and_then(Yaml::as_seq).unwrap_or_default()
    }

    fn list_names(value: &Yaml, key: &str) -> Vec<String> {
        list(value, key)
            .iter()
            .map(|entry| entry.string_at(&["name"]).unwrap().to_owned())
            .collect()
    }

    fn keys(value: &Yaml) -> Vec<String> {
        match value {
            Yaml::Map(entries) => entries
                .iter()
                .map(|(key, _)| key.as_str().unwrap().to_owned())
                .collect(),
            _ => Vec::new(),
        }
    }

    #[test]
    fn a_missing_or_empty_file_gets_one_cluster_user_and_context_and_a_current_context() {
        for base in [None, Some(""), Some("# nothing yet\n"), Some("---\n")] {
            let mut config = Kubeconfig::parse(base.map(str::as_bytes)).unwrap();

            let changes = config
                .merge_login(
                    &entries("default", "prod"),
                    CurrentContextRule::SetWhenMissing,
                )
                .unwrap();

            let value = reparsed(&config);
            assert!(changes.current_context_set, "{base:?}");
            assert_eq!(
                keys(&value),
                [
                    "apiVersion",
                    "clusters",
                    "contexts",
                    "current-context",
                    "kind",
                    "preferences",
                    "users"
                ]
            );
            assert_eq!(
                value.string_at(&["current-context"]),
                Some("jaunt-default-prod")
            );
            let cluster = &list(&value, "clusters")[0];
            assert_eq!(
                cluster.string_at(&["cluster", "server"]),
                Some("https://prod.kube.example.test")
            );
            assert_eq!(
                cluster.string_at(&["cluster", "certificate-authority-data"]),
                Some("Uk9PVFM=")
            );
            let context = &list(&value, "contexts")[0];
            assert_eq!(
                context.string_at(&["context", "cluster"]),
                Some("jaunt-default-prod")
            );
            assert_eq!(
                context.string_at(&["context", "user"]),
                Some("jaunt-default")
            );
            let user = &list(&value, "users")[0];
            let exec = user.get("user").and_then(|user| user.get("exec")).unwrap();
            assert_eq!(
                exec.string_at(&["apiVersion"]),
                Some("client.authentication.k8s.io/v1")
            );
            assert_eq!(exec.string_at(&["command"]), Some("/usr/local/bin/jaunt"));
            assert_eq!(exec.string_at(&["interactiveMode"]), Some("IfAvailable"));
            assert_eq!(exec.get("provideClusterInfo"), Some(&Yaml::Bool(false)));
            assert_eq!(
                exec.get("args"),
                Some(&Yaml::Seq(
                    entries("default", "prod")
                        .args
                        .iter()
                        .map(|arg| Yaml::text(arg))
                        .collect()
                ))
            );
            for (key, inner) in [
                ("clusters", "cluster"),
                ("contexts", "context"),
                ("users", "user"),
            ] {
                assert!(is_marked(&list(&value, key)[0], inner, "default"), "{key}");
                assert!(!is_marked(&list(&value, key)[0], inner, "other"), "{key}");
            }
        }
    }

    #[test]
    fn unrelated_entries_and_unknown_fields_survive_as_data_in_their_order() {
        let original = parse_yaml(RICH).unwrap();
        let config = logged_in(Some(RICH), &[("default", "prod")]);

        let merged = reparsed(&config);

        let original_keys = keys(&original);
        assert_eq!(
            &keys(&merged)[..original_keys.len()],
            original_keys.as_slice()
        );
        for key in &original_keys {
            match key.as_str() {
                "clusters" | "contexts" | "users" => {
                    let before = list(&original, key);
                    let after = list(&merged, key);
                    assert_eq!(&after[..before.len()], before, "{key}");
                    assert_eq!(after.len(), before.len() + 1, "{key}");
                }
                _ => assert_eq!(merged.get(key), original.get(key), "{key}"),
            }
        }
        assert_eq!(merged.string_at(&["current-context"]), Some("work"));
        assert_eq!(
            merged.string_at(&["unknown-top-level", "multi"]),
            Some("line one\nline two")
        );
        let rendered = config.render().unwrap();
        let again = Kubeconfig::parse(Some(&rendered))
            .unwrap()
            .render()
            .unwrap();
        assert_eq!(again, rendered);
    }

    #[test]
    fn repeating_a_login_changes_nothing_and_another_cluster_shares_the_user_entry() {
        let once = logged_in(Some(RICH), &[("default", "prod")]);
        let twice = logged_in(Some(RICH), &[("default", "prod"), ("default", "prod")]);
        assert_eq!(once, twice);
        assert_eq!(once.render().unwrap(), twice.render().unwrap());

        let both = reparsed(&logged_in(
            Some(RICH),
            &[
                ("default", "prod"),
                ("default", "stage"),
                ("default", "prod"),
            ],
        ));

        assert_eq!(
            list_names(&both, "clusters"),
            [
                "work",
                "legacy",
                "jaunt-default-prod",
                "jaunt-default-stage"
            ]
        );
        assert_eq!(
            list_names(&both, "contexts"),
            [
                "work",
                "legacy",
                "jaunt-default-prod",
                "jaunt-default-stage"
            ]
        );
        assert_eq!(
            list_names(&both, "users"),
            ["alice", "token-user", "cert-user", "jaunt-default"]
        );
        let stage = &list(&both, "contexts")[3];
        assert_eq!(stage.string_at(&["context", "user"]), Some("jaunt-default"));
    }

    #[test]
    fn an_owned_entry_is_updated_in_place_keeping_the_fields_a_person_added() {
        let mut config = logged_in(None, &[("default", "prod")]);
        let mut value = config.value();
        if let Some(Yaml::Seq(contexts)) = value.get_mut("contexts")
            && let Some(Yaml::Map(inner)) = contexts[0].get_mut("context")
        {
            inner.push((Yaml::text("namespace"), Yaml::text("team")));
        }
        let text = String::from_utf8(
            Kubeconfig {
                root: match value {
                    Yaml::Map(root) => root,
                    _ => Vec::new(),
                },
            }
            .render()
            .unwrap(),
        )
        .unwrap();
        config = Kubeconfig::parse(Some(text.as_bytes())).unwrap();
        let mut moved = entries("default", "prod");
        moved.server = "https://prod.kube.moved.test".to_owned();
        moved.command = "/opt/jaunt/bin/jaunt".to_owned();

        config
            .merge_login(&moved, CurrentContextRule::SetWhenMissing)
            .unwrap();

        let value = reparsed(&config);
        let context = &list(&value, "contexts")[0];
        assert_eq!(context.string_at(&["context", "namespace"]), Some("team"));
        assert_eq!(
            list(&value, "clusters")[0].string_at(&["cluster", "server"]),
            Some("https://prod.kube.moved.test")
        );
        assert_eq!(
            list(&value, "users")[0].string_at(&["user", "exec", "command"]),
            Some("/opt/jaunt/bin/jaunt")
        );
        assert_eq!(list(&value, "clusters").len(), 1);
    }

    #[test]
    fn an_entry_of_the_same_name_not_added_for_this_profile_is_never_overwritten() {
        let unmarked = |list: &str, inner: &str, name: &str| {
            format!(
                "apiVersion: v1\nkind: Config\n{list}:\n- name: {name}\n  {inner}: {{keep: me}}\n"
            )
        };
        let cases = [
            (
                unmarked("contexts", "context", "jaunt-default-prod"),
                ConflictError::Context {
                    name: "jaunt-default-prod".to_owned(),
                },
            ),
            (
                unmarked("clusters", "cluster", "jaunt-default-prod"),
                ConflictError::Entry {
                    kind: "cluster",
                    name: "jaunt-default-prod".to_owned(),
                },
            ),
            (
                unmarked("users", "user", "jaunt-default"),
                ConflictError::Entry {
                    kind: "user",
                    name: "jaunt-default".to_owned(),
                },
            ),
            (
                "apiVersion: v1\nkind: Config\nusers:\n- name: jaunt-default\n  user: {}\n- name: jaunt-default\n  user: {}\n"
                    .to_owned(),
                ConflictError::Repeated {
                    kind: "user",
                    name: "jaunt-default".to_owned(),
                },
            ),
        ];
        for (text, expected) in cases {
            let mut config = Kubeconfig::parse(Some(text.as_bytes())).unwrap();
            let before = config.clone();

            let outcome = config.merge_login(
                &entries("default", "prod"),
                CurrentContextRule::SetWhenMissing,
            );

            assert_eq!(outcome, Err(expected), "{text}");
            assert_eq!(config, before, "{text}");
        }

        let mut config = logged_in(None, &[("a-b", "c")]);
        let before = config.clone();
        let outcome = config.merge_login(&entries("a", "b-c"), CurrentContextRule::SetWhenMissing);
        assert_eq!(
            outcome,
            Err(ConflictError::Entry {
                kind: "cluster",
                name: "jaunt-a-b-c".to_owned()
            })
        );
        assert_eq!(config, before);
        assert!(
            outcome
                .unwrap_err()
                .to_string()
                .contains("rename or remove it")
        );
        let context = ConflictError::Context {
            name: "x".to_owned(),
        };
        assert!(context.to_string().contains("--context NAME"));
    }

    #[test]
    fn a_file_that_is_not_a_v1_config_is_refused() {
        let cases: [(&[u8], KubeconfigError); 15] = [
            (
                b"clusters: [\n",
                KubeconfigError::Syntax { line: 2, column: 1 },
            ),
            (
                b"a: 1\n---\nb: 2\n",
                KubeconfigError::Syntax { line: 3, column: 1 },
            ),
            (b"\xff\xfe", KubeconfigError::NotUtf8),
            (b"- a\n- b\n", KubeconfigError::NotAMapping),
            (b"kind: Config\n", KubeconfigError::MissingApiVersion),
            (b"apiVersion: v1\n", KubeconfigError::MissingKind),
            (
                b"apiVersion: v2\nkind: Config\n",
                KubeconfigError::ApiVersion,
            ),
            (b"apiVersion: v1\nkind: Pod\n", KubeconfigError::Kind),
            (
                b"apiVersion: v1\nkind: Config\nusers: {a: 1}\n",
                KubeconfigError::Malformed { list: "users" },
            ),
            (
                b"apiVersion: v1\nkind: Config\ncurrent-context: [a]\n",
                KubeconfigError::CurrentContext,
            ),
            (
                b"apiVersion: v1\nkind: Config\ncontexts:\n- name: yes\n  context: {}\n",
                KubeconfigError::NameNotText {
                    list: "contexts",
                    shown: "true".to_owned(),
                },
            ),
            (
                b"apiVersion: v1\nkind: Config\nusers:\n- name: 1\n  user: {}\n",
                KubeconfigError::NameNotText {
                    list: "users",
                    shown: "1".to_owned(),
                },
            ),
            (
                b"apiVersion: v1\nkind: Config\nextra: {1: a, \"1\": b}\n",
                KubeconfigError::RepeatedKey,
            ),
            (
                b"apiVersion: v1\nkind: Config\nextra: [{y: a, true: b}]\n",
                KubeconfigError::RepeatedKey,
            ),
            (
                b"apiVersion: v1\nkind: Config\nextra: {~: a}\n",
                KubeconfigError::KeyNotText,
            ),
        ];
        for (bytes, expected) in cases {
            let outcome = Kubeconfig::parse(Some(bytes));
            match (&outcome, &expected) {
                (Err(KubeconfigError::Syntax { .. }), KubeconfigError::Syntax { .. }) => {}
                _ => assert_eq!(outcome.as_ref().err(), Some(&expected), "{bytes:?}"),
            }
        }
        let unnamed = b"apiVersion: v1\nkind: Config\nclusters:\n- cluster: {}\n";
        assert_eq!(
            Kubeconfig::parse(Some(unnamed)).err(),
            Some(KubeconfigError::Malformed { list: "clusters" })
        );
        let secret =
            b"apiVersion: v1\nkind: Config\nusers:\n- name: a\n  user: {token: s3cr3t-value\n";
        let message = Kubeconfig::parse(Some(secret)).unwrap_err().to_string();
        assert!(!message.contains("s3cr3t"), "{message}");
        let missing = KubeconfigError::MissingKind.to_string();
        assert!(missing.contains("kubectl accepts that"), "{missing}");
        assert!(missing.contains("config view --raw"), "{missing}");
    }

    #[test]
    fn many_keys_are_checked_in_linear_time() {
        let mut text = String::from("apiVersion: v1\nkind: Config\nextra:\n");
        for key in 0..20_000 {
            text.push_str(&format!("  {key}: x\n  k{key}: value\n"));
        }
        let started = Instant::now();

        let config = Kubeconfig::parse(Some(text.as_bytes())).unwrap();

        assert!(
            started.elapsed() < Duration::from_secs(20),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(
            config
                .value()
                .get("extra")
                .and_then(|extra| extra.get("k19999")),
            Some(&Yaml::text("value"))
        );
    }

    #[test]
    fn strings_that_a_yaml_reader_could_take_for_something_else_stay_quoted() {
        let words = [
            "y",
            "n",
            "on",
            "off",
            "~",
            "null",
            "0o17",
            "1_000",
            "12:30",
            "<<",
            "---",
            "0O17",
            "0X1f",
            "0B11",
            "1__0",
            "1_",
            "tRUE",
            "yEs",
            "nULL",
            "Off",
            ".inf",
            ".NaN",
            "-.5",
            "+1",
            "1e3",
            "0x_1",
            "2001-12-14",
            "1:2:3",
            "=",
            "",
            " lead",
            "#x",
            "- x",
        ];
        let mut root = vec![
            (Yaml::text("apiVersion"), Yaml::text("v1")),
            (Yaml::text("kind"), Yaml::text("Config")),
        ];
        for (index, word) in words.iter().enumerate() {
            root.push((Yaml::text(&format!("key{index}")), Yaml::text(word)));
            root.push((Yaml::text(word), Yaml::text(&format!("value{index}"))));
        }
        let config = Kubeconfig { root };

        let rendered = String::from_utf8(config.render().unwrap()).unwrap();

        for (index, word) in words.iter().enumerate() {
            let quoted = [format!("\"{word}\""), format!("'{word}'")];
            let as_value = rendered
                .lines()
                .find_map(|line| line.strip_prefix(&format!("key{index}: ")))
                .unwrap();
            assert!(
                quoted.iter().any(|form| form == as_value),
                "{word:?}: {as_value}"
            );
            let as_key = format!("value{index}");
            let key_line = rendered
                .lines()
                .find(|line| line.ends_with(&format!(": {as_key}")))
                .unwrap();
            assert!(
                quoted
                    .iter()
                    .any(|form| key_line.starts_with(form.as_str())),
                "{word:?}: {key_line}"
            );
        }
        assert_eq!(
            Kubeconfig::parse(Some(rendered.as_bytes())).unwrap(),
            config
        );
    }

    #[test]
    fn a_value_that_would_not_read_back_the_same_is_never_rendered() {
        let config = Kubeconfig {
            root: vec![
                (Yaml::text("apiVersion"), Yaml::text("v1")),
                (Yaml::text("kind"), Yaml::text("Config")),
                (Yaml::text("ratio"), Yaml::Float(f64::NAN)),
            ],
        };

        assert_eq!(config.render(), Err(KubeconfigError::Render));
    }

    #[test]
    fn the_current_context_is_set_only_when_the_file_has_none() {
        let cases = [
            ("", true),
            ("current-context: null\n", true),
            ("current-context: ''\n", true),
            ("current-context: work\n", false),
        ];
        for (line, set) in cases {
            let text = format!("apiVersion: v1\nkind: Config\n{line}");
            let mut config = Kubeconfig::parse(Some(text.as_bytes())).unwrap();
            let mut kept = config.clone();

            let changes = config
                .merge_login(
                    &entries("default", "prod"),
                    CurrentContextRule::SetWhenMissing,
                )
                .unwrap();
            let unset = kept
                .merge_login(&entries("default", "prod"), CurrentContextRule::Keep)
                .unwrap();

            assert_eq!(changes.current_context_set, set, "{line:?}");
            let expected = if set { "jaunt-default-prod" } else { "work" };
            assert_eq!(config.current_context(), Some(expected), "{line:?}");
            assert!(!unset.current_context_set, "{line:?}");
            let untouched = if set { None } else { Some("work") };
            assert_eq!(kept.current_context(), untouched, "{line:?}");
        }
    }

    #[test]
    fn logout_removes_only_marked_entries_and_keeps_a_shared_user_while_it_is_used() {
        let mut config = logged_in(
            Some(RICH),
            &[("default", "prod"), ("default", "stage"), ("work", "prod")],
        );
        let untouched = |value: &Yaml| {
            for (key, names) in [
                ("clusters", vec!["work", "legacy"]),
                ("contexts", vec!["work", "legacy"]),
                ("users", vec!["alice", "token-user", "cert-user"]),
            ] {
                let found = list_names(value, key);
                assert_eq!(&found[..names.len()], names.as_slice(), "{key}");
            }
        };

        let one = config.remove_profile("default", Some("jaunt-default-prod"));

        assert_eq!(one.contexts, ["jaunt-default-prod"]);
        assert_eq!(one.clusters, ["jaunt-default-prod"]);
        assert!(one.users.is_empty());
        assert_eq!(
            one.kept,
            [KeptEntry {
                kind: "user",
                name: "jaunt-default".to_owned(),
                used_by: "jaunt-default-stage".to_owned()
            }]
        );
        let value = reparsed(&config);
        untouched(&value);
        assert_eq!(
            list_names(&value, "users"),
            [
                "alice",
                "token-user",
                "cert-user",
                "jaunt-default",
                "jaunt-work"
            ]
        );
        assert_eq!(value.string_at(&["current-context"]), Some("work"));

        let rest = config.remove_profile("default", None);

        assert_eq!(rest.contexts, ["jaunt-default-stage"]);
        assert_eq!(rest.clusters, ["jaunt-default-stage"]);
        assert_eq!(rest.users, ["jaunt-default"]);
        let value = reparsed(&config);
        untouched(&value);
        assert_eq!(
            list_names(&value, "clusters"),
            ["work", "legacy", "jaunt-work-prod"]
        );
        assert_eq!(
            list_names(&value, "contexts"),
            ["work", "legacy", "jaunt-work-prod"]
        );
        assert_eq!(
            list_names(&value, "users"),
            ["alice", "token-user", "cert-user", "jaunt-work"]
        );
        let before = config.clone();
        assert!(config.remove_profile("default", None).is_empty());
        assert_eq!(config, before);
    }

    #[test]
    fn logout_keeps_an_owned_entry_that_a_hand_made_context_still_uses() {
        let mut config = logged_in(None, &[("default", "prod")]);
        let text = String::from_utf8(config.render().unwrap())
            .unwrap()
            .replace(
                "contexts:\n",
                "contexts:\n- name: mine\n  context:\n    cluster: jaunt-default-prod\n    user: jaunt-default\n",
            );
        config = Kubeconfig::parse(Some(text.as_bytes())).unwrap();

        let removal = config.remove_profile("default", None);

        assert_eq!(removal.contexts, ["jaunt-default-prod"]);
        assert!(removal.clusters.is_empty() && removal.users.is_empty());
        assert_eq!(
            removal.kept,
            [
                KeptEntry {
                    kind: "cluster",
                    name: "jaunt-default-prod".to_owned(),
                    used_by: "mine".to_owned()
                },
                KeptEntry {
                    kind: "user",
                    name: "jaunt-default".to_owned(),
                    used_by: "mine".to_owned()
                }
            ]
        );
        assert_eq!(
            removal.current_context_removed.as_deref(),
            Some("jaunt-default-prod")
        );
        assert_eq!(list_names(&reparsed(&config), "contexts"), ["mine"]);
    }
}
