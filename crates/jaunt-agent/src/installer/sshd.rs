use std::fs;

use super::env::Env;
use super::error::{InstallError, ValidationProblem};
use super::layout::{DEFAULT_SSHD, DROPIN_PATH, Layout, SSHD_CONFIG};
use super::runner::{Output, RunnerError, command_line, excerpt};

pub const LOOPBACK_SPEC: &str = "addr=127.0.0.1,user=root,host=localhost,laddr=127.0.0.1,lport=22";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    Trusted,
    NotTrusted,
}

#[derive(Debug, Clone, Copy)]
pub struct Probe {
    pub spec: &'static str,
    pub expect: Expect,
}

pub const PROBES: [Probe; 4] = [
    Probe {
        spec: LOOPBACK_SPEC,
        expect: Expect::Trusted,
    },
    Probe {
        spec: "addr=::1,user=root,host=localhost,laddr=::1,lport=22",
        expect: Expect::Trusted,
    },
    Probe {
        spec: "addr=10.255.255.1,laddr=10.255.255.2,lport=22",
        expect: Expect::NotTrusted,
    },
    Probe {
        spec: "addr=203.0.113.9,laddr=203.0.113.10,lport=22",
        expect: Expect::NotTrusted,
    },
];

pub const LOOPBACK_DEPLOY_SPEC: &str =
    "addr=127.0.0.1,user=deploy,host=localhost,laddr=127.0.0.1,lport=22";

pub struct Sshd {
    program: String,
    config: Option<String>,
}

impl Sshd {
    pub fn locate(layout: &Layout, path_env: &str) -> Result<Self, InstallError> {
        let mut candidates = vec![DEFAULT_SSHD.to_string()];
        for dir in path_env.split(':') {
            if dir.starts_with('/') {
                candidates.push(format!("{}/sshd", dir.trim_end_matches('/')));
            }
        }
        for candidate in candidates {
            let real = layout.path(&candidate);
            if fs::metadata(&real)
                .map(|meta| meta.is_file())
                .unwrap_or(false)
            {
                return Ok(Self {
                    program: real.to_string_lossy().into_owned(),
                    config: (!layout.is_live()).then(|| layout.path_string(SSHD_CONFIG)),
                });
            }
        }
        Err(InstallError::SshdNotFound)
    }

    pub fn command(&self, tail: &[&str]) -> (String, Vec<String>) {
        let mut args = Vec::new();
        if let Some(config) = &self.config {
            args.push("-f".to_string());
            args.push(config.clone());
        }
        args.extend(tail.iter().map(|arg| arg.to_string()));
        (self.program.clone(), args)
    }

    pub fn command_text(&self, tail: &[&str]) -> String {
        let (program, args) = self.command(tail);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        command_line(&program, &refs)
    }

    pub fn syntax_check(&self, env: &mut Env<'_>) -> Result<Output, RunnerError> {
        self.run(env, &["-t"])
    }

    pub fn effective(&self, env: &mut Env<'_>, spec: Option<&str>) -> Result<Output, RunnerError> {
        match spec {
            Some(spec) => self.run(env, &["-T", "-C", spec]),
            None => self.run(env, &["-T"]),
        }
    }

    fn run(&self, env: &mut Env<'_>, tail: &[&str]) -> Result<Output, RunnerError> {
        let (program, args) = self.command(tail);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        env.query(&program, &refs)
    }

    pub fn validation_plan(&self) -> Vec<String> {
        let mut plan = vec![self.command_text(&["-t"])];
        plan.extend(
            PROBES
                .iter()
                .map(|probe| self.command_text(&["-T", "-C", probe.spec])),
        );
        plan
    }

    pub fn validate_dropin(
        &self,
        env: &mut Env<'_>,
        ca_path: &str,
    ) -> Result<(), ValidationProblem> {
        let test = self.syntax_check(env)?;
        if !test.success() {
            return Err(ValidationProblem::ConfigTest {
                stderr: excerpt(&test.stderr),
            });
        }
        for probe in PROBES {
            let output = self.effective(env, Some(probe.spec))?;
            if !output.success() {
                return Err(ValidationProblem::ProbeCommand {
                    spec: probe.spec.to_string(),
                    stderr: excerpt(&output.stderr),
                });
            }
            check_probe(&probe, &Effective::parse(&output.stdout), ca_path)?;
        }
        Ok(())
    }
}

pub fn check_probe(
    probe: &Probe,
    effective: &Effective,
    ca_path: &str,
) -> Result<(), ValidationProblem> {
    let values = effective.values("trustedusercakeys");
    let observed = if values.is_empty() {
        "no trustedusercakeys line".to_string()
    } else {
        format!("trustedusercakeys {}", values.join(" "))
    };
    let ok = match probe.expect {
        Expect::Trusted => values == [ca_path],
        Expect::NotTrusted => values.iter().all(|value| *value == "none"),
    };
    if ok {
        return Ok(());
    }
    let expected = match probe.expect {
        Expect::Trusted => format!("trustedusercakeys {ca_path}"),
        Expect::NotTrusted => "no user CA trust (trustedusercakeys none)".to_string(),
    };
    Err(ValidationProblem::Mismatch {
        spec: probe.spec.to_string(),
        expected,
        observed,
    })
}

pub fn preexisting_trust(effective: &Effective, allowed: Option<&str>) -> Option<String> {
    let offending: Vec<&str> = effective
        .values("trustedusercakeys")
        .into_iter()
        .filter(|value| *value != "none" && Some(*value) != allowed)
        .collect();
    if offending.is_empty() {
        None
    } else {
        Some(offending.join(" "))
    }
}

#[derive(Debug, Default)]
pub struct Effective {
    entries: Vec<(String, String)>,
}

impl Effective {
    pub fn parse(text: &str) -> Self {
        let mut entries = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (key, value) = match line.split_once(char::is_whitespace) {
                Some((key, value)) => (key, value.trim()),
                None => (line, ""),
            };
            entries.push((key.to_ascii_lowercase(), value.to_string()));
        }
        Self { entries }
    }

    pub fn values(&self, key: &str) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn first(&self, key: &str) -> Option<&str> {
        self.values(key).into_iter().next()
    }
}

fn listen_host(entry: &str) -> &str {
    if let Some(rest) = entry.strip_prefix('[') {
        return rest.split_once(']').map_or(rest, |(host, _)| host);
    }
    if entry.matches(':').count() == 1 {
        return entry.split_once(':').map_or(entry, |(host, _)| host);
    }
    entry
}

pub fn serves_loopback(listen_addresses: &[&str]) -> bool {
    listen_addresses
        .iter()
        .any(|entry| matches!(listen_host(entry), "0.0.0.0" | "::" | "127.0.0.1" | "::1"))
}

pub fn split_keyword(line: &str) -> (&str, &str) {
    let end = line
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(line.len());
    let (keyword, rest) = line.split_at(end);
    (
        keyword,
        rest.trim_start_matches(|c: char| c.is_whitespace() || c == '='),
    )
}

pub fn includes_dropin(config: &str) -> bool {
    for raw in config.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (keyword, rest) = split_keyword(line);
        if keyword.eq_ignore_ascii_case("match") {
            return false;
        }
        if keyword.eq_ignore_ascii_case("include")
            && rest
                .split_whitespace()
                .any(|pattern| pattern_matches(pattern.trim_matches('"'), DROPIN_PATH))
        {
            return true;
        }
    }
    false
}

fn pattern_matches(pattern: &str, path: &str) -> bool {
    let absolute = if pattern.starts_with('/') {
        pattern.to_string()
    } else {
        format!("/etc/ssh/{pattern}")
    };
    let pattern_parts: Vec<&str> = absolute.split('/').collect();
    let path_parts: Vec<&str> = path.split('/').collect();
    pattern_parts.len() == path_parts.len()
        && pattern_parts
            .iter()
            .zip(&path_parts)
            .all(|(pattern, part)| segment_matches(pattern, part))
}

pub fn segment_matches(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut p, mut t) = (0, 0);
    let mut backtrack: Option<(usize, usize)> = None;
    while t < text.len() {
        if p < pattern.len() && pattern[p] == '*' {
            backtrack = Some((p, t));
            p += 1;
        } else if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if let Some((star, matched)) = backtrack {
            p = star + 1;
            t = matched + 1;
            backtrack = Some((star, matched + 1));
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::super::error::InstallError;
    use super::super::layout::Layout;
    use super::super::testing::TempRoot;
    use super::{
        Effective, Expect, PROBES, Probe, Sshd, check_probe, includes_dropin, listen_host,
        preexisting_trust, serves_loopback,
    };

    const CA: &str = "/var/lib/jaunt/inner-ca.pub";

    #[test]
    fn preexisting_trust_allows_only_none_and_the_allowed_path() {
        let cases = [
            ("port 22\n", None, None),
            ("trustedusercakeys none\n", None, None),
            (
                "trustedusercakeys /etc/ssh/ca.pub\n",
                None,
                Some("/etc/ssh/ca.pub"),
            ),
            (
                "trustedusercakeys /var/lib/jaunt/inner-ca.pub\n",
                None,
                Some(CA),
            ),
            (
                "trustedusercakeys /var/lib/jaunt/inner-ca.pub\n",
                Some(CA),
                None,
            ),
            (
                "trustedusercakeys /etc/ssh/ca.pub\n",
                Some(CA),
                Some("/etc/ssh/ca.pub"),
            ),
        ];
        for (text, allowed, expected) in cases {
            assert_eq!(
                preexisting_trust(&Effective::parse(text), allowed).as_deref(),
                expected,
                "{text}"
            );
        }
    }

    #[test]
    fn sshd_is_found_at_the_default_path_then_in_path_else_refused() {
        let root = TempRoot::new();
        let layout = Layout::new(root.path()).unwrap();
        assert!(matches!(
            Sshd::locate(&layout, "/opt/ssh/sbin"),
            Err(InstallError::SshdNotFound)
        ));
        root.write("/opt/ssh/sbin/sshd", "");
        let from_path = Sshd::locate(&layout, "relative:/opt/ssh/sbin").unwrap();
        assert!(from_path.command(&["-t"]).0.ends_with("/opt/ssh/sbin/sshd"));
        root.write("/usr/sbin/sshd", "");
        let default = Sshd::locate(&layout, "/opt/ssh/sbin").unwrap();
        assert!(default.command(&["-t"]).0.ends_with("/usr/sbin/sshd"));
    }

    #[test]
    fn effective_config_is_parsed_as_lowercase_key_value_lines() {
        let effective = Effective::parse(
            "port 22\nListenAddress 0.0.0.0:22\nlistenaddress [::]:22\n\nauthenticationmethods any\npermitrootlogin\n",
        );
        assert_eq!(
            effective.values("listenaddress"),
            vec!["0.0.0.0:22", "[::]:22"]
        );
        assert_eq!(effective.first("authenticationmethods"), Some("any"));
        assert_eq!(effective.first("permitrootlogin"), Some(""));
        assert_eq!(effective.first("trustedusercakeys"), None);
    }

    #[test]
    fn loopback_service_detection_table() {
        let cases: [(&[&str], bool); 9] = [
            (&["0.0.0.0:22"], true),
            (&["[::]:22"], true),
            (&["127.0.0.1:22"], true),
            (&["[::1]:2222"], true),
            (&["::"], true),
            (&["192.0.2.1:22"], false),
            (&["192.0.2.1:22", "[2001:db8::1]:22"], false),
            (&["192.0.2.1:22", "127.0.0.1:22"], true),
            (&[], false),
        ];
        for (entries, expected) in cases {
            assert_eq!(serves_loopback(entries), expected, "{entries:?}");
        }
        assert_eq!(listen_host("[2001:db8::1]:22"), "2001:db8::1");
    }

    #[test]
    fn include_detection_table() {
        let cases = [
            ("Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n", true),
            ("# comment\n  include /etc/ssh/sshd_config.d/*.conf\n", true),
            ("Include sshd_config.d/*.conf\n", true),
            ("Include \"/etc/ssh/sshd_config.d/*.conf\"\n", true),
            ("Include=/etc/ssh/sshd_config.d/*\n", true),
            (
                "Include /etc/ssh/other.d/*.conf /etc/ssh/sshd_config.d/*.conf\n",
                true,
            ),
            ("Port 22\n", false),
            ("#Include /etc/ssh/sshd_config.d/*.conf\n", false),
            ("Include /etc/ssh/other.d/*.conf\n", false),
            ("Include /etc/ssh/sshd_config.d/*.disabled\n", false),
            ("Include /etc/ssh/sshd_config.d/*/*.conf\n", false),
            (
                "Match User bob\nInclude /etc/ssh/sshd_config.d/*.conf\n",
                false,
            ),
            ("Port 22\nMatch all\n", false),
        ];
        for (config, expected) in cases {
            assert_eq!(includes_dropin(config), expected, "{config}");
        }
    }

    fn effective_with(trust: Option<&str>) -> Effective {
        match trust {
            Some(value) => Effective::parse(&format!("trustedusercakeys {value}\n")),
            None => Effective::parse("port 22\n"),
        }
    }

    #[test]
    fn loopback_probes_require_exactly_the_inner_ca_path() {
        let loopback: &Probe = &PROBES[0];
        assert_eq!(loopback.expect, Expect::Trusted);
        assert!(check_probe(loopback, &effective_with(Some(CA)), CA).is_ok());
        assert!(check_probe(loopback, &effective_with(Some("none")), CA).is_err());
        assert!(check_probe(loopback, &effective_with(None), CA).is_err());
        assert!(check_probe(loopback, &effective_with(Some("/etc/ssh/other.pub")), CA).is_err());
        assert!(check_probe(loopback, &effective_with(Some(&format!("{CA} /x"))), CA).is_err());
    }

    #[test]
    fn outside_probes_accept_only_none_or_absent() {
        for probe in &PROBES[2..] {
            assert_eq!(probe.expect, Expect::NotTrusted);
            assert!(check_probe(probe, &effective_with(Some("none")), CA).is_ok());
            assert!(check_probe(probe, &effective_with(None), CA).is_ok());
            assert!(check_probe(probe, &effective_with(Some(CA)), CA).is_err());
            assert!(check_probe(probe, &effective_with(Some("/etc/ssh/other.pub")), CA).is_err());
        }
    }
}
