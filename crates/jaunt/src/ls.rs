use std::collections::BTreeMap;

use clap::ValueEnum;
use jaunt_proto::{NodeList, NodeSummary, ServiceKind, ServiceList};
use serde::Serialize;

use crate::display::printable;
use crate::ssh_config::is_dns_label;

const NAME_HEADER: &str = "NAME";
const LABELS_HEADER: &str = "LABELS";
const KIND_HEADER: &str = "KIND";
const CONNECTED_HEADER: &str = "CONNECTED";
const COLUMN_GAP: usize = 2;
const NO_LABELS: &str = "-";
const SSH_KIND: &str = "ssh";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ListKind {
    Ssh,
    Kube,
    Db,
    Tcp,
    All,
}

impl ListKind {
    pub fn includes(self, kind: ServiceKind) -> bool {
        match self {
            ListKind::Ssh => false,
            ListKind::Kube => kind == ServiceKind::Kubernetes,
            ListKind::Db => kind == ServiceKind::Postgres,
            ListKind::Tcp => kind == ServiceKind::Tcp,
            ListKind::All => true,
        }
    }
}

pub fn kind_label(kind: ServiceKind) -> &'static str {
    match kind {
        ServiceKind::Kubernetes => "kube",
        ServiceKind::Postgres => "db",
        ServiceKind::Tcp => "tcp",
    }
}

pub fn select_services(list: ServiceList, kind: ListKind) -> ServiceList {
    ServiceList {
        services: list
            .services
            .into_iter()
            .filter(|service| kind.includes(service.kind))
            .collect(),
        truncated: list.truncated,
    }
}

fn full_name(node: &NodeSummary, suffix: Option<&str>) -> String {
    match suffix {
        Some(suffix) => printable(&format!("{}.{suffix}", node.name)),
        None => printable(&node.name),
    }
}

fn labels_text(labels: &BTreeMap<String, String>) -> String {
    if labels.is_empty() {
        return NO_LABELS.to_owned();
    }
    let pairs: Vec<String> = labels
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    printable(&pairs.join(","))
}

fn label_text(node: &NodeSummary) -> String {
    labels_text(&node.labels)
}

fn connected_text(connected: bool) -> &'static str {
    if connected { "yes" } else { "no" }
}

pub fn render_text(list: &NodeList, suffix: Option<&str>) -> String {
    if list.nodes.is_empty() {
        return "No reachable hosts.".to_owned();
    }
    let rows: Vec<(String, String)> = list
        .nodes
        .iter()
        .map(|node| (full_name(node, suffix), label_text(node)))
        .collect();
    let width = rows
        .iter()
        .map(|(name, _)| name.chars().count())
        .chain([NAME_HEADER.len()])
        .max()
        .unwrap_or(NAME_HEADER.len())
        + COLUMN_GAP;
    let mut text = format!("{NAME_HEADER:<width$}{LABELS_HEADER}\n");
    for (name, labels) in &rows {
        text.push_str(&format!("{name:<width$}{labels}\n"));
    }
    if list.truncated {
        text.push_str(&format!(
            "Only the first {} hosts are shown: the server cut the list.\n",
            list.nodes.len()
        ));
    }
    let hint_node = list
        .nodes
        .iter()
        .find(|node| is_dns_label(&node.name))
        .map(|node| full_name(node, suffix));
    if let (Some(_), Some(first)) = (suffix, hint_node) {
        text.push_str(&format!("ssh <login>@{first}\n"));
    }
    text.truncate(text.trim_end_matches('\n').len());
    text
}

pub fn render_json(list: &NodeList) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(list)
}

pub struct Listing<'a> {
    pub nodes: Option<&'a NodeList>,
    pub suffix: Option<&'a str>,
    pub services: Option<&'a ServiceList>,
}

#[derive(Serialize)]
struct Everything<'a> {
    nodes: &'a NodeList,
    services: Option<&'a ServiceList>,
}

pub fn render_everything_json(
    nodes: &NodeList,
    services: Option<&ServiceList>,
) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&Everything { nodes, services })
}

pub fn render_services_json(list: &ServiceList) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(list)
}

pub fn render_kinds_text(listing: &Listing<'_>) -> String {
    let mut rows: Vec<[String; 4]> = Vec::new();
    if let Some(nodes) = listing.nodes {
        rows.extend(nodes.nodes.iter().map(|node| {
            [
                SSH_KIND.to_owned(),
                full_name(node, listing.suffix),
                label_text(node),
                connected_text(node.connected).to_owned(),
            ]
        }));
    }
    if let Some(services) = listing.services {
        rows.extend(services.services.iter().map(|service| {
            [
                kind_label(service.kind).to_owned(),
                printable(&service.name),
                labels_text(&service.labels),
                connected_text(service.connected).to_owned(),
            ]
        }));
    }
    if rows.is_empty() {
        return if listing.nodes.is_some() {
            "No reachable hosts or services.".to_owned()
        } else {
            "No reachable services.".to_owned()
        };
    }
    let headers = [KIND_HEADER, NAME_HEADER, LABELS_HEADER, CONNECTED_HEADER];
    let mut widths = headers.map(str::len);
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let mut text = table_line(&headers.map(str::to_owned), &widths);
    for row in &rows {
        text.push_str(&table_line(row, &widths));
    }
    if listing.nodes.is_some_and(|nodes| nodes.truncated) {
        text.push_str("The server cut the list of hosts: some are not shown.\n");
    }
    if listing.services.is_some_and(|services| services.truncated) {
        text.push_str("The server cut the list of services: some are not shown.\n");
    }
    text.truncate(text.trim_end_matches('\n').len());
    text
}

fn table_line(cells: &[String; 4], widths: &[usize; 4]) -> String {
    let mut line = String::new();
    for (index, (cell, width)) in cells.iter().zip(widths).enumerate() {
        if index + 1 == cells.len() {
            line.push_str(cell);
        } else {
            let padded = width + COLUMN_GAP;
            line.push_str(&format!("{cell:<padded$}"));
        }
    }
    line.push('\n');
    line
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use jaunt_proto::{NodeList, NodeSummary, ServiceKind, ServiceList, ServiceSummary};

    use super::{ListKind, Listing, render_json, render_kinds_text, render_text, select_services};

    fn node(name: &str, labels: &[(&str, &str)]) -> NodeSummary {
        NodeSummary {
            name: name.to_owned(),
            labels: labels
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<BTreeMap<_, _>>(),
            hostname: format!("{name}.internal"),
            connected: false,
        }
    }

    #[test]
    fn the_table_shows_full_names_labels_and_the_connection_hint() {
        let list = NodeList {
            nodes: vec![
                node("web-01", &[("env", "prod"), ("tier", "1")]),
                node("db-1", &[]),
            ],
            truncated: false,
        };

        let text = render_text(&list, Some("example.test"));

        let expected = "NAME                 LABELS
web-01.example.test  env=prod,tier=1
db-1.example.test    -
ssh <login>@web-01.example.test";
        assert_eq!(text, expected);
    }

    #[test]
    fn without_a_suffix_names_are_bare_and_there_is_no_hint() {
        let list = NodeList {
            nodes: vec![node("web-01", &[("env", "prod")])],
            truncated: false,
        };

        assert_eq!(render_text(&list, None), "NAME    LABELS\nweb-01  env=prod");
    }

    #[test]
    fn an_empty_list_a_cut_list_and_control_characters_are_handled() {
        let empty = NodeList {
            nodes: Vec::new(),
            truncated: false,
        };
        assert_eq!(
            render_text(&empty, Some("example.test")),
            "No reachable hosts."
        );

        let cut = NodeList {
            nodes: vec![node("web-01", &[])],
            truncated: true,
        };
        assert!(
            render_text(&cut, Some("example.test")).contains("Only the first 1 hosts are shown")
        );

        let hostile = NodeList {
            nodes: vec![node("web\x1b[31m", &[("env", "a\nb")])],
            truncated: false,
        };
        let text = render_text(&hostile, Some("example.test"));
        assert!(!text.contains('\x1b'), "{text:?}");
        assert_eq!(text.lines().count(), 2, "{text:?}");
        assert!(!text.contains("ssh <login>@"), "{text:?}");

        let mixed = NodeList {
            nodes: vec![
                node("evil\u{202e}-01", &[]),
                node("Web", &[]),
                node("web-02", &[]),
            ],
            truncated: false,
        };
        let text = render_text(&mixed, Some("example.test"));
        assert!(!text.contains('\u{202e}'), "{text:?}");
        assert!(
            text.ends_with("ssh <login>@web-02.example.test"),
            "{text:?}"
        );
    }

    #[test]
    fn json_output_is_the_response_itself() {
        let list = NodeList {
            nodes: vec![node("web-01", &[("env", "prod")])],
            truncated: false,
        };

        let parsed: NodeList = serde_json::from_str(&render_json(&list).unwrap()).unwrap();

        assert_eq!(parsed, list);
    }

    #[test]
    fn services_are_filtered_by_kind_and_hostile_names_or_cut_lists_are_shown_safely() {
        let list = ServiceList {
            services: vec![
                ServiceSummary {
                    kind: ServiceKind::Tcp,
                    name: "graf\x1b[31mana".to_owned(),
                    labels: [("env".to_owned(), "a\nb".to_owned())].into(),
                    connected: false,
                },
                ServiceSummary {
                    kind: ServiceKind::Postgres,
                    name: "orders".to_owned(),
                    labels: BTreeMap::new(),
                    connected: true,
                },
            ],
            truncated: true,
        };

        let tcp = select_services(list.clone(), ListKind::Tcp);
        let kube = select_services(list.clone(), ListKind::Kube);
        let text = render_kinds_text(&Listing {
            nodes: None,
            suffix: None,
            services: Some(&tcp),
        });
        let empty = render_kinds_text(&Listing {
            nodes: None,
            suffix: None,
            services: Some(&ServiceList {
                services: kube.services.clone(),
                truncated: false,
            }),
        });

        assert_eq!(tcp.services.len(), 1);
        assert!(tcp.truncated);
        assert!(kube.services.is_empty());
        assert_eq!(select_services(list.clone(), ListKind::All), list);
        assert!(!text.contains('\x1b'), "{text:?}");
        assert_eq!(text.lines().count(), 3, "{text:?}");
        assert!(
            text.ends_with("The server cut the list of services: some are not shown."),
            "{text:?}"
        );
        assert_eq!(empty, "No reachable services.");
    }
}
