use jaunt_proto::{NodeList, NodeSummary};

use crate::display::printable;
use crate::ssh_config::is_dns_label;

const NAME_HEADER: &str = "NAME";
const LABELS_HEADER: &str = "LABELS";
const COLUMN_GAP: usize = 2;
const NO_LABELS: &str = "-";

fn full_name(node: &NodeSummary, suffix: Option<&str>) -> String {
    match suffix {
        Some(suffix) => printable(&format!("{}.{suffix}", node.name)),
        None => printable(&node.name),
    }
}

fn label_text(node: &NodeSummary) -> String {
    if node.labels.is_empty() {
        return NO_LABELS.to_owned();
    }
    let pairs: Vec<String> = node
        .labels
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    printable(&pairs.join(","))
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use jaunt_proto::{NodeList, NodeSummary};

    use super::{render_json, render_text};

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
}
