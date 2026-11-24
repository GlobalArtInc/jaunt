use chrono::{DateTime, Local, SecondsFormat};

pub fn format_local(secs: i64) -> String {
    match DateTime::from_timestamp(secs, 0) {
        Some(utc) => utc
            .with_timezone(&Local)
            .to_rfc3339_opts(SecondsFormat::Secs, false),
        None => format!("@{secs}"),
    }
}

pub fn format_span(total_secs: u64) -> String {
    let days = total_secs / 86_400;
    let hours = total_secs % 86_400 / 3_600;
    let minutes = total_secs % 3_600 / 60;
    let seconds = total_secs % 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m")
    } else {
        format!("{seconds}s")
    }
}

pub fn printable(text: &str) -> String {
    text.chars()
        .map(|ch| if ch.is_control() { '?' } else { ch })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{format_local, format_span, printable};

    #[test]
    fn spans_use_the_two_most_significant_units() {
        assert_eq!(format_span(0), "0s");
        assert_eq!(format_span(59), "59s");
        assert_eq!(format_span(60), "1m");
        assert_eq!(format_span(3_599), "59m");
        assert_eq!(format_span(3_600 + 5 * 60 + 9), "1h 5m");
        assert_eq!(format_span(2 * 86_400 + 3 * 3_600 + 59), "2d 3h");
    }

    #[test]
    fn local_time_is_rfc_3339_and_control_characters_are_masked() {
        let text = format_local(1_700_000_000);
        assert!(text.len() == 25 || text.ends_with('Z'), "{text}");
        assert!(text.starts_with("2023-11-1"), "{text}");
        assert_eq!(format_local(i64::MAX), format!("@{}", i64::MAX));
        assert_eq!(printable("a\x1b[31mb\nc"), "a?[31mb?c");
    }
}
