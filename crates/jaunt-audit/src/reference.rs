use jaunt_proto::{AUDIT_REFERENCE_DIGITS, DENIAL_REFERENCE_PREFIX, is_denial_reference};
use uuid::Uuid;

#[cfg(test)]
const SEQUENCE_DIGITS: usize = 16;

pub fn new_denial_reference() -> String {
    let random = Uuid::new_v4().simple().to_string();
    format!(
        "{DENIAL_REFERENCE_PREFIX}{}",
        random[..AUDIT_REFERENCE_DIGITS].to_ascii_uppercase()
    )
}

#[cfg(test)]
pub(crate) fn denial_reference_of(event_id: &str) -> Option<String> {
    let digits = event_id.get(SEQUENCE_DIGITS..SEQUENCE_DIGITS + AUDIT_REFERENCE_DIGITS)?;
    let reference = format!("{DENIAL_REFERENCE_PREFIX}{}", digits.to_ascii_uppercase());
    (is_denial_reference(&reference) && digits.bytes().all(|byte| !byte.is_ascii_uppercase()))
        .then_some(reference)
}

pub(crate) fn event_id(sequence: u64, denial_reference: Option<&str>) -> String {
    let random = Uuid::new_v4().simple().to_string();
    let digits = denial_reference
        .filter(|reference| is_denial_reference(reference))
        .and_then(|reference| reference.get(DENIAL_REFERENCE_PREFIX.len()..));
    match digits {
        Some(digits) => format!(
            "{sequence:016x}{}{}",
            digits.to_ascii_lowercase(),
            &random[AUDIT_REFERENCE_DIGITS..]
        ),
        None => format!("{sequence:016x}{random}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{denial_reference_of, event_id, new_denial_reference};

    #[test]
    fn a_denial_reference_is_part_of_the_event_id_it_names() {
        let reference = new_denial_reference();
        assert!(jaunt_proto::is_denial_reference(&reference), "{reference}");
        let id = event_id(7, Some(&reference));
        assert_eq!(id.len(), 48);
        assert!(id.starts_with("0000000000000007"));
        assert_eq!(
            denial_reference_of(&id).as_deref(),
            Some(reference.as_str())
        );
        assert_ne!(event_id(7, Some(&reference)), id);
        for ignored in [None, Some("H-9D0311FE"), Some("D-0000abcd"), Some("D-1")] {
            let plain = event_id(8, ignored);
            assert_eq!(plain.len(), 48);
            assert!(plain.starts_with("0000000000000008"));
        }
        assert_eq!(denial_reference_of("short"), None);
        assert_eq!(
            denial_reference_of("0000000000000001ABCDEF01aaaaaaaaaaaaaaaaaaaaaaaa"),
            None
        );
        assert_eq!(
            denial_reference_of("0000000000000001zzzzzzzzaaaaaaaaaaaaaaaaaaaaaaaa"),
            None
        );
    }
}
