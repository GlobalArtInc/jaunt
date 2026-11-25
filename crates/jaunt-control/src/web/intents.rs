use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::completion;
use crate::token::{EntropyUnavailable, hash_secret};

pub(crate) const INTENT_TTL_SECS: i64 = 300;
pub(crate) const MAX_INTENTS: usize = 1024;

struct Intent {
    session_hash: String,
    enrollment_id: String,
    code_hash: String,
    expires_at: i64,
}

pub(crate) struct IssuedIntent {
    pub(crate) token: String,
    pub(crate) expires_at: i64,
}

pub(crate) struct Binding<'a> {
    pub(crate) session_hash: &'a str,
    pub(crate) enrollment_id: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IntentRefusal {
    Unknown,
    ForeignSession,
    OtherEnrolment,
    Expired,
}

#[derive(Default)]
pub(crate) struct IntentTable(Mutex<HashMap<String, Intent>>);

impl IntentTable {
    fn lock(&self) -> MutexGuard<'_, HashMap<String, Intent>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn issue(
        &self,
        binding: &Binding<'_>,
        code_hash: &str,
        enrollment_expires_at: i64,
        now: i64,
    ) -> Result<IssuedIntent, EntropyUnavailable> {
        let issued = completion::issue()?;
        let expires_at = now
            .saturating_add(INTENT_TTL_SECS)
            .min(enrollment_expires_at);
        let mut intents = self.lock();
        intents.retain(|_, intent| {
            intent.expires_at > now
                && !(intent.session_hash == binding.session_hash
                    && intent.enrollment_id == binding.enrollment_id)
        });
        while intents.len() >= MAX_INTENTS {
            let Some(oldest) = intents
                .iter()
                .min_by_key(|(_, intent)| intent.expires_at)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            intents.remove(&oldest);
        }
        intents.insert(
            issued.hash,
            Intent {
                session_hash: binding.session_hash.to_owned(),
                enrollment_id: binding.enrollment_id.to_owned(),
                code_hash: code_hash.to_owned(),
                expires_at,
            },
        );
        Ok(IssuedIntent {
            token: issued.secret,
            expires_at,
        })
    }

    pub(crate) fn redeem(
        &self,
        token: &str,
        binding: &Binding<'_>,
        now: i64,
    ) -> Result<String, IntentRefusal> {
        if !completion::is_well_formed(token) {
            return Err(IntentRefusal::Unknown);
        }
        let key = hash_secret(token);
        let mut intents = self.lock();
        let intent = intents.get(&key).ok_or(IntentRefusal::Unknown)?;
        if intent.session_hash != binding.session_hash {
            return Err(IntentRefusal::ForeignSession);
        }
        let intent = intents.remove(&key).ok_or(IntentRefusal::Unknown)?;
        if intent.expires_at <= now {
            return Err(IntentRefusal::Expired);
        }
        if intent.enrollment_id != binding.enrollment_id {
            return Err(IntentRefusal::OtherEnrolment);
        }
        Ok(intent.code_hash)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::{Binding, INTENT_TTL_SECS, IntentRefusal, IntentTable, MAX_INTENTS};

    const NOW: i64 = 1_000_000;

    fn bound<'a>(session_hash: &'a str, enrollment_id: &'a str) -> Binding<'a> {
        Binding {
            session_hash,
            enrollment_id,
        }
    }

    #[test]
    fn an_intent_is_single_use_and_bound_to_its_session_and_enrolment() {
        let table = IntentTable::default();
        let issued = table
            .issue(&bound("s-1", "e-1"), "code-hash", NOW + 3_600, NOW)
            .unwrap();
        assert_eq!(issued.expires_at, NOW + INTENT_TTL_SECS);

        assert_eq!(
            table.redeem(&issued.token, &bound("s-2", "e-1"), NOW),
            Err(IntentRefusal::ForeignSession)
        );
        assert_eq!(
            table.redeem(&issued.token, &bound("s-1", "e-1"), NOW),
            Ok("code-hash".to_owned())
        );
        assert_eq!(
            table.redeem(&issued.token, &bound("s-1", "e-1"), NOW),
            Err(IntentRefusal::Unknown)
        );

        let other = table
            .issue(&bound("s-1", "e-1"), "code-hash", NOW + 3_600, NOW)
            .unwrap();
        assert_eq!(
            table.redeem(&other.token, &bound("s-1", "e-2"), NOW),
            Err(IntentRefusal::OtherEnrolment)
        );
        assert_eq!(
            table.redeem(&other.token, &bound("s-1", "e-1"), NOW),
            Err(IntentRefusal::Unknown)
        );
        for malformed in ["", "short", &"x".repeat(44), &"!".repeat(43)] {
            assert_eq!(
                table.redeem(malformed, &bound("s-1", "e-1"), NOW),
                Err(IntentRefusal::Unknown)
            );
        }
    }

    #[test]
    fn a_new_lookup_replaces_the_live_intent_of_the_same_session_and_enrolment() {
        let table = IntentTable::default();
        let old = table
            .issue(&bound("s", "e"), "h", NOW + 3_600, NOW)
            .unwrap();
        let other_session = table
            .issue(&bound("t", "e"), "h", NOW + 3_600, NOW)
            .unwrap();
        let other_enrolment = table
            .issue(&bound("s", "f"), "h", NOW + 3_600, NOW)
            .unwrap();
        let new = table
            .issue(&bound("s", "e"), "h", NOW + 3_600, NOW)
            .unwrap();

        assert_eq!(table.len(), 3);
        assert_eq!(
            table.redeem(&old.token, &bound("s", "e"), NOW),
            Err(IntentRefusal::Unknown)
        );
        assert!(table.redeem(&new.token, &bound("s", "e"), NOW).is_ok());
        assert!(
            table
                .redeem(&other_session.token, &bound("t", "e"), NOW)
                .is_ok()
        );
        assert!(
            table
                .redeem(&other_enrolment.token, &bound("s", "f"), NOW)
                .is_ok()
        );
    }

    #[test]
    fn an_intent_expires_after_five_minutes_or_with_its_enrolment() {
        let table = IntentTable::default();
        let long = table
            .issue(&bound("s", "long"), "h", NOW + 3_600, NOW)
            .unwrap();
        let short = table
            .issue(&bound("s", "short"), "h", NOW + 10, NOW)
            .unwrap();
        assert_eq!(short.expires_at, NOW + 10);

        assert_eq!(
            table.redeem(&short.token, &bound("s", "short"), NOW + 10),
            Err(IntentRefusal::Expired)
        );
        assert_eq!(
            table.redeem(&long.token, &bound("s", "long"), NOW + INTENT_TTL_SECS - 1),
            Ok("h".to_owned())
        );
        let late = table
            .issue(&bound("s", "late"), "h", NOW + 3_600, NOW)
            .unwrap();
        assert_eq!(
            table.redeem(&late.token, &bound("s", "late"), NOW + INTENT_TTL_SECS),
            Err(IntentRefusal::Expired)
        );
    }

    #[test]
    fn the_table_stays_bounded_and_drops_the_soonest_expiring_intent() {
        let table = IntentTable::default();
        let first = table.issue(&bound("s", "e-0"), "h", NOW + 1, NOW).unwrap();
        for index in 1..MAX_INTENTS {
            table
                .issue(&bound("s", &format!("e-{index}")), "h", NOW + 3_600, NOW)
                .unwrap();
        }
        assert_eq!(table.len(), MAX_INTENTS);
        let newest = table
            .issue(&bound("s", "e-new"), "h", NOW + 3_600, NOW)
            .unwrap();
        assert_eq!(table.len(), MAX_INTENTS);
        assert_eq!(
            table.redeem(&first.token, &bound("s", "e-0"), NOW),
            Err(IntentRefusal::Unknown)
        );
        assert_eq!(
            table.redeem(&newest.token, &bound("s", "e-new"), NOW),
            Ok("h".to_owned())
        );
    }
}
