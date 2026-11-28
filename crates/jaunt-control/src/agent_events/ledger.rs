use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use jaunt_limits::LogThrottle;

pub(crate) const NOISY_PER_HOUR: u32 = 10_000;
pub(crate) const EXEC_PER_HOUR: u32 = 5_000;
pub(crate) const PROTOCOL_ERRORS_PER_HOUR: u32 = 20;
pub(crate) const ENDED_GRACE_SECS: i64 = 300;
pub(crate) const FORGET_AFTER_END_SECS: i64 = ENDED_GRACE_SECS + 60;
pub(crate) const MAX_TRACKED_SESSIONS: usize = 65_536;
pub(crate) const IDLE_LIMIT_SECS: i64 = 25 * 3600;
pub(crate) const WINDOW_SECS: i64 = (WINDOW_SLOTS as i64) * MINUTE_SECS;
const WINDOW_SLOTS: usize = 61;
const MINUTE_SECS: i64 = 60;
const EVICTION_LOG_EVERY: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Edge {
    Start,
    End,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Budget {
    Noisy,
    Exec,
    ProtocolError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Charge {
    Invalid,
    Once(Edge),
    Budgeted(Budget),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gate {
    Open,
    Node,
    Agents,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Repeat,
    Accept,
    Invalid,
    OverBudget,
    Duplicate,
    NodeCeiling,
    AgentsCeiling,
}

impl Gate {
    fn verdict(self) -> Option<Verdict> {
        match self {
            Gate::Open => None,
            Gate::Node => Some(Verdict::NodeCeiling),
            Gate::Agents => Some(Verdict::AgentsCeiling),
        }
    }
}

struct Window {
    counts: [u16; WINDOW_SLOTS],
    last: i64,
    used: u32,
}

impl Window {
    fn new(now: i64) -> Window {
        Window {
            counts: [0; WINDOW_SLOTS],
            last: now.div_euclid(MINUTE_SECS),
            used: 0,
        }
    }

    fn slot(minute: i64) -> usize {
        usize::try_from(minute.rem_euclid(WINDOW_SLOTS as i64)).unwrap_or(0)
    }

    fn roll(&mut self, now: i64) {
        let minute = now.div_euclid(MINUTE_SECS);
        let gap = minute.saturating_sub(self.last);
        if gap <= 0 {
            return;
        }
        if gap >= WINDOW_SLOTS as i64 {
            self.counts = [0; WINDOW_SLOTS];
            self.used = 0;
        } else {
            for step in 1..=gap {
                let slot = Window::slot(self.last + step);
                self.used = self.used.saturating_sub(u32::from(self.counts[slot]));
                self.counts[slot] = 0;
            }
        }
        self.last = minute;
    }

    fn has_room(&mut self, now: i64, limit: u32) -> bool {
        self.roll(now);
        self.used < limit
    }

    fn record(&mut self) {
        let slot = Window::slot(self.last);
        self.counts[slot] = self.counts[slot].saturating_add(1);
        self.used = self.used.saturating_add(1);
    }
}

struct Entry {
    mark: Option<u64>,
    windows: Vec<(Budget, Window)>,
    started: bool,
    ended: bool,
    dropped_total: u64,
    needs_mark: bool,
    needs_event: bool,
    ended_at: Option<i64>,
    seen_at: i64,
    checked_at: i64,
    offered_at: i64,
    mark_offered_at: i64,
}

impl Entry {
    fn new(now: i64) -> Entry {
        Entry {
            mark: None,
            windows: Vec::new(),
            started: false,
            ended: false,
            dropped_total: 0,
            needs_mark: false,
            needs_event: false,
            ended_at: None,
            seen_at: now,
            checked_at: now,
            offered_at: i64::MIN,
            mark_offered_at: i64::MIN,
        }
    }

    fn window(&mut self, budget: Budget, now: i64) -> &mut Window {
        let position = match self.windows.iter().position(|(owner, _)| *owner == budget) {
            Some(position) => position,
            None => {
                self.windows.push((budget, Window::new(now)));
                self.windows.len() - 1
            }
        };
        &mut self.windows[position].1
    }

    fn expired(&self, now: i64) -> bool {
        let ended_long_ago = self
            .ended_at
            .is_some_and(|ended| now.saturating_sub(ended) > FORGET_AFTER_END_SECS);
        let idle = now.saturating_sub(self.seen_at) > IDLE_LIMIT_SECS;
        (ended_long_ago && !self.needs_mark && !self.needs_event) || idle
    }
}

pub(crate) struct Ledger {
    noisy_per_hour: u32,
    capacity: usize,
    entries: Mutex<HashMap<String, Entry>>,
    evictions: LogThrottle,
}

impl Ledger {
    pub(crate) fn new() -> Ledger {
        Ledger::sized(NOISY_PER_HOUR, MAX_TRACKED_SESSIONS)
    }

    pub(crate) fn sized(noisy_per_hour: u32, capacity: usize) -> Ledger {
        Ledger {
            noisy_per_hour,
            capacity: capacity.max(1),
            entries: Mutex::new(HashMap::new()),
            evictions: LogThrottle::new(EVICTION_LOG_EVERY),
        }
    }

    fn per_hour(&self, budget: Budget) -> u32 {
        match budget {
            Budget::Noisy => self.noisy_per_hour,
            Budget::Exec => EXEC_PER_HOUR,
            Budget::ProtocolError => PROTOCOL_ERRORS_PER_HOUR,
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn with_entry<T>(
        &self,
        id: &str,
        ended_at: Option<i64>,
        now: i64,
        apply: impl FnOnce(&mut Entry) -> T,
    ) -> T {
        let mut entries = self.lock();
        if !entries.contains_key(id) && entries.len() >= self.capacity {
            entries.retain(|_, entry| !entry.expired(now));
            if entries.len() >= self.capacity {
                self.evict_least_recent(&mut entries, now);
            }
        }
        let entry = entries
            .entry(id.to_owned())
            .or_insert_with(|| Entry::new(now));
        entry.seen_at = now;
        if ended_at.is_some() {
            entry.ended_at = ended_at;
        }
        apply(entry)
    }

    fn evict_least_recent(&self, entries: &mut HashMap<String, Entry>, now: i64) {
        let oldest = entries
            .iter()
            .min_by_key(|(_, entry)| entry.seen_at)
            .map(|(id, _)| id.clone());
        if let Some(id) = oldest {
            entries.remove(&id);
            let tick = Duration::from_secs(u64::try_from(now).unwrap_or(0));
            if let Some(suppressed) = self.evictions.admit(tick) {
                tracing::warn!(
                    target: "jaunt::control",
                    capacity = self.capacity,
                    suppressed,
                    "the table of agent event sequence marks is full; the least recently used session was forgotten"
                );
            }
        }
    }

    pub(crate) fn is_repeat(&self, id: &str, seq: u64) -> bool {
        self.lock()
            .get(id)
            .and_then(|entry| entry.mark)
            .is_some_and(|mark| seq <= mark)
    }

    pub(crate) fn decide(
        &self,
        id: &str,
        seq: u64,
        charge: Charge,
        ended_at: Option<i64>,
        now: i64,
        admit: impl FnOnce(Charge) -> Gate,
    ) -> Verdict {
        let limit = match charge {
            Charge::Budgeted(budget) => self.per_hour(budget),
            Charge::Invalid | Charge::Once(_) => 0,
        };
        self.with_entry(id, ended_at, now, |entry| {
            if entry.mark.is_some_and(|mark| seq <= mark) {
                return Verdict::Repeat;
            }
            entry.mark = Some(seq);
            match charge {
                Charge::Invalid => Verdict::Invalid,
                Charge::Once(edge) => {
                    let seen = match edge {
                        Edge::Start => entry.started,
                        Edge::End => entry.ended,
                    };
                    if seen {
                        return Verdict::Duplicate;
                    }
                    if let Some(refused) = admit(charge).verdict() {
                        return refused;
                    }
                    match edge {
                        Edge::Start => entry.started = true,
                        Edge::End => entry.ended = true,
                    }
                    Verdict::Accept
                }
                Charge::Budgeted(budget) => {
                    let window = entry.window(budget, now);
                    if !window.has_room(now, limit) {
                        return Verdict::OverBudget;
                    }
                    if budget != Budget::Noisy
                        && let Some(refused) = admit(charge).verdict()
                    {
                        return refused;
                    }
                    window.record();
                    Verdict::Accept
                }
            }
        })
    }

    pub(crate) fn note_dropped(
        &self,
        id: &str,
        count: u64,
        mark: bool,
        ended_at: Option<i64>,
        now: i64,
    ) {
        self.with_entry(id, ended_at, now, |entry| {
            entry.dropped_total = entry.dropped_total.saturating_add(count);
            if mark {
                entry.needs_mark = true;
            }
        });
    }

    pub(crate) fn pending_mark(&self, id: &str) -> Option<u64> {
        self.lock()
            .get(id)
            .filter(|entry| entry.needs_mark)
            .map(|entry| entry.dropped_total)
    }

    pub(crate) fn marked(&self, id: &str) {
        if let Some(entry) = self.lock().get_mut(id) {
            entry.needs_mark = false;
        }
    }

    pub(crate) fn defer_event(&self, id: &str) {
        if let Some(entry) = self.lock().get_mut(id) {
            entry.needs_event = true;
        }
    }

    pub(crate) fn claim_event(&self, id: &str) -> Option<u64> {
        let mut entries = self.lock();
        let entry = entries.get_mut(id).filter(|entry| entry.needs_event)?;
        entry.needs_event = false;
        Some(entry.dropped_total)
    }

    pub(crate) fn deferred_events(&self, now: i64, limit: usize) -> Vec<String> {
        self.offer(now, limit, |entry| {
            entry.needs_event.then_some(&mut entry.offered_at)
        })
    }

    pub(crate) fn deferred_marks(&self, now: i64, limit: usize) -> Vec<String> {
        self.offer(now, limit, |entry| {
            entry.needs_mark.then_some(&mut entry.mark_offered_at)
        })
    }

    fn offer(
        &self,
        now: i64,
        limit: usize,
        stamp: impl Fn(&mut Entry) -> Option<&mut i64>,
    ) -> Vec<String> {
        let mut entries = self.lock();
        let mut waiting: Vec<(i64, String)> = entries
            .iter_mut()
            .filter_map(|(id, entry)| stamp(entry).map(|at| (*at, id.clone())))
            .collect();
        waiting.sort_unstable();
        waiting.truncate(limit);
        for (_, id) in &waiting {
            if let Some(at) = entries.get_mut(id).and_then(&stamp) {
                *at = now;
            }
        }
        waiting.into_iter().map(|(_, id)| id).collect()
    }

    pub(crate) fn unresolved(&self, now: i64, limit: usize) -> Vec<String> {
        let mut entries = self.lock();
        let mut found = Vec::new();
        for (id, entry) in entries.iter_mut() {
            if found.len() >= limit {
                break;
            }
            let unknown_end = entry.ended_at.is_none()
                && now.saturating_sub(entry.checked_at.max(entry.seen_at)) >= ENDED_GRACE_SECS;
            if unknown_end || entry.needs_mark || entry.needs_event {
                entry.checked_at = now;
                found.push(id.clone());
            }
        }
        found
    }

    pub(crate) fn resolve(&self, id: &str, ended_at: Option<i64>) {
        if let Some(entry) = self.lock().get_mut(id)
            && ended_at.is_some()
        {
            entry.ended_at = ended_at;
        }
    }

    pub(crate) fn forget(&self, id: &str) {
        self.lock().remove(id);
    }

    pub(crate) fn sweep(&self, now: i64) -> usize {
        let mut entries = self.lock();
        let before = entries.len();
        entries.retain(|_, entry| !entry.expired(now));
        before - entries.len()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn len(&self) -> usize {
        self.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Budget, Charge, ENDED_GRACE_SECS, Edge, FORGET_AFTER_END_SECS, Gate, IDLE_LIMIT_SECS,
        Ledger, Verdict,
    };

    const NOW: i64 = 1_800_000_000;
    const NOISY: Charge = Charge::Budgeted(Budget::Noisy);
    const EXEC: Charge = Charge::Budgeted(Budget::Exec);
    const START: Charge = Charge::Once(Edge::Start);
    const END: Charge = Charge::Once(Edge::End);

    fn decide(ledger: &Ledger, id: &str, seq: u64, charge: Charge, at: i64) -> Verdict {
        ledger.decide(id, seq, charge, None, at, |_| Gate::Open)
    }

    #[test]
    fn a_sequence_at_or_below_the_mark_is_a_repeat_whatever_it_carries() {
        let ledger = Ledger::new();
        let at = |seq, charge| decide(&ledger, "s", seq, charge, NOW);
        assert!(!ledger.is_repeat("s", 0));
        assert_eq!(at(0, NOISY), Verdict::Accept);
        assert!(ledger.is_repeat("s", 0));
        assert_eq!(at(0, NOISY), Verdict::Repeat);
        assert_eq!(at(5, Charge::Invalid), Verdict::Invalid);
        assert!(ledger.is_repeat("s", 5) && !ledger.is_repeat("s", 6));
        assert_eq!(at(5, NOISY), Verdict::Repeat);
        assert_eq!(at(3, NOISY), Verdict::Repeat);
        assert_eq!(at(6, NOISY), Verdict::Accept);
        assert_eq!(at(u64::MAX, START), Verdict::Accept);
        assert_eq!(at(u64::MAX, START), Verdict::Repeat);
        assert!(!ledger.is_repeat("other", 1));
        assert_eq!(decide(&ledger, "other", 1, NOISY, NOW), Verdict::Accept);
    }

    #[test]
    fn the_start_and_the_end_of_a_session_are_written_once_each() {
        let ledger = Ledger::new();
        assert_eq!(decide(&ledger, "s", 1, START, NOW), Verdict::Accept);
        assert_eq!(decide(&ledger, "s", 2, START, NOW), Verdict::Duplicate);
        assert_eq!(decide(&ledger, "s", 3, END, NOW), Verdict::Accept);
        assert_eq!(decide(&ledger, "s", 4, END, NOW + 7200), Verdict::Duplicate);
        assert_eq!(
            decide(&ledger, "s", 5, START, NOW + 7200),
            Verdict::Duplicate
        );
        assert_eq!(decide(&ledger, "t", 1, END, NOW), Verdict::Accept);
        assert_eq!(decide(&ledger, "t", 2, START, NOW), Verdict::Accept);
    }

    #[test]
    fn each_critical_kind_has_its_own_hourly_budget_per_session() {
        let ledger = Ledger::new();
        let mut seq = 0;
        let mut fill = |id: &str, charge: Charge, count: u32| {
            for index in 0..count {
                seq += 1;
                assert_eq!(
                    decide(&ledger, id, seq, charge, NOW),
                    Verdict::Accept,
                    "{index}"
                );
            }
            seq += 1;
            assert_eq!(decide(&ledger, id, seq, charge, NOW), Verdict::OverBudget);
        };
        fill("s", EXEC, 5000);
        fill("s", Charge::Budgeted(Budget::ProtocolError), 20);
        fill("s", NOISY, 10_000);
        fill("t", Charge::Budgeted(Budget::ProtocolError), 20);
    }

    #[test]
    fn the_gate_is_asked_only_for_critical_events_that_would_be_written_and_its_answer_is_kept() {
        let ledger = Ledger::new();
        let asked = std::cell::RefCell::new(Vec::new());
        let gate = |answer: Gate| {
            let asked = &asked;
            move |charge: Charge| {
                asked.borrow_mut().push(charge);
                answer
            }
        };
        assert_eq!(
            ledger.decide("s", 1, NOISY, None, NOW, gate(Gate::Node)),
            Verdict::Accept
        );
        assert_eq!(
            ledger.decide("s", 2, Charge::Invalid, None, NOW, gate(Gate::Node)),
            Verdict::Invalid
        );
        assert_eq!(
            ledger.decide("s", 2, START, None, NOW, gate(Gate::Node)),
            Verdict::Repeat
        );
        assert!(asked.borrow().is_empty());
        assert_eq!(
            ledger.decide("s", 3, START, None, NOW, gate(Gate::Node)),
            Verdict::NodeCeiling
        );
        assert_eq!(
            ledger.decide("s", 4, START, None, NOW, gate(Gate::Agents)),
            Verdict::AgentsCeiling
        );
        assert_eq!(decide(&ledger, "s", 5, START, NOW), Verdict::Accept);
        assert_eq!(
            ledger.decide("s", 6, START, None, NOW, gate(Gate::Node)),
            Verdict::Duplicate
        );
        assert_eq!(
            ledger.decide("s", 7, EXEC, None, NOW, gate(Gate::Node)),
            Verdict::NodeCeiling
        );
        for seq in 8..8 + 5000 {
            assert_eq!(decide(&ledger, "s", seq, EXEC, NOW), Verdict::Accept);
        }
        assert_eq!(
            ledger.decide("s", 9000, EXEC, None, NOW, gate(Gate::Node)),
            Verdict::OverBudget
        );
        assert_eq!(*asked.borrow(), [START, START, EXEC]);
    }

    #[test]
    fn the_noisy_budget_holds_ten_thousand_events_an_hour_and_invalid_or_lifecycle_spend_none() {
        let ledger = Ledger::new();
        let mut seq = 0;
        let mut next = |charge, at| {
            seq += 1;
            decide(&ledger, "s", seq, charge, at)
        };
        for _ in 0..10_000 {
            assert_eq!(next(Charge::Invalid, NOW), Verdict::Invalid);
        }
        for index in 0..10_000 {
            let at = NOW + i64::from(index % 3000);
            assert_eq!(next(NOISY, at), Verdict::Accept, "{index}");
        }
        assert_eq!(next(NOISY, NOW + 3000), Verdict::OverBudget);
        assert_eq!(next(START, NOW + 3000), Verdict::Accept);
        assert_eq!(next(EXEC, NOW + 3000), Verdict::Accept);
        assert_eq!(next(NOISY, NOW + 3000), Verdict::OverBudget);
        assert_eq!(
            decide(&ledger, "fresh", 1, NOISY, NOW + 3000),
            Verdict::Accept
        );
    }

    #[test]
    fn the_window_rolls_by_the_minute_and_no_hour_ever_holds_more_than_the_budget() {
        let ledger = Ledger::sized(10, 16);
        let mut seq = 0;
        let mut next = |at| {
            seq += 1;
            decide(&ledger, "s", seq, NOISY, at)
        };
        let start = NOW - NOW.rem_euclid(60) + 59;
        for _ in 0..10 {
            assert_eq!(next(start), Verdict::Accept);
        }
        assert_eq!(next(start + 1), Verdict::OverBudget);
        assert_eq!(next(start + 3600), Verdict::OverBudget);
        assert_eq!(next(start + 3601), Verdict::Accept);
        for _ in 0..9 {
            assert_eq!(next(start + 3601), Verdict::Accept);
        }
        assert_eq!(next(start + 7200), Verdict::OverBudget);
        assert_eq!(next(start + 7260), Verdict::OverBudget);
        assert_eq!(next(start + 7261), Verdict::Accept);
    }

    #[test]
    fn a_window_covers_sixty_one_minutes_exactly_and_a_clock_going_back_counts_in_the_newest() {
        let ledger = Ledger::sized(61, 16);
        let start = NOW - NOW.rem_euclid(60);
        let mut seq = 0;
        for minute in 0..240 {
            seq += 1;
            assert_eq!(
                decide(&ledger, "s", seq, NOISY, start + minute * 60),
                Verdict::Accept,
                "{minute}"
            );
        }
        seq += 1;
        assert_eq!(
            decide(&ledger, "s", seq, NOISY, start + 239 * 60 + 30),
            Verdict::OverBudget
        );
        let back = Ledger::sized(2, 16);
        assert_eq!(decide(&back, "s", 1, NOISY, start + 600), Verdict::Accept);
        assert_eq!(decide(&back, "s", 2, NOISY, start + 300), Verdict::Accept);
        assert_eq!(
            decide(&back, "s", 3, NOISY, start + 100),
            Verdict::OverBudget
        );
        assert_eq!(
            decide(&back, "s", 4, NOISY, start + 600 + 3600),
            Verdict::OverBudget
        );
        assert_eq!(
            decide(&back, "s", 5, NOISY, start + 600 + 3660),
            Verdict::Accept
        );
    }

    #[test]
    fn drops_wait_for_a_mark_and_a_deferred_event_until_each_is_settled() {
        let ledger = Ledger::new();
        assert_eq!(ledger.pending_mark("s"), None);
        ledger.note_dropped("s", 3, false, None, NOW);
        assert_eq!(ledger.pending_mark("s"), None);
        ledger.note_dropped("s", 4, true, None, NOW);
        assert_eq!(ledger.pending_mark("s"), Some(7));
        ledger.marked("s");
        assert_eq!(ledger.pending_mark("s"), None);
        assert_eq!(ledger.claim_event("s"), None);
        ledger.defer_event("s");
        assert_eq!(ledger.claim_event("s"), Some(7));
        assert_eq!(ledger.claim_event("s"), None);
        assert_eq!(ledger.claim_event("unknown"), None);
        ledger.note_dropped("s", u64::MAX, true, None, NOW);
        assert_eq!(ledger.pending_mark("s"), Some(u64::MAX));
    }

    #[test]
    fn a_known_end_is_never_cleared_by_a_later_unknown_one() {
        let ledger = Ledger::new();
        let ended = NOW - 10;
        ledger.decide("s", 1, NOISY, Some(ended), NOW, |_| Gate::Open);
        ledger.decide("s", 2, NOISY, None, NOW, |_| Gate::Open);
        ledger.resolve("s", None);
        assert_eq!(ledger.sweep(ended + FORGET_AFTER_END_SECS + 1), 1);
    }

    #[test]
    fn entries_are_forgotten_after_the_end_window_unless_a_mark_or_an_event_is_pending() {
        let ledger = Ledger::new();
        let ended = NOW - ENDED_GRACE_SECS;
        for id in ["ended", "pending", "deferred"] {
            ledger.decide(id, 1, START, Some(ended), NOW, |_| Gate::Open);
        }
        ledger.note_dropped("pending", 1, true, None, NOW);
        ledger.defer_event("deferred");
        decide(&ledger, "live", 1, START, NOW);
        assert_eq!(ledger.sweep(ended + FORGET_AFTER_END_SECS), 0);
        assert_eq!(ledger.sweep(ended + FORGET_AFTER_END_SECS + 1), 1);
        assert_eq!(decide(&ledger, "ended", 1, START, NOW), Verdict::Accept);
        assert_eq!(ledger.len(), 4);
        ledger.marked("pending");
        ledger.claim_event("deferred");
        assert_eq!(ledger.sweep(ended + FORGET_AFTER_END_SECS + 1), 2);
        assert_eq!(ledger.sweep(NOW + IDLE_LIMIT_SECS), 0);
        assert_eq!(ledger.sweep(NOW + IDLE_LIMIT_SECS + 1), 2);
        assert_eq!(ledger.len(), 0);
    }

    #[test]
    fn sessions_with_an_unknown_end_are_rechecked_after_the_window_and_not_every_sweep() {
        let ledger = Ledger::new();
        decide(&ledger, "live", 1, START, NOW);
        for id in ["ended", "pending", "deferred"] {
            ledger.decide(id, 1, START, Some(NOW), NOW, |_| Gate::Open);
        }
        ledger.note_dropped("pending", 1, true, None, NOW);
        ledger.defer_event("deferred");
        let mut first = ledger.unresolved(NOW + 1, 10);
        first.sort();
        assert_eq!(first, ["deferred", "pending"]);
        let mut later = ledger.unresolved(NOW + ENDED_GRACE_SECS, 10);
        later.sort();
        assert_eq!(later, ["deferred", "live", "pending"]);
        assert_eq!(
            ledger.unresolved(NOW + ENDED_GRACE_SECS + 1, 0),
            Vec::<String>::new()
        );
        ledger.resolve("live", Some(NOW + 2));
        ledger.forget("pending");
        ledger.claim_event("deferred");
        assert!(ledger.unresolved(NOW + 4 * ENDED_GRACE_SECS, 10).is_empty());
    }

    #[test]
    fn deferred_events_are_offered_least_recently_offered_first_and_a_claimed_one_is_not_offered() {
        let ledger = Ledger::new();
        for id in ["a", "b", "c", "quiet"] {
            decide(&ledger, id, 1, START, NOW);
        }
        for id in ["a", "b", "c"] {
            ledger.defer_event(id);
        }
        let mut first = ledger.deferred_events(NOW, 2);
        first.sort();
        assert_eq!(first.len(), 2);
        let second = ledger.deferred_events(NOW + 5, 2);
        assert_eq!(second.len(), 2);
        let mut offered: Vec<String> = first.iter().chain(&second).cloned().collect();
        offered.sort();
        offered.dedup();
        assert_eq!(offered, ["a", "b", "c"]);
        assert!(!first.contains(&second[0]));
        assert_eq!(ledger.claim_event("c"), Some(0));
        let mut rest = ledger.deferred_events(NOW + 10, 10);
        rest.sort();
        assert_eq!(rest, ["a", "b"]);
        assert!(ledger.deferred_events(NOW + 15, 0).is_empty());
    }

    #[test]
    fn marks_waiting_for_their_flag_are_offered_in_bounded_portions_oldest_offer_first() {
        let ledger = Ledger::new();
        for id in ["a", "b", "c"] {
            ledger.note_dropped(id, 1, true, None, NOW);
        }
        ledger.note_dropped("unflagged", 1, false, None, NOW);
        assert_eq!(ledger.deferred_marks(NOW, 2), ["a", "b"]);
        assert_eq!(ledger.deferred_marks(NOW + 5, 2), ["c", "a"]);
        ledger.marked("b");
        assert_eq!(ledger.deferred_marks(NOW + 10, 10), ["a", "c"]);
        assert!(ledger.deferred_events(NOW + 10, 10).is_empty());
    }

    #[test]
    fn the_table_is_bounded_and_forgets_the_least_recently_seen_session_first() {
        let ledger = Ledger::sized(10_000, 3);
        for (index, id) in ["a", "b", "c"].into_iter().enumerate() {
            let at = NOW + i64::try_from(index).unwrap();
            decide(&ledger, id, 5, NOISY, at);
        }
        decide(&ledger, "a", 6, NOISY, NOW + 10);
        decide(&ledger, "d", 1, NOISY, NOW + 11);
        assert_eq!(ledger.len(), 3);
        assert_eq!(decide(&ledger, "a", 6, NOISY, NOW + 12), Verdict::Repeat);
        assert_eq!(decide(&ledger, "b", 5, NOISY, NOW + 13), Verdict::Accept);
        assert_eq!(ledger.len(), 3);
    }
}
