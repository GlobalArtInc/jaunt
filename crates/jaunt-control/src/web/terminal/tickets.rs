use std::collections::HashMap;
use std::sync::Mutex;

use crate::completion;
use crate::token::hash_secret;

use super::{TERMINAL_TICKET_TTL_SECS, locked};

pub(crate) const MAX_TICKETS_PER_SESSION: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Binding {
    pub(crate) web_session: String,
    pub(crate) user_id: String,
    pub(crate) node: String,
    pub(crate) login: String,
}

struct Ticket {
    binding: Binding,
    expires_at: i64,
    order: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TicketProblem {
    Unknown,
    Expired,
    Foreign,
    OtherTarget,
}

impl TicketProblem {
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            TicketProblem::Unknown => "ticket_unknown",
            TicketProblem::Expired => "ticket_expired",
            TicketProblem::Foreign => "ticket_foreign",
            TicketProblem::OtherTarget => "ticket_other_target",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IssueProblem {
    Full,
    Entropy,
}

#[derive(Default)]
struct Book {
    tickets: HashMap<String, Ticket>,
    next: u64,
}

pub(crate) struct TicketTable {
    book: Mutex<Book>,
    capacity: usize,
}

impl TicketTable {
    pub(crate) fn new(capacity: usize) -> TicketTable {
        TicketTable {
            book: Mutex::new(Book::default()),
            capacity: capacity.max(1),
        }
    }

    pub(crate) fn issue(&self, binding: Binding, now: i64) -> Result<String, IssueProblem> {
        let code = completion::issue().map_err(|_| IssueProblem::Entropy)?;
        let mut book = locked(&self.book);
        book.tickets.retain(|_, ticket| ticket.expires_at > now);
        let mut own: Vec<(u64, String)> = book
            .tickets
            .iter()
            .filter(|(_, ticket)| ticket.binding.web_session == binding.web_session)
            .map(|(hash, ticket)| (ticket.order, hash.clone()))
            .collect();
        own.sort();
        let surplus = (own.len() + 1).saturating_sub(MAX_TICKETS_PER_SESSION);
        for (_, hash) in own.into_iter().take(surplus) {
            book.tickets.remove(&hash);
        }
        if book.tickets.len() >= self.capacity {
            return Err(IssueProblem::Full);
        }
        let order = book.next;
        book.next = book.next.wrapping_add(1);
        book.tickets.insert(
            code.hash,
            Ticket {
                binding,
                expires_at: now.saturating_add(TERMINAL_TICKET_TTL_SECS),
                order,
            },
        );
        Ok(code.secret)
    }

    pub(crate) fn check(
        &self,
        presented: &str,
        wanted: &Binding,
        now: i64,
    ) -> Result<(), TicketProblem> {
        let book = locked(&self.book);
        Self::matching(&book, presented, wanted, now).map(|_| ())
    }

    pub(crate) fn take(
        &self,
        presented: &str,
        wanted: &Binding,
        now: i64,
    ) -> Result<(), TicketProblem> {
        let mut book = locked(&self.book);
        let hash = Self::matching(&book, presented, wanted, now)?;
        book.tickets.remove(&hash);
        Ok(())
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        locked(&self.book).tickets.len()
    }

    fn matching(
        book: &Book,
        presented: &str,
        wanted: &Binding,
        now: i64,
    ) -> Result<String, TicketProblem> {
        if !completion::is_well_formed(presented) {
            return Err(TicketProblem::Unknown);
        }
        let hash = hash_secret(presented);
        let Some(ticket) = book.tickets.get(&hash) else {
            return Err(TicketProblem::Unknown);
        };
        if ticket.expires_at <= now {
            return Err(TicketProblem::Expired);
        }
        if ticket.binding.web_session != wanted.web_session
            || ticket.binding.user_id != wanted.user_id
        {
            return Err(TicketProblem::Foreign);
        }
        if ticket.binding.node != wanted.node || ticket.binding.login != wanted.login {
            return Err(TicketProblem::OtherTarget);
        }
        Ok(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::{Binding, IssueProblem, MAX_TICKETS_PER_SESSION, TicketProblem, TicketTable};

    const NOW: i64 = 1_700_000_000;

    fn binding(session: &str, node: &str, login: &str) -> Binding {
        Binding {
            web_session: session.to_owned(),
            user_id: format!("user-of-{session}"),
            node: node.to_owned(),
            login: login.to_owned(),
        }
    }

    #[test]
    fn a_ticket_opens_once_for_its_own_session_and_target_within_thirty_seconds() {
        let table = TicketTable::new(16);
        let wanted = binding("s1", "web-01", "deploy");
        let ticket = table.issue(wanted.clone(), NOW).unwrap();
        assert_eq!(ticket.len(), 43);

        let other_session = Binding {
            web_session: "s2".to_owned(),
            ..wanted.clone()
        };
        let other_user = Binding {
            user_id: "someone".to_owned(),
            ..wanted.clone()
        };
        for (presented, binding, now, problem) in [
            (ticket.as_str(), &other_session, NOW, TicketProblem::Foreign),
            (ticket.as_str(), &other_user, NOW, TicketProblem::Foreign),
            (
                ticket.as_str(),
                &binding("s1", "web-02", "deploy"),
                NOW,
                TicketProblem::OtherTarget,
            ),
            (
                ticket.as_str(),
                &binding("s1", "web-01", "root"),
                NOW,
                TicketProblem::OtherTarget,
            ),
            (ticket.as_str(), &wanted, NOW + 30, TicketProblem::Expired),
            ("not-a-ticket", &wanted, NOW, TicketProblem::Unknown),
            (&ticket[1..], &wanted, NOW, TicketProblem::Unknown),
        ] {
            assert_eq!(table.check(presented, binding, now), Err(problem));
            assert_eq!(table.take(presented, binding, now), Err(problem));
        }
        assert_eq!(table.check(&ticket, &wanted, NOW + 29), Ok(()));
        assert_eq!(table.take(&ticket, &wanted, NOW + 29), Ok(()));
        assert_eq!(
            table.take(&ticket, &wanted, NOW + 29),
            Err(TicketProblem::Unknown)
        );
    }

    #[test]
    fn the_table_is_bounded_per_session_and_in_total_and_drops_expired_tickets() {
        let table = TicketTable::new(10);
        let first = table.issue(binding("s1", "web-01", "deploy"), NOW).unwrap();
        for _ in 1..MAX_TICKETS_PER_SESSION + 3 {
            table.issue(binding("s1", "web-01", "deploy"), NOW).unwrap();
        }
        assert_eq!(table.len(), MAX_TICKETS_PER_SESSION);
        assert_eq!(
            table.check(&first, &binding("s1", "web-01", "deploy"), NOW),
            Err(TicketProblem::Unknown)
        );
        table.issue(binding("s2", "web-01", "deploy"), NOW).unwrap();
        table.issue(binding("s3", "web-01", "deploy"), NOW).unwrap();
        assert_eq!(
            table.issue(binding("s4", "web-01", "deploy"), NOW),
            Err(IssueProblem::Full)
        );
        assert!(
            table
                .issue(binding("s4", "web-01", "deploy"), NOW + 30)
                .is_ok()
        );
        assert_eq!(table.len(), 1);
    }
}
