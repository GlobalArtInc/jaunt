use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
pub(crate) struct Budget {
    used: AtomicUsize,
    max: usize,
}

impl Budget {
    pub(crate) fn new(max: usize) -> Self {
        Self {
            used: AtomicUsize::new(0),
            max,
        }
    }

    pub(crate) fn try_reserve(&self, bytes: usize) -> bool {
        self.used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|total| *total <= self.max)
            })
            .is_ok()
    }

    pub(crate) fn release(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let released = self
            .used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                Some(used.saturating_sub(bytes))
            });
        if released.is_ok_and(|before| before < bytes) {
            tracing::error!(
                target: "jaunt::agent",
                event = "agent.ssh.recording_budget_underflow",
                "the recording memory budget released more than it held"
            );
        }
    }

    #[cfg(test)]
    pub(crate) fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
}
