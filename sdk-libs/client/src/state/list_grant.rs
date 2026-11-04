//! What a Present rule reads for one subject, enrolling moves its position.

/// A subject's reading of a grant list, the last state needs a curator write and no retry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresentRead {
    Granted,
    NotListed,
    /// Allowlisted at salt zero and enrolled, a proof reads the salted position alone.
    SaltedWriteMissing,
}

/// One list bit at each position a subject has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListBits {
    /// `None` for a subject with no tracking row.
    pub salted: Option<bool>,
    pub salt_zero: bool,
}

impl ListBits {
    #[must_use]
    pub const fn present_read(self) -> PresentRead {
        match (self.salted, self.salt_zero) {
            (Some(true), _) | (None, true) => PresentRead::Granted,
            (Some(false), true) => PresentRead::SaltedWriteMissing,
            (Some(false), false) | (None, false) => PresentRead::NotListed,
        }
    }
}
