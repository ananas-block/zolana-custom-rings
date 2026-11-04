//! One state per published nullifier, driven only by finalized frames and note openings.

use zolana_ring_client::rpc::WalletNoteStatus;

use crate::utxos::CreatedIn;

/// `Padding`, `External` and `Resolved` are terminal, an unresolved row never reads as padding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SpendState {
    /// The frame's stream is unreadable, the frame retries.
    Observed,
    Padding,
    External,
    Resolved {
        note: [u8; 32],
    },
    /// `evidence` is the commitment a hash-bearing frame names.
    UnresolvedReal {
        evidence: Option<[u8; 32]>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SpendRow {
    pub nullifier: [u8; 32],
    pub frame: CreatedIn,
    pub position: u16,
    pub state: SpendState,
}

/// What the frame's proven stream says of one input position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InputRead {
    Unreadable,
    Padding,
    External,
    Real { evidence: Option<[u8; 32]> },
}

/// The envelope's real-input count and default bits, dummies sit last.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TransferStream {
    pub real_inputs: u8,
    pub default_bits: u64,
}

/// One nullifier as a frame publishes it, `hit` is the note index's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Observation {
    pub nullifier: [u8; 32],
    pub frame: CreatedIn,
    pub position: u16,
    pub read: InputRead,
    pub hit: Option<[u8; 32]>,
}

#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Transition {
    Unchanged,
    Write(SpendRow),
    /// A second event on one nullifier, the first state stays.
    Integrity(SpendRow),
}

impl TransferStream {
    /// Only a position at or past the count is padding.
    pub(crate) fn read(self, position: u16) -> InputRead {
        if position >= u16::from(self.real_inputs) {
            return InputRead::Padding;
        }
        let default_input = u32::from(position) < u64::BITS
            && self.default_bits & (1u64 << u32::from(position)) != 0;
        match default_input {
            true => InputRead::External,
            false => InputRead::Real { evidence: None },
        }
    }
}

impl Observation {
    pub(crate) fn state(self) -> SpendState {
        match (self.read, self.hit) {
            (InputRead::Unreadable, _) => SpendState::Observed,
            (InputRead::Padding, _) => SpendState::Padding,
            (InputRead::External, _) => SpendState::External,
            (InputRead::Real { .. }, Some(note)) => SpendState::Resolved { note },
            (InputRead::Real { evidence }, None) => SpendState::UnresolvedReal { evidence },
        }
    }

    /// A replay of one frame is idempotent, a read moves only `Observed` or `UnresolvedReal`.
    pub(crate) fn apply(self, existing: Option<&SpendRow>) -> Transition {
        let row = SpendRow {
            nullifier: self.nullifier,
            frame: self.frame,
            position: self.position,
            state: self.state(),
        };
        let Some(existing) = existing else {
            return Transition::Write(row);
        };
        if existing.frame != self.frame || existing.position != self.position {
            return Transition::Integrity(row);
        }
        let moves = match existing.state {
            SpendState::Observed => row.state != SpendState::Observed,
            SpendState::UnresolvedReal { .. } => matches!(row.state, SpendState::Resolved { .. }),
            SpendState::Padding | SpendState::External | SpendState::Resolved { .. } => false,
        };
        match moves {
            true => Transition::Write(row),
            false => Transition::Unchanged,
        }
    }
}

impl SpendRow {
    /// A newly opened note or a late secret moves an unresolved row only.
    pub(crate) fn opened(self, note: [u8; 32]) -> Transition {
        match self.state {
            SpendState::UnresolvedReal { .. } => Transition::Write(Self {
                state: SpendState::Resolved { note },
                ..self
            }),
            SpendState::Resolved { note: held } if held != note => Transition::Integrity(self),
            SpendState::Resolved { .. }
            | SpendState::Observed
            | SpendState::Padding
            | SpendState::External => Transition::Unchanged,
        }
    }
}

/// The inputs of one note's status, each read from its own nullifier and no other row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NoteRead {
    pub nullifier_known: bool,
    /// The published row of the note's nullifier, or a historical row's slot.
    pub spent_at: Option<u64>,
    pub zero_key_wallet: bool,
    pub history_through: u64,
}

impl NoteRead {
    /// `Spent` comes first, a spent zero key note leaves the exposed list.
    pub(crate) fn status(self) -> WalletNoteStatus {
        let spent = self
            .spent_at
            .is_some_and(|slot| slot <= self.history_through);
        match (spent, self.nullifier_known, self.zero_key_wallet) {
            (true, _, _) => WalletNoteStatus::Spent,
            (false, _, true) => WalletNoteStatus::ExposedIfSpent,
            (false, false, false) => WalletNoteStatus::Unknown,
            (false, true, false) => WalletNoteStatus::Unspent,
        }
    }
}

#[cfg(test)]
mod tests {
    use solana_signature::Signature;

    use super::*;

    const STREAM: TransferStream = TransferStream {
        real_inputs: 3,
        default_bits: 0b010,
    };

    fn frame(byte: u8) -> CreatedIn {
        CreatedIn {
            slot: u64::from(byte),
            tx_signature: Signature::from([byte; 64]),
            event_index: 0,
        }
    }

    fn observed(read: InputRead, hit: Option<[u8; 32]>) -> Observation {
        Observation {
            nullifier: [1; 32],
            frame: frame(1),
            position: 0,
            read,
            hit,
        }
    }

    fn written(transition: Transition) -> SpendState {
        match transition {
            Transition::Write(row) => row.state,
            other => panic!("expected a write, got {other:?}"),
        }
    }

    #[test]
    fn a_transfer_position_reads_from_the_count_and_the_default_bits() {
        assert_eq!(STREAM.read(0), InputRead::Real { evidence: None });
        assert_eq!(STREAM.read(1), InputRead::External);
        assert_eq!(STREAM.read(2), InputRead::Real { evidence: None });
        assert_eq!(STREAM.read(3), InputRead::Padding);
        assert_eq!(STREAM.read(u16::MAX), InputRead::Padding);
    }

    #[test]
    fn each_read_enters_its_state() {
        let real = InputRead::Real { evidence: None };
        for (read, hit, state) in [
            (InputRead::Padding, None, SpendState::Padding),
            (InputRead::External, None, SpendState::External),
            (real, None, SpendState::UnresolvedReal { evidence: None }),
            (real, Some([2; 32]), SpendState::Resolved { note: [2; 32] }),
            (InputRead::Unreadable, None, SpendState::Observed),
            (InputRead::Unreadable, Some([2; 32]), SpendState::Observed),
        ] {
            assert_eq!(written(observed(read, hit).apply(None)), state);
        }
    }

    #[test]
    fn padding_and_external_ignore_a_hit() {
        for read in [InputRead::Padding, InputRead::External] {
            assert!(!matches!(
                observed(read, Some([2; 32])).state(),
                SpendState::Resolved { .. }
            ));
        }
    }

    #[test]
    fn an_unreadable_row_moves_only_once_read() {
        let row = SpendRow {
            nullifier: [1; 32],
            frame: frame(1),
            position: 0,
            state: SpendState::Observed,
        };
        assert_eq!(
            observed(InputRead::Unreadable, None).apply(Some(&row)),
            Transition::Unchanged
        );
        assert_eq!(
            written(observed(InputRead::Padding, None).apply(Some(&row))),
            SpendState::Padding
        );
    }

    #[test]
    fn a_replay_changes_no_terminal_row() {
        for state in [
            SpendState::Padding,
            SpendState::External,
            SpendState::Resolved { note: [2; 32] },
        ] {
            let row = SpendRow {
                nullifier: [1; 32],
                frame: frame(1),
                position: 0,
                state,
            };
            for read in [
                InputRead::Padding,
                InputRead::External,
                InputRead::Unreadable,
                InputRead::Real { evidence: None },
            ] {
                assert_eq!(
                    observed(read, Some([3; 32])).apply(Some(&row)),
                    Transition::Unchanged
                );
            }
        }
    }

    #[test]
    fn a_second_event_on_one_nullifier_is_an_integrity_fault_and_overwrites_nothing() {
        let row = SpendRow {
            nullifier: [1; 32],
            frame: frame(1),
            position: 0,
            state: SpendState::Resolved { note: [2; 32] },
        };
        let second = Observation {
            frame: frame(2),
            ..observed(InputRead::Real { evidence: None }, Some([3; 32]))
        };
        assert!(matches!(
            second.apply(Some(&row)),
            Transition::Integrity(fault) if fault.frame == frame(2)
        ));
    }

    #[test]
    fn an_opened_note_resolves_an_unresolved_row_and_no_other() {
        let row = |state| SpendRow {
            nullifier: [1; 32],
            frame: frame(1),
            position: 0,
            state,
        };
        assert_eq!(
            written(row(SpendState::UnresolvedReal { evidence: None }).opened([2; 32])),
            SpendState::Resolved { note: [2; 32] }
        );
        for state in [
            SpendState::Observed,
            SpendState::Padding,
            SpendState::External,
            SpendState::Resolved { note: [2; 32] },
        ] {
            assert_eq!(row(state).opened([2; 32]), Transition::Unchanged);
        }
        assert!(matches!(
            row(SpendState::Resolved { note: [3; 32] }).opened([2; 32]),
            Transition::Integrity(_)
        ));
    }

    #[test]
    fn spent_comes_before_every_other_status() {
        let read = NoteRead {
            nullifier_known: true,
            spent_at: None,
            zero_key_wallet: false,
            history_through: 10,
        };
        assert_eq!(read.status(), WalletNoteStatus::Unspent);
        assert_eq!(
            NoteRead {
                nullifier_known: false,
                ..read
            }
            .status(),
            WalletNoteStatus::Unknown
        );
        let exposed = NoteRead {
            zero_key_wallet: true,
            ..read
        };
        assert_eq!(exposed.status(), WalletNoteStatus::ExposedIfSpent);
        assert_eq!(
            NoteRead {
                spent_at: Some(10),
                ..exposed
            }
            .status(),
            WalletNoteStatus::Spent
        );
    }

    #[test]
    fn a_spend_past_the_history_slot_stays_unspent_so_a_note_and_its_change_never_both_count() {
        let read = NoteRead {
            nullifier_known: true,
            spent_at: Some(11),
            zero_key_wallet: false,
            history_through: 10,
        };
        assert_eq!(read.status(), WalletNoteStatus::Unspent);
    }
}
