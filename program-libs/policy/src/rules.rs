//! The list rules one transfer meets before proving, mirror
//! `prover/circuits/policy/rules.go` and `subjects.go`.

use core::fmt;

use thiserror::Error;

use crate::{
    DebitInput, DebitOutput, Guard, GuardScope, ListSet, Rule, RuleSource, RuleTable, SourceMap,
    Subject,
};

/// A member's record `lists` in each registry, zero for an absent member.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordLists {
    pub own: u64,
    /// Read only for a list a curator serves.
    pub curator: u64,
    /// Zero with no tracking row.
    pub salted: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputSubjects {
    /// Set on a same-ring output, clear on an exit or a withdrawal.
    pub ring: bool,
    /// The owner identity, zero carries no owner obligation.
    pub owner: [u8; 32],
    /// `Member::asset` of the mint.
    pub asset: [u8; 32],
    pub amount: u64,
    pub owner_lists: RecordLists,
    pub asset_lists: RecordLists,
    pub mint_policy: crate::MintPolicy,
}

#[derive(Clone, Copy, Debug)]
pub struct TransferSubjects<'a> {
    pub sender: RecordLists,
    /// Live inputs of the ring, a default-ring note and a deposit net no receipt.
    pub ring_inputs: &'a [DebitInput],
    /// The payments in slot order, dummies and compact padding left out.
    pub outputs: &'a [OutputSubjects],
}

/// The side of a transfer the owner and asset rules read, it holds no sender row.
#[derive(Clone, Copy, Debug)]
pub struct PaymentSubjects<'a> {
    /// Live inputs of the ring, a default-ring note and a deposit net no receipt.
    pub ring_inputs: &'a [DebitInput],
    /// The payments in slot order, dummies and compact padding left out.
    pub outputs: &'a [OutputSubjects],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferSubject {
    Sender,
    /// A position in `TransferSubjects::outputs`.
    Owner(usize),
    /// A position in `TransferSubjects::outputs`.
    Asset(usize),
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RuleRefusal {
    #[error("rule {rule} refuses {subject}")]
    Lists {
        rule: usize,
        subject: TransferSubject,
    },
}

impl RuleTable {
    /// The first refusal in the circuit's constraint order, caps, outflow and co-sign left out.
    pub fn admit(
        &self,
        sources: &SourceMap,
        transfer: &TransferSubjects<'_>,
    ) -> Result<(), RuleRefusal> {
        self.screen(
            sources,
            Screened {
                senders: &[transfer.sender],
                payments: PaymentSubjects {
                    ring_inputs: transfer.ring_inputs,
                    outputs: transfer.outputs,
                },
            },
        )
    }

    /// The sender rules over each live sender row, an owner or asset rule is not read.
    pub fn evaluate_senders(
        &self,
        sources: &SourceMap,
        senders: &[RecordLists],
    ) -> Result<(), RuleRefusal> {
        self.screen(
            sources,
            Screened {
                senders,
                payments: PaymentSubjects {
                    ring_inputs: &[],
                    outputs: &[],
                },
            },
        )
    }

    /// The owner and asset rules over the payments, a sender rule is not read.
    ///
    /// The circuit screens each payment whatever the sender rows hold, a transfer with no live
    /// sender row owes the check all the same. Running it inside a loop over sender rows skips
    /// it there, and the refusal then surfaces only as a failed proof.
    pub fn evaluate_payments(
        &self,
        sources: &SourceMap,
        payments: PaymentSubjects<'_>,
    ) -> Result<(), RuleRefusal> {
        self.screen(
            sources,
            Screened {
                senders: &[],
                payments,
            },
        )
    }

    fn screen(&self, sources: &SourceMap, screened: Screened<'_>) -> Result<(), RuleRefusal> {
        let Screened { senders, payments } = screened;
        let foreign = foreign_lists(sources);
        let salted = sources.salted();
        let debits: Vec<DebitOutput> = payments
            .outputs
            .iter()
            .map(|output| DebitOutput {
                ring: output.ring,
                owner: output.owner,
                asset: output.asset,
                amount: output.amount,
            })
            .collect();
        for (index, rule) in self.rules().iter().enumerate() {
            let check = RuleCheck {
                outputs: payments.outputs,
                scope: GuardScope {
                    ring_inputs: payments.ring_inputs,
                    payments: &debits,
                },
                foreign,
                salted,
                index,
                rule,
            };
            match rule.subject {
                // No guard exempts the sender, with or without a spent input.
                Subject::Sender => senders
                    .iter()
                    .try_for_each(|sender| check.listed(TransferSubject::Sender, *sender))?,
                Subject::OutputOwner | Subject::Asset => {
                    (0..payments.outputs.len()).try_for_each(|output| check.output(output))?
                }
                Subject::ExitDestination => {}
            }
        }
        Ok(())
    }
}

impl fmt::Display for TransferSubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sender => f.write_str("the sender"),
            Self::Owner(output) => write!(f, "the owner of output {output}"),
            Self::Asset(output) => write!(f, "the asset of output {output}"),
        }
    }
}

impl RecordLists {
    /// List `i + 1` reads the curator record when a curator serves it, else the own record.
    fn on(self, foreign: ListSet, salted: ListSet) -> ListSet {
        let (foreign, salted) = (foreign.record_bits(), salted.record_bits());
        let public = (self.own & !foreign) | (self.curator & foreign);
        ListSet::from_bits(((public & !salted) | (self.salted & salted)) as u8)
    }
}

struct Screened<'a> {
    senders: &'a [RecordLists],
    payments: PaymentSubjects<'a>,
}

struct RuleCheck<'a> {
    outputs: &'a [OutputSubjects],
    scope: GuardScope<'a>,
    foreign: ListSet,
    salted: ListSet,
    index: usize,
    rule: &'a Rule,
}

impl RuleCheck<'_> {
    fn output(&self, index: usize) -> Result<(), RuleRefusal> {
        let output = &self.outputs[index];
        let on_asset = self.rule.subject == Subject::Asset;
        if !on_asset && output.owner == [0; 32] {
            return Ok(());
        }
        let owner_guard = self.scope.owner(&output.owner, &output.asset);
        let exempt = match self.rule.guard {
            Guard::Always => false,
            Guard::AboveAmount(threshold) if on_asset => {
                self.scope.asset(&output.asset) <= u128::from(threshold)
            }
            Guard::AboveAmount(threshold) => owner_guard <= u128::from(threshold),
            Guard::AboveAmountByAsset => owner_guard <= u128::from(output.mint_policy.threshold),
        };
        if exempt {
            return Ok(());
        }
        if on_asset {
            self.listed(TransferSubject::Asset(index), output.asset_lists)
        } else {
            self.listed(TransferSubject::Owner(index), output.owner_lists)
        }
    }

    fn listed(&self, subject: TransferSubject, records: RecordLists) -> Result<(), RuleRefusal> {
        let salted = match subject {
            TransferSubject::Asset(_) => ListSet::EMPTY,
            TransferSubject::Sender | TransferSubject::Owner(_) => self.salted,
        };
        if holds(self.rule, records.on(self.foreign, salted)) {
            return Ok(());
        }
        Err(RuleRefusal::Lists {
            rule: self.index,
            subject,
        })
    }
}

/// On any list of the present set, or off any list of the absent set.
fn holds(rule: &Rule, on: ListSet) -> bool {
    let RuleSource::Lists { present, absent } = rule.source;
    present.intersects(on) || !absent.difference(on).is_empty()
}

fn foreign_lists(sources: &SourceMap) -> ListSet {
    let bits = sources
        .slots()
        .iter()
        .enumerate()
        .filter(|(_, slot)| slot.registry != [0; 32])
        .fold(0u8, |bits, (slot, _)| bits | 1 << slot);
    ListSet::from_bits(bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DebitInput, ListId, MintPolicy, RuleTableBuilder};

    const OWNER: [u8; 32] = [1; 32];
    const ASSET: [u8; 32] = [2; 32];
    const BLOCK: u64 = ListId::Block.record_bit();
    const PRIVATE_BLOCK: u64 = ListId::PrivateBlock.record_bit();

    fn admit(table: RuleTableBuilder, lists: RecordLists) -> Result<(), RuleRefusal> {
        let sources =
            SourceMap::new(&[(ListId::Block, [0; 32]), (ListId::PrivateBlock, [0; 32])]).unwrap();
        let outputs = [OutputSubjects {
            ring: true,
            owner: OWNER,
            asset: ASSET,
            amount: 1,
            owner_lists: lists,
            asset_lists: lists,
            mint_policy: MintPolicy::EMPTY,
        }];
        let ring_inputs: [DebitInput; 0] = [];
        table.build().admit(
            &sources,
            &TransferSubjects {
                sender: RecordLists::default(),
                ring_inputs: &ring_inputs,
                outputs: &outputs,
            },
        )
    }

    fn payment(owner_lists: RecordLists) -> OutputSubjects {
        OutputSubjects {
            ring: true,
            owner: OWNER,
            asset: ASSET,
            amount: 1,
            owner_lists,
            asset_lists: RecordLists::default(),
            mint_policy: MintPolicy::EMPTY,
        }
    }

    fn listed(public: bool, salted: bool, enrolled: bool) -> RecordLists {
        RecordLists {
            own: if public { BLOCK } else { 0 },
            curator: 0,
            salted: if salted && enrolled { PRIVATE_BLOCK } else { 0 },
        }
    }

    #[test]
    fn two_deny_rules_hold_each_owner_to_both_lists_before_and_after_enrolling() {
        let both = ListSet::of(&[ListId::Block, ListId::PrivateBlock]);
        let each = || RuleTable::builder().forbid_each(Subject::OutputOwner, both);
        for (public, salted, before, after) in [
            (false, false, true, true),
            (true, false, false, false),
            (false, true, true, false),
            (true, true, false, false),
        ] {
            assert_eq!(admit(each(), listed(public, salted, false)).is_ok(), before);
            assert_eq!(admit(each(), listed(public, salted, true)).is_ok(), after);
        }
    }

    #[test]
    fn one_rule_over_both_lists_admits_an_owner_off_either() {
        let both = ListSet::of(&[ListId::Block, ListId::PrivateBlock]);
        let one =
            || RuleTable::builder().rule(Rule::forbid_only_on_all(Subject::OutputOwner, both));
        assert!(admit(one(), listed(true, false, true)).is_ok());
        assert!(admit(one(), listed(false, true, true)).is_ok());
        assert!(admit(one(), listed(true, true, true)).is_err());
    }

    #[test]
    fn an_owner_row_reads_the_salted_bit_and_an_asset_row_the_public_one() {
        let owner =
            RuleTable::builder().rule(Rule::forbid(Subject::OutputOwner, ListId::PrivateBlock));
        let asset = RuleTable::builder().rule(Rule::forbid(Subject::Asset, ListId::PrivateBlock));
        let salted_only = RecordLists {
            salted: PRIVATE_BLOCK,
            ..RecordLists::default()
        };
        let public_only = RecordLists {
            own: PRIVATE_BLOCK,
            ..RecordLists::default()
        };
        assert!(admit(owner, salted_only).is_err());
        assert!(admit(owner, public_only).is_ok());
        assert!(admit(asset, salted_only).is_ok());
        assert!(admit(asset, public_only).is_err());
    }

    #[test]
    fn a_blocked_payment_refuses_with_no_live_sender_row() {
        let table = RuleTable::builder()
            .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
            .rule(Rule::forbid(Subject::OutputOwner, ListId::Block))
            .build();
        let sources =
            SourceMap::new(&[(ListId::Frozen, [0; 32]), (ListId::Block, [0; 32])]).unwrap();
        let outputs = [payment(RecordLists {
            own: BLOCK,
            ..RecordLists::default()
        })];
        assert_eq!(table.evaluate_senders(&sources, &[]), Ok(()));
        assert_eq!(
            table.evaluate_payments(
                &sources,
                PaymentSubjects {
                    ring_inputs: &[],
                    outputs: &outputs,
                },
            ),
            Err(RuleRefusal::Lists {
                rule: 1,
                subject: TransferSubject::Owner(0),
            })
        );
    }

    #[test]
    fn each_evaluation_reads_only_its_own_rules() {
        const FROZEN: u64 = ListId::Frozen.record_bit();
        let table = RuleTable::builder()
            .rule(Rule::forbid(Subject::OutputOwner, ListId::Block))
            .rule(Rule::forbid(Subject::Sender, ListId::Frozen))
            .build();
        let sources =
            SourceMap::new(&[(ListId::Frozen, [0; 32]), (ListId::Block, [0; 32])]).unwrap();
        let frozen = RecordLists {
            own: FROZEN,
            ..RecordLists::default()
        };
        assert_eq!(
            table.evaluate_senders(&sources, &[RecordLists::default(), frozen]),
            Err(RuleRefusal::Lists {
                rule: 1,
                subject: TransferSubject::Sender,
            })
        );
        let clean = [payment(RecordLists::default())];
        assert_eq!(
            table.evaluate_payments(
                &sources,
                PaymentSubjects {
                    ring_inputs: &[],
                    outputs: &clean,
                },
            ),
            Ok(())
        );
    }

    #[test]
    fn admit_refuses_what_either_evaluation_refuses() {
        let table = RuleTable::builder()
            .rule(Rule::forbid(Subject::OutputOwner, ListId::Block))
            .rule(Rule::forbid(Subject::Sender, ListId::Block))
            .build();
        let sources = SourceMap::new(&[(ListId::Block, [0; 32])]).unwrap();
        let blocked = RecordLists {
            own: BLOCK,
            ..RecordLists::default()
        };
        let admit = |sender, owner| {
            let outputs = [payment(owner)];
            table.admit(
                &sources,
                &TransferSubjects {
                    sender,
                    ring_inputs: &[],
                    outputs: &outputs,
                },
            )
        };
        let clean = RecordLists::default();
        assert_eq!(admit(clean, clean), Ok(()));
        assert!(admit(blocked, clean).is_err());
        assert!(admit(clean, blocked).is_err());
    }
}
