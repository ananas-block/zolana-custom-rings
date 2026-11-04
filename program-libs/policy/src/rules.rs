//! The list rules one transfer meets before proving, mirror
//! `prover/circuits/policy/rules.go` and `subjects.go`.

use core::fmt;

use thiserror::Error;

use crate::{
    asset_guard, owner_guard, DebitInput, DebitOutput, Guard, ListSet, Rule, RuleSource, RuleTable,
    SourceMap, Subject,
};

/// A member's record `lists` in each registry, zero for an absent member.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordLists {
    pub own: u64,
    /// Read only for a list a curator serves.
    pub curator: u64,
    /// Read only for an owner row's list a private source serves.
    pub private: u64,
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
        let foreign = foreign_lists(sources);
        let private = sources.private().owner_lists;
        let payments: Vec<DebitOutput> = transfer
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
                outputs: transfer.outputs,
                ring_inputs: transfer.ring_inputs,
                payments: &payments,
                foreign,
                private,
                index,
                rule,
            };
            match rule.subject {
                // No guard exempts the sender, with or without a spent input.
                Subject::Sender => check.listed(TransferSubject::Sender, transfer.sender)?,
                Subject::OutputOwner | Subject::Asset => {
                    (0..transfer.outputs.len()).try_for_each(|output| check.output(output))?
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
    fn on(self, foreign: ListSet, private: ListSet) -> ListSet {
        let (foreign, private) = (foreign.record_bits(), private.record_bits());
        let public = (self.own & !foreign) | (self.curator & foreign);
        ListSet::from_bits(((public & !private) | (self.private & private)) as u8)
    }
}

struct RuleCheck<'a> {
    outputs: &'a [OutputSubjects],
    ring_inputs: &'a [DebitInput],
    payments: &'a [DebitOutput],
    foreign: ListSet,
    private: ListSet,
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
        let exempt = match self.rule.guard {
            Guard::Always => false,
            Guard::AboveAmount(threshold) if on_asset => {
                asset_guard(self.ring_inputs, self.payments, &output.asset) <= u128::from(threshold)
            }
            Guard::AboveAmount(threshold) => self.guard(output) <= u128::from(threshold),
            Guard::AboveAmountByAsset => {
                self.guard(output) <= u128::from(output.mint_policy.threshold)
            }
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

    fn guard(&self, output: &OutputSubjects) -> u128 {
        owner_guard(
            self.ring_inputs,
            self.payments,
            &output.owner,
            &output.asset,
        )
    }

    fn listed(&self, subject: TransferSubject, records: RecordLists) -> Result<(), RuleRefusal> {
        let private = match subject {
            TransferSubject::Asset(_) => ListSet::EMPTY,
            TransferSubject::Sender | TransferSubject::Owner(_) => self.private,
        };
        if holds(self.rule, records.on(self.foreign, private)) {
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
    use crate::{DebitInput, ListId, MintPolicy, PrivateSource, RuleTableBuilder};

    const OWNER: [u8; 32] = [1; 32];
    const ASSET: [u8; 32] = [2; 32];
    const BLOCK: u64 = ListId::Block.record_bit();

    fn admit(table: RuleTableBuilder, lists: RecordLists) -> Result<(), RuleRefusal> {
        let private = PrivateSource::new(ListSet::single(ListId::Block), [7; 32]).unwrap();
        let sources = SourceMap::new(&[(ListId::Block, [0; 32])])
            .unwrap()
            .with_private(private)
            .unwrap();
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

    #[test]
    fn an_owner_row_reads_the_private_bit_and_an_asset_row_the_public_one() {
        let owner = RuleTable::builder().rule(Rule::forbid(Subject::OutputOwner, ListId::Block));
        let asset = RuleTable::builder().rule(Rule::forbid(Subject::Asset, ListId::Block));
        let private_only = RecordLists {
            private: BLOCK,
            ..RecordLists::default()
        };
        let public_only = RecordLists {
            own: BLOCK,
            ..RecordLists::default()
        };
        assert!(admit(owner, private_only).is_err());
        assert!(admit(owner, public_only).is_ok());
        assert!(admit(asset, private_only).is_ok());
        assert!(admit(asset, public_only).is_err());
    }
}
