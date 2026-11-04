use custom_ring_interface::{
    CustomRingError, PolicySourceIxData, PolicyTableIxData, PrivateSourceWrite, RingPolicy,
    RingRole, SourceSlot, UpdatePolicyIxData,
};
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use spr_account_checks::AccountIterator;
use zolana_ring_policy::{ListId, ListSet};

use crate::instructions::{
    instruction_runtime::parse,
    loader::{load_records_registry, load_storage_registry, RoleHolder},
    policy_binding::{curator_source, TableBinding},
};

#[inline(never)]
pub fn process_update_policy_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let ix: UpdatePolicyIxData = parse(data)?;
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("policy_authority")?;
    let ring = iter.next_mut("ring")?;
    let trailing = iter.remaining_unchecked()?;

    // 1. Only the policy authority rewrites the policy.
    let mut policy = RoleHolder {
        program_id,
        role: RingRole::Policy,
        signer: authority,
    }
    .load_mut(ring)?;
    let write = PolicyWrite {
        program_id,
        policy: &mut policy,
        trailing,
        slot: Clock::get()?.slot,
    };
    // 2. Every write repins the hash or the records, a proof over the old state is refused.
    match ix {
        UpdatePolicyIxData::Rules(table) => write.replace_rules(&table),
        UpdatePolicyIxData::Source(source) => write.move_source(source),
        UpdatePolicyIxData::Records => write.rebind_records(),
        UpdatePolicyIxData::PrivateSource { owner_lists } => write.private_source(owner_lists),
    }
}

#[must_use]
struct PolicyWrite<'a> {
    program_id: &'a Address,
    policy: &'a mut RingPolicy,
    trailing: &'a [AccountView],
    slot: u64,
}

impl PolicyWrite<'_> {
    /// Refused on an audit-only ring, sources name exactly the lists the rules reference.
    #[inline(never)]
    fn replace_rules(self, table: &PolicyTableIxData) -> ProgramResult {
        self.policy.policy_hash()?;
        let bound = TableBinding {
            records: &self.policy.records,
            table,
            curators: self.trailing,
        }
        .bind()?;
        self.policy
            .set_policy(bound.sources, bound.rules, self.slot)?;
        Ok(())
    }

    /// Only a list the rules reference has a source, the own records or one curator.
    #[inline(never)]
    fn move_source(self, source: PolicySourceIxData) -> ProgramResult {
        let list_id =
            ListId::try_from(source.list_id).map_err(|_| CustomRingError::InvalidListId)?;
        let registry = match (source.source, self.trailing) {
            (0, []) => Address::default(),
            (1, [curator]) => curator_source(&self.policy.records, curator)?,
            _ => return Err(CustomRingError::InvalidSource.into()),
        };
        let mut sources = self.policy.sources;
        if sources[list_id.slot()].list_id == 0 {
            return Err(CustomRingError::InvalidSource.into());
        }
        sources[list_id.slot()] = SourceSlot {
            list_id: list_id as u8,
            registry,
        };
        // The rehashed source map refuses a second distinct curator.
        let rules = self.policy.rules;
        self.policy.set_policy(sources, rules, self.slot)?;
        Ok(())
    }

    /// A policy ring alone, a table needs to read the lists.
    #[inline(never)]
    fn private_source(self, owner_lists: u8) -> ProgramResult {
        self.policy.policy_hash()?;
        let owner_lists = ListSet::from_bits(owner_lists);
        match self.trailing {
            [] => self.policy.set_private_source(
                PrivateSourceWrite {
                    owner_lists,
                    source: None,
                },
                self.slot,
            )?,
            [registry] => {
                let source = load_storage_registry(registry)?;
                self.policy.set_private_source(
                    PrivateSourceWrite {
                        owner_lists,
                        source: Some((*registry.address(), &source)),
                    },
                    self.slot,
                )?
            }
            _ => return Err(CustomRingError::InvalidSource.into()),
        }
        Ok(())
    }

    #[inline(never)]
    fn rebind_records(self) -> ProgramResult {
        let [records] = self.trailing else {
            return Err(CustomRingError::InvalidStorageRegistry.into());
        };
        load_records_registry(self.program_id, records)?;
        self.policy.rebind_records(*records.address(), self.slot)?;
        Ok(())
    }
}
