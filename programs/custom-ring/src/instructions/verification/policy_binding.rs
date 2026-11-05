//! Turns instruction table data into the rule table and source slots a ring stores.
//!
//! The policy hash covers the rules and their source map, and every policy proof binds that hash. A
//! source for a list no rule reads would change the hash with no rule behind it.
//!
//! Read after `instructions/configuration/setup/initialize.rs`. Read before `instructions/configuration/policy/update_policy.rs`.

use bytemuck::Zeroable;
use custom_ring_interface::{CustomRingError, PolicyTableIxData, SourceSlot, N_SOURCE_SLOTS};
use pinocchio::{error::ProgramError, AccountView, Address};
use zolana_ring_policy::{EncodedRuleTable, ListId, ListSet, TableParts};

use crate::instructions::loader::load_storage_registry;

pub(crate) struct BoundTable {
    pub rules: EncodedRuleTable,
    pub sources: [SourceSlot; N_SOURCE_SLOTS],
}

#[must_use]
pub(crate) struct TableBinding<'a> {
    pub table: &'a PolicyTableIxData,
    pub curators: &'a [AccountView],
}

impl TableBinding<'_> {
    /// Boxed off the SBF stack, the sources name only lists the table references.
    #[inline(never)]
    pub fn bind(self) -> Result<Box<BoundTable>, ProgramError> {
        let table = self.table;
        let rules = TableParts { rows: &table.rules }
            .encode()
            .map_err(CustomRingError::from)?;
        let sources = self.sources(rules.referenced())?;
        Ok(Box::new(BoundTable { rules, sources }))
    }

    #[inline(never)]
    fn sources(&self, referenced: ListSet) -> Result<[SourceSlot; N_SOURCE_SLOTS], ProgramError> {
        let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
        let mut seen = ListSet::EMPTY;
        // Lists sharing a curator load its registry once.
        let mut loaded: Vec<Address> = Vec::new();
        for spec in &self.table.sources {
            let list_id =
                ListId::try_from(spec.list_id).map_err(|_| CustomRingError::InvalidSource)?;
            if !referenced.contains(list_id) || seen.contains(list_id) {
                return Err(CustomRingError::InvalidSource.into());
            }
            seen = seen.union(ListSet::single(list_id));
            let registry = match spec.source {
                0 => Address::default(),
                n => {
                    let curator = self
                        .curators
                        .get(usize::from(n) - 1)
                        .ok_or(CustomRingError::InvalidSource)?;
                    if !loaded.contains(curator.address()) {
                        loaded.push(curator_source(curator)?);
                    }
                    *curator.address()
                }
            };
            sources[list_id.slot()] = SourceSlot {
                list_id: list_id as u8,
                registry,
            };
        }
        Ok(sources)
    }
}

/// Any authority's registry, the program checks its owner and layout alone.
pub(crate) fn curator_source(curator: &AccountView) -> Result<Address, ProgramError> {
    load_storage_registry(curator)?;
    Ok(*curator.address())
}
