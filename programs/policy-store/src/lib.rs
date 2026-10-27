//! Transfer authorization remains the consumer's responsibility.

use bytemuck::{Pod, Zeroable};
use custom_ring_interface::{
    domain, key_catalog::RingCircuit, policy_withdrawal_hash, queue_chain, verifying_key,
    ApplyRecordsStatement, AuthorityWriteRecordsIxData, CustomRingError, CustomRingProof,
    PolicyKey, PolicyStatement, RingProof, MEMBER_REGISTRY_CAPACITY, MEMBER_REGISTRY_EMPTY_ROOT,
    ROOT_HISTORY,
};
use pinocchio::{
    account::RefMut,
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use thiserror::Error;
use zolana_account_checks::AccountIterator;
use zolana_hasher::{hash_chain::create_hash_chain_4_from_slice, primitives::right_align};
use zolana_interface::N_PUBLIC_SLOTS;
use zolana_ring_policy::{registry_field, EncodedRuleTable, SourceMap};

#[cfg(all(feature = "bpf-entrypoint", not(feature = "no-entrypoint")))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

pub const REGISTRY_PDA_SEED: &[u8] = b"policy-store";

pub mod tag {
    pub const INITIALIZE: u8 = 0;
    pub const UPDATE: u8 = 1;
    pub const UPDATE_IMMEDIATE: u8 = 2;
    pub const VERIFY_POLICY: u8 = 3;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Pod, Zeroable)]
#[repr(transparent)]
pub struct Revision(pub [u8; 8]);

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Root {
    pub hash: [u8; 32],
    pub revision: Revision,
    pub expires_at: [u8; 8],
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct Registry {
    pub discriminator: u8,
    pub writer: Address,
    pub grace_slots: [u8; 8],
    pub next_index: [u8; 4],
    /// Newest first, only retired roots have an expiry.
    pub roots: [Root; ROOT_HISTORY],
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct InitializeIxData {
    pub grace_slots: [u8; 8],
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct VerifyPolicyIxData {
    pub revision: Revision,
    pub table: EncodedRuleTable,
    pub action: [u8; 32],
    pub sender: [u8; 32],
    pub proof: CustomRingProof,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[repr(u32)]
pub enum StoreError {
    #[error("invalid registry")]
    InvalidRegistry = 9000,
    #[error("writer does not match")]
    Unauthorized,
    #[error("revision changed")]
    RevisionChanged,
    #[error("root expired or absent")]
    RootExpired,
    #[error("root history is full")]
    HistoryFull,
}

impl From<u64> for Revision {
    fn from(value: u64) -> Self {
        Self(value.to_le_bytes())
    }
}

impl From<StoreError> for ProgramError {
    fn from(error: StoreError) -> Self {
        Self::Custom(error as u32)
    }
}

impl Revision {
    pub const fn value(self) -> u64 {
        u64::from_le_bytes(self.0)
    }
}

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let (instruction, data) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    let mut accounts = AccountIterator::new(accounts);
    match *instruction {
        tag::INITIALIZE => {
            let ix: &InitializeIxData = parse(data)?;
            let writer_account = accounts.next_signer_mut("writer")?;
            let registry_account = accounts.next_mut("registry")?;
            let system_program_account = accounts.next_account("system")?;
            if !pinocchio_system::check_id(system_program_account.address()) {
                return Err(ProgramError::IncorrectProgramId);
            }
            let (registry_pda, bump) = Address::derive_program_address(
                &[REGISTRY_PDA_SEED, writer_account.address().as_ref()],
                program_id,
            )
            .ok_or(StoreError::InvalidRegistry)?;
            if registry_account.address() != &registry_pda {
                return Err(StoreError::InvalidRegistry.into());
            }
            if registry_account.data_len() != 0 {
                return Err(ProgramError::AccountAlreadyInitialized);
            }
            let bump = [bump];
            let seeds = [
                Seed::from(REGISTRY_PDA_SEED),
                Seed::from(writer_account.address().as_ref()),
                Seed::from(&bump),
            ];
            pinocchio_system::create_account_with_minimum_balance_signed(
                registry_account,
                core::mem::size_of::<Registry>(),
                program_id,
                writer_account,
                None,
                &[Signer::from(seeds.as_slice())],
            )?;
            let mut bytes = registry_account.try_borrow_mut()?;
            let registry: &mut Registry = bytemuck::try_from_bytes_mut(&mut bytes)
                .map_err(|_| StoreError::InvalidRegistry)?;
            *registry = Registry::zeroed();
            registry.discriminator = 1;
            registry.writer = *writer_account.address();
            registry.grace_slots = ix.grace_slots;
            registry.next_index = 1u32.to_le_bytes();
            registry.roots[0].hash = MEMBER_REGISTRY_EMPTY_ROOT;
            Ok(())
        }
        tag::UPDATE | tag::UPDATE_IMMEDIATE => {
            let (revision, data) = data
                .split_at_checked(core::mem::size_of::<Revision>())
                .ok_or(ProgramError::InvalidInstructionData)?;
            let revision = *parse::<Revision>(revision)?;
            let ix = AuthorityWriteRecordsIxData::parse(data)?;
            let writer_account = accounts.next_signer("writer")?;
            let registry_account = accounts.next_mut("registry")?;
            let chain_start = chain_start(registry_account.address(), revision)?;
            let mut registry = load_registry_mut(program_id, registry_account)?;
            if writer_account.address() != &registry.writer {
                return Err(StoreError::Unauthorized.into());
            }
            if revision != registry.roots[0].revision {
                return Err(StoreError::RevisionChanged.into());
            }
            let next_revision = revision
                .value()
                .checked_add(1)
                .ok_or(ProgramError::ArithmeticOverflow)?;
            let slot = Clock::get()?.slot;
            let expires_at = slot
                .checked_add(u64::from_le_bytes(registry.grace_slots))
                .ok_or(ProgramError::ArithmeticOverflow)?;
            if *instruction == tag::UPDATE
                && slot < u64::from_le_bytes(registry.roots[ROOT_HISTORY - 1].expires_at)
            {
                return Err(StoreError::HistoryFull.into());
            }
            // `APPLY_RECORDS` binds the registry address and revision before the ordered writes.
            let chain_end = ix.writes.iter().try_fold(chain_start, |chain, write| {
                Ok::<_, CustomRingError>(queue_chain(&chain, &write.entry()?)?)
            })?;
            let statement = ApplyRecordsStatement {
                old_root: registry.roots[0].hash,
                new_root: ix.apply.new_root,
                old_next_index: u32::from_le_bytes(registry.next_index),
                new_next_index: ix.apply.new_next_index(),
                chain_start,
                chain_end,
                count: ix.writes.len() as u64,
            };
            RingProof {
                proof: &ix.apply.proof,
                statement: statement.hash()?,
                key: verifying_key(RingCircuit::apply_records(statement.count))
                    .ok_or(CustomRingError::UnsupportedCircuit)?,
            }
            .verify()?;
            if *instruction == tag::UPDATE {
                registry.roots[0].expires_at = expires_at.to_le_bytes();
                registry.roots.rotate_right(1);
            } else {
                registry.roots.fill(Root::zeroed());
            }
            registry.roots[0] = Root {
                hash: statement.new_root,
                revision: next_revision.into(),
                expires_at: [0; 8],
            };
            registry.next_index = ix.apply.new_next_index;
            Ok(())
        }
        tag::VERIFY_POLICY => {
            let ix: &VerifyPolicyIxData = parse(data)?;
            let registry_account = accounts.next_account("registry")?;
            let instance = registry_field(registry_account.address().as_array())
                .map_err(CustomRingError::from)?;
            let registry = load_registry_mut(program_id, registry_account)?;
            let root = registry.root(ix.revision, Clock::get()?.slot)?;
            let sources = SourceMap::new(
                &ix.table
                    .referenced()
                    .iter()
                    .map(|list| (list, [0; 32]))
                    .collect::<Vec<_>>(),
            )
            .map_err(CustomRingError::from)?;
            ix.table.validate(&sources).map_err(CustomRingError::from)?;
            // The rule hash authenticates the supplied table only.
            let statement = PolicyStatement {
                key: PolicyKey::Member { anonymous: false },
                private_tx_hash: &ix.action,
                policy_hash: &ix.table.hash(&sources).map_err(CustomRingError::from)?,
                ring_id: &instance,
                approval_required: false,
                key_escrow: false,
                own_root: &root,
                curator_root: &[0; 32],
                sender: &ix.sender,
                public_assets: &[[0; 32]; N_PUBLIC_SLOTS],
                public_amounts: &[[0; 32]; N_PUBLIC_SLOTS],
                withdrawal_hash: &policy_withdrawal_hash(&[]).map_err(CustomRingError::from)?,
            };
            RingProof {
                proof: &ix.proof,
                statement: statement.hash().map_err(CustomRingError::from)?,
                key: verifying_key(RingCircuit::MemberPolicy {
                    outputs: 2,
                    withdrawals: 0,
                    own_only: true,
                })
                .ok_or(CustomRingError::UnsupportedCircuit)?,
            }
            .verify()
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

impl Registry {
    fn root(&self, revision: Revision, slot: u64) -> Result<[u8; 32], StoreError> {
        self.roots
            .iter()
            .find(|root| {
                root.hash != [0; 32]
                    && root.revision == revision
                    && (revision == self.roots[0].revision
                        || slot < u64::from_le_bytes(root.expires_at))
            })
            .map(|root| root.hash)
            .ok_or(StoreError::RootExpired)
    }
}

pub fn chain_start(registry: &Address, revision: Revision) -> Result<[u8; 32], CustomRingError> {
    Ok(create_hash_chain_4_from_slice(&[
        domain::field(domain::APPLY_RECORDS),
        registry_field(registry.as_array())?,
        right_align(&revision.value().to_be_bytes()),
    ])?)
}

fn load_registry_mut<'a>(
    program_id: &Address,
    registry_account: &'a mut AccountView,
) -> Result<RefMut<'a, Registry>, ProgramError> {
    if !registry_account.owned_by(program_id) {
        return Err(StoreError::InvalidRegistry.into());
    }
    RefMut::filter_map(registry_account.try_borrow_mut()?, |data| {
        bytemuck::try_from_bytes_mut::<Registry>(data)
            .ok()
            .filter(|registry| {
                registry.discriminator == 1
                    && (1..=MEMBER_REGISTRY_CAPACITY)
                        .contains(&u64::from(u32::from_le_bytes(registry.next_index)))
            })
    })
    .map_err(|_| StoreError::InvalidRegistry.into())
}

fn parse<T: Pod>(data: &[u8]) -> Result<&T, ProgramError> {
    bytemuck::try_from_bytes(data).map_err(|_| ProgramError::InvalidInstructionData)
}
