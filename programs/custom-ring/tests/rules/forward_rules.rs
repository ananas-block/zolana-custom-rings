//! Audited deposit refusals ahead of the forward.

use bytemuck::Zeroable;
use custom_ring_interface::{
    tag, CoSignScope, CustomRingError, DepositPrefix, RingDepositAuditCapsule, RootRead,
    MAX_RING_DEPOSIT_AUDIT_SLOTS, RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN, RING_DEPOSIT_DEPOSITOR_INDEX,
    RING_DEPOSIT_RING_CONFIG_INDEX,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::{Keypair, Signer};
use spr_interface::instruction::instruction_data::deposit::{
    DepositAssetKind, EncryptedRingDepositData, RingDepositEntry, RingDepositIxData,
};

use crate::common::{
    auditor_pubkey, delegate_ring, policy_pda, reaches_verification, refused, ring_auth,
    set_co_signer, CoSignerSlot, Ring, Sent, Setup, PROGRAM, SYSTEM,
};

fn deposit_entry(slot_index: u8, eph_pk: &[u8; 33]) -> RingDepositEntry {
    let capsule = RingDepositAuditCapsule {
        slot_index,
        eph_pk,
        ciphertext: &[3; RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN],
        recipient_ciphertext: &[],
    }
    .encode();
    RingDepositEntry {
        asset_index: 0,
        view_tag: [1; 32],
        owner_utxo_hash: [0x0f; 32],
        amount: 10,
        ring_data_hash: [0; 32],
        encrypted: EncryptedRingDepositData {
            tx_viewing_pk: auditor_pubkey(),
            salt: [2; 16],
            ciphertext: capsule,
        },
    }
}

fn deposit_of(deposits: Vec<RingDepositEntry>) -> RingDepositIxData {
    RingDepositIxData {
        assets: vec![DepositAssetKind::Sol],
        deposits,
    }
}

pub fn ring_deposit() -> RingDepositIxData {
    deposit_of(vec![deposit_entry(0, &auditor_pubkey())])
}

/// `registry` the own revision an escrow-mode ring binds.
fn audited_deposit(ring: &mut Ring, registry: Option<u64>) -> Sent {
    let instruction = deposit_instruction(ring, registry, &ring_deposit());
    ring.send(instruction, &[])
}

pub fn deposit_instruction(
    ring: &Ring,
    registry: Option<u64>,
    deposit: &RingDepositIxData,
) -> Instruction {
    let prefix = DepositPrefix {
        tag: tag::DEPOSIT,
        key_capacity: 1,
        proof: Zeroable::zeroed(),
        tracking_revision: Default::default(),
        own_revision: registry.unwrap_or_default().into(),
        curator_revision: Default::default(),
    };
    let data = [
        bytemuck::bytes_of(&prefix),
        &[spr_interface::instruction::tag::RING_DEPOSIT],
        &deposit.serialize().unwrap(),
    ]
    .concat();
    let mut spp: Vec<AccountMeta> = (0..=RING_DEPOSIT_RING_CONFIG_INDEX)
        .map(|_| AccountMeta::new(Address::new_unique(), false))
        .collect();
    spp[RING_DEPOSIT_DEPOSITOR_INDEX] = AccountMeta::new(ring.payer.pubkey(), true);
    spp[RING_DEPOSIT_RING_CONFIG_INDEX] = AccountMeta::new(ring_auth(), false);
    spp.extend([
        AccountMeta::new_readonly(Address::new_unique(), false),
        AccountMeta::new_readonly(SYSTEM, false),
        AccountMeta::new(Address::new_unique(), false),
    ]);
    let mut accounts = vec![AccountMeta::new_readonly(policy_pda(), false)];
    accounts.extend(ring.registries(RootRead::deposit(&ring.read(&policy_pda()))));
    accounts.extend(spp);
    Instruction {
        program_id: PROGRAM,
        accounts,
        data,
    }
}

#[test]
fn an_escrowing_deposit_revision_its_registry_does_not_serve_is_refused() {
    let mut ring = delegate_ring(&Keypair::new());
    refused(
        audited_deposit(&mut ring, Some(1)),
        CustomRingError::RootNotServed,
    );
    reaches_verification(audited_deposit(&mut ring, Some(0)));
}

#[test]
fn a_deposit_carries_the_co_signer_its_class_demands() {
    let co_signer = Keypair::new();
    let mut ring = Ring::new(Setup::AuditOnly);
    set_co_signer(&mut ring, &co_signer.pubkey(), CoSignScope::DEPOSITS.bits());
    let mut deposit = deposit_instruction(&ring, None, &ring_deposit());
    refused(
        ring.send(deposit.clone(), &[]),
        CustomRingError::InvalidCoSignerRecord,
    );
    let pair = CoSignerSlot::own(co_signer.pubkey()).signed();
    deposit.accounts.splice(DEPOSIT_SPP..DEPOSIT_SPP, pair);
    reaches_verification(ring.send(deposit, &[&co_signer]));
}

#[test]
fn an_audited_deposit_without_a_bound_root_reaches_its_proof() {
    let mut ring = Ring::new(Setup::AuditOnly);
    reaches_verification(audited_deposit(&mut ring, None));
}

/// The deposit's forwarded list starts after the ring account and the pinned tracking registry.
const DEPOSIT_SPP: usize = 2;

#[test]
fn an_audited_deposit_forwards_deposit_data_its_capsules_open() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let mut untagged = deposit_instruction(&ring, None, &ring_deposit());
    untagged.data[core::mem::size_of::<DepositPrefix>()] =
        spr_interface::instruction::tag::RING_DEPOSIT.wrapping_add(1);
    refused(
        ring.send(untagged, &[]),
        CustomRingError::InvalidAuditedDeposit,
    );
    let mut truncated = deposit_instruction(&ring, None, &ring_deposit());
    truncated.data.pop();
    refused(
        ring.send(truncated, &[]),
        CustomRingError::InvalidDepositData,
    );
    let misplaced = deposit_instruction(
        &ring,
        None,
        &deposit_of(vec![deposit_entry(1, &auditor_pubkey())]),
    );
    refused(
        ring.send(misplaced, &[]),
        CustomRingError::InvalidDepositDisclosure,
    );
    let mut unhashable = ring_deposit();
    unhashable.deposits[0].owner_utxo_hash = [0xff; 32];
    let instruction = deposit_instruction(&ring, None, &unhashable);
    refused(ring.send(instruction, &[]), CustomRingError::HashingFailed);
}

#[test]
fn every_deposit_capsule_opens_under_one_key_at_its_own_index() {
    let mut ring = Ring::new(Setup::AuditOnly);
    let key = auditor_pubkey();
    let mut other = key;
    other[1] ^= 1;
    let mut mistagged = key;
    mistagged[0] = 0x02;
    let mut bare = deposit_entry(1, &key);
    bare.encrypted.ciphertext[0] ^= 1;
    let mut send = |entries| {
        let instruction = deposit_instruction(&ring, None, &deposit_of(entries));
        ring.send(instruction, &[])
    };
    for refused_entries in [
        vec![deposit_entry(0, &key), deposit_entry(1, &other)],
        vec![deposit_entry(0, &key), deposit_entry(0, &key)],
        vec![deposit_entry(0, &key), bare],
        vec![deposit_entry(0, &mistagged)],
        Vec::new(),
        (0..=MAX_RING_DEPOSIT_AUDIT_SLOTS as u8)
            .map(|slot| deposit_entry(slot, &key))
            .collect(),
    ] {
        refused(
            send(refused_entries),
            CustomRingError::InvalidDepositDisclosure,
        );
    }
    reaches_verification(send(vec![deposit_entry(0, &key), deposit_entry(1, &key)]));
}

#[test]
fn an_audited_deposit_holds_the_ring_pda_and_a_signing_depositor() {
    let mut ring = Ring::new(Setup::AuditOnly);
    for (index, error) in [
        (
            RING_DEPOSIT_RING_CONFIG_INDEX,
            CustomRingError::MissingRingAuth,
        ),
        (
            RING_DEPOSIT_DEPOSITOR_INDEX,
            CustomRingError::MissingFundingSigner,
        ),
    ] {
        let mut instruction = deposit_instruction(&ring, None, &ring_deposit());
        instruction.accounts[DEPOSIT_SPP + index] = AccountMeta::new(Address::new_unique(), false);
        refused(ring.send(instruction, &[]), error);
    }
}
