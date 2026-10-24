//! The SPP account positions the ring program reads, against the pinned SPP builders.

use custom_ring_interface::{
    RING_DEPOSIT_DEPOSITOR_INDEX, RING_DEPOSIT_RING_CONFIG_INDEX, RING_MERGE_PAYER_INDEX,
    RING_MERGE_RING_CONFIG_INDEX, RING_TRANSACT_ACCOUNT_PREFIX_LEN,
    RING_TRANSACT_RING_CONFIG_INDEX, SOL_ASSET_ADDRESS, SYSTEM_PROGRAM_ID, TRANSACT_PAYER_INDEX,
};
use solana_address::Address;
use zolana_event::EncryptedRingDepositData;
use zolana_instruction::instruction::{
    DepositAsset, MergeRing, RingAssetDeposit, RingDeposit, RingTransact,
};
use zolana_interface::{
    instruction::{
        instruction_data::merge_transact::{MergeOutputEncryption, MergeProof},
        CircuitId, MergeTransactIxData, TransactIxData, TransactProof,
    },
    pda, N_PUBLIC_SLOTS,
};

const PAYER: Address = Address::new_from_array([1; 32]);
const RING: Address = Address::new_from_array([2; 32]);
const TREE: Address = Address::new_from_array([3; 32]);
const INPUT_TREE: Address = Address::new_from_array([4; 32]);

fn ring_config() -> Address {
    pda::ring_auth(&RING).0
}

#[test]
fn transact_accounts_put_the_payer_and_the_ring_config_where_the_ring_reads_them() {
    let transact = RingTransact {
        payer: PAYER,
        input_trees: vec![INPUT_TREE],
        output_tree: TREE,
        ring_program_id: RING,
        owner_signers: vec![],
        interface_transfer_accounts: vec![],
        data: TransactIxData {
            expiry_unix_ts: 0,
            tx_viewing_pk: [4; 33],
            salt: [0; 16],
            interface_transfers: vec![],
            data_hash: None,
            ring_data_hash: None,
            outputs: vec![],
            messages: vec![],
            private_tx_hash: [0; 32],
            circuit: CircuitId::ConfidentialRingEddsa(1, 2, N_PUBLIC_SLOTS as u8),
            proof: TransactProof::zeroed(),
            inputs: vec![],
            tree_contexts: vec![],
        },
    }
    .cpi_instruction();
    let accounts = &transact.accounts;
    assert_eq!(accounts[TRANSACT_PAYER_INDEX].pubkey, PAYER);
    assert!(accounts[TRANSACT_PAYER_INDEX].is_signer);
    assert_eq!(
        accounts[RING_TRANSACT_RING_CONFIG_INDEX].pubkey,
        ring_config()
    );
    assert!(accounts[RING_TRANSACT_RING_CONFIG_INDEX].is_signer);
    assert_eq!(
        accounts[RING_TRANSACT_ACCOUNT_PREFIX_LEN].pubkey,
        INPUT_TREE
    );
}

#[test]
fn deposit_accounts_put_the_depositor_and_the_ring_config_where_the_ring_reads_them() {
    let deposit = RingDeposit {
        tree: TREE,
        depositor: PAYER,
        ring_program_id: RING,
        deposits: vec![RingAssetDeposit {
            asset: DepositAsset::Sol,
            view_tag: [0; 32],
            owner_utxo_hash: [0; 32],
            amount: 1,
            ring_data_hash: [0; 32],
            encrypted: EncryptedRingDepositData {
                tx_viewing_pk: [4; 33],
                salt: [0; 16],
                ciphertext: vec![],
            },
        }],
    }
    .cpi_instruction()
    .unwrap();
    let accounts = &deposit.accounts;
    assert_eq!(accounts[RING_DEPOSIT_DEPOSITOR_INDEX].pubkey, PAYER);
    assert!(accounts[RING_DEPOSIT_DEPOSITOR_INDEX].is_signer);
    assert_eq!(
        accounts[RING_DEPOSIT_RING_CONFIG_INDEX].pubkey,
        ring_config()
    );
    assert!(accounts[RING_DEPOSIT_RING_CONFIG_INDEX].is_signer);
}

#[test]
fn merge_accounts_put_the_payer_and_the_ring_config_where_the_ring_reads_them() {
    let merge = MergeRing {
        input_tree: INPUT_TREE,
        output_tree: TREE,
        ring_program_id: RING,
        payer: PAYER,
        data: MergeTransactIxData {
            expiry_unix_ts: 0,
            proof: MergeProof {
                a: [0; 32],
                b: [0; 128],
                c: [0; 32],
            },
            output_utxo_hash: [0; 32],
            output_encryption: MergeOutputEncryption::PoseidonCtrV1 {
                salt: Default::default(),
                ciphertext: Default::default(),
            },
            private_tx_hash: [0; 32],
            nullifiers: vec![[1; 32]],
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
            cache_slot: None,
        },
        output_ring_data_hash: [0; 32],
        cache: None,
    }
    .cpi_instruction();
    let accounts = &merge.accounts;
    assert_eq!(accounts[RING_MERGE_PAYER_INDEX].pubkey, PAYER);
    assert!(accounts[RING_MERGE_PAYER_INDEX].is_signer);
    assert_eq!(accounts[RING_MERGE_RING_CONFIG_INDEX].pubkey, ring_config());
    assert!(accounts[RING_MERGE_RING_CONFIG_INDEX].is_signer);
}

#[test]
fn sol_and_the_system_program_keep_their_zero_addresses() {
    assert_eq!(SOL_ASSET_ADDRESS, DepositAsset::Sol.mint().to_bytes());
    assert_eq!(
        SYSTEM_PROGRAM_ID,
        solana_address::address!("11111111111111111111111111111111")
    );
}
