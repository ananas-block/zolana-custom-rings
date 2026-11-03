use spr_client::{OutputContext, OutputSlot};
use spr_event::{encode_merge_output_data, MergeOutputDataRef};
use spr_hasher::primitives::hash_bytes;
use spr_transaction::{
    instructions::merge::{merge_output_blinding, merge_output_key, MergeOutputPlaintext},
    Mint, WalletUtxo,
};
use zolana_ring_client::{
    ConfirmedMergeDisclosure, CreatedUtxo, KnownUtxo, KnownUtxos, MergeDisclosureEncryption,
    MergeOpening, NullifierKeyEnvelope, UtxoOwner,
};

use super::*;
use crate::{
    managed_merge::tests::{Fixture, MINT, RING},
    upstream::origin_fixture,
    utxos::SpendableNotes,
};

const SALT: [u8; 16] = [8; 16];

struct MergeFixture {
    fixture: Fixture,
    key: NullifierKey,
    input: CreatedUtxo,
    output: KnownUtxo,
    transaction: ShieldedTransaction,
}

impl MergeFixture {
    async fn new() -> Self {
        let fixture = Fixture::serving(None, None).await;
        let key = NullifierKey::from_secret([3; 31]);
        let owner_key = Address::new_from_array([4; 32]).to_bytes();
        let input = KnownUtxo {
            owner_key,
            owner: UtxoOwner::Keyed {
                nullifier_pk: key.pubkey().unwrap(),
            },
            asset: hash_bytes(MINT.as_array()).unwrap(),
            mint: Some(MINT),
            amount: 11,
            blinding: [1; 32],
            data_hash: [0; 32],
            ring_data_hash: [0; 32],
            tree_id: 1,
        };
        let commitment = input.commitment(Some(RING)).unwrap();
        let first_nullifier = key.nullifier(&commitment, &input.blinding).unwrap();
        let output = KnownUtxo {
            blinding: merge_output_blinding(&key, &first_nullifier).unwrap(),
            ring_data_hash: [2; 32],
            tree_id: 2,
            ..input
        };
        let ciphertext = MergeOutputPlaintext {
            amount: output.amount + 1,
            mint: MINT,
        }
        .encrypt(&merge_output_key(&key, &first_nullifier).unwrap(), &SALT)
        .unwrap();
        let transaction = ShieldedTransaction {
            slot: 9,
            tx_signature: Signature::from([9; 64]),
            event_index: Some(0),
            tx_viewing_pk: None,
            salt: None,
            output_slots: vec![OutputSlot {
                view_tag: first_nullifier,
                output_context: OutputContext {
                    hash: output.commitment(Some(RING)).unwrap(),
                    tree_id: output.tree_id,
                    leaf_index: 19,
                },
                payload: encode_merge_output_data(MergeOutputDataRef {
                    salt: &SALT,
                    ciphertext: &ciphertext,
                    prefix: &[output.ring_data_hash],
                }),
            }],
            messages: Vec::new(),
            nullifiers: vec![first_nullifier],
            proofless: false,
            ring_config: None,
            ring_program_id: Some(RING),
        };
        Self {
            fixture,
            key,
            input: CreatedUtxo {
                commitment,
                slot_index: 0,
                leaf_index: 3,
                utxo: input,
                ring_note: true,
            },
            output,
            transaction,
        }
    }

    fn created_in(&self) -> CreatedIn {
        CreatedIn {
            slot: 1,
            tx_signature: Signature::from([1; 64]),
            event_index: 0,
        }
    }

    fn escrow(&self, store: &AuditStore) {
        let service = self.fixture.hub.service(None).unwrap();
        let owner = EscrowedOwner {
            owner_key: self.input.utxo.owner_key,
            nullifier_pk: self.key.pubkey().unwrap(),
            owner_hash: self.input.utxo.owner_hash().unwrap(),
            sealed: NullifierKeyEnvelope::new(&self.key, &service.auditor_pubkey())
                .unwrap()
                .sealed,
        };
        store.replace_escrow(
            EscrowRoot {
                registry: Address::new_from_array([6; 32]),
                root: [7; 32],
                revision: 1,
            },
            HashMap::from([(owner.owner_key, owner)]),
        );
    }

    fn selected(&self, store: &AuditStore) -> Vec<WalletUtxo> {
        store
            .spendable(SpendableNotes {
                ring: RING,
                owner_key: self.input.utxo.owner_key,
                mint: Mint::new(MINT, 7),
                nullifier_key: &self.key,
            })
            .unwrap()
    }

    fn origin(&self) -> RingOrigin {
        let service = self.fixture.hub.service(None).unwrap();
        let mut inputs = vec![[0; 32]; 8];
        inputs[0] = self.input.commitment;
        let sealed = MergeDisclosureEncryption::new(
            &MergeOpening {
                input_commitments: inputs,
            },
            SALT,
            &service.auditor_pubkey(),
        )
        .unwrap();
        RingOrigin {
            ring_invoked: true,
            event: origin_fixture::event(&self.transaction),
            signers: Vec::new(),
            withdrawals: Vec::new(),
            deposits: Vec::new(),
            merge_disclosure: Some(ConfirmedMergeDisclosure {
                eph_pk: *sealed.eph_pk.as_bytes(),
                ciphertext: sealed.ciphertext,
                fields: sealed.fields,
            }),
            transact: None,
            pool_accounts: Vec::new(),
        }
    }

    async fn audit(&self, store: &AuditStore) {
        self.fixture
            .hub
            .shared()
            .source
            .origins
            .lock()
            .unwrap()
            .insert(self.transaction.tx_signature, self.origin());
        let service = self.fixture.hub.service(None).unwrap();
        let rows = service
            .audit_rows(
                GetShieldedTransactionsByTagsResponse {
                    context: spr_client::Context {
                        slot: self.transaction.slot,
                        block_time: 0,
                    },
                    data: vec![spr_client::rpc::TransactionEvents {
                        slot: self.transaction.slot,
                        signature: self.transaction.tx_signature,
                        events: vec![self.transaction.clone()],
                    }],
                    pagination_token: None,
                    output_tree_id: None,
                },
                RingMode::ConfidentialEscrow,
                store,
            )
            .await
            .unwrap();
        assert!(rows.unfinished.is_none());
        assert!(rows.skipped.is_empty());
    }
}

#[tokio::test]
async fn a_confirmed_merge_successor_is_spendable_with_invalid_native_plaintext() {
    let fixture = MergeFixture::new().await;
    let store = AuditStore::default();
    store.record(fixture.created_in(), [fixture.input]);
    fixture.audit(&store).await;
    let selected = fixture.selected(&store);
    assert_eq!(selected.len(), 1);
    let note = &selected[0];
    assert_eq!(
        note.utxo_hash,
        fixture.output.commitment(Some(RING)).unwrap()
    );
    assert_eq!(note.utxo.amount, fixture.output.amount);
    assert_eq!(note.utxo.blinding, fixture.output.blinding);
    assert_eq!(note.ring_data_hash, Some(fixture.output.ring_data_hash));
    assert_eq!(note.tree_id, fixture.output.tree_id);
    assert_eq!(note.leaf_index, 19);
    assert_eq!(note.slot, fixture.transaction.slot);
    assert_eq!(note.tx_signature, fixture.transaction.tx_signature);
    assert!(store.utxo(&note.utxo_hash).is_none());
    store.spend([note.nullifier]);
    assert!(fixture.selected(&store).is_empty());
}

#[tokio::test]
async fn a_merge_successor_waits_for_the_input_escrow_key() {
    let fixture = MergeFixture::new().await;
    let store = AuditStore::default();
    store.hold(
        fixture.created_in(),
        [HeldNote::Deposit(DepositNote {
            commitment: fixture.input.commitment,
            slot_index: fixture.input.slot_index,
            leaf_index: fixture.input.leaf_index,
            owner_hash: fixture.input.utxo.owner_hash().unwrap(),
            owner_key: fixture.input.utxo.owner_key,
            asset: fixture.input.utxo.asset,
            mint: MINT,
            amount: fixture.input.utxo.amount,
            blinding: fixture.input.utxo.blinding,
            data_hash: [0; 32],
            ring_data_hash: [0; 32],
            tree_id: fixture.input.utxo.tree_id,
        })],
    );
    fixture.audit(&store).await;
    assert!(fixture.selected(&store).is_empty());
    fixture.escrow(&store);
    assert_eq!(fixture.selected(&store).len(), 1);
}

#[tokio::test]
async fn a_merge_replay_restores_recovery_after_its_ledger_already_resolved() {
    let fixture = MergeFixture::new().await;
    let service = fixture.fixture.hub.service(None).unwrap();
    let merge = confirmed_merge(
        &fixture.transaction,
        0,
        &fixture.origin(),
        service.auditor_keypair(),
    )
    .unwrap()
    .unwrap();
    for _ in 0..2 {
        let restarted = AuditStore::default();
        restarted.record(fixture.created_in(), [fixture.input]);
        apply_confirmed_merge(
            fixture.fixture.hub.shared().database.as_ref(),
            &restarted,
            merge.clone(),
        )
        .await
        .unwrap();
        assert!(fixture.selected(&restarted).is_empty());
        fixture.audit(&restarted).await;
        fixture.audit(&restarted).await;
        assert_eq!(fixture.selected(&restarted).len(), 1);
        restarted.spend_commitments([SpentCommitment {
            utxo_hash: merge.output_commitment,
            slot: 10,
            tx_signature: Signature::from([10; 64]),
            event_index: 0,
            first_nullifier: [3; 32],
            source: SpentSource::Transfer,
        }]);
        assert!(fixture.selected(&restarted).is_empty());
    }
}

#[tokio::test]
async fn merge_metadata_with_a_wrong_output_commitment_is_not_spendable() {
    let mut fixture = MergeFixture::new().await;
    fixture.transaction.output_slots[0].output_context.hash = [4; 32];
    let store = AuditStore::default();
    store.record(fixture.created_in(), [fixture.input]);
    fixture.audit(&store).await;
    assert!(store.merged(&[4; 32]).is_some());
    assert!(fixture.selected(&store).is_empty());
}

#[tokio::test]
async fn a_noncanonical_native_merge_ciphertext_does_not_block_checked_recovery() {
    let mut fixture = MergeFixture::new().await;
    fixture.transaction.output_slots[0].payload = encode_merge_output_data(MergeOutputDataRef {
        salt: &SALT,
        ciphertext: &[[0xff; 32]; 3],
        prefix: &[fixture.output.ring_data_hash],
    });
    let store = AuditStore::default();
    store.record(fixture.created_in(), [fixture.input]);
    fixture.audit(&store).await;
    assert_eq!(fixture.selected(&store).len(), 1);
}
