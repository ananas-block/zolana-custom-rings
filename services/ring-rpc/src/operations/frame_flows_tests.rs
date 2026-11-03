use solana_signature::Signature;
use spr_keypair::{PublicKey, X25519Keypair};
use spr_transaction::{Mint, OutputContext};
use zolana_ring_client::{
    AuditedInputOpening, AuditedOutput, AuditedSender, AuditedUtxo, CreatedUtxo,
    EscrowPendingOutput, EscrowPendingSlot, KnownUtxo, MergeInput, MergedInput, OutputPayloadError,
    OutputPayloadErrorKind, RingOwnerTag, UtxoOwner,
};

use super::*;
use crate::utxos::CreatedIn;

const ALICE: [u8; 32] = [0xa1; 32];
const BOB: [u8; 32] = [0xb2; 32];
const OLD_KEY: [u8; 32] = [0x01; 32];
const NEW_KEY: [u8; 32] = [0x02; 32];
const ASSET: [u8; 32] = [0x07; 32];

fn mint_of_asset() -> Address {
    Address::new_from_array(ASSET)
}

fn assets() -> RingAssets {
    let mint = Mint::new(mint_of_asset(), 6);
    RingAssets::new([mint]).expect("assets")
}

/// The field `assets` holds for its registered mint.
fn asset_field(assets: &RingAssets) -> [u8; 32] {
    assets
        .fields()
        .find(|(_, mint)| mint.asset == mint_of_asset())
        .expect("registered")
        .0
}

fn owner_identity(owner_key: &[u8; 32]) -> [u8; 32] {
    *Member::owner_tag(owner_key).expect("identity").as_bytes()
}

fn note(owner_key: [u8; 32], nullifier_pk: [u8; 32], asset: [u8; 32], amount: u64) -> CreatedUtxo {
    CreatedUtxo {
        commitment: [nullifier_pk[0] ^ owner_key[0] ^ amount as u8; 32],
        slot_index: 0,
        leaf_index: 0,
        utxo: KnownUtxo {
            owner_key,
            owner: UtxoOwner::Keyed { nullifier_pk },
            asset,
            mint: None,
            amount,
            blinding: [5; 32],
            data_hash: [0; 32],
            ring_data_hash: [0; 32],
            tree_id: 1,
        },
        ring_note: true,
    }
}

fn store_with(notes: &[CreatedUtxo]) -> AuditStore {
    let store = AuditStore::default();
    store.record(
        CreatedIn {
            slot: 1,
            tx_signature: Signature::from([7; 64]),
            event_index: 0,
        },
        notes.iter().copied(),
    );
    store
}

fn spend(created: &CreatedUtxo) -> AuditedInput {
    AuditedInput {
        nullifier: [0x11; 32],
        hash: created.commitment,
        opening: InputOpening::Opened(AuditedInputOpening {
            asset: created.utxo.asset,
            mint: None,
            amount: created.utxo.amount,
            blinding: created.utxo.blinding,
            ring: None,
        }),
    }
}

fn utxo(owner_key: [u8; 32], nullifier_pk: [u8; 32], asset: [u8; 32], amount: u64) -> AuditedUtxo {
    AuditedUtxo {
        owner_key,
        nullifier_pk,
        asset,
        mint: None,
        amount,
        blinding: [6; 32],
        data_hash: [0; 32],
        ring_data_hash: [0; 32],
    }
}

fn slot(slot_index: u32, opening: OutputOpening) -> AuditedOutput {
    AuditedOutput {
        slot_index,
        context: OutputContext {
            hash: [slot_index as u8 + 1; 32],
            tree_id: 1,
            leaf_index: 0,
        },
        opening,
    }
}

fn ring_slot(
    index: u32,
    owner_key: [u8; 32],
    nullifier_pk: [u8; 32],
    asset: [u8; 32],
    amount: u64,
) -> AuditedOutput {
    slot(
        index,
        OutputOpening::Ring {
            utxo: utxo(owner_key, nullifier_pk, asset, amount),
            owner_tag: RingOwnerTag::View([0x33; 32]),
        },
    )
}

fn audited(inputs: Vec<AuditedInput>, outputs: Vec<AuditedOutput>) -> AuditedTransaction {
    AuditedTransaction {
        tx_signature: Signature::from([9; 64]),
        slot: 2,
        tx_viewing_pk: X25519Keypair::from_bytes(&[3; 32]).pubkey(),
        outputs,
        payload_errors: Vec::new(),
        sender: None,
        inputs,
        unresolved: Vec::new(),
    }
}

struct Rows {
    store: AuditStore,
    assets: RingAssets,
}

impl Rows {
    fn of(notes: &[CreatedUtxo]) -> Self {
        Self {
            store: store_with(notes),
            assets: assets(),
        }
    }

    fn read(&self, audited: &AuditedTransaction) -> Result<Vec<OwnerFlow>, RingRpcError> {
        FrameFlows {
            audited,
            store: &self.store,
            owner_signers: Vec::new(),
            public: Vec::new(),
            assets: &self.assets,
        }
        .flows()
    }
}

fn debits(flows: &[OwnerFlow]) -> Vec<([u8; 32], u64)> {
    flows
        .iter()
        .map(|flow| (*flow.owner.as_bytes(), flow.flow.debit))
        .collect()
}

fn refused(flows: Result<Vec<OwnerFlow>, RingRpcError>) -> bool {
    matches!(
        flows,
        Err(RingRpcError::CoSign(CoSignError::LimitsUnavailable))
    )
}

/// The vector Go `TestRingSecretsMatchRustVectors` holds `SolanaOwnerIdentity` to.
#[test]
fn the_reservation_key_is_the_identity_a_deposit_and_the_circuit_hold() {
    let wallet = PublicKey::from_ed25519(&ALICE);
    assert_eq!(
        owner_identity(&ALICE),
        wallet.owner_proof_input_hash().expect("identity")
    );
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../test-vectors/wallet/ring-secrets.json"
    ))
    .expect("vector");
    let field = |name: &str| -> [u8; 32] {
        hex::decode(vector[name].as_str().expect(name))
            .expect("hex")
            .try_into()
            .expect("32 bytes")
    };
    assert_eq!(
        owner_identity(&field("sender_key")),
        field("sender_pk_hash")
    );
}

#[test]
fn notes_of_one_owner_under_two_nullifier_keys_take_one_row() {
    let held = assets();
    let asset = asset_field(&held);
    let notes = [
        note(ALICE, OLD_KEY, asset, 30),
        note(ALICE, NEW_KEY, asset, 20),
    ];
    let rows = Rows::of(&notes).read(&audited(
        vec![spend(&notes[0]), spend(&notes[1])],
        vec![ring_slot(0, BOB, [0x44; 32], asset, 50)],
    ));
    assert_eq!(debits(&rows.expect("rows")), [(owner_identity(&ALICE), 50)]);
}

#[test]
fn change_under_a_new_nullifier_key_returns_to_its_owner() {
    let held = assets();
    let asset = asset_field(&held);
    let notes = [note(ALICE, OLD_KEY, asset, 50)];
    let rows = Rows::of(&notes).read(&audited(
        vec![spend(&notes[0])],
        vec![
            ring_slot(0, BOB, [0x44; 32], asset, 15),
            ring_slot(1, ALICE, NEW_KEY, asset, 35),
        ],
    ));
    assert_eq!(debits(&rows.expect("rows")), [(owner_identity(&ALICE), 15)]);
}

#[test]
fn a_credit_never_moves_between_owners() {
    let held = assets();
    let asset = asset_field(&held);
    let notes = [
        note(ALICE, OLD_KEY, asset, 30),
        note(BOB, NEW_KEY, asset, 10),
    ];
    let rows = Rows::of(&notes).read(&audited(
        vec![spend(&notes[0]), spend(&notes[1])],
        vec![ring_slot(0, BOB, NEW_KEY, asset, 40)],
    ));
    assert_eq!(debits(&rows.expect("rows")), [(owner_identity(&ALICE), 30)]);
}

#[test]
fn an_exit_to_the_same_owner_counts_as_leaving() {
    let held = assets();
    let asset = asset_field(&held);
    let notes = [note(ALICE, OLD_KEY, asset, 50)];
    let rows = Rows::of(&notes).read(&audited(
        vec![spend(&notes[0])],
        vec![
            slot(0, OutputOpening::Exit(utxo(ALICE, OLD_KEY, asset, 20))),
            ring_slot(1, ALICE, OLD_KEY, asset, 30),
        ],
    ));
    assert_eq!(debits(&rows.expect("rows")), [(owner_identity(&ALICE), 20)]);
}

#[test]
fn a_dummy_input_and_a_dummy_slot_answer_for_nothing() {
    let held = assets();
    let asset = asset_field(&held);
    let notes = [note(ALICE, OLD_KEY, asset, 50)];
    let dummy = AuditedInput {
        nullifier: [0x12; 32],
        hash: [0; 32],
        opening: InputOpening::Dummy,
    };
    let rows = Rows::of(&notes).read(&audited(
        vec![spend(&notes[0]), dummy],
        vec![
            ring_slot(0, BOB, [0x44; 32], asset, 50),
            slot(1, OutputOpening::Dummy),
        ],
    ));
    assert_eq!(debits(&rows.expect("rows")), [(owner_identity(&ALICE), 50)]);
}

#[test]
fn a_merge_output_answers_under_its_inherited_owner() {
    let held = assets();
    let asset = asset_field(&held);
    let merged = AuditedInput {
        nullifier: [0x13; 32],
        hash: [0x66; 32],
        opening: InputOpening::Merged(MergedInput {
            commitment: [0x66; 32],
            input: MergeInput {
                owner_key: ALICE,
                owner: UtxoOwner::Keyed {
                    nullifier_pk: OLD_KEY,
                },
                asset,
                mint: None,
                amount: 70,
            },
        }),
    };
    let rows = Rows::of(&[]).read(&audited(
        vec![merged],
        vec![ring_slot(0, BOB, [0x44; 32], asset, 70)],
    ));
    assert_eq!(debits(&rows.expect("rows")), [(owner_identity(&ALICE), 70)]);
}

#[test]
fn an_entry_input_answers_under_the_envelope_sender() {
    let held = assets();
    let asset = asset_field(&held);
    let entry = note(ALICE, OLD_KEY, asset, 40);
    let mut transaction = audited(
        vec![spend(&entry)],
        vec![ring_slot(0, BOB, [0x44; 32], asset, 40)],
    );
    let rows = Rows::of(&[]);
    assert!(refused(rows.read(&transaction)));
    transaction.sender = Some(AuditedSender {
        owner_key: ALICE,
        nullifier_pk: Some(OLD_KEY),
    });
    assert_eq!(
        debits(&rows.read(&transaction).expect("rows")),
        [(owner_identity(&ALICE), 40)]
    );
}

#[test]
fn an_unnamed_input_or_an_unread_slot_refuses_the_whole_debit() {
    let held = assets();
    let asset = asset_field(&held);
    let notes = [note(ALICE, OLD_KEY, asset, 50)];
    let rows = Rows::of(&notes);
    let unseen = AuditedInput {
        nullifier: [0x14; 32],
        hash: [0x67; 32],
        opening: InputOpening::UnseenHash { hash: [0x67; 32] },
    };
    assert!(refused(rows.read(&audited(vec![unseen], Vec::new()))));

    let pending = EscrowPendingOutput {
        owner_key: ALICE,
        amount: 10,
        blinding: [8; 32],
        slot: EscrowPendingSlot::Exit { asset, mint: None },
    };
    assert!(refused(rows.read(&audited(
        vec![spend(&notes[0])],
        vec![slot(0, OutputOpening::EscrowPending(pending))],
    ))));

    let mut unopened = audited(vec![spend(&notes[0])], Vec::new());
    unopened.payload_errors.push(OutputPayloadError {
        slot_index: 0,
        kind: OutputPayloadErrorKind::UnknownAsset,
    });
    assert!(refused(rows.read(&unopened)));
}

#[test]
fn a_debit_of_a_mint_the_registry_lacks_refuses() {
    let unregistered = [0x55; 32];
    let notes = [note(ALICE, OLD_KEY, unregistered, 50)];
    let rows = Rows::of(&notes).read(&audited(
        vec![spend(&notes[0])],
        vec![ring_slot(0, BOB, [0x44; 32], unregistered, 50)],
    ));
    assert!(refused(rows));
}

#[test]
fn a_public_leg_joins_the_first_sender_and_leaves_its_debit_alone() {
    let held = assets();
    let asset = asset_field(&held);
    let notes = [
        note(ALICE, OLD_KEY, asset, 30),
        note(BOB, NEW_KEY, asset, 10),
    ];
    let store = store_with(&notes);
    let flows = FrameFlows {
        audited: &audited(
            vec![spend(&notes[0]), spend(&notes[1])],
            vec![ring_slot(0, BOB, NEW_KEY, asset, 15)],
        ),
        store: &store,
        owner_signers: Vec::new(),
        public: vec![PublicFlow {
            mint: mint_of_asset(),
            deposited: 0,
            withdrawn: 25,
        }],
        assets: &held,
    }
    .flows()
    .expect("rows");
    let row = |owner: &[u8; 32]| {
        flows
            .iter()
            .find(|flow| flow.owner.as_bytes() == &owner_identity(owner))
            .copied()
    };
    let first = row(&ALICE).expect("first sender");
    assert_eq!((first.flow.debit, first.flow.withdrawn), (30, 25));
    assert!(row(&BOB).is_none(), "a credit covers the second sender");
}

#[test]
fn a_public_funded_transfer_with_no_sender_refuses() {
    let held = assets();
    let asset = asset_field(&held);
    let store = store_with(&[]);
    let flows = FrameFlows {
        audited: &audited(Vec::new(), vec![ring_slot(0, BOB, NEW_KEY, asset, 15)]),
        store: &store,
        owner_signers: Vec::new(),
        public: vec![PublicFlow {
            mint: mint_of_asset(),
            deposited: 15,
            withdrawn: 0,
        }],
        assets: &held,
    }
    .flows();
    assert!(refused(flows));
}

/// `test-vectors/policy/debit.json`, the figure the transfer circuit settles at.
#[test]
fn the_reserved_figure_matches_the_circuit_debit_table() {
    fn identity(value: &serde_json::Value) -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[24..].copy_from_slice(&value.as_u64().expect("identity").to_be_bytes());
        bytes
    }
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("../../../../test-vectors/policy/debit.json"))
            .expect("vector");
    for case in vector["cases"].as_array().expect("cases") {
        let inputs: Vec<DebitInput> = case["inputs"]
            .as_array()
            .expect("inputs")
            .iter()
            .map(|input| DebitInput {
                owner: identity(&input["owner"]),
                asset: identity(&input["asset"]),
                amount: input["amount"].as_u64().expect("amount"),
            })
            .collect();
        let outputs: Vec<DebitOutput> = case["outputs"]
            .as_array()
            .expect("outputs")
            .iter()
            .map(|output| DebitOutput {
                ring: output["ring"].as_bool().expect("ring"),
                owner: identity(&output["owner"]),
                asset: identity(&output["asset"]),
                amount: output["amount"].as_u64().expect("amount"),
            })
            .collect();
        let rows = OwnerFlows {
            inputs: &inputs,
            outputs: &outputs,
            owner_signers: &[],
            public: &[],
        }
        .rows(|asset| Ok(Address::new_from_array(*asset)))
        .expect("rows");
        let reserved: Vec<([u8; 32], [u8; 32], u64)> = rows
            .iter()
            .map(|row| {
                (
                    *row.owner.as_bytes(),
                    row.flow.asset.to_bytes(),
                    row.flow.debit,
                )
            })
            .collect();
        let circuit: Vec<([u8; 32], [u8; 32], u64)> = case["debits"]
            .as_array()
            .expect("debits")
            .iter()
            .filter(|row| row["debit"].as_u64() != Some(0))
            .map(|row| {
                (
                    identity(&row["owner"]),
                    identity(&row["asset"]),
                    row["debit"].as_u64().expect("debit"),
                )
            })
            .collect();
        assert_eq!(reserved, circuit, "{}", case["name"]);
    }
}
