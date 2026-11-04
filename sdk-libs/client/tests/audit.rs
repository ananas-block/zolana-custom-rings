//! Audits of synthetic ring transfers built as the ring program publishes them.

#[path = "common/deposit.rs"]
mod deposit_fixture;
#[path = "common/history_page.rs"]
pub mod history_page;
#[path = "common/origin.rs"]
mod origin_fixture;
#[path = "common/transfer.rs"]
pub mod transfer;

use std::{
    collections::HashMap,
    num::{NonZeroU32, NonZeroUsize},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};

use custom_ring_interface::{
    AuditEvidence, AuditStreamLayout, DeliveredBody, EntryInput, ExitRecord,
    RingDepositAuditCapsule, RingMode,
};
use solana_address::Address;
use solana_signature::Signature;
use spr_client::{
    AsyncRpc, Context, GetShieldedTransactionsByTagsResponse, HistoryFilters, IndexerRpcConfig,
    PaginationToken, ShieldedTransaction,
};
use spr_event::{
    encode_encrypted_ring_deposit_output, encode_merge_output_data, EncryptedRingDepositData,
    EncryptedRingDepositOutput, MergeOutputDataRef, MessageData,
};
use spr_keypair::{ViewingKey, X25519Keypair, X25519Pubkey};
use spr_transaction::{owner_utxo_hash, Mint, OutputContext, OutputSlot};
use zolana_ring_client::{
    auditor_view_tag, confirmed_merge,
    history::{HistoryCursor, HistoryQuery, HistoryStream},
    input_hash_evidence, ring_event_origin_in, seal_deposits, AuditError, AuditStreamSeal,
    AuditedInputOpening, AuditedSender, AuditedTransaction, ConfirmedMerge,
    ConfirmedMergeDisclosure, CreatedUtxo, CreatedUtxoScan, CreatedUtxos, DepositOpening,
    EscrowPendingSlot, InputOpening, InputRing, KnownUtxo, KnownUtxoIndex, KnownUtxos, MergeAudit,
    MergeDisclosureEncryption, MergeInput, MergeLedger, MergeOpening, MergedInput, OutputOpening,
    OutputPayloadError, OutputPayloadErrorKind, OutputRecord, RingOrigin, RingOwnerTag, RingScan,
    TransactionAudit, TransactionOrigin, UtxoOwner,
};
use zolana_ring_transaction::{seal_delivered_body, RingAssets};

use history_page::{position, EventsPage};
use transfer::{
    audited_opening, auditor, field, input_opening, known_utxo, x25519_u, Disclosure, Frame,
    Output, Placement, Publish, Rail, Slot, Transfer, UtxoFields,
};

const SOL: Address = Address::new_from_array([0; 32]);
const MINT: Address = Address::new_from_array([0x0a; 32]);

fn assets() -> RingAssets {
    RingAssets::new([Mint::new(MINT, 7)]).unwrap()
}

fn utxo(owner: u8, asset_address: Address, amount: u64) -> UtxoFields {
    UtxoFields {
        owner_key: [owner; 32],
        nullifier_pk: field(owner - 0x80),
        asset_address,
        amount,
        ..UtxoFields::default()
    }
}

fn transfer(seed: u8) -> Transfer {
    let first_nullifier = field(seed);
    Transfer {
        tx_key: ViewingKey::from_bytes(&[seed; 32]),
        first_nullifier,
        salt: [seed; 16],
        nullifiers: vec![first_nullifier],
        ..Transfer::fixture()
    }
}

struct Built {
    transaction: ShieldedTransaction,
    outputs: Vec<Output>,
    slots: Vec<Slot>,
    layout: AuditStreamLayout,
    frame: Vec<u8>,
}

#[derive(Clone, Copy)]
struct Spend {
    utxo: UtxoFields,
    blinding: [u8; 32],
}

fn build(transfer: &Transfer, rail: Rail, outputs: Vec<Output>) -> Built {
    build_with(transfer, rail, outputs, false)
}

fn build_with(transfer: &Transfer, rail: Rail, outputs: Vec<Output>, key_escrow: bool) -> Built {
    let slots = transfer.slots(
        match key_escrow {
            true => Rail::Escrowed,
            false => rail,
        },
        &outputs,
    );
    let disclosure = transfer.disclosure(rail, &outputs, key_escrow);
    publish(transfer, slots, outputs, &disclosure)
}

#[derive(Clone, Copy)]
enum Spending {
    /// Every note a ring note, disclosed by its commitment.
    RingUtxos,
    /// Note 0 a ring note and every later one a default-ring note, the entry key opens them all.
    Entry,
}

/// The anonymous transfer of `spent`, sent by the first note's owner.
fn build_anonymous(
    transfer: &Transfer,
    outputs: Vec<Output>,
    spent: &[Spend],
    spending: Spending,
) -> Built {
    let slots = transfer.slots(Rail::Anonymous, &outputs);
    let sender = spent[0].utxo;
    let inputs = match spending {
        Spending::RingUtxos => input_hash_evidence(
            &spent
                .iter()
                .map(|spend| Some(spend.commitment(transfer, Some(transfer.ring))))
                .collect::<Vec<_>>(),
        )
        .unwrap(),
        Spending::Entry => AuditEvidence::Entry {
            sender_key: sender.owner_key,
            sender_nullifier_pk: sender.nullifier_pk,
            inputs: entry_inputs(transfer, spent),
        },
    };
    let disclosure = transfer.anonymous_disclosure(&outputs, inputs);
    publish(transfer, slots, outputs, &disclosure)
}

/// Note 0 under the ring, every later note under the default ring.
fn entry_inputs(transfer: &Transfer, spent: &[Spend]) -> Vec<EntryInput> {
    spent
        .iter()
        .enumerate()
        .map(|(index, spend)| {
            let ring = (index == 0).then_some(transfer.ring);
            input_opening(&spend.utxo, spend.placement(transfer, ring))
        })
        .collect()
}

impl Spend {
    fn placement(&self, transfer: &Transfer, ring: Option<Address>) -> Placement {
        Placement {
            blinding: self.blinding,
            ring,
            tree_id: transfer.tree_id,
        }
    }

    fn commitment(&self, transfer: &Transfer, ring: Option<Address>) -> [u8; 32] {
        self.utxo.commitment(self.placement(transfer, ring))
    }

    fn known(&self, transfer: &Transfer) -> KnownUtxo {
        known_utxo(&self.utxo, self.placement(transfer, Some(transfer.ring)))
    }
}

fn publish(
    transfer: &Transfer,
    slots: Vec<Slot>,
    outputs: Vec<Output>,
    disclosure: &Disclosure,
) -> Built {
    let transaction = transfer.publish(Publish {
        slots: slots.iter().map(|slot| slot.output.clone()).collect(),
        disclosure,
        auditor: &auditor().pubkey(),
    });
    let layout = disclosure.layout;
    Built {
        frame: transfer.frame(Frame {
            tx: &transaction,
            disclosure,
        }),
        transaction,
        outputs,
        slots,
        layout,
    }
}

/// The record kinds of a delivered transfer, the exit's fixed by the layout.
fn transfer_records(built: &Built) -> Vec<OutputRecord> {
    built
        .outputs
        .iter()
        .map(|output| match output {
            Output::Exit(utxo) => OutputRecord::Exit(ExitRecord {
                asset: utxo.asset(),
                amount: utxo.amount,
                nullifier_pk: Some(utxo.nullifier_pk),
            }),
            Output::Ring { .. } | Output::Dummy => OutputRecord::Delivered,
        })
        .collect()
}

fn delivered_outputs() -> Vec<Output> {
    let mut outputs: Vec<Output> = (0u8..5)
        .map(|k| Output::Ring {
            utxo: utxo(0xb0 + k, [SOL, MINT][usize::from(k % 2)], 10 + u64::from(k)),
            recipient_u: x25519_u(0x40 + k),
            tag: None,
        })
        .collect();
    outputs.extend([
        Output::Exit(utxo(0xe5, SOL, 40)),
        Output::Dummy,
        Output::Dummy,
    ]);
    outputs
}

fn audit(
    transaction: &ShieldedTransaction,
    layout: AuditStreamLayout,
) -> Result<AuditedTransaction, AuditError> {
    TransactionAudit::new(transaction, layout).run(&auditor(), &assets())
}

fn slot_error(slot_index: u32, kind: OutputPayloadErrorKind) -> OutputPayloadError {
    OutputPayloadError { slot_index, kind }
}

fn opened_slots(audited: &AuditedTransaction) -> Vec<u32> {
    audited
        .outputs
        .iter()
        .map(|output| output.slot_index)
        .collect()
}

#[test]
fn every_delivered_slot_opens_to_its_published_commitment() {
    let built = build(&Transfer::fixture(), Rail::Delivered, delivered_outputs());
    let audited = audit(&built.transaction, built.layout).unwrap();
    assert!(audited.payload_errors.is_empty());
    assert_eq!(audited.tx_viewing_pk, Transfer::fixture().tx_key.pubkey());
    for ((output, slot), audited) in built.outputs.iter().zip(&built.slots).zip(&audited.outputs) {
        assert_eq!(audited.opening, audited_opening(output, slot));
        assert_eq!(audited.context, slot.output.output_context);
    }
}

#[test]
fn a_key_escrow_transfer_opens_each_slot_under_its_owners_escrowed_key() {
    let narrow = vec![
        delivered_outputs()[0],
        Output::Exit(utxo(0xe5, SOL, 40)),
        Output::Dummy,
        Output::Dummy,
    ];
    for outputs in [narrow, delivered_outputs()] {
        let built = build_with(&Transfer::fixture(), Rail::Delivered, outputs, true);
        let mut escrowed: HashMap<[u8; 32], [u8; 32]> = built
            .outputs
            .iter()
            .filter_map(|output| match output {
                Output::Ring { utxo, .. } | Output::Exit(utxo) => {
                    Some((utxo.owner_key, utxo.nullifier_pk))
                }
                Output::Dummy => None,
            })
            .collect();
        let opened = TransactionAudit::new(&built.transaction, built.layout)
            .with_escrowed_keys(&escrowed)
            .run(&auditor(), &assets())
            .unwrap();
        assert!(opened.payload_errors.is_empty());
        for ((output, slot), audited) in built.outputs.iter().zip(&built.slots).zip(&opened.outputs)
        {
            assert_eq!(audited.opening, audited_opening(output, slot));
        }
        escrowed.remove(&[0xe5; 32]);
        let exit_slot = built
            .outputs
            .iter()
            .position(|output| matches!(output, Output::Exit(_)))
            .unwrap();
        let unescrowed = TransactionAudit::new(&built.transaction, built.layout)
            .with_escrowed_keys(&escrowed)
            .run(&auditor(), &assets())
            .unwrap();
        assert!(unescrowed.payload_errors.is_empty());
        assert_eq!(unescrowed.outputs.len(), built.outputs.len());
        let OutputOpening::EscrowPending(pending) = unescrowed.outputs[exit_slot].opening else {
            panic!("the exit awaits its owner's escrow record");
        };
        let Output::Exit(exit) = &built.outputs[exit_slot] else {
            panic!("an exit");
        };
        assert_eq!(pending.owner_key, exit.owner_key);
        assert_eq!(pending.amount, exit.amount);
        assert_eq!(pending.blinding, built.slots[exit_slot].blinding);
        assert_eq!(
            pending.slot,
            EscrowPendingSlot::Exit {
                asset: exit.asset(),
                mint: Some(exit.asset_address),
            }
        );
    }
}

#[test]
fn a_key_escrow_body_returns_its_proven_fields_until_the_owner_record_arrives() {
    let built = build_with(
        &Transfer::fixture(),
        Rail::Delivered,
        delivered_outputs(),
        true,
    );
    let pending = TransactionAudit::new(&built.transaction, built.layout)
        .run(&auditor(), &assets())
        .unwrap();
    assert!(pending.payload_errors.is_empty());
    assert_eq!(pending.utxos().count(), 0);
    for ((audited, output), slot) in pending.outputs.iter().zip(&built.outputs).zip(&built.slots) {
        match (output, &audited.opening) {
            (Output::Dummy, OutputOpening::Dummy) => {}
            (
                Output::Ring {
                    utxo, recipient_u, ..
                },
                OutputOpening::EscrowPending(opening),
            ) => {
                assert_eq!(opening.owner_key, utxo.owner_key);
                assert_eq!(opening.amount, utxo.amount);
                assert_eq!(opening.blinding, slot.blinding);
                assert_eq!(
                    opening.slot,
                    EscrowPendingSlot::Ring {
                        recipient_u: *recipient_u
                    }
                );
            }
            (Output::Exit(_), OutputOpening::EscrowPending(_)) => {}
            (output, opening) => panic!("{output:?} opened as {opening:?}"),
        }
    }
    let escrowed: HashMap<[u8; 32], [u8; 32]> = built
        .outputs
        .iter()
        .filter_map(|output| match output {
            Output::Ring { utxo, .. } | Output::Exit(utxo) => {
                Some((utxo.owner_key, utxo.nullifier_pk))
            }
            Output::Dummy => None,
        })
        .collect();
    let resolved = TransactionAudit::new(&built.transaction, built.layout)
        .with_escrowed_keys(&escrowed)
        .run(&auditor(), &assets())
        .unwrap();
    for ((output, slot), audited) in built
        .outputs
        .iter()
        .zip(&built.slots)
        .zip(&resolved.outputs)
    {
        assert_eq!(audited.opening, audited_opening(output, slot));
    }
}

struct HashedSpend {
    transfer: Transfer,
    spent: [Spend; 2],
    built: Built,
    commitments: [[u8; 32]; 2],
}

/// A transfer of two ring notes, each named by its full hash.
fn hashed_spend() -> HashedSpend {
    let (transfer, _, spent) = anonymous_spend();
    let outputs = vec![
        Output::Ring {
            utxo: utxo(0xb5, SOL, 50),
            recipient_u: x25519_u(0x50),
            tag: Some(field(0x51)),
        },
        Output::Dummy,
    ];
    let built = build_anonymous(&transfer, outputs, &spent, Spending::RingUtxos);
    let commitments = spent
        .each_ref()
        .map(|spend| spend.commitment(&transfer, Some(transfer.ring)));
    HashedSpend {
        transfer,
        spent,
        built,
        commitments,
    }
}

#[test]
fn a_ring_utxo_input_opens_by_its_full_hash() {
    let HashedSpend {
        transfer,
        spent,
        built,
        commitments,
    } = hashed_spend();
    let known: KnownUtxoIndex = commitments
        .iter()
        .zip(&spent)
        .map(|(commitment, spend)| (*commitment, spend.known(&transfer)))
        .collect();
    let audited = TransactionAudit::new(&built.transaction, built.layout)
        .with_known_utxos(&known)
        .run(&auditor(), &assets())
        .unwrap();
    for ((input, spend), commitment) in audited.inputs.iter().zip(&spent).zip(&commitments) {
        assert_eq!(
            input.opening,
            InputOpening::Opened(AuditedInputOpening {
                asset: spend.utxo.asset(),
                mint: Some(spend.utxo.asset_address),
                amount: spend.utxo.amount,
                blinding: spend.blinding,
                ring: Some(InputRing::Ring {
                    commitment: *commitment
                }),
            })
        );
    }
    let sender = audited.sender.unwrap();
    assert_eq!(
        (sender.owner_key, sender.nullifier_pk),
        (spent[0].utxo.owner_key, Some(spent[0].utxo.nullifier_pk))
    );
}

#[test]
fn an_unseen_spent_note_withholds_no_slot_and_resolves_once_known() {
    let HashedSpend {
        transfer,
        spent,
        built,
        commitments,
    } = hashed_spend();
    let audit = |notes: &[usize]| {
        let known: KnownUtxoIndex = notes
            .iter()
            .map(|&note| (commitments[note], spent[note].known(&transfer)))
            .collect();
        TransactionAudit::new(&built.transaction, built.layout)
            .with_known_utxos(&known)
            .run(&auditor(), &assets())
            .unwrap()
    };
    let resolved = audit(&[0, 1]);
    assert_eq!(resolved.outputs.len(), built.transaction.output_slots.len());
    let opening = |note: usize| {
        InputOpening::Opened(AuditedInputOpening {
            asset: spent[note].utxo.asset(),
            mint: Some(spent[note].utxo.asset_address),
            amount: spent[note].utxo.amount,
            blinding: spent[note].blinding,
            ring: Some(InputRing::Ring {
                commitment: commitments[note],
            }),
        })
    };
    let unseen = |note: usize| InputOpening::UnseenHash {
        hash: commitments[note],
    };
    let sender = Some(AuditedSender {
        owner_key: spent[0].utxo.owner_key,
        nullifier_pk: Some(spent[0].utxo.nullifier_pk),
    });
    for (notes, expected_sender, first, later) in [
        (&[][..], None, unseen(0), unseen(1)),
        (&[0][..], sender, opening(0), unseen(1)),
        (&[1][..], None, unseen(0), opening(1)),
        (&[0, 1][..], sender, opening(0), opening(1)),
    ] {
        let audited = audit(notes);
        assert!(audited.payload_errors.is_empty());
        assert_eq!(audited.outputs, resolved.outputs, "{notes:?}");
        assert_eq!(audited.sender, expected_sender, "{notes:?}");
        let inputs: Vec<_> = audited.inputs.iter().map(|input| &input.opening).collect();
        assert_eq!(inputs, [&first, &later], "{notes:?}");
        let nullifiers: Vec<_> = audited.inputs.iter().map(|input| input.nullifier).collect();
        assert_eq!(nullifiers, built.transaction.nullifiers);
    }
}

/// Notes sharing 16 leading bytes stay apart, the evidence names one whole hash.
#[test]
fn a_full_hash_opens_only_the_note_it_names() {
    let HashedSpend {
        transfer,
        spent,
        built,
        commitments,
    } = hashed_spend();
    let first = (commitments[0], spent[0].known(&transfer));
    let mut twin = commitments[1];
    twin[31] ^= 1;
    assert_eq!(twin[..16], commitments[1][..16]);
    let audit = |index: KnownUtxoIndex| {
        TransactionAudit::new(&built.transaction, built.layout)
            .with_known_utxos(&index)
            .run(&auditor(), &assets())
            .unwrap()
    };
    let twin_only = KnownUtxoIndex::from_iter([first, (twin, spent[1].known(&transfer))]);
    assert_eq!(
        audit(twin_only).inputs[1].opening,
        InputOpening::UnseenHash {
            hash: commitments[1]
        }
    );
    let both = KnownUtxoIndex::from_iter([
        first,
        (twin, spent[0].known(&transfer)),
        (commitments[1], spent[1].known(&transfer)),
    ]);
    assert!(matches!(
        audit(both).inputs[1].opening,
        InputOpening::Opened(AuditedInputOpening {
            ring: Some(InputRing::Ring { commitment }),
            amount: 30,
            ..
        }) if commitment == commitments[1]
    ));
}

/// The signer rail names every published input, a dummy reads zero and never as a note.
#[test]
fn a_signer_input_opens_by_its_full_hash_and_a_dummy_reads_zero() {
    let mut transfer = Transfer::fixture();
    transfer.nullifiers.push(field(0x1e));
    let spend = Spend {
        utxo: utxo(0xa1, SOL, 900),
        blinding: field(0x60),
    };
    let hash = spend.commitment(&transfer, Some(transfer.ring));
    let outputs = vec![
        Output::Ring {
            utxo: utxo(0xb5, SOL, 50),
            recipient_u: x25519_u(0x50),
            tag: None,
        },
        Output::Dummy,
    ];
    let slots = transfer.slots(Rail::Delivered, &outputs);
    let disclosure =
        transfer.signer_disclosure(&outputs, input_hash_evidence(&[Some(hash), None]).unwrap());
    let built = publish(&transfer, slots, outputs, &disclosure);
    let known: KnownUtxoIndex = [(hash, spend.known(&transfer))].into_iter().collect();
    let audited = TransactionAudit::new(&built.transaction, built.layout)
        .with_known_utxos(&known)
        .run(&auditor(), &assets())
        .unwrap();
    assert_eq!(audited.sender, None);
    assert_eq!(audited.inputs[0].hash, hash);
    assert!(matches!(
        audited.inputs[0].opening,
        InputOpening::Opened(AuditedInputOpening { amount: 900, .. })
    ));
    assert_eq!(audited.inputs[1].hash, [0; 32]);
    assert_eq!(audited.inputs[1].opening, InputOpening::Dummy);
}

/// The confirmed deposit of `spend` into the ring, its capsule sealed to the auditor.
fn deposited(transfer: &Transfer, spend: &Spend) -> Confirmed {
    let opening = DepositOpening {
        owner_hash: spend.utxo.owner_hash(),
        blinding: zeroize::Zeroizing::new(spend.blinding),
        owner_key: spend.utxo.owner_key,
    };
    let owner_utxo_hash = owner_utxo_hash(&opening.owner_hash, &opening.blinding).unwrap();
    let sealed = seal_deposits(&[opening], &auditor().pubkey()).unwrap();
    let capsule = RingDepositAuditCapsule {
        slot_index: 0,
        eph_pk: sealed.ephemeral_pk.as_bytes(),
        ciphertext: &sealed.ciphertexts[0],
        recipient_ciphertext: &[],
    }
    .encode();
    let group = deposit_fixture::group(
        transfer.ring,
        true,
        vec![(owner_utxo_hash, capsule.clone())],
    );
    let payload = encode_encrypted_ring_deposit_output(EncryptedRingDepositOutput {
        owner_utxo_hash,
        asset: spend.utxo.asset_address.to_bytes(),
        amount: spend.utxo.amount,
        data_hash: None,
        ring_program_id: transfer.ring.to_bytes(),
        ring_data_hash: [0; 32],
        encrypted: EncryptedRingDepositData {
            tx_viewing_pk: [0; 33],
            salt: [0; 16],
            ciphertext: capsule,
        },
    });
    let transaction = created_transaction(transfer, spend, payload, Vec::new());
    Confirmed {
        origin: RingOrigin {
            deposits: ring_event_origin_in(&[group], 0, transfer.ring)
                .unwrap()
                .deposits,
            ..confirmed(&transaction)
        },
        transaction,
    }
}

/// The confirmed merge of `MERGED_INPUT` into `spend`, its disclosure sealed to the auditor.
fn merged(transfer: &Transfer, spend: &Spend) -> Confirmed {
    let salt = [0x4d; 16];
    let mut input_commitments = vec![[0; 32]; 8];
    input_commitments[0] = field(MERGED_INPUT);
    let opening = MergeOpening { input_commitments };
    let sealed = MergeDisclosureEncryption::new(&opening, salt, &auditor().pubkey()).unwrap();
    let payload = encode_merge_output_data(MergeOutputDataRef {
        salt: &salt,
        ciphertext: &[field(0x73); 3],
        prefix: &[[0; 32]],
    });
    let transaction = created_transaction(transfer, spend, payload, vec![field(0x74)]);
    Confirmed {
        origin: RingOrigin {
            merge_disclosure: Some(ConfirmedMergeDisclosure {
                eph_pk: *sealed.eph_pk.as_bytes(),
                ciphertext: sealed.ciphertext,
                fields: sealed.fields,
            }),
            ..confirmed(&transaction)
        },
        transaction,
    }
}

const MERGED_INPUT: u8 = 0x71;

struct Confirmed {
    transaction: ShieldedTransaction,
    origin: RingOrigin,
}

impl Confirmed {
    fn open(&self, transfer: &Transfer) -> Result<Vec<CreatedUtxo>, AuditError> {
        CreatedUtxos {
            transaction: &self.transaction,
            origin: &self.origin,
            ring: transfer.ring,
        }
        .open(&auditor())
    }

    /// `None` off a v3 merge, the disclosure names the merged commitments.
    fn merge(&self) -> Result<Option<ConfirmedMerge>, AuditError> {
        confirmed_merge(
            &self.transaction,
            self.transaction.event_index.unwrap(),
            &self.origin,
            &auditor(),
        )
    }
}

/// Answers an opened note or a merge output the ledger resolved.
struct LedgerKnown {
    index: KnownUtxoIndex,
    ledger: MergeLedger,
}

impl KnownUtxos for LedgerKnown {
    fn utxo(&self, commitment: &[u8; 32]) -> Option<KnownUtxo> {
        self.index.utxo(commitment)
    }

    fn merged(&self, commitment: &[u8; 32]) -> Option<MergeInput> {
        self.ledger.output(commitment).map(MergeInput::from)
    }
}

/// A proofless deposit without nullifiers, a merge with them, its one output `spend`'s note.
fn created_transaction(
    transfer: &Transfer,
    spend: &Spend,
    payload: Vec<u8>,
    nullifiers: Vec<[u8; 32]>,
) -> ShieldedTransaction {
    ShieldedTransaction {
        slot: 1,
        tx_signature: Signature::from([0xd0; 64]),
        event_index: Some(0),
        tx_viewing_pk: None,
        salt: None,
        output_slots: vec![OutputSlot {
            view_tag: field(0x72),
            output_context: OutputContext {
                hash: spend.commitment(transfer, Some(transfer.ring)),
                tree_id: transfer.tree_id,
                leaf_index: 0,
            },
            payload,
        }],
        messages: Vec::new(),
        proofless: nullifiers.is_empty(),
        nullifiers,
        ring_config: None,
        ring_program_id: Some(transfer.ring),
    }
}

fn confirmed(transaction: &ShieldedTransaction) -> RingOrigin {
    RingOrigin {
        ring_invoked: true,
        event: origin_fixture::event(transaction),
        signers: Vec::new(),
        pool_accounts: Vec::new(),
        withdrawals: Vec::new(),
        deposits: Vec::new(),
        merge_disclosure: None,
        transact: None,
    }
}

#[test]
fn a_deposited_note_opens_and_a_merge_output_reads_as_its_audit_record() {
    let (transfer, _, spent) = anonymous_spend();
    let outputs = vec![
        Output::Ring {
            utxo: utxo(0xb5, SOL, 50),
            recipient_u: x25519_u(0x50),
            tag: Some(field(0x51)),
        },
        Output::Dummy,
    ];
    let built = build_anonymous(&transfer, outputs, &spent, Spending::RingUtxos);
    let deposit_hash = spent[0].commitment(&transfer, Some(transfer.ring));
    let merge_hash = spent[1].commitment(&transfer, Some(transfer.ring));
    assert_eq!(
        audit(&built.transaction, built.layout).unwrap().inputs[0].opening,
        InputOpening::UnseenHash { hash: deposit_hash }
    );
    let deposit = deposited(&transfer, &spent[0]);
    let merge = merged(&transfer, &spent[1]);
    let created = deposit.open(&transfer).unwrap();
    assert_eq!(
        created.iter().map(|note| note.utxo).collect::<Vec<_>>(),
        [KnownUtxo {
            owner: UtxoOwner::Deposited {
                owner_hash: spent[0].utxo.owner_hash(),
            },
            ..spent[0].known(&transfer)
        }]
    );
    assert_eq!(
        created[0].utxo.commitment(Some(transfer.ring)).unwrap(),
        deposit_hash
    );
    // A merge output gets no wallet opening, it holds only what its inputs name.
    assert!(merge.open(&transfer).unwrap().is_empty());
    let mut ledger = MergeLedger::default();
    let inherited = MergeInput::from(&spent[1].known(&transfer));
    let transition = ledger.apply(merge.merge().unwrap().unwrap(), |commitment| {
        (*commitment == field(MERGED_INPUT)).then_some(inherited)
    });
    assert_eq!(transition.spent, [field(MERGED_INPUT)]);
    assert_eq!(transition.resolved[0].commitment, merge_hash);
    assert_eq!(transition.resolved[0].amount, spent[1].utxo.amount);

    let known = LedgerKnown {
        index: created
            .iter()
            .map(|created| (created.commitment, created.utxo))
            .collect(),
        ledger,
    };
    let audited = TransactionAudit::new(&built.transaction, built.layout)
        .with_known_utxos(&known)
        .run(&auditor(), &assets())
        .unwrap();
    assert_eq!(
        audited.inputs[0].opening,
        InputOpening::Opened(AuditedInputOpening {
            asset: spent[0].utxo.asset(),
            mint: Some(spent[0].utxo.asset_address),
            amount: spent[0].utxo.amount,
            blinding: spent[0].blinding,
            ring: Some(InputRing::Ring {
                commitment: deposit_hash,
            }),
        })
    );
    assert_eq!(
        audited.inputs[1].opening,
        InputOpening::Merged(MergedInput {
            commitment: merge_hash,
            input: inherited,
        })
    );
    assert_eq!(audited.sender.unwrap().nullifier_pk, None);

    let mut forged = deposit;
    forged.transaction.output_slots[0].output_context.hash = field(0x79);
    assert!(matches!(
        forged.open(&transfer),
        Err(AuditError::DepositOpeningMismatch)
    ));
    // Nine nullifiers need the 24 slot key, the disclosure holds the 8 slot list.
    let mut forged = merge;
    forged.transaction.nullifiers = vec![field(0x74); 9];
    assert!(matches!(
        forged.merge(),
        Err(AuditError::MergeDisclosureMismatch)
    ));
}

/// The in-proof and authority rails name each input by its full hash, an unopened note leaves the outputs readable.
#[test]
fn an_in_proof_input_opens_by_its_hash_or_stays_unseen_beside_readable_outputs() {
    let mut transfer = Transfer::fixture();
    transfer.nullifiers.push(field(0x1e));
    let spend = Spend {
        utxo: UtxoFields {
            owner_key: [0xa1; 32],
            nullifier_pk: field(0x5a),
            asset_address: MINT,
            amount: 900,
            ..UtxoFields::default()
        },
        blinding: field(0x60),
    };
    let unseen = field(0x61);
    let hash = spend.commitment(&transfer, Some(transfer.ring));
    let outputs = vec![
        Output::Ring {
            utxo: utxo(0xb5, SOL, 50),
            recipient_u: x25519_u(0x50),
            tag: None,
        },
        Output::Dummy,
    ];
    let slots = transfer.slots(Rail::Delivered, &outputs);
    let disclosure = transfer.in_proof_disclosure(
        &outputs,
        input_hash_evidence(&[Some(hash), Some(unseen)]).unwrap(),
    );
    let built = publish(&transfer, slots, outputs, &disclosure);
    let known: KnownUtxoIndex = [(hash, spend.known(&transfer))].into_iter().collect();
    let audited = TransactionAudit::new(&built.transaction, built.layout)
        .with_known_utxos(&known)
        .run(&auditor(), &assets())
        .unwrap();
    assert_eq!(opened_slots(&audited), [0, 1]);
    assert_eq!(audited.sender, None);
    assert!(matches!(
        audited.inputs[0].opening,
        InputOpening::Opened(AuditedInputOpening { amount: 900, .. })
    ));
    assert_eq!(
        audited.inputs[1].opening,
        InputOpening::UnseenHash { hash: unseen }
    );
    let audited = audit(&built.transaction, built.layout).unwrap();
    assert_eq!(opened_slots(&audited), [0, 1]);
    assert_eq!(audited.inputs.len(), 2);
}

/// A record outside the field opens nothing, that slot alone is reported.
#[test]
fn an_unreadable_anonymous_slot_is_reported_and_the_rest_opens() {
    let (transfer, _, spent) = anonymous_spend();
    let outputs = vec![
        Output::Ring {
            utxo: utxo(0xb5, SOL, 50),
            recipient_u: x25519_u(0x50),
            tag: Some(field(0x51)),
        },
        Output::Exit(utxo(0xe5, SOL, 20)),
    ];
    let slots = transfer.slots(Rail::Anonymous, &outputs);
    let mut disclosure = transfer.anonymous_disclosure(
        &outputs,
        AuditEvidence::Entry {
            sender_key: spent[0].utxo.owner_key,
            sender_nullifier_pk: spent[0].utxo.nullifier_pk,
            inputs: entry_inputs(&transfer, &spent),
        },
    );
    let OutputRecord::Anonymous(record) = &mut disclosure.records[0] else {
        panic!("slot 0 is a ring output");
    };
    record.asset = [0xff; 32];
    let built = publish(&transfer, slots, outputs, &disclosure);
    let audited = audit(&built.transaction, built.layout).unwrap();
    assert_eq!(
        audited.payload_errors,
        [slot_error(0, OutputPayloadErrorKind::Disclosure)]
    );
    assert_eq!(opened_slots(&audited), [1]);
    assert!(audited.sender.is_some());
}

/// The page after the one a token closes, the first without a token.
fn page_after(pages: &[Vec<ShieldedTransaction>], token: Option<PaginationToken>) -> usize {
    token.map_or(0, |token| {
        pages
            .iter()
            .rposition(|page| page.iter().map(position).max() == Some(token))
            .map_or(pages.len(), |index| index + 1)
    })
}

/// Ring history pages in order, a token closes every page but the last.
struct RingHistory(Vec<Vec<ShieldedTransaction>>);

#[async_trait::async_trait]
impl AsyncRpc for RingHistory {
    async fn get_shielded_transactions_by_ring(
        &self,
        options: spr_client::RingHistoryOptions,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, spr_client::ClientError> {
        let index = page_after(&self.0, options.pagination_token);
        Ok(EventsPage {
            context: Context {
                block_time: 0,
                slot: 1,
            },
            output_tree_id: None,
            rows: self.0.get(index).cloned().unwrap_or_default(),
            more: index + 1 < self.0.len(),
        }
        .response())
    }
}

struct ConfirmedOrigins(HashMap<Signature, RingOrigin>);

impl TransactionOrigin for ConfirmedOrigins {
    async fn origin(
        &self,
        signature: Signature,
        _event_index: u16,
        _ring: Address,
    ) -> Result<RingOrigin, AuditError> {
        self.0
            .get(&signature)
            .cloned()
            .ok_or_else(|| AuditError::Unavailable {
                signature,
                message: "not found".to_owned(),
            })
    }
}

#[tokio::test]
async fn the_created_utxo_scan_opens_every_deposit_and_the_merge_audit_reads_every_merge() {
    let (transfer, built, spent) = anonymous_spend();
    let deposit = deposited(&transfer, &spent[0]);
    let mut merge = merged(&transfer, &spent[1]);
    merge.transaction.tx_signature = Signature::from([0xd1; 64]);
    // A ring transfer and a row the ring never invoked open nothing.
    let mut foreign = deposited(&transfer, &spent[1]);
    foreign.transaction.tx_signature = Signature::from([0xd2; 64]);
    foreign.origin.ring_invoked = false;
    let rows = [&deposit, &merge, &foreign];
    let mut origins: HashMap<Signature, RingOrigin> = rows
        .iter()
        .map(|row| (row.transaction.tx_signature, row.origin.clone()))
        .collect();
    origins.insert(
        built.transaction.tx_signature,
        confirmed(&built.transaction),
    );
    let pages = vec![
        vec![deposit.transaction.clone(), built.transaction.clone()],
        vec![merge.transaction.clone(), foreign.transaction.clone()],
    ];
    let history = RingHistory(pages.clone());
    let auditor = auditor();
    let page = CreatedUtxoScan::new(transfer.ring, &auditor)
        .run(&history, &ConfirmedOrigins(origins.clone()))
        .await
        .unwrap();
    let opened: Vec<[u8; 32]> = page.utxos.iter().map(|utxo| utxo.commitment).collect();
    assert_eq!(
        opened,
        [spent[0].commitment(&transfer, Some(transfer.ring))]
    );
    assert_eq!(page.next_cursor, None);
    assert_eq!(page.merges.len(), 1);
    assert_eq!(page.merges[0].inputs, [field(MERGED_INPUT)]);
    let merges = MergeAudit::new(transfer.ring, &auditor)
        .run(&history, &ConfirmedOrigins(origins.clone()))
        .await
        .unwrap();
    assert_eq!(
        merges
            .iter()
            .map(|merge| (merge.output_commitment, merge.inputs.clone()))
            .collect::<Vec<_>>(),
        [(
            spent[1].commitment(&transfer, Some(transfer.ring)),
            vec![field(MERGED_INPUT)]
        )]
    );

    let capped = CreatedUtxoScan::new(transfer.ring, &auditor)
        .with_max_pages(NonZeroUsize::new(1).unwrap())
        .run(&history, &ConfirmedOrigins(origins.clone()))
        .await
        .unwrap();
    assert_eq!(capped.utxos.len(), 1);
    assert_eq!(
        capped.next_cursor,
        Some(HistoryCursor {
            query: HistoryQuery {
                ring: transfer.ring,
                stream: HistoryStream::Ring,
            },
            token: position(&deposit.transaction),
        })
    );

    // An indexed row its confirmed event does not match is refused.
    let mut altered = pages;
    altered[0][0].output_slots[0].output_context.hash = field(0x7b);
    assert!(matches!(
        CreatedUtxoScan::new(transfer.ring, &auditor)
            .run(&RingHistory(altered), &ConfirmedOrigins(origins))
            .await,
        Err(AuditError::ConfirmedEventMismatch)
    ));
}

#[test]
fn a_body_sealed_to_another_recipient_is_flagged_on_its_slot() {
    let transfer = Transfer::fixture();
    let mut built = build(&transfer, Rail::Delivered, delivered_outputs());
    let Output::Ring { utxo, .. } = built.outputs[2] else {
        panic!("slot 2 is a ring output");
    };
    let foreign = seal_delivered_body(
        &DeliveredBody {
            blinding: built.slots[2].blinding,
            amount: utxo.amount,
            owner_key: utxo.owner_key,
            nullifier_pk: Some(utxo.nullifier_pk),
        },
        &transfer.delivered_secret(&x25519_u(0x7f), 2),
    )
    .unwrap();
    built.transaction.output_slots[2].payload =
        custom_ring_interface::encode_ring_confidential_delivered_output(&foreign).unwrap();
    let audited = audit(&built.transaction, built.layout).unwrap();
    assert_eq!(
        audited.payload_errors,
        [slot_error(2, OutputPayloadErrorKind::Commitment)]
    );
    assert_eq!(opened_slots(&audited), [0, 1, 3, 4, 5, 6, 7]);
}

#[test]
fn an_exit_opens_with_its_published_owner_tag() {
    let mut built = build(&Transfer::fixture(), Rail::Delivered, delivered_outputs());
    let audited = audit(&built.transaction, built.layout).unwrap();
    let OutputOpening::Exit(exit) = audited.outputs[5].opening else {
        panic!("slot 5 exits the ring");
    };
    assert_eq!(exit.owner_key, built.transaction.output_slots[5].view_tag);
    assert_eq!(exit.owner_key, [0xe5; 32]);
    built.transaction.output_slots[5].view_tag = [0xe6; 32];
    let audited = audit(&built.transaction, built.layout).unwrap();
    assert_eq!(
        audited.payload_errors,
        [slot_error(5, OutputPayloadErrorKind::Commitment)]
    );
}

#[test]
fn a_ring_slot_without_its_body_or_agreement_is_flagged() {
    let mut built = build(&Transfer::fixture(), Rail::Delivered, delivered_outputs());
    built.transaction.output_slots[0].payload = vec![0xff];
    // A zero u is a low-order point, no secret agrees with it.
    built.transaction.output_slots[1].view_tag = [0; 32];
    let audited = audit(&built.transaction, built.layout).unwrap();
    assert_eq!(
        audited.payload_errors,
        [
            slot_error(0, OutputPayloadErrorKind::Frame),
            slot_error(1, OutputPayloadErrorKind::RecipientKey),
        ]
    );
}

#[test]
fn an_unknown_asset_keeps_the_verified_opening() {
    let outputs = vec![
        Output::Exit(utxo(0xe1, MINT, 9)),
        Output::Exit(utxo(0xe2, SOL, 3)),
    ];
    let built = build(&Transfer::fixture(), Rail::Delivered, outputs);
    let audited = TransactionAudit::new(&built.transaction, built.layout)
        .run(&auditor(), &RingAssets::new([]).unwrap())
        .unwrap();
    assert!(audited.has_unknown_assets());
    let mints: Vec<_> = audited
        .outputs
        .iter()
        .map(|output| output.opening.utxo().unwrap().mint)
        .collect();
    assert_eq!(mints, [None, Some(SOL)]);
    assert!(!audit(&built.transaction, built.layout)
        .unwrap()
        .has_unknown_assets());
}

fn anonymous_spend() -> (Transfer, Built, [Spend; 2]) {
    let mut transfer = Transfer::fixture();
    transfer.nullifiers.push(field(0x1e));
    let sender = |asset_address, amount| UtxoFields {
        owner_key: [0xa1; 32],
        nullifier_pk: field(0x5a),
        asset_address,
        amount,
        ..UtxoFields::default()
    };
    let spent = [
        Spend {
            utxo: sender(SOL, 50),
            blinding: field(0x60),
        },
        Spend {
            utxo: sender(MINT, 30),
            blinding: field(0x61),
        },
    ];
    let outputs = vec![
        Output::Ring {
            utxo: utxo(0xb5, SOL, 50),
            recipient_u: x25519_u(0x50),
            tag: Some(field(0x51)),
        },
        Output::Ring {
            utxo: sender(MINT, 30),
            recipient_u: x25519_u(0x52),
            tag: Some(field(0x53)),
        },
    ];
    let built = build_anonymous(&transfer, outputs, &spent, Spending::Entry);
    (transfer, built, spent)
}

#[test]
fn an_anonymous_input_resolves_to_its_ring_or_the_default_ring() {
    let (transfer, built, spent) = anonymous_spend();
    let trees = [Some(transfer.tree_id); 2];
    let rings = |audited: AuditedTransaction| -> Vec<Option<InputRing>> {
        audited
            .inputs
            .iter()
            .map(|input| input.opening.opened().unwrap().ring)
            .collect()
    };
    let audited = TransactionAudit::new(&built.transaction, built.layout)
        .with_input_trees(&trees)
        .unwrap()
        .run(&auditor(), &assets())
        .unwrap();
    assert_eq!(
        rings(audited),
        [
            Some(InputRing::Ring {
                commitment: spent[0].commitment(&transfer, Some(transfer.ring)),
            }),
            Some(InputRing::Default {
                commitment: spent[1].commitment(&transfer, None),
            }),
        ]
    );
    // Off the note's tree the named hash rebuilds neither candidate.
    let other_tree = transfer.tree_id + 1;
    let candidates = |spend: &Spend| {
        let placement = |ring| Placement {
            tree_id: other_tree,
            ..spend.placement(&transfer, ring)
        };
        Some(InputRing::Unresolved {
            ring: spend.utxo.commitment(placement(Some(transfer.ring))),
            default: spend.utxo.commitment(placement(None)),
        })
    };
    let audited = TransactionAudit::new(&built.transaction, built.layout)
        .with_input_trees(&[Some(other_tree); 2])
        .unwrap()
        .run(&auditor(), &assets())
        .unwrap();
    assert_eq!(
        rings(audited),
        [candidates(&spent[0]), candidates(&spent[1])]
    );
    let audited = audit(&built.transaction, built.layout).unwrap();
    assert_eq!(
        audited.inputs[1].opening,
        InputOpening::Opened(AuditedInputOpening {
            asset: spent[1].utxo.asset(),
            mint: Some(MINT),
            amount: 30,
            blinding: spent[1].blinding,
            ring: None,
        })
    );
    assert_eq!(audited.inputs[1].nullifier, field(0x1e));
    let sender = audited.sender.unwrap();
    assert_eq!(
        (sender.owner_key, sender.nullifier_pk),
        ([0xa1; 32], Some(field(0x5a)))
    );
    assert!(matches!(
        TransactionAudit::new(&built.transaction, built.layout).with_input_trees(&trees[1..]),
        Err(AuditError::InputTreeCount {
            trees: 1,
            inputs: 2
        })
    ));
}

/// The proof leaves the tag free, the auditor opens the output from the disclosure alone.
#[test]
fn an_anonymous_ring_slot_opens_under_any_published_tag() {
    let (_, mut built, _) = anonymous_spend();
    let tag = [0xfe; 32];
    built.transaction.output_slots[0].view_tag = tag;
    let audited = audit(&built.transaction, built.layout).unwrap();
    assert!(audited.payload_errors.is_empty());
    assert!(matches!(
        audited.outputs[0].opening,
        OutputOpening::Ring {
            owner_tag: RingOwnerTag::View(opened),
            ..
        } if opened == tag
    ));
}

#[test]
fn the_envelope_must_seal_the_published_transaction_key() {
    let built = build(&Transfer::fixture(), Rail::Delivered, delivered_outputs());
    let mut forged = built.transaction.clone();
    let other_key = ViewingKey::new();
    let sealed = AuditStreamSeal {
        layout: built.layout,
        tx_viewing_key: &other_key,
        evidence: input_hash_evidence(&[None]).unwrap(),
        records: transfer_records(&built),
    }
    .seal(&auditor().pubkey())
    .unwrap();
    let stream = [&sealed.eph_u[..], &sealed.envelope].concat();
    forged.messages[0].data[1..=stream.len()].copy_from_slice(&stream);
    assert!(matches!(
        audit(&forged, built.layout),
        Err(AuditError::TxViewingKeyMismatch)
    ));
}

#[test]
fn the_auditor_message_is_unique_and_last() {
    let built = build(&Transfer::fixture(), Rail::Delivered, delivered_outputs());
    let free_form = MessageData {
        view_tag: [0x77; 32],
        data: vec![1, 2, 3],
    };
    let mut missing = built.transaction.clone();
    missing.messages = vec![free_form.clone()];
    assert!(matches!(
        audit(&missing, built.layout),
        Err(AuditError::MissingAuditorMessage)
    ));
    let mut misplaced = built.transaction.clone();
    misplaced.messages.push(free_form);
    assert!(matches!(
        audit(&misplaced, built.layout),
        Err(AuditError::MissingAuditorMessage)
    ));
    assert!(matches!(
        TransactionAudit::new(&built.transaction, built.layout)
            .run(&X25519Keypair::new(), &assets()),
        Err(AuditError::MissingAuditorMessage)
    ));
}

#[test]
fn a_message_off_the_layout_is_refused() {
    let built = build(&Transfer::fixture(), Rail::Delivered, delivered_outputs());
    let length = built.transaction.messages[0].data.len();
    for mutated in [length - 32, length + 32] {
        let mut transaction = built.transaction.clone();
        transaction.messages[0].data.resize(mutated, 0);
        assert!(matches!(
            audit(&transaction, built.layout),
            Err(AuditError::AuditorMessageLength(len)) if len == mutated
        ));
    }
    let mut widened = built.transaction.clone();
    widened.output_slots.truncate(5);
    assert!(matches!(
        audit(&widened, built.layout),
        Err(AuditError::DisclosureLayout)
    ));
}

#[test]
fn the_layout_comes_from_the_ring_frame() {
    let built = build(&Transfer::fixture(), Rail::Delivered, delivered_outputs());
    let origin = |transact| RingOrigin {
        transact,
        ..confirmed(&built.transaction)
    };
    assert_eq!(
        origin(Some(built.frame.clone()))
            .audit_stream(RingMode::Confidential)
            .unwrap(),
        built.layout
    );
    assert!(matches!(
        origin(None).audit_stream(RingMode::Confidential),
        Err(AuditError::MissingRingTransact)
    ));
    // An anonymous ring parses a `Transact` frame under its own rail.
    assert!(matches!(
        origin(Some(built.frame.clone())).audit_stream(RingMode::Anonymous),
        Err(AuditError::InvalidTransactData(_))
    ));
    let escrowed = AuditStreamLayout {
        key_escrow: true,
        ..built.layout
    };
    assert!(matches!(
        audit(&built.transaction, escrowed),
        Err(AuditError::AuditorMessageLength(_))
    ));
}

/// Token paging plus the message-tag filter. Photon's tag filter is an OR over
/// output tags and message tags, so a transaction can arrive because an output
/// tag matched; the scan drops those.
struct PagedIndexer {
    expected_tag: [u8; 32],
    pages: Vec<Vec<ShieldedTransaction>>,
    /// Page size asked for on each round trip, in call order.
    requested: Mutex<Vec<Option<u32>>>,
}

#[async_trait::async_trait]
impl AsyncRpc for PagedIndexer {
    async fn get_shielded_transactions_by_tags(
        &self,
        tags: Vec<[u8; 32]>,
        pagination_token: Option<PaginationToken>,
        limit: Option<u32>,
        _filters: HistoryFilters,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, spr_client::ClientError> {
        assert_eq!(tags, vec![self.expected_tag]);
        self.requested.lock().unwrap().push(limit);
        let index = page_after(&self.pages, pagination_token);
        Ok(EventsPage {
            context: Context {
                block_time: 0,
                slot: 1,
            },
            output_tree_id: None,
            rows: self.pages.get(index).cloned().unwrap_or_default(),
            more: index + 1 < self.pages.len(),
        }
        .response())
    }
}

struct KnownOrigins {
    ring: Address,
    origins: HashMap<Signature, bool>,
    confirmed: HashMap<Signature, zolana_ring_client::ConfirmedEvent>,
    frames: HashMap<Signature, Vec<u8>>,
    lookups: AtomicUsize,
}

impl TransactionOrigin for KnownOrigins {
    async fn origin(
        &self,
        signature: Signature,
        _event_index: u16,
        ring: Address,
    ) -> Result<RingOrigin, AuditError> {
        assert_eq!(ring, self.ring);
        self.lookups.fetch_add(1, Ordering::Relaxed);
        self.origins
            .get(&signature)
            .copied()
            .map(|ring_invoked| RingOrigin {
                event: self
                    .confirmed
                    .get(&signature)
                    .expect("confirmed event")
                    .clone(),
                ring_invoked,
                signers: Vec::new(),
                pool_accounts: Vec::new(),
                withdrawals: Vec::new(),
                deposits: Vec::new(),
                merge_disclosure: None,
                transact: self.frames.get(&signature).cloned(),
            })
            .ok_or_else(|| AuditError::Unavailable {
                signature,
                message: "not found".to_owned(),
            })
    }
}

fn with_signature(mut tx: ShieldedTransaction, byte: u8) -> ShieldedTransaction {
    tx.tx_signature = Signature::from([byte; 64]);
    tx
}

fn ring() -> Address {
    Transfer::fixture().ring
}

fn delivered_transfer(seed: u8) -> Built {
    let outputs = vec![
        Output::Ring {
            utxo: utxo(
                0xb0 + seed % 0x10,
                [SOL, MINT][usize::from(seed % 2)],
                u64::from(seed),
            ),
            recipient_u: x25519_u(seed),
            tag: None,
        },
        Output::Dummy,
    ];
    build(&transfer(seed), Rail::Delivered, outputs)
}

#[tokio::test]
async fn scan_walks_every_page_and_keeps_only_ring_transactions_tagged_for_the_auditor() {
    let auditor_pk = auditor().pubkey();
    let first_built = delivered_transfer(1);
    let second_built = delivered_transfer(2);
    let first = with_signature(first_built.transaction.clone(), 1);
    let second = with_signature(second_built.transaction.clone(), 5);
    // An output tag match must still be attributed before it can be excluded.
    let mut output_tag_match = with_signature(delivered_transfer(3).transaction, 3);
    output_tag_match.messages.clear();
    output_tag_match.output_slots[0].view_tag = auditor_view_tag(&auditor_pk);
    let foreign_ring = with_signature(first.clone(), 4);
    let indexer = PagedIndexer {
        expected_tag: auditor_view_tag(&auditor_pk),
        pages: vec![
            vec![first.clone(), output_tag_match, foreign_ring.clone()],
            vec![second.clone()],
        ],
        requested: Mutex::new(Vec::new()),
    };
    let origin = KnownOrigins {
        ring: ring(),
        origins: HashMap::from([
            (first.tx_signature, true),
            (second.tx_signature, true),
            (foreign_ring.tx_signature, false),
            (Signature::from([3; 64]), false),
        ]),
        confirmed: indexer
            .pages
            .iter()
            .flatten()
            .map(|tx| (tx.tx_signature, origin_fixture::event(tx)))
            .collect(),
        frames: HashMap::from([
            (first.tx_signature, first_built.frame.clone()),
            (second.tx_signature, second_built.frame.clone()),
        ]),
        lookups: AtomicUsize::new(0),
    };
    assert_eq!(
        RingScan::new(ring(), auditor_pk)
            .with_max_pages(NonZeroUsize::new(2).expect("page limit"))
            .run(&indexer, &origin)
            .await
            .expect("scan")
            .transactions,
        vec![first, second]
    );
    assert_eq!(
        origin.lookups.load(Ordering::Relaxed),
        4,
        "one lookup per signature"
    );
    let audited = RingScan::new(ring(), auditor_pk)
        .with_max_pages(NonZeroUsize::new(2).expect("page limit"))
        .audit(&auditor(), &indexer, &origin, &assets())
        .await
        .expect("audit all")
        .transactions;
    assert_eq!(audited.len(), 2);
    for (audited, built) in audited.iter().zip([&first_built, &second_built]) {
        assert_eq!(
            audited.outputs[0].opening,
            audited_opening(&built.outputs[0], &built.slots[0])
        );
    }
    assert_eq!(audited[0].tx_viewing_pk, transfer(1).tx_key.pubkey());
}

/// A payment to a member, then the member's commitment-key spend of it.
fn paid_and_spent() -> (Built, Built) {
    let member = |asset_address, amount| UtxoFields {
        owner_key: [0xa4; 32],
        nullifier_pk: field(0x64),
        asset_address,
        amount,
        ..UtxoFields::default()
    };
    let paying = transfer(5);
    let payer = Spend {
        utxo: UtxoFields {
            owner_key: [0xa5; 32],
            ..member(SOL, 70)
        },
        blinding: field(0x65),
    };
    let tag = |byte| Some(field(byte));
    let paid = build_anonymous(
        &paying,
        vec![
            Output::Ring {
                utxo: member(SOL, 70),
                recipient_u: x25519_u(0x54),
                tag: tag(0x55),
            },
            Output::Dummy,
        ],
        &[payer],
        Spending::Entry,
    );
    let spending = transfer(6);
    let received = Spend {
        utxo: UtxoFields {
            ring_data_hash: paid.slots[0].ring_data_hash,
            ..member(SOL, 70)
        },
        blinding: paid.slots[0].blinding,
    };
    let spent = build_anonymous(
        &spending,
        vec![Output::Exit(utxo(0xe8, SOL, 70)), Output::Dummy],
        &[received],
        Spending::RingUtxos,
    );
    (paid, spent)
}

/// One page of `built` under signatures from 5, every frame known.
fn anonymous_page(built: &[&Built]) -> (PagedIndexer, KnownOrigins) {
    let page: Vec<ShieldedTransaction> = (5..)
        .zip(built)
        .map(|(byte, built)| with_signature(built.transaction.clone(), byte))
        .collect();
    let mut origin = ring_origins(ring(), std::slice::from_ref(&page));
    origin.frames = page
        .iter()
        .zip(built)
        .map(|(tx, built)| (tx.tx_signature, built.frame.clone()))
        .collect();
    (indexer(&auditor().pubkey(), vec![page]), origin)
}

#[tokio::test]
async fn an_input_resolves_against_an_output_the_page_opened_before_it() {
    let (paid, spent) = paid_and_spent();
    let (indexer, origin) = anonymous_page(&[&paid, &spent]);
    let audited = RingScan::new(ring(), auditor().pubkey())
        .with_mode(RingMode::Anonymous)
        .audit(&auditor(), &indexer, &origin, &assets())
        .await
        .expect("audit")
        .transactions;
    assert_eq!(
        audited[1].inputs[0].opening.opened().unwrap().ring,
        Some(InputRing::Ring {
            commitment: paid.slots[0].output.output_context.hash
        })
    );
}

#[tokio::test]
async fn an_input_an_earlier_page_opened_resolves_through_the_known_utxos() {
    let (paid, spent) = paid_and_spent();
    let (indexer, origin) = anonymous_page(&[&spent]);
    let scan = || RingScan::new(ring(), auditor().pubkey()).with_mode(RingMode::Anonymous);
    let unseen = scan()
        .audit(&auditor(), &indexer, &origin, &assets())
        .await
        .expect("audit")
        .transactions;
    assert_eq!(unseen[0].sender, None);
    assert_eq!(
        unseen[0].outputs.len(),
        spent.transaction.output_slots.len()
    );
    assert_eq!(
        unseen[0].inputs[0].opening,
        InputOpening::UnseenHash {
            hash: paid.slots[0].output.output_context.hash
        }
    );
    let known = audit(&paid.transaction, paid.layout)
        .unwrap()
        .utxos()
        .map(|created| (created.commitment, created.utxo))
        .collect();
    let audited = scan()
        .with_known_utxos(known)
        .audit(&auditor(), &indexer, &origin, &assets())
        .await
        .expect("audit")
        .transactions;
    assert_eq!(
        audited[0].inputs[0].opening.opened().unwrap().ring,
        Some(InputRing::Ring {
            commitment: paid.slots[0].output.output_context.hash
        })
    );
}

#[tokio::test]
async fn a_confirmed_ring_match_without_mandatory_disclosure_is_incomplete() {
    let mut tx = delivered_transfer(1).transaction;
    tx.messages.clear();
    let origin = KnownOrigins {
        ring: ring(),
        origins: HashMap::from([(tx.tx_signature, true)]),
        confirmed: HashMap::from([(tx.tx_signature, origin_fixture::event(&tx))]),
        frames: HashMap::new(),
        lookups: AtomicUsize::new(0),
    };
    let indexer = indexer(&auditor().pubkey(), vec![vec![tx]]);
    assert!(matches!(
        RingScan::new(ring(), auditor().pubkey())
            .audit(&auditor(), &indexer, &origin, &assets())
            .await,
        Err(AuditError::MissingAuditorMessage)
    ));
}

#[tokio::test]
async fn scan_fails_when_an_origin_is_unavailable() {
    let auditor_pk = auditor().pubkey();
    let indexer = indexer(&auditor_pk, vec![vec![delivered_transfer(1).transaction]]);
    let origin = KnownOrigins {
        ring: ring(),
        origins: HashMap::new(),
        confirmed: HashMap::new(),
        frames: HashMap::new(),
        lookups: AtomicUsize::new(0),
    };
    assert!(matches!(
        RingScan::new(ring(), auditor_pk)
            .with_max_pages(NonZeroUsize::new(1).expect("page limit"))
            .run(&indexer, &origin)
            .await,
        Err(AuditError::Unavailable { .. })
    ));
}

/// One auditor-tagged transaction per page, so the paging rules are what the
/// scan is measured on.
fn paged_history(pages: u8) -> Vec<Vec<ShieldedTransaction>> {
    (0..pages)
        .map(|index| {
            vec![with_signature(
                delivered_transfer(index + 1).transaction,
                index + 1,
            )]
        })
        .collect()
}

fn indexer(auditor_pk: &X25519Pubkey, pages: Vec<Vec<ShieldedTransaction>>) -> PagedIndexer {
    PagedIndexer {
        expected_tag: auditor_view_tag(auditor_pk),
        pages,
        requested: Mutex::new(Vec::new()),
    }
}

fn ring_origins(ring: Address, pages: &[Vec<ShieldedTransaction>]) -> KnownOrigins {
    KnownOrigins {
        ring,
        confirmed: pages
            .iter()
            .flatten()
            .map(|tx| (tx.tx_signature, origin_fixture::event(tx)))
            .collect(),
        origins: pages
            .iter()
            .flatten()
            .map(|tx| (tx.tx_signature, true))
            .collect(),
        frames: HashMap::new(),
        lookups: AtomicUsize::new(0),
    }
}

fn signatures(transactions: &[ShieldedTransaction]) -> Vec<Signature> {
    transactions.iter().map(|tx| tx.tx_signature).collect()
}

#[tokio::test]
async fn the_page_size_is_asked_for_on_every_round_trip() {
    let auditor_pk = auditor().pubkey();
    let pages = paged_history(3);
    let origin = ring_origins(ring(), &pages);
    let indexer = indexer(&auditor_pk, pages.clone());
    let page = RingScan::new(ring(), auditor_pk)
        .with_page_size(NonZeroU32::new(1).expect("page size"))
        .with_max_pages(NonZeroUsize::new(3).expect("page limit"))
        .run(&indexer, &origin)
        .await
        .expect("scan");
    assert_eq!(*indexer.requested.lock().unwrap(), vec![Some(1); 3]);
    assert_eq!(signatures(&page.transactions), signatures(&pages.concat()));
}

/// A scan cut short by `max_pages` hands back the cursor of the page it did
/// not read, and resuming there repeats nothing and skips nothing.
#[tokio::test]
async fn a_scan_stopped_by_max_pages_resumes_where_it_stopped() {
    let auditor_pk = auditor().pubkey();
    let pages = paged_history(3);
    let origin = ring_origins(ring(), &pages);
    let indexer = indexer(&auditor_pk, pages.clone());
    let stopped = RingScan::new(ring(), auditor_pk)
        .with_max_pages(NonZeroUsize::new(2).expect("page limit"))
        .run(&indexer, &origin)
        .await
        .expect("first scan");
    let cursor = stopped.next_cursor.expect("unread history");
    assert_eq!(
        signatures(&stopped.transactions),
        signatures(&pages[..2].concat())
    );
    let resumed = RingScan::new(ring(), auditor_pk)
        .with_cursor(cursor)
        .with_max_pages(NonZeroUsize::new(2).expect("page limit"))
        .run(&indexer, &origin)
        .await
        .expect("resumed scan");
    assert_eq!(resumed.next_cursor, None);
    assert_eq!(signatures(&resumed.transactions), signatures(&pages[2]));
}

/// A token names the last transaction returned, so an empty page never carries one.
struct TokenOnAnEmptyPage;

#[async_trait::async_trait]
impl AsyncRpc for TokenOnAnEmptyPage {
    async fn get_shielded_transactions_by_tags(
        &self,
        _tags: Vec<[u8; 32]>,
        _pagination_token: Option<PaginationToken>,
        _limit: Option<u32>,
        _filters: HistoryFilters,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, spr_client::ClientError> {
        Ok(GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 0,
                slot: 1,
            },
            output_tree_id: None,
            data: Vec::new(),
            pagination_token: Some(PaginationToken::new(1, Signature::from([1; 64]))),
        })
    }
}

#[tokio::test]
async fn an_empty_page_with_a_token_is_refused_and_an_empty_terminal_page_ends_the_scan() {
    let auditor_pk = auditor().pubkey();
    let origin = ring_origins(ring(), &[]);
    let scan = || {
        RingScan::new(ring(), auditor_pk).with_max_pages(NonZeroUsize::new(2).expect("page limit"))
    };
    assert!(matches!(
        scan().run(&TokenOnAnEmptyPage, &origin).await,
        Err(AuditError::InvalidHistoryPage)
    ));
    let page = scan()
        .run(&indexer(&auditor_pk, vec![Vec::new()]), &origin)
        .await
        .expect("scan");
    assert!(page.transactions.is_empty());
    assert_eq!(page.next_cursor, None);
}

#[tokio::test]
async fn a_cursor_at_the_end_of_history_returns_an_empty_page() {
    let auditor_pk = auditor().pubkey();
    let pages = paged_history(2);
    let origin = ring_origins(ring(), &pages);
    let token = position(pages[1].last().expect("a row"));
    let indexer = indexer(&auditor_pk, pages);
    let page = RingScan::new(ring(), auditor_pk)
        .with_cursor(HistoryCursor {
            query: HistoryQuery {
                ring: ring(),
                stream: HistoryStream::Tags,
            },
            token,
        })
        .with_max_pages(NonZeroUsize::new(2).expect("page limit"))
        .run(&indexer, &origin)
        .await
        .expect("scan");
    assert!(page.transactions.is_empty());
    assert_eq!(page.next_cursor, None);
    assert_eq!(origin.lookups.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_row_of_another_ring_never_reaches_the_created_scan_origin_read() {
    let (transfer, built, _) = anonymous_spend();
    let mut outsider = built.transaction.clone();
    outsider.ring_program_id = None;
    let auditor = auditor();
    let page = CreatedUtxoScan::new(transfer.ring, &auditor)
        .run(
            &RingHistory(vec![vec![outsider]]),
            &ConfirmedOrigins(HashMap::new()),
        )
        .await
        .unwrap();
    assert!(page.utxos.is_empty());
}

#[test]
fn a_mint_the_registry_lacks_reads_as_an_unknown_asset_and_opens_once_registered() {
    let fresh = Address::new_from_array([0xee; 32]);
    let outputs = vec![
        Output::Ring {
            utxo: utxo(0xb5, fresh, 0),
            recipient_u: x25519_u(0x50),
            tag: None,
        },
        Output::Dummy,
    ];
    let built = build(&Transfer::fixture(), Rail::Delivered, outputs);
    let audited = audit(&built.transaction, built.layout).unwrap();
    assert_eq!(opened_slots(&audited), [1]);
    assert_eq!(
        audited.payload_errors,
        [slot_error(0, OutputPayloadErrorKind::UnknownAsset)]
    );
    assert!(audited.has_unknown_assets());
    let registered = RingAssets::new([Mint::new(fresh, 8)]).unwrap();
    let resolved = TransactionAudit::new(&built.transaction, built.layout)
        .run(&auditor(), &registered)
        .unwrap();
    assert!(resolved.payload_errors.is_empty());
    assert_eq!(opened_slots(&resolved), [0, 1]);
    assert!(!resolved.has_unknown_assets());

    let mut retried = audited.clone();
    let no_keys = HashMap::new();
    retried.resolve(&no_keys, &assets()).unwrap();
    assert_eq!(retried, audited);
    retried.resolve(&no_keys, &registered).unwrap();
    assert_eq!(retried.outputs, resolved.outputs);
    assert!(retried.payload_errors.is_empty());
    assert!(retried.unresolved.is_empty());
}

#[test]
fn a_commitment_error_leaves_every_pending_output_for_the_retry() {
    let outputs = vec![
        delivered_outputs()[0],
        Output::Exit(utxo(0xe5, SOL, 40)),
        Output::Dummy,
        Output::Dummy,
    ];
    let built = build_with(&Transfer::fixture(), Rail::Delivered, outputs, true);
    let keys: HashMap<[u8; 32], [u8; 32]> = built
        .outputs
        .iter()
        .filter_map(|output| match output {
            Output::Ring { utxo, .. } | Output::Exit(utxo) => {
                Some((utxo.owner_key, utxo.nullifier_pk))
            }
            Output::Dummy => None,
        })
        .collect();
    let opened = TransactionAudit::new(&built.transaction, built.layout)
        .with_escrowed_keys(&keys)
        .run(&auditor(), &assets())
        .unwrap();
    let mut pending = TransactionAudit::new(&built.transaction, built.layout)
        .with_escrowed_keys(&HashMap::new())
        .run(&auditor(), &assets())
        .unwrap();
    assert_eq!(pending.unresolved.len(), 2);
    let noncanonical: HashMap<[u8; 32], [u8; 32]> =
        keys.keys().map(|owner| (*owner, [0xff; 32])).collect();
    let before = pending.clone();
    assert!(pending.resolve(&noncanonical, &assets()).is_err());
    assert_eq!(pending, before);
    pending.resolve(&keys, &assets()).unwrap();
    assert!(pending.unresolved.is_empty());
    assert_eq!(pending.outputs, opened.outputs);
}

#[test]
fn a_sender_bundle_under_the_auditor_tag_leaves_the_transfer_open() {
    let (_, built, _) = anonymous_spend();
    let expected = audit(&built.transaction, built.layout).unwrap();
    let mut transaction = built.transaction.clone();
    assert_eq!(transaction.messages.len(), 2);
    transaction.messages[0].view_tag = auditor_view_tag(&auditor().pubkey());
    assert_eq!(audit(&transaction, built.layout).unwrap(), expected);
}

#[test]
fn an_anonymous_output_under_a_zero_nullifier_key_opens() {
    let (transfer, _, spent) = anonymous_spend();
    let outputs = vec![
        Output::Ring {
            utxo: UtxoFields {
                nullifier_pk: [0; 32],
                ..utxo(0xb5, SOL, 50)
            },
            recipient_u: x25519_u(0x50),
            tag: Some(field(0x51)),
        },
        Output::Dummy,
    ];
    let built = build_anonymous(&transfer, outputs, &spent, Spending::Entry);
    let audited = audit(&built.transaction, built.layout).unwrap();
    assert_eq!(opened_slots(&audited), [0, 1]);
    assert!(audited.payload_errors.is_empty());
}

/// Answers one row with `error`, the known origin for the rest.
struct FailingOrigin {
    known: KnownOrigins,
    failing: Signature,
    error: fn(Signature) -> AuditError,
}

impl TransactionOrigin for FailingOrigin {
    async fn origin(
        &self,
        signature: Signature,
        event_index: u16,
        ring: Address,
    ) -> Result<RingOrigin, AuditError> {
        if signature == self.failing {
            return Err((self.error)(signature));
        }
        self.known.origin(signature, event_index, ring).await
    }
}

fn anonymous_scan() -> RingScan {
    RingScan::new(ring(), auditor().pubkey()).with_mode(RingMode::Anonymous)
}

#[tokio::test]
async fn a_scan_goes_past_a_row_that_does_not_decode_and_stops_at_a_failed_read() {
    let (paid, spent) = paid_and_spent();
    let (indexer, known) = anonymous_page(&[&paid, &spent]);
    let mut origin = FailingOrigin {
        known,
        failing: Signature::from([5; 64]),
        error: |_| AuditError::InvalidTransactData("forged".to_owned()),
    };
    let page = anonymous_scan()
        .audit(&auditor(), &indexer, &origin, &assets())
        .await
        .expect("audit");
    assert_eq!(page.transactions.len(), 1);
    let [row] = page.skipped.as_slice() else {
        panic!("one bad row");
    };
    assert_eq!(row.tx_signature, origin.failing);
    assert!(matches!(row.error, AuditError::InvalidTransactData(_)));
    origin.error = |signature| AuditError::Unavailable {
        signature,
        message: "unreachable".to_owned(),
    };
    assert!(matches!(
        anonymous_scan()
            .audit(&auditor(), &indexer, &origin, &assets())
            .await,
        Err(AuditError::Unavailable { .. })
    ));
    origin.error = |_| AuditError::InvalidStackHeight(4);
    assert!(matches!(
        anonymous_scan()
            .audit(&auditor(), &indexer, &origin, &assets())
            .await,
        Err(AuditError::InvalidStackHeight(4))
    ));
}

#[tokio::test]
async fn a_scan_lists_a_row_its_audit_refuses_and_opens_the_next() {
    let (mut paid, spent) = paid_and_spent();
    // The envelope's first byte, past the tagged ephemeral key.
    let refused = paid
        .transaction
        .messages
        .last_mut()
        .expect("auditor message");
    refused.data[33] ^= 1;
    let (indexer, origin) = anonymous_page(&[&paid, &spent]);
    let page = anonymous_scan()
        .audit(&auditor(), &indexer, &origin, &assets())
        .await
        .expect("audit");
    let [row] = page.skipped.as_slice() else {
        panic!("one refused row");
    };
    assert_eq!(row.tx_signature, Signature::from([5; 64]));
    // The refused row opened nothing, the spend of its output stays unseen.
    let [opened] = page.transactions.as_slice() else {
        panic!("the row after the refused one");
    };
    assert!(matches!(
        opened.inputs[0].opening,
        InputOpening::UnseenHash { .. }
    ));
}

#[tokio::test]
async fn a_lost_auditor_message_stays_fatal_in_a_local_scan() {
    let (_, mut built, _) = anonymous_spend();
    let tag = auditor_view_tag(&auditor().pubkey());
    // A free tag keeps the row on the auditor's page, the last message names no auditor.
    built.transaction.messages[0].view_tag = tag;
    built.transaction.messages[1].view_tag = field(0x7c);
    let (indexer, origin) = anonymous_page(&[&built]);
    assert!(matches!(
        anonymous_scan()
            .audit(&auditor(), &indexer, &origin, &assets())
            .await,
        Err(AuditError::MissingAuditorMessage)
    ));
}

#[tokio::test]
async fn the_created_utxo_scan_lists_a_row_it_cannot_open_and_opens_the_next() {
    let (transfer, _, spent) = anonymous_spend();
    let mut unopenable = deposited(&transfer, &spent[1]);
    unopenable.transaction.tx_signature = Signature::from([0xd1; 64]);
    unopenable.transaction.output_slots[0].output_context.hash = field(0x7c);
    unopenable.origin.event = origin_fixture::event(&unopenable.transaction);
    let deposit = deposited(&transfer, &spent[0]);
    let origins: HashMap<Signature, RingOrigin> = [&unopenable, &deposit]
        .into_iter()
        .map(|row| (row.transaction.tx_signature, row.origin.clone()))
        .collect();
    let history = RingHistory(vec![vec![
        unopenable.transaction.clone(),
        deposit.transaction.clone(),
    ]]);
    let auditor = auditor();
    let page = CreatedUtxoScan::new(transfer.ring, &auditor)
        .run(&history, &ConfirmedOrigins(origins))
        .await
        .expect("scan");
    let opened: Vec<[u8; 32]> = page.utxos.iter().map(|utxo| utxo.commitment).collect();
    assert_eq!(
        opened,
        [spent[0].commitment(&transfer, Some(transfer.ring))]
    );
    let [row] = page.skipped.as_slice() else {
        panic!("one row left unopened");
    };
    assert_eq!(row.tx_signature, unopenable.transaction.tx_signature);
}

/// A tampered disclosure stops the merge audit, a spend it would name stays unread and never unspent.
#[tokio::test]
async fn the_merge_audit_refuses_a_disclosure_it_cannot_open() {
    let (transfer, _, spent) = anonymous_spend();
    let mut merge = merged(&transfer, &spent[1]);
    merge.transaction.tx_signature = Signature::from([0xd1; 64]);
    let disclosure = merge.origin.merge_disclosure.as_mut().expect("disclosure");
    disclosure.ciphertext[0] ^= 1;
    let origins: HashMap<Signature, RingOrigin> =
        [(merge.transaction.tx_signature, merge.origin.clone())]
            .into_iter()
            .collect();
    let history = RingHistory(vec![vec![merge.transaction.clone()]]);
    let auditor = auditor();
    assert!(MergeAudit::new(transfer.ring, &auditor)
        .run(&history, &ConfirmedOrigins(origins))
        .await
        .is_err());
}

#[tokio::test]
async fn input_metadata_resolves_after_the_page_opens_a_later_output() {
    let (paid, spent) = paid_and_spent();
    let (indexer, origin) = anonymous_page(&[&spent, &paid]);
    let audited = anonymous_scan()
        .audit(&auditor(), &indexer, &origin, &assets())
        .await
        .unwrap();
    let spending = &audited.transactions[0];
    assert!(spending.sender.is_some());
    assert_eq!(
        spending.inputs[0].opening.opened().unwrap().ring,
        Some(InputRing::Ring {
            commitment: paid.slots[0].output.output_context.hash,
        })
    );
}
