//! Audits of synthetic ring transfers built as the ring program publishes them.

#[path = "common/deposit.rs"]
mod deposit_fixture;
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
    AuditEvidence, AuditStreamLayout, DeliveredBody, ExitRecord, InputPrefix,
    RingDepositAuditCapsule, RingMode,
};
use solana_address::Address;
use solana_signature::Signature;
use spr_client::{
    AsyncRpc, Context, GetShieldedTransactionsByTagsResponse, IndexerRpcConfig, ShieldedTransaction,
};
use spr_event::{
    encode_encrypted_ring_deposit_output, encode_merge_output_data, EncryptedRingDepositData,
    EncryptedRingDepositOutput, MergeOutputDataRef, MessageData,
};
use spr_keypair::{ViewingKey, X25519Keypair, X25519Pubkey};
use spr_transaction::{owner_utxo_hash, Mint, OutputContext, OutputSlot};
use zolana_ring_client::{
    auditor_view_tag, commitment_evidence, prefix_evidence, ring_event_origin_in, seal_deposits,
    AuditError, AuditStreamSeal, AuditedInputOpening, AuditedSender, AuditedTransaction,
    ConfirmedMergeDisclosure, CreatedUtxo, CreatedUtxoScan, CreatedUtxos, DepositOpening,
    EscrowPendingSlot, InputOpening, InputRing, KnownUtxo, KnownUtxoIndex, KnownUtxos,
    MergeDisclosureEncryption, MergeOpening, OutputOpening, OutputPayloadError,
    OutputPayloadErrorKind, OutputRecord, RingOrigin, RingOwnerTag, RingScan, TransactionAudit,
    TransactionOrigin, UtxoOwner,
};
use zolana_ring_transaction::{seal_delivered_body, RingAssets};

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
    /// A default-ring note among them, the entry key opens every note.
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
        Spending::RingUtxos => commitment_evidence(
            &spent
                .iter()
                .map(|spend| Some(spend.commitment(transfer, Some(transfer.ring))))
                .collect::<Vec<_>>(),
        )
        .unwrap(),
        Spending::Entry => AuditEvidence::Entry {
            sender_key: sender.owner_key,
            sender_nullifier_pk: sender.nullifier_pk,
            inputs: spent
                .iter()
                .map(|spend| input_opening(&spend.utxo, spend.blinding))
                .collect(),
        },
    };
    let disclosure = transfer.anonymous_disclosure(&outputs, inputs);
    publish(transfer, slots, outputs, &disclosure)
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
            layout,
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

struct PrefixedSpend {
    transfer: Transfer,
    spent: [Spend; 2],
    built: Built,
    commitments: [[u8; 32]; 2],
}

/// A transfer of two ring notes, the second named by its prefix.
fn prefixed_spend() -> PrefixedSpend {
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
    PrefixedSpend {
        transfer,
        spent,
        built,
        commitments,
    }
}

#[test]
fn a_ring_utxo_input_opens_by_its_prefix_or_is_reported_unseen() {
    let PrefixedSpend {
        transfer,
        spent,
        built,
        commitments,
    } = prefixed_spend();
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
    let PrefixedSpend {
        transfer,
        spent,
        built,
        commitments,
    } = prefixed_spend();
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
    let hash = InputOpening::UnseenHash {
        hash: commitments[0],
    };
    let prefix = InputOpening::Unseen {
        prefix: InputPrefix::of(&commitments[1]).unwrap(),
    };
    let sender = Some(AuditedSender {
        owner_key: spent[0].utxo.owner_key,
        nullifier_pk: Some(spent[0].utxo.nullifier_pk),
    });
    for (notes, expected_sender, first, later) in [
        (&[][..], None, hash.clone(), prefix.clone()),
        (&[0][..], sender, opening(0), prefix),
        (&[1][..], None, hash, opening(1)),
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

struct Misfiled {
    index: KnownUtxoIndex,
    prefix: InputPrefix,
    answer: Vec<[u8; 32]>,
}

impl KnownUtxos for Misfiled {
    fn utxo(&self, commitment: &[u8; 32]) -> Option<KnownUtxo> {
        self.index.utxo(commitment)
    }

    fn with_prefix(&self, owner_key: &[u8; 32], prefix: InputPrefix) -> Vec<[u8; 32]> {
        match prefix == self.prefix {
            true => self.answer.clone(),
            false => self.index.with_prefix(owner_key, prefix),
        }
    }

    fn with_prefix_of_anyone(&self, prefix: InputPrefix) -> Vec<[u8; 32]> {
        self.index.with_prefix_of_anyone(prefix)
    }
}

#[test]
fn a_prefix_opens_only_a_note_of_the_sender_that_carries_it() {
    let PrefixedSpend {
        transfer,
        spent,
        built,
        commitments,
    } = prefixed_spend();
    let prefix = InputPrefix::of(&commitments[1]).unwrap();
    let first = (commitments[0], spent[0].known(&transfer));
    let twin = Spend {
        utxo: spent[1].utxo,
        blinding: field(0x62),
    };
    let twin_commitment = twin.commitment(&transfer, Some(transfer.ring));
    // A deposited record hashes to the commitment under any owner key.
    let misowned = KnownUtxo {
        owner_key: [0x77; 32],
        owner: UtxoOwner::Deposited {
            owner_hash: spent[1].utxo.owner_hash(),
        },
        ..spent[1].known(&transfer)
    };
    let spent_note = (commitments[1], spent[1].known(&transfer));
    let audit = |index: Vec<([u8; 32], KnownUtxo)>, answer: Vec<[u8; 32]>| {
        let store = Misfiled {
            index: index.into_iter().collect(),
            prefix,
            answer,
        };
        TransactionAudit::new(&built.transaction, built.layout)
            .with_known_utxos(&store)
            .run(&auditor(), &assets())
    };
    for (index, answer) in [
        (
            vec![first, spent_note, (twin_commitment, twin.known(&transfer))],
            twin_commitment,
        ),
        (vec![first, (commitments[1], misowned)], commitments[1]),
    ] {
        assert_eq!(
            audit(index, vec![answer]).unwrap().inputs[1].opening,
            InputOpening::Unseen { prefix }
        );
    }
    let audited = audit(vec![first, spent_note], vec![commitments[1]; 2]).unwrap();
    assert!(matches!(
        audited.inputs[1].opening,
        InputOpening::Opened(AuditedInputOpening {
            ring: Some(InputRing::Ring { commitment }),
            ..
        }) if commitment == commitments[1]
    ));
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

/// The confirmed anonymous merge into `spend`, its disclosure sealed to the auditor.
fn merged(transfer: &Transfer, spend: &Spend) -> Confirmed {
    let salt = [0x4d; 16];
    let opening = MergeOpening {
        owner_key: spend.utxo.owner_key,
        nullifier_pk: spend.utxo.nullifier_pk,
        mint: spend.utxo.asset_address.to_bytes(),
        amount: spend.utxo.amount,
        output_blinding: spend.blinding,
        input_commitments: vec![field(0x71); 8],
    };
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
fn a_deposited_or_merged_ring_utxo_opens_as_a_commitment_input() {
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
    assert_eq!(
        audit(&built.transaction, built.layout).unwrap().inputs[0].opening,
        InputOpening::UnseenHash {
            hash: spent[0].commitment(&transfer, Some(transfer.ring))
        }
    );
    let deposit = deposited(&transfer, &spent[0]);
    let merge = merged(&transfer, &spent[1]);
    let created: Vec<CreatedUtxo> = [&deposit, &merge]
        .into_iter()
        .flat_map(|confirmed| confirmed.open(&transfer).unwrap())
        .collect();
    let utxos: Vec<KnownUtxo> = created.iter().map(|created| created.utxo).collect();
    assert_eq!(
        utxos,
        [
            KnownUtxo {
                owner: UtxoOwner::Deposited {
                    owner_hash: spent[0].utxo.owner_hash(),
                },
                ..spent[0].known(&transfer)
            },
            spent[1].known(&transfer),
        ]
    );
    for (created, spend) in created.iter().zip(&spent) {
        assert_eq!(
            created.utxo.commitment(Some(transfer.ring)).unwrap(),
            spend.commitment(&transfer, Some(transfer.ring))
        );
    }
    let known: KnownUtxoIndex = created
        .iter()
        .map(|created| (created.commitment, created.utxo))
        .collect();
    let audited = TransactionAudit::new(&built.transaction, built.layout)
        .with_known_utxos(&known)
        .run(&auditor(), &assets())
        .unwrap();
    let openings: Vec<Option<AuditedInputOpening>> = audited
        .inputs
        .iter()
        .map(|input| input.opening.opened().copied())
        .collect();
    let expected: Vec<Option<AuditedInputOpening>> = spent
        .iter()
        .map(|spend| {
            Some(AuditedInputOpening {
                asset: spend.utxo.asset(),
                mint: Some(spend.utxo.asset_address),
                amount: spend.utxo.amount,
                blinding: spend.blinding,
                ring: Some(InputRing::Ring {
                    commitment: spend.commitment(&transfer, Some(transfer.ring)),
                }),
            })
        })
        .collect();
    assert_eq!(openings, expected);
    assert_eq!(audited.sender.unwrap().nullifier_pk, None);

    let mut forged = deposit;
    forged.transaction.output_slots[0].output_context.hash = field(0x79);
    assert!(matches!(
        forged.open(&transfer),
        Err(AuditError::DepositOpeningMismatch)
    ));
    let mut forged = merge;
    forged.transaction.output_slots[0].output_context.hash = field(0x7a);
    assert!(matches!(
        forged.open(&transfer),
        Err(AuditError::MergeDisclosureMismatch)
    ));
}

/// The in-proof and authority rails name each input by its prefix, a note no earlier audit opened
/// leaves the outputs readable.
#[test]
fn an_in_proof_input_opens_by_its_prefix_or_stays_unseen_beside_readable_outputs() {
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
        prefix_evidence(&[Some(hash), Some(unseen)]).unwrap(),
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
        InputOpening::Unseen {
            prefix: InputPrefix::of(&unseen).unwrap()
        }
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
            inputs: spent
                .iter()
                .map(|spend| input_opening(&spend.utxo, spend.blinding))
                .collect(),
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

/// Ring history pages in order, a cursor names the next page and the last one states its frontier.
struct RingHistory(Vec<Vec<ShieldedTransaction>>);

#[async_trait::async_trait]
impl AsyncRpc for RingHistory {
    async fn get_shielded_transactions_by_ring(
        &self,
        options: spr_client::RingHistoryOptions,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, spr_client::ClientError> {
        let index = options.cursor.map_or(0, |cursor| usize::from(cursor[0]));
        let last = index + 1 == self.0.len();
        Ok(GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 0,
                slot: 1,
            },
            transactions: self.0[index].clone(),
            next_cursor: (!last).then(|| vec![index as u8 + 1]),
            scanned_through: last.then(|| vec![index as u8]),
            output_tree_id: None,
        })
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
async fn the_created_utxo_scan_opens_every_deposit_and_merge_of_the_ring_history() {
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
        spent.map(|spend| spend.commitment(&transfer, Some(transfer.ring)))
    );
    assert_eq!(page.next_cursor, None);

    let capped = CreatedUtxoScan::new(transfer.ring, &auditor)
        .with_max_pages(NonZeroUsize::new(1).unwrap())
        .run(&history, &ConfirmedOrigins(origins.clone()))
        .await
        .unwrap();
    assert_eq!(capped.utxos.len(), 1);
    assert_eq!(capped.next_cursor, Some(vec![1]));

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

fn candidates(transfer: &Transfer, spend: &Spend) -> InputRing {
    InputRing::Unresolved {
        ring: spend.commitment(transfer, Some(transfer.ring)),
        default: spend.commitment(transfer, None),
    }
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
    let unresolved: Vec<_> = spent
        .iter()
        .map(|spend| candidates(&transfer, spend))
        .collect();
    let audited = TransactionAudit::new(&built.transaction, built.layout)
        .with_input_trees(&trees)
        .unwrap()
        .run(&auditor(), &assets())
        .unwrap();
    assert_eq!(
        rings(audited),
        unresolved.iter().copied().map(Some).collect::<Vec<_>>()
    );
    let [InputRing::Unresolved { ring, .. }, InputRing::Unresolved { default, .. }] =
        [unresolved[0], unresolved[1]]
    else {
        panic!("unresolved candidates");
    };
    let earlier = |commitment| (commitment, spent[0].known(&transfer));
    let known = KnownUtxoIndex::from_iter([earlier(ring), earlier(default)]);
    let audited = TransactionAudit::new(&built.transaction, built.layout)
        .with_input_trees(&trees)
        .unwrap()
        .with_known_utxos(&known)
        .run(&auditor(), &assets())
        .unwrap();
    assert_eq!(
        rings(audited),
        [
            Some(InputRing::Ring { commitment: ring }),
            Some(InputRing::Default {
                commitment: default
            }),
        ]
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
        evidence: AuditEvidence::None,
        records: transfer_records(&built),
    }
    .seal(&auditor().pubkey())
    .unwrap();
    forged.messages[0].data[1..65].copy_from_slice(&[&sealed.eph_u[..], &sealed.envelope].concat());
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

/// Cursor paging plus the message-tag filter. Photon's tag filter is an OR over
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
        cursor: Option<Vec<u8>>,
        limit: Option<u32>,
        _config: Option<IndexerRpcConfig>,
    ) -> Result<GetShieldedTransactionsByTagsResponse, spr_client::ClientError> {
        assert_eq!(tags, vec![self.expected_tag]);
        self.requested.lock().unwrap().push(limit);
        let page_index = usize::from(*cursor.unwrap_or_default().first().unwrap_or(&0));
        let transactions = self.pages.get(page_index).cloned().unwrap_or_default();
        let next_cursor = (page_index + 1 < self.pages.len())
            .then(|| vec![u8::try_from(page_index + 1).expect("page index")]);
        let scanned_through = next_cursor
            .is_none()
            .then(|| vec![u8::try_from(page_index).expect("page index")]);
        Ok(GetShieldedTransactionsByTagsResponse {
            context: Context {
                block_time: 0,
                slot: 1,
            },
            transactions,
            next_cursor,
            scanned_through,
            output_tree_id: None,
        })
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
    let second = with_signature(second_built.transaction.clone(), 2);
    // An output tag match must still be attributed before it can be excluded.
    let mut output_tag_match = with_signature(delivered_transfer(3).transaction, 3);
    output_tag_match.messages.clear();
    output_tag_match.output_slots[0].view_tag = auditor_view_tag(&auditor_pk);
    let foreign_ring = with_signature(first.clone(), 4);
    let indexer = PagedIndexer {
        expected_tag: auditor_view_tag(&auditor_pk),
        pages: vec![
            vec![
                first.clone(),
                output_tag_match,
                foreign_ring.clone(),
                foreign_ring.clone(),
            ],
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
    let cursor = stopped.next_cursor.clone().expect("unread history");
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

#[tokio::test]
async fn an_empty_page_does_not_end_the_scan() {
    let auditor_pk = auditor().pubkey();
    let last = paged_history(1);
    let pages = vec![Vec::new(), last[0].clone()];
    let origin = ring_origins(ring(), &pages);
    let indexer = indexer(&auditor_pk, pages.clone());
    let page = RingScan::new(ring(), auditor_pk)
        .with_max_pages(NonZeroUsize::new(2).expect("page limit"))
        .run(&indexer, &origin)
        .await
        .expect("scan");
    assert_eq!(page.next_cursor, None);
    assert_eq!(signatures(&page.transactions), signatures(&pages[1]));
}

#[tokio::test]
async fn a_cursor_at_the_end_of_history_returns_an_empty_page() {
    let auditor_pk = auditor().pubkey();
    let pages = paged_history(2);
    let origin = ring_origins(ring(), &pages);
    let indexer = indexer(&auditor_pk, pages);
    let page = RingScan::new(ring(), auditor_pk)
        .with_cursor(vec![2])
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
    let mut merge = merged(&transfer, &spent[1]);
    merge.transaction.tx_signature = Signature::from([0xd1; 64]);
    let disclosure = merge.origin.merge_disclosure.as_mut().expect("disclosure");
    disclosure.ciphertext[0] ^= 1;
    let deposit = deposited(&transfer, &spent[0]);
    let origins: HashMap<Signature, RingOrigin> = [&merge, &deposit]
        .into_iter()
        .map(|row| (row.transaction.tx_signature, row.origin.clone()))
        .collect();
    let history = RingHistory(vec![vec![
        merge.transaction.clone(),
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
    assert_eq!(row.tx_signature, merge.transaction.tx_signature);
}
