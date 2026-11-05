//! Buffered transfer validation with seeded state.

use std::time::Instant;

use super::{
    one_key::{
        newest_root, nullifier_accounts, own_tree, tracking_tree, with_altered_record, AccountEdit,
        FrameReport, Landed, NoteSeed, RingBody, Seeded, SeededChain, SettledState,
    },
    *,
};
use custom_ring_cli::Zolana;
use custom_ring_interface::{
    key_catalog::{RingCircuit, RING_KEYS},
    storage::StorageRegistry,
    tracking::TrackingRegistry,
    FRAME_BUFFER_HEADER_LEN,
};
use custom_ring_sdk::BufferedFrame;
use custom_ring_test_validator::{policy::RELEASED, ring_wallet::RingWallet};
use solana_account::Account;
use solana_transaction_status_client_types::EncodedConfirmedTransactionWithStatusMeta;
use spr_client::{ConfirmedInstructionGroups, TransactionSize};
use spr_interface::shape::Shape;
use spr_transaction::Mint;
use zolana_ring_client::ring_event_origin_in;
use zolana_ring_member_registry::RecordTree;

pub(super) const KEY: RingCircuit = RingCircuit::Transfer {
    outputs: 16,
    inputs: 5,
    withdrawals: 8,
    owners: 5,
    entry: false,
    wide: false,
};
const FRAME_NONCE: u64 = 1;
const RESPEND_NONCE: u64 = 2;
const DATA_NOTE: u64 = 700_000_000;
const PAID: u64 = 1_100_000_000;
const CHANGE: u64 = RING_DEPOSIT_A + RING_DEPOSIT_B - DATA_NOTE - PAID;
const DATA_HASH: [u8; 32] = field_value(0x31);
const RING_DATA_HASH: [u8; 32] = field_value(0x32);
const APP_DATA: &[u8] = b"buffered validation";
const FINALITY_DEADLINE: Duration = Duration::from_secs(180);

const fn field_value(byte: u8) -> [u8; 32] {
    let mut value = [0; 32];
    value[31] = byte;
    value
}

#[derive(Debug, PartialEq, Eq)]
struct Watched {
    tree: Option<Account>,
    nullifiers: Vec<Option<Account>>,
    buffer: Option<Account>,
}

struct Watch<'a> {
    env: &'a TestEnv,
    buffer: Address,
    nullifiers: &'a [[u8; 32]],
}

impl Watch<'_> {
    fn read(&self) -> Result<Watched> {
        let rpc = self.env.client.rpc();
        Ok(Watched {
            tree: rpc.get_account(self.env.tree)?,
            nullifiers: nullifier_accounts(self.env, self.nullifiers)?,
            buffer: rpc.get_account(self.buffer)?,
        })
    }
}

struct Refusal<'a> {
    label: &'a str,
    watch: &'a Watch<'a>,
    writer: &'a Keypair,
    settle: Instruction,
    code: u32,
}

impl Refusal<'_> {
    fn check(self) -> Result<()> {
        let before = self.watch.read()?;
        let refused = RejectedTransact {
            payer: self.writer,
            signers: &[],
            instruction: self.settle,
        }
        .send(self.watch.env.client.rpc())?;
        Rejection::custom(self.code).at(0).assert_client(&refused);
        ensure!(
            self.watch.read()? == before,
            "{} moved the tree, a nullifier or the buffer",
            self.label
        );
        println!(
            "{}: refused with code {}, state unchanged",
            self.label, self.code
        );
        Ok(())
    }
}

struct Upload<'a> {
    env: &'a TestEnv,
    writer: &'a Keypair,
    label: &'a str,
}

impl Upload<'_> {
    fn send(&self, writes: impl IntoIterator<Item = Instruction>) -> Result<()> {
        for (index, write) in writes.into_iter().enumerate() {
            let signature = land(self.env, write.clone(), self.writer, &[])?;
            Landed {
                env: self.env,
                signature,
            }
            .cost_with_heap(&format!("{} write {index}", self.label))?;
        }
        Ok(())
    }
}

struct FrameDiff<'a> {
    from: &'a BufferedFrame,
    to: &'a BufferedFrame,
}

impl FrameDiff<'_> {
    fn writes(self) -> Result<Vec<Instruction>> {
        let from = self.from.writes()?;
        let to = self.to.writes()?;
        ensure!(from.len() == to.len(), "an altered record keeps the chunks");
        Ok(to
            .into_iter()
            .zip(from)
            .filter(|(to, from)| to.data != from.data)
            .map(|(to, _)| to)
            .collect())
    }
}

pub(super) fn finalized_transaction(
    env: &TestEnv,
    signature: Signature,
) -> Result<EncodedConfirmedTransactionWithStatusMeta> {
    let started = Instant::now();
    loop {
        let read: Option<EncodedConfirmedTransactionWithStatusMeta> =
            env.client.rpc().client().send(
                solana_rpc_client_api::request::RpcRequest::GetTransaction,
                serde_json::json!([signature.to_string(), {
                    "encoding": "json",
                    "commitment": "finalized",
                    "maxSupportedTransactionVersion": 1,
                }]),
            )?;
        if let Some(transaction) = read {
            return Ok(transaction);
        }
        ensure!(
            started.elapsed() < FINALITY_DEADLINE,
            "{signature} did not finalize"
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

struct HiddenTransfer<'a> {
    ring: CustomRing,
    sender: &'a ShieldedKeypair,
    recipient: &'a ShieldedKeypair,
    writer: Address,
    notes: &'a [WalletUtxo],
}

impl HiddenTransfer<'_> {
    fn prove(
        self,
        chain: &Zolana<SolanaRpc, one_key::SeededIndexer>,
    ) -> Result<ProvenRingTransfer> {
        let ring = self.ring.program_id();
        let mut transaction =
            ConfidentialTransaction::new_with_ring(self.notes.to_vec(), self.writer, ring)?;
        transaction.add_output_utxo(
            SppProofOutputUtxo::new(Mint::SOL, DATA_NOTE, self.sender.shielded_address()?)?
                .with_ring_data_hash(ring, RING_DATA_HASH)
                .with_utxo_data(APP_DATA.to_vec(), DATA_HASH),
        )?;
        let pay = |to: &ShieldedKeypair, amount| -> Result<_> {
            Ok(custom_ring_sdk::AnonymousPayment {
                to: ring_address(to, ring)?,
                asset: Mint::SOL,
                amount,
                reply: None,
                data: custom_ring_sdk::NoteData::default(),
            })
        };
        let transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring: self.ring,
            sender: self.sender,
            nullifier_key: Some(&self.sender.nullifier_key),
            transaction,
        })
        .with_anonymous_signer(&self.sender.signing_key)
        .with_payment(pay(self.sender, CHANGE)?)?
        .with_payment(pay(self.recipient, PAID)?)?
        .with_shape(Shape::new(5, 16))?
        .with_buffered_settlement();
        Ok(chain.block_on(transfer.prove(chain.ring_client()))?)
    }
}

#[test]
fn buffered_validation_settles_the_oversized_frame_and_refuses_changes_and_a_respend() -> Result<()>
{
    let env = setup()?;
    let ring = CustomRing::new(custom_ring_program_id()?);
    let ring_program = ring.program_id();
    let auditor = X25519Keypair::new();
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::anonymous_policy(&RELEASED),
    }
    .send(&env.client)?;
    let sender = &env.sender.keypair;
    let recipient = &env.recipient.keypair;
    let rows = [sender.shielded_address()?, recipient.shielded_address()?];
    let policy = policy_registry(ring, &env)?;
    let own_root = own_tree(&rows, &[])?.root()?;
    let tracking_root = tracking_tree(&rows)?.root()?;
    AccountEdit {
        env: &env,
        address: policy.records,
    }
    .apply(|registry: &mut StorageRegistry| registry.roots[0] = newest_root(own_root))?;
    AccountEdit {
        env: &env,
        address: policy.tracking,
    }
    .apply(|registry: &mut TrackingRegistry| registry.roots[0] = newest_root(tracking_root))?;
    let Seeded {
        wallets: notes,
        notes: seeded,
    } = NoteSeed {
        env: &env,
        ring,
        owner: sender,
        amounts: &[RING_DEPOSIT_A, RING_DEPOSIT_B],
    }
    .write()?;
    println!("seeded: own and tracking roots, two unbacked ring notes, throwaway key setup");

    let body = RingBody::default();
    let chain = SeededChain {
        env: &env,
        notes: seeded,
        rows: &rows,
        body: &body,
    }
    .connect()?;
    let writer = env.funded_keypair()?;
    let proven = HiddenTransfer {
        ring,
        sender,
        recipient,
        writer: writer.pubkey(),
        notes: &notes,
    }
    .prove(&chain)?;
    let name = RING_KEYS
        .iter()
        .find(|key| key.circuit == KEY)
        .context("the key is catalogued")?;
    ensure!(
        body.take()?["circuitType"] == name.name,
        "another key proved the frame"
    );

    let inline = proven.instruction()?;
    let TransactionSize { bytes, addresses } = spr_client::transaction_size(
        &writer.pubkey(),
        core::slice::from_ref(&inline),
        ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::Transfer)),
    )?;
    ensure!(
        bytes > MAX_TRANSACTION_SIZE,
        "the inline frame takes {bytes} bytes, the buffer is not required"
    );
    println!("inline transaction: {bytes} bytes of {MAX_TRANSACTION_SIZE}, {addresses} addresses");
    FrameReport {
        frame: &inline.data,
        rail: RingRail::Anonymous,
        policy: &policy,
    }
    .check("buffered data fixture")?;
    let data = frame(&inline, RingRail::Anonymous)?;
    ensure!(data.has_data, "the frame carries no data tail");
    assert_eq!(
        data.nullifiers[..notes.len()],
        [notes[0].nullifier, notes[1].nullifier]
    );

    let buffered = proven.buffered(FRAME_NONCE)?;
    let upload = Upload {
        env: &env,
        writer: &writer,
        label: "upload",
    };
    upload.send(buffered.writes()?)?;
    let written = env
        .client
        .rpc()
        .get_account(buffered.buffer())?
        .context("the written buffer")?;
    ensure!(
        written.data[FRAME_BUFFER_HEADER_LEN..] == inline.data,
        "the buffer differs from the frame"
    );

    let watch = Watch {
        env: &env,
        buffer: buffered.buffer(),
        nullifiers: data.nullifiers,
    };
    let altered = BufferedFrame::new(
        &with_altered_record(&inline, RingRail::Anonymous)?,
        writer.pubkey(),
        FRAME_NONCE,
    )?;
    let changed = FrameDiff {
        from: &buffered,
        to: &altered,
    }
    .writes()?;
    let restored = FrameDiff {
        from: &altered,
        to: &buffered,
    }
    .writes()?;
    upload.send(changed)?;
    Refusal {
        label: "changed bytes under the signed digest",
        watch: &watch,
        writer: &writer,
        settle: buffered.settle(),
        code: CustomRingError::FrameDigestMismatch as u32,
    }
    .check()?;
    Refusal {
        label: "changed bytes under their own digest",
        watch: &watch,
        writer: &writer,
        settle: altered.settle(),
        code: CustomRingError::ProofVerificationFailed as u32,
    }
    .check()?;
    upload.send(restored)?;

    let tree_before = fetch_account(env.client.rpc(), &env.tree)?;
    let settle = buffered.settle();
    let signature = land(&env, settle.clone(), &writer, &[])?;
    Landed {
        env: &env,
        signature,
    }
    .cost_with_heap("settlement")?;
    ensure!(
        !signers(&settle).contains(&sender.pubkey()),
        "the hidden owner signed the settlement"
    );
    SettledState {
        env: &env,
        before: &tree_before,
        commitments: data.outputs.iter().map(|output| *output.hash).collect(),
        nullifiers: data.nullifiers,
    }
    .check()?;
    ensure!(
        env.client.rpc().get_account(buffered.buffer())?.is_none(),
        "the settlement left its buffer"
    );
    println!("settled: {signature}, buffer closed, nullifiers consumed, commitments appended");

    let confirmed = finalized_transaction(&env, signature)?;
    let groups = ConfirmedInstructionGroups::try_from(confirmed)?;
    let origin = ring_event_origin_in(&groups.groups, 0, ring_program)?;
    ensure!(origin.ring_invoked, "the ring called no settled event");
    ensure!(
        origin.transact.as_deref() == Some(inline.data.as_slice()),
        "the finalized history rebuilds another frame"
    );
    println!("reader: the finalized event rebuilt the frame");
    let audited = AuditLookup {
        scan: RingScan::new(ring_program, auditor.pubkey()).with_mode(RingMode::Anonymous),
        auditor: &auditor,
        signature,
    }
    .run(&env)?;
    let mut audited_amounts = ring_amounts(&audited)?;
    audited_amounts.sort_unstable();
    let mut declared: Vec<u64> = proven
        .outputs
        .iter()
        .filter(|output| !output.is_dummy())
        .map(|output| output.amount)
        .collect();
    declared.sort_unstable();
    assert_eq!(audited_amounts, declared);
    assert_eq!(
        declared.iter().sum::<u64>(),
        RING_DEPOSIT_A + RING_DEPOSIT_B
    );
    let hashed = audited.outputs.iter().any(|output| {
        matches!(&output.opening, OutputOpening::Ring { utxo, .. }
            if utxo.data_hash == DATA_HASH && utxo.ring_data_hash == RING_DATA_HASH)
    });
    ensure!(hashed, "the auditor opened no data hashes");
    println!("auditor: reconstructed every output and the data hashes");

    let assets = env.ring_assets()?;
    let mut recipient_wallet = RingWallet::new(recipient, assets.clone(), ring_program);
    recipient_wallet.sync(&env)?;
    let paid = proven
        .outputs
        .iter()
        .find(|output| output.owner_address == Some(rows[1]))
        .context("the recipient's output")?;
    ensure!(
        recipient_wallet
            .unspent()
            .any(|held| held.utxo.amount == PAID && held.utxo.blinding == paid.blinding),
        "the recipient rebuilt no note"
    );
    let mut sender_wallet = RingWallet::new(sender, assets, ring_program);
    sender_wallet.sync(&env)?;
    ensure!(
        sender_wallet
            .unspent()
            .any(|held| held.data_hash == Some(DATA_HASH) && held.utxo.amount == DATA_NOTE),
        "the sender rebuilt no data note"
    );
    println!("recipient and sender: reconstructed their notes after the buffer closed");

    let respend = proven.buffered(RESPEND_NONCE)?;
    upload.send(respend.writes()?)?;
    Refusal {
        label: "a second settlement of the same inputs",
        watch: &Watch {
            env: &env,
            buffer: respend.buffer(),
            nullifiers: data.nullifiers,
        },
        writer: &writer,
        settle: respend.settle(),
        code: ShieldedPoolError::NullifierAlreadyQueued as u32,
    }
    .check()
}
