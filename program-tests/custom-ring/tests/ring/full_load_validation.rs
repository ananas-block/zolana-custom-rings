//! Full load validation with seeded state, through the production submission and relay.

use std::{convert::Infallible, net::Ipv4Addr, sync::Arc};

use super::{
    buffered_validation::finalized_transaction,
    one_key::{
        context, newest_root, own_tree, tracking_tree, AccountEdit, FrameReport, Landed, NoteSeed,
        Seeded, SeededIndexer, SettledState,
    },
    *,
};
use custom_ring_interface::{
    cosign::ApprovalMask, storage::StorageRegistry, tag, tracking::TrackingRegistry,
    PolicyWithdrawal, FRAME_BUFFER_HEADER_LEN,
};
use custom_ring_sdk::{
    ApprovalLimit, CoSignerApproval, CoSignerRule, CustomRingConfig, ExactApproval,
    MessageMismatch, RelaySent, RingRelay, RingSubmission, SetCoSigner, SettledSubmission,
};
use custom_ring_test_validator::{
    policy::{CuratedRings, RELEASED},
    ring_rpc::{RelayedRingRpc, RELAY_BUDGET_LAMPORTS, RELAY_SIGNER_BUDGET_LAMPORTS},
    ring_wallet::RingWallet,
    shared::restart_prover,
};
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
    Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use solana_account::Account;
use spr_client::ConfirmedInstructionGroups;
use spr_indexer_api::{
    GetMerkleProofsRequest, GetMerkleProofsResponse, Hash, MerkleContext, MerkleProof, RpcMethod,
    SerializablePubkey, GET_MERKLE_PROOFS,
};
use spr_interface::{shape::Shape, SOL_INTERFACE};
use spr_program::instruction::TransactSolTransferAccounts;
use spr_transaction::Mint;
use zolana_ring_client::{
    ring_event_origin_in,
    rpc::{GetRelayStatusRequest, RelayOperation, RelayStatus},
    RingIndexer,
};
use zolana_ring_indexer::{
    rpc::{method::GetStorageRecordPool, GetStorageRecordPoolRequest},
    tracking::{method::GetTrackingRecordPool, GetTrackingRecordPoolRequest},
};
use zolana_ring_member_registry::RecordTree;

const STORAGE_POOL: &str = GetStorageRecordPool::NAME;
const TRACKING_POOL: &str = GetTrackingRecordPool::NAME;
const NOTE: u64 = 1_000_000_000;
const SPENT_NOTES: usize = 5;
const SPENT_TOTAL: u64 = SPENT_NOTES as u64 * NOTE;
const PAYMENTS: usize = 15;
const LEGS: usize = 4;
const PAID: u64 = 300_000_000;
const LEG: u64 = 10_000_000;
const EXIT: u64 = SPENT_TOTAL - PAYMENTS as u64 * PAID - LEGS as u64 * LEG;
const PRIORITY_FEE: u64 = 1_000;
const DESTINATION_FUNDING: u64 = 1_000_000;
const RING_DATA_HASH: [u8; 32] = field_value(0x42);

const fn field_value(byte: u8) -> [u8; 32] {
    let mut value = [0; 32];
    value[31] = byte;
    value
}

struct SeededService {
    seeded: SeededIndexer,
    upstream: String,
    http: reqwest::Client,
}

impl SeededService {
    /// `None` forwards the call.
    fn answer(&self, call: &Value) -> Result<Option<Value>> {
        let params = call["params"].clone();
        Ok(match call["method"].as_str() {
            Some(GET_MERKLE_PROOFS) => {
                let request: GetMerkleProofsRequest = serde_json::from_value(params)?;
                self.merkle_proofs(request)?
                    .map(serde_json::to_value)
                    .transpose()?
            }
            Some(STORAGE_POOL) => {
                let request: GetStorageRecordPoolRequest = serde_json::from_value(params)?;
                Some(serde_json::to_value(
                    self.seeded.get_storage_record_pool(request)?,
                )?)
            }
            Some(TRACKING_POOL) => {
                let request: GetTrackingRecordPoolRequest = serde_json::from_value(params)?;
                Some(serde_json::to_value(
                    self.seeded.get_tracking_record_pool(request)?,
                )?)
            }
            _ => None,
        })
    }

    fn merkle_proofs(
        &self,
        request: GetMerkleProofsRequest,
    ) -> Result<Option<GetMerkleProofsResponse>> {
        let tree = request.tree_account.0;
        let held = request
            .leaves
            .iter()
            .map(|leaf| self.seeded.notes.proof(tree, leaf.0))
            .collect::<Result<Option<Vec<_>>, _>>()?;
        Ok(held.map(|proofs| GetMerkleProofsResponse {
            context: context(&self.seeded.notes),
            proofs: proofs
                .into_iter()
                .map(|proof| MerkleProof {
                    leaf: Hash(proof.leaf),
                    merkle_context: MerkleContext {
                        tree_type: proof.merkle_context.tree_type,
                        tree: SerializablePubkey(proof.merkle_context.tree),
                    },
                    path: proof.path.into_iter().map(Hash).collect(),
                    leaf_index: proof.leaf_index,
                    root: Hash(proof.root),
                    root_seq: proof.root_seq,
                    root_index: proof.root_index,
                })
                .collect(),
        }))
    }

    async fn respond(self: Arc<Self>, request: Request<Incoming>) -> Result<Response<Full<Bytes>>> {
        let (method, path) = (request.method().clone(), request.uri().path().to_owned());
        let body = request.into_body().collect().await?.to_bytes();
        let call: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let served = {
            let service = self.clone();
            let call = call.clone();
            tokio::task::spawn_blocking(move || service.answer(&call)).await??
        };
        if let Some(result) = served {
            let reply = json!({ "jsonrpc": "2.0", "id": call["id"], "result": result });
            return json_response(StatusCode::OK, Bytes::from(serde_json::to_vec(&reply)?));
        }
        let forwarded = self
            .http
            .request(method, format!("{}{path}", self.upstream))
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await?;
        let status = forwarded.status();
        json_response(status, forwarded.bytes().await?)
    }
}

fn json_response(status: StatusCode, body: Bytes) -> Result<Response<Full<Bytes>>> {
    Ok(Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(body))?)
}

struct SeededHttp {
    url: String,
    _runtime: tokio::runtime::Runtime,
}

impl SeededHttp {
    fn serve(service: SeededService) -> Result<Self> {
        let runtime = tokio::runtime::Runtime::new()?;
        let listener = runtime.block_on(tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))?;
        let url = format!("http://{}", listener.local_addr()?);
        let service = Arc::new(service);
        runtime.spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let service = service.clone();
                tokio::spawn(async move {
                    let answer = service_fn(move |request| {
                        let service = service.clone();
                        async move {
                            let response = match service.respond(request).await {
                                Ok(response) => response,
                                Err(error) => {
                                    let mut failed =
                                        Response::new(Full::new(Bytes::from(error.to_string())));
                                    *failed.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                                    failed
                                }
                            };
                            Ok::<_, Infallible>(response)
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), answer)
                        .await;
                });
            }
        });
        Ok(Self {
            url,
            _runtime: runtime,
        })
    }
}

struct FullLoad<'a> {
    ring: CustomRing,
    sender: &'a ShieldedKeypair,
    recipients: &'a [ShieldedKeypair],
    payer: Address,
    notes: &'a [WalletUtxo],
    destination: Address,
}

impl<'a> FullLoad<'a> {
    fn transfer(self) -> Result<AnonymousTransfer<'a>> {
        let ring = self.ring.program_id();
        let mut transaction =
            ConfidentialTransaction::new_with_ring(self.notes.to_vec(), self.payer, ring)?;
        transaction.transfer_with_ring(
            &self.recipients[0].shielded_address()?,
            Mint::SOL,
            EXIT,
            None,
        )?;
        let mut settlements = Vec::with_capacity(LEGS);
        for _ in 0..LEGS {
            transaction.withdraw_sol(LEG, self.destination)?;
            settlements.push(TransactInterfaceTransferAccounts::Sol(
                TransactSolTransferAccounts {
                    recipient: self.destination,
                },
            ));
        }
        let mut transfer = CustomRingTransfer::new(CustomRingTransferInput {
            ring: self.ring,
            sender: self.sender,
            nullifier_key: Some(&self.sender.nullifier_key),
            transaction,
        })
        .with_interface_transfer_accounts(settlements)
        .with_anonymous_signer(&self.sender.signing_key);
        for recipient in self.recipients {
            transfer = transfer.with_payment(custom_ring_sdk::AnonymousPayment {
                to: ring_address(recipient, ring)?,
                asset: Mint::SOL,
                amount: PAID,
                reply: None,
                data: custom_ring_sdk::NoteData {
                    ring_data_hash: Some(RING_DATA_HASH),
                    application: None,
                },
            })?;
        }
        Ok(transfer
            .with_shape(Shape::new(SPENT_NOTES, 16))?
            .with_buffered_settlement())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ApprovalRead {
    ProvenMask,
    Opening,
}

struct Settlement<'a> {
    env: &'a TestEnv,
    label: &'a str,
    approval: ApprovalRead,
    ring: CustomRing,
    policy: &'a RingPolicy,
    auditor: &'a X25519Keypair,
    writer: Address,
    signature: Signature,
    before: &'a Account,
}

impl Settlement<'_> {
    /// The frame's length, tag included.
    fn check(self) -> Result<usize> {
        let env = self.env;
        let groups =
            ConfirmedInstructionGroups::try_from(finalized_transaction(env, self.signature)?)?;
        let origin = ring_event_origin_in(&groups.groups, 0, self.ring.program_id())?;
        let frame = origin.transact.context("the finalized event's frame")?;
        ensure!(
            frame.len() > MAX_TRANSACTION_SIZE,
            "{} needs no buffer at {} bytes",
            self.label,
            frame.len()
        );
        FrameReport {
            frame: &frame,
            rail: RingRail::Anonymous,
            policy: self.policy,
        }
        .check(self.label)?;
        let (_, body) = frame.split_first().context("a tagged frame")?;
        let data = RingTransactData::parse(body, RingRail::Anonymous)?.into_data();
        ensure!(data.has_data, "{} carries no data tail", self.label);
        let digest = data.extensions.approval_totals.copied();
        ensure!(
            match self.approval {
                ApprovalRead::ProvenMask => digest.is_none(),
                ApprovalRead::Opening => digest.is_some_and(|digest| digest != [0; 32]),
            },
            "{} carries approval digest {digest:?}",
            self.label
        );
        let mut history = env
            .client
            .rpc()
            .client()
            .get_signatures_for_address(&self.writer)?;
        history.reverse();
        let mut uploads = 0;
        for row in history.iter().filter(|row| row.err.is_none()) {
            let signature: Signature = row.signature.parse()?;
            let landed = Landed { env, signature };
            match landed.tag()? {
                Some(tag::WRITE_FRAME) => {
                    uploads += 1;
                    landed.cost_with_heap(&format!("{} write {uploads}", self.label))?;
                }
                Some(tag::SETTLE_BUFFERED) if signature == self.signature => {
                    landed.cost_with_heap(&format!("{} settlement", self.label))?;
                }
                _ => {}
            }
        }
        ensure!(uploads > 1, "{} wrote {uploads} chunks", self.label);
        let buffer = groups.groups[0].outer.accounts[0];
        ensure!(
            env.client.rpc().get_account(buffer)?.is_none(),
            "{} left its buffer",
            self.label
        );
        SettledState {
            env,
            before: self.before,
            commitments: data.outputs.iter().map(|output| *output.hash).collect(),
            nullifiers: data.nullifiers,
        }
        .check()?;
        let audited = AuditLookup {
            scan: RingScan::new(self.ring.program_id(), self.auditor.pubkey())
                .with_mode(RingMode::Anonymous),
            auditor: self.auditor,
            signature: self.signature,
        }
        .run(env)?;
        let opened = opened(&audited);
        ensure!(
            opened.iter().map(|output| output.amount).sum::<u64>()
                == SPENT_TOTAL - LEGS as u64 * LEG,
            "{} audits another value",
            self.label
        );
        ensure!(
            audited.outputs.iter().any(|output| matches!(
                &output.opening,
                OutputOpening::Ring { utxo, .. } if utxo.ring_data_hash == RING_DATA_HASH
            )),
            "{} opened no data hashes",
            self.label
        );
        println!(
            "{}: settled and audited after its buffer closed",
            self.label
        );
        Ok(frame.len())
    }
}

struct RelayLeg<'a> {
    env: &'a TestEnv,
    label: &'a str,
    approval: ApprovalRead,
    ring: CustomRing,
    policy: &'a RingPolicy,
    config: &'a CustomRingConfig,
    auditor: &'a X25519Keypair,
    ring_rpc: &'a RelayedRingRpc,
    co_signer: &'a Keypair,
    sender: &'a ShieldedKeypair,
    recipients: &'a [ShieldedKeypair],
    notes: &'a [WalletUtxo],
    destination: Address,
}

impl RelayLeg<'_> {
    fn run(self) -> Result<()> {
        let (env, ring_rpc) = (self.env, self.ring_rpc);
        let before = fetch_account(env.client.rpc(), &env.tree)?;
        let transfer = FullLoad {
            ring: self.ring,
            sender: self.sender,
            recipients: self.recipients,
            payer: ring_rpc.fee_payer,
            notes: self.notes,
            destination: self.destination,
        }
        .transfer()?
        .with_co_signer(self.co_signer.pubkey());
        let transfer = match self.approval {
            ApprovalRead::ProvenMask => transfer,
            ApprovalRead::Opening => transfer.with_exact_approval(),
        };
        let quote = ring_rpc.quote(env, RelayOperation::Anonymous)?;
        let prepared = env.run(transfer.prepare_relay(env.client.as_async(), quote))?;
        let RelaySent::SignMessage(pending) = env.run(prepared.send(&ring_rpc.relay))? else {
            bail!("{} asked no co-signature", self.label);
        };
        let relay_id = pending.relay_id().clone();
        let holding = |rule| {
            CoSignerApproval {
                relay_id: relay_id.clone(),
                message: pending.message().to_vec(),
                ring: self.ring.program_id(),
                fee_payer: ring_rpc.fee_payer,
                signer: self.co_signer.pubkey(),
                config: self.config,
                setup: Vec::new(),
                rule,
            }
            .pending()
        };
        let rule = match self.approval {
            ApprovalRead::ProvenMask => CoSignerRule::Threshold {
                accepts: ApprovalMask::new(
                    ApprovalMask::OUTFLOW.bits() | ApprovalMask::WITHDRAWAL.bits(),
                )
                .context("the proven approval bits")?,
            },
            ApprovalRead::Opening => {
                let exact = |opening| {
                    CoSignerRule::Exact(ExactApproval {
                        opening,
                        limits: vec![ApprovalLimit {
                            mint: SOL_MINT,
                            peak: u128::from(SPENT_TOTAL),
                            outflow: u128::from(SPENT_TOTAL),
                        }],
                        seen_blinders: Vec::new(),
                    })
                };
                let opening = pending
                    .approval_opening()
                    .context("the wallet's approval opening")?
                    .clone();
                let mut false_opening = opening.clone();
                let first = false_opening
                    .outputs
                    .first_mut()
                    .context("an output total")?;
                first.outflow = "1".to_owned();
                let refused = env.run(holding(exact(false_opening)).sign_on_chain(
                    &ring_rpc.relay,
                    env.client.as_async(),
                    self.co_signer,
                ));
                ensure!(
                    matches!(
                        refused,
                        Err(RingError::RelayMessage(
                            MessageMismatch::FalseApprovalOpening
                        ))
                    ),
                    "a false opening reached {:?}",
                    refused.map(|_| ())
                );
                let status = env.run(ring_rpc.relay.get_relay_status(GetRelayStatusRequest {
                    relay_id: relay_id.clone(),
                }))?;
                ensure!(
                    matches!(status, RelayStatus::AwaitingSignature),
                    "a false opening moved the relay to {status:?}"
                );
                ensure!(
                    fetch_account(env.client.rpc(), &env.tree)? == before,
                    "a false opening moved the tree"
                );
                println!(
                    "{}: false opening refused by the co-signer, state unchanged",
                    self.label
                );
                exact(opening)
            }
        };
        env.run(holding(rule).sign_on_chain(
            &ring_rpc.relay,
            env.client.as_async(),
            self.co_signer,
        ))?;
        let signature = ring_rpc.confirmed(env, &relay_id)?;
        let frame_len = Settlement {
            env,
            label: self.label,
            approval: self.approval,
            ring: self.ring,
            policy: self.policy,
            auditor: self.auditor,
            writer: ring_rpc.fee_payer,
            signature,
            before: &before,
        }
        .check()?;
        let rent = env
            .client
            .rpc()
            .client()
            .get_minimum_balance_for_rent_exemption(FRAME_BUFFER_HEADER_LEN + frame_len)?;
        let budget = wait_for("the relay to release its reservation", || {
            let budget = ring_rpc.budget_use()?;
            Ok(match budget.reservations {
                0 => Probe::Ready(budget),
                _ => Probe::NotYet,
            })
        })?;
        ensure!(
            budget.signer_scopes == 0,
            "{budget:?} keeps a signer's share"
        );
        ensure!(
            (1..rent).contains(&u64::try_from(budget.spent_lamports)?),
            "{budget:?} against {rent} lamports of buffer rent"
        );
        println!(
            "{}: reservation released, {} lamports spent of {RELAY_BUDGET_LAMPORTS}, {rent} of rent returned, signer share {RELAY_SIGNER_BUDGET_LAMPORTS}",
            self.label, budget.spent_lamports
        );
        Ok(())
    }
}

#[test]
fn full_load_validation_settles_through_the_submission_and_the_relay() -> Result<()> {
    let CuratedRings {
        mut env,
        curator,
        subscriber: ring,
    } = CuratedRings::setup()?;
    let auditor = X25519Keypair::new();
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::AnonymousPolicy {
            rules: &RELEASED,
            shared_sources: vec![(ListId::Block, curator)],
        },
    }
    .send(&env.client)?;
    let sender = env.sender.keypair.clone();
    let recipients = (0..PAYMENTS)
        .map(|_| Ok(ShieldedKeypair::new_ed25519()?))
        .collect::<Result<Vec<_>>>()?;
    let destination = Keypair::new().pubkey();
    env.fund(destination, DESTINATION_FUNDING)?;
    env.fund(
        Address::new_from_array(SOL_INTERFACE),
        3 * LEGS as u64 * LEG,
    )?;
    let rows = std::iter::once(&sender)
        .chain(&recipients)
        .map(|keys| Ok(keys.shielded_address()?))
        .collect::<Result<Vec<_>>>()?;
    let withdrawal_owner = PolicyWithdrawal::new(destination.as_array(), None, LEG)?.owner;
    let policy = policy_registry(ring, &env)?;
    let curator_records = policy_registry(curator, &env)?.records;
    let curator_tree = own_tree(&[], &[])?;
    for (address, root) in [
        (
            policy.records,
            own_tree(&rows, &[withdrawal_owner])?.root()?,
        ),
        (curator_records, curator_tree.root()?),
    ] {
        AccountEdit { env: &env, address }
            .apply(|registry: &mut StorageRegistry| registry.roots[0] = newest_root(root))?;
    }
    let tracking_root = tracking_tree(&rows)?.root()?;
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
        owner: &sender,
        amounts: &[NOTE; 3 * SPENT_NOTES],
    }
    .write()?;
    println!("seeded: own, curator and tracking roots, fifteen unbacked ring notes, a funded SOL interface, throwaway key setup");

    let indexer = SeededHttp::serve(SeededService {
        seeded: SeededIndexer {
            indexer: ZolanaIndexer::new(env.indexer_url.clone()),
            notes: seeded,
            own: own_tree(&rows, &[withdrawal_owner])?,
            curator: Some((curator_records, curator_tree)),
            tracking: tracking_tree(&rows)?,
        },
        upstream: env.indexer_url.clone(),
        http: reqwest::Client::new(),
    })?;
    // The production prover reads its witnesses from this indexer.
    std::env::set_var("ZOLANA_INDEXER_URL", &indexer.url);
    restart_prover()?;
    env.indexer_url.clone_from(&indexer.url);

    let cosign_admin = RingRoleKeys::of(&env.payer).cosign_admin;
    let co_signer = env.funded_keypair()?;
    SendAs {
        rpc: env.client.rpc(),
        payer: &env.payer,
        holder: &cosign_admin,
    }
    .send(&[SetCoSigner {
        ring,
        payer: env.payer.pubkey(),
        authority: cosign_admin.pubkey(),
        signer: co_signer.pubkey(),
        scope: CoSignScope::ALL,
    }
    .instruction()?])?;
    let writer = env.funded_keypair()?;
    let before = fetch_account(env.client.rpc(), &env.tree)?;
    let client = env.client_with(AsyncProverClient::local);
    let transfer = FullLoad {
        ring,
        sender: &sender,
        recipients: &recipients,
        payer: writer.pubkey(),
        notes: &notes[..SPENT_NOTES],
        destination,
    }
    .transfer()?
    .with_co_signer(co_signer.pubkey());
    let settled = client.block_on(
        RingSubmission::new(transfer)
            .with_priority_fee(PRIORITY_FEE)
            .send_until_settled(client.ring_client(), &writer, &[&co_signer]),
    )?;
    let SettledSubmission::Confirmed { signature, .. } = settled else {
        bail!("the submission failed, {settled:?}");
    };
    Settlement {
        env: &env,
        label: "submission",
        approval: ApprovalRead::ProvenMask,
        ring,
        policy: &policy,
        auditor: &auditor,
        writer: writer.pubkey(),
        signature,
        before: &before,
    }
    .check()?;

    let ring_rpc = RingRpcSpec {
        env: &env,
        ring: ring.program_id(),
        auditor: auditor.clone(),
    }
    .serve_relayed()?;
    let config = env.run(ring.require_config(env.client.as_async()))?;
    let relay_leg = |label, approval, notes| RelayLeg {
        env: &env,
        label,
        approval,
        ring,
        policy: &policy,
        config: &config,
        auditor: &auditor,
        ring_rpc: &ring_rpc,
        co_signer: &co_signer,
        sender: &sender,
        recipients: &recipients,
        notes,
        destination,
    };
    relay_leg(
        "relay threshold",
        ApprovalRead::ProvenMask,
        &notes[SPENT_NOTES..2 * SPENT_NOTES],
    )
    .run()?;
    relay_leg(
        "relay exact",
        ApprovalRead::Opening,
        &notes[2 * SPENT_NOTES..],
    )
    .run()?;

    let mut wallet = RingWallet::new(&recipients[0], env.ring_assets()?, ring.program_id());
    wallet.sync(&env)?;
    ensure!(
        wallet
            .unspent()
            .filter(|held| held.utxo.amount == PAID && held.ring_data_hash == Some(RING_DATA_HASH))
            .count()
            == 3,
        "the recipient rebuilt another note count"
    );
    println!("recipient: reconstructed every paid note");
    Ok(())
}
