use std::sync::{Arc, Mutex};

use custom_ring_interface::{tag, RingMode};
use solana_account::Account;
use solana_instruction::AccountMeta;
use solana_message::Hash;
use spr_client::{AsyncProverClient, AsyncZolanaClient};
use spr_keypair::ShieldedKeypair;

use super::*;
use crate::tests::support::{keypair, program, ring, Chain, Registry, RingSettings, SLOT};

#[tokio::test]
async fn a_policy_write_moves_the_proof() {
    let chain = Chain::ring(RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::Confidential)
    })
    .with_registry(Registry::new(&[]), &crate::tests::pipeline_rules());
    let pinned = ring().require_policy(&chain).await.unwrap().policy_hash;
    let policy = |hash| BoundState {
        policy: Some(BoundPolicy { ring: ring(), hash }),
        ..BoundState::default()
    };
    assert!(!policy(pinned).moved(&chain).await.unwrap());
    assert!(policy([1; 32]).moved(&chain).await.unwrap());
}

#[tokio::test]
async fn a_fresh_proof_fixes_a_stale_root_and_an_expired_blockhash_alone() {
    let chain = Chain::ring(RingSettings::new(RingMode::Confidential));
    let ring_failure = |error: CustomRingError| {
        TransactionError::InstructionError(0, InstructionError::Custom(error as u32))
    };
    let unmoved = BoundState::default();
    for (error, fixed) in [
        (TransactionError::BlockhashNotFound, true),
        (ring_failure(CustomRingError::RootNotServed), true),
        (ring_failure(CustomRingError::UnboundRegistry), true),
        (
            ring_failure(CustomRingError::ProofVerificationFailed),
            false,
        ),
        (ring_failure(CustomRingError::UnauthorizedAuthority), false),
        (TransactionError::AccountNotFound, false),
    ] {
        assert_eq!(
            unmoved.reproof_fixes(&error, &chain).await.unwrap(),
            fixed,
            "{error:?}"
        );
    }
}

/// Answers the block height alone, every status lookup fails.
struct StatusRefused {
    block_height: u64,
}

#[async_trait::async_trait]
impl AsyncRpc for StatusRefused {
    async fn get_block_height(&self) -> Result<u64, spr_client::ClientError> {
        Ok(self.block_height)
    }
}

#[tokio::test]
async fn a_refused_status_lookup_keeps_polling_until_the_blockhash_expires() {
    let rpc = StatusRefused { block_height: 10 };
    assert_eq!(
        outcome(&rpc, Signature::default(), 10).await.unwrap(),
        Outcome::Unknown
    );
    assert!(matches!(
        outcome(&rpc, Signature::default(), 9).await,
        Err(RingError::Client(_))
    ));
}

#[test]
fn only_a_confirmed_status_settles_an_attempt() {
    let status = |confirmation, err| TransactionStatus {
        slot: SLOT,
        confirmations: None,
        status: Ok(()),
        err,
        confirmation_status: Some(confirmation),
    };
    assert_eq!(decode_status(vec![None]), None);
    assert_eq!(decode_status(Vec::new()), Some(Outcome::Unknown));
    assert_eq!(
        decode_status(vec![Some(status(
            TransactionConfirmationStatus::Processed,
            None
        ))]),
        Some(Outcome::Unknown)
    );
    assert_eq!(
        decode_status(vec![Some(status(
            TransactionConfirmationStatus::Confirmed,
            None
        ))]),
        Some(Outcome::Confirmed { slot: SLOT })
    );
    assert_eq!(
        decode_status(vec![Some(status(
            TransactionConfirmationStatus::Finalized,
            Some(TransactionError::AccountNotFound)
        ))]),
        Some(Outcome::Failed(TransactionError::AccountNotFound))
    );
}

const VALID_UNTIL: u64 = 100;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Status {
    #[default]
    Landed,
    Absent,
    LookupFails,
    Failed,
}

#[derive(Default)]
struct ClusterState {
    sent: Vec<VersionedTransaction>,
    settlement: Status,
    write: Status,
    expired: bool,
    buffer_exists: bool,
    buffer_lookup_fails: bool,
}

/// Answers by the tag of each sent transaction, a close removes the buffer.
#[derive(Clone, Default)]
struct Cluster(Arc<Mutex<ClusterState>>);

fn first_tag(transaction: &VersionedTransaction) -> u8 {
    transaction.message.instructions()[0].data[0]
}

const REFUSED: ClientError = ClientError::UnsupportedRpcMethod("refused");

impl Cluster {
    fn set(&self, change: impl FnOnce(&mut ClusterState)) {
        change(&mut self.0.lock().unwrap());
    }

    fn sent_tags(&self) -> Vec<u8> {
        self.0.lock().unwrap().sent.iter().map(first_tag).collect()
    }

    fn last_signature(&self) -> Signature {
        self.0.lock().unwrap().sent.last().unwrap().signatures[0]
    }
}

#[async_trait::async_trait]
impl AsyncRpc for Cluster {
    async fn get_account(&self, _: Address) -> Result<Option<Account>, ClientError> {
        let state = self.0.lock().unwrap();
        if state.buffer_lookup_fails {
            return Err(REFUSED);
        }
        Ok(state.buffer_exists.then(Account::default))
    }

    async fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        Ok((Hash::default(), VALID_UNTIL))
    }

    async fn get_block_height(&self) -> Result<u64, ClientError> {
        let state = self.0.lock().unwrap();
        let settling = state
            .sent
            .last()
            .is_some_and(|sent| first_tag(sent) == tag::SETTLE_BUFFERED);
        if settling && state.settlement == Status::LookupFails {
            return Err(REFUSED);
        }
        Ok(VALID_UNTIL + u64::from(state.expired))
    }

    async fn get_signature_statuses(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        let state = self.0.lock().unwrap();
        signatures
            .iter()
            .map(|signature| {
                let tag_of = state
                    .sent
                    .iter()
                    .find(|sent| sent.signatures[0] == *signature)
                    .map(first_tag);
                let status = match tag_of {
                    Some(tag::SETTLE_BUFFERED) => state.settlement,
                    Some(tag::WRITE_FRAME) => state.write,
                    Some(_) => Status::Landed,
                    None => Status::Absent,
                };
                let settled = |err| {
                    Some(TransactionStatus {
                        slot: SLOT,
                        confirmations: None,
                        status: Ok(()),
                        err,
                        confirmation_status: Some(TransactionConfirmationStatus::Confirmed),
                    })
                };
                match status {
                    Status::Landed => Ok(settled(None)),
                    Status::Failed => Ok(settled(Some(TransactionError::AccountNotFound))),
                    Status::Absent => Ok(None),
                    Status::LookupFails => Err(REFUSED),
                }
            })
            .collect()
    }

    async fn send_transaction_with_config(
        &self,
        transaction: &VersionedTransaction,
        _: RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        let mut state = self.0.lock().unwrap();
        if first_tag(transaction) == tag::CLOSE_FRAME_BUFFER {
            state.buffer_exists = false;
        }
        state.sent.push(transaction.clone());
        Ok(transaction.signatures[0])
    }
}

fn client(cluster: &Cluster) -> RingClient<Cluster, Chain> {
    let chain = Chain::ring(RingSettings::new(RingMode::Confidential));
    RingClient::new(
        AsyncZolanaClient::new(cluster.clone(), chain, AsyncProverClient::local()),
        AsyncProverClient::local(),
    )
}

/// Holds a proven upload at its first write, a new proof shows as `tag::SET_DELEGATE`.
fn uploading(payer: &ShieldedKeypair) -> RingSubmission<'static> {
    let proved = Proved {
        instruction: Instruction {
            program_id: program(),
            accounts: vec![AccountMeta::new(payer.pubkey(), true)],
            data: [vec![tag::TRANSFER], vec![0; 5000]].concat(),
        },
        budget: send_budget(InstructionTag::Transfer, None),
        bound: BoundState::default(),
    };
    let mut submission = RingSubmission::new(RingOperation::Instruction(Instruction {
        program_id: program(),
        accounts: vec![AccountMeta::new(payer.pubkey(), true)],
        data: vec![tag::SET_DELEGATE],
    }));
    submission.pending = Some(Attempt {
        step: Step::upload(proved, payer.pubkey(), None).unwrap(),
        sent: None,
    });
    submission.attempts = 1;
    submission
}

#[tokio::test]
async fn an_unknown_settlement_holds_its_attempt_and_blocks_a_new_proof() {
    let cluster = Cluster::default();
    cluster.set(|state| state.settlement = Status::LookupFails);
    let client = client(&cluster);
    let payer = keypair(1);
    let mut submission = uploading(&payer);

    assert!(matches!(
        submission.send(&client, &payer, &[]).await,
        Err(RingError::Client(_))
    ));
    let sent = cluster.sent_tags();
    assert_eq!(sent.last(), Some(&tag::SETTLE_BUFFERED));
    assert!(sent[..sent.len() - 1]
        .iter()
        .all(|tag_of| *tag_of == tag::WRITE_FRAME));
    assert!(sent.len() > 2);
    let settlement = cluster.last_signature();
    assert_eq!(
        submission.pending_transaction().unwrap().signatures[0],
        settlement
    );

    assert!(matches!(
        submission.send(&client, &payer, &[]).await,
        Err(RingError::Client(_))
    ));
    cluster.set(|state| state.settlement = Status::Absent);
    assert_eq!(
        submission.send(&client, &payer, &[]).await.unwrap(),
        SubmissionStatus::Pending {
            signature: settlement
        }
    );
    assert_eq!(cluster.sent_tags(), sent);
    assert_eq!(submission.attempts(), 1);

    cluster.set(|state| state.settlement = Status::Landed);
    assert_eq!(
        submission.send(&client, &payer, &[]).await.unwrap(),
        SubmissionStatus::Settled(SettledSubmission::Confirmed {
            signature: settlement,
            slot: SLOT,
        })
    );
    assert_eq!(cluster.sent_tags(), sent);
    assert!(submission.pending_transaction().is_none());
}

#[tokio::test]
async fn an_expired_settlement_closes_its_buffer_ahead_of_the_new_proof() {
    let cluster = Cluster::default();
    cluster.set(|state| {
        state.settlement = Status::Absent;
        state.buffer_exists = true;
    });
    let client = client(&cluster);
    let payer = keypair(1);
    let mut submission = uploading(&payer);
    let held = submission.send(&client, &payer, &[]).await.unwrap();
    assert!(matches!(held, SubmissionStatus::Pending { .. }));

    cluster.set(|state| state.expired = true);
    let settled = submission.send(&client, &payer, &[]).await.unwrap();
    assert!(matches!(
        settled,
        SubmissionStatus::Settled(SettledSubmission::Confirmed { .. })
    ));
    let sent = cluster.sent_tags();
    assert_eq!(
        sent[sent.len() - 3..],
        [
            tag::SETTLE_BUFFERED,
            tag::CLOSE_FRAME_BUFFER,
            tag::SET_DELEGATE
        ]
    );
    assert_eq!(submission.attempts(), 2);
}

#[tokio::test]
async fn a_failed_close_keeps_the_settlement_final_and_retries_the_close() {
    let cluster = Cluster::default();
    cluster.set(|state| {
        state.settlement = Status::Failed;
        state.buffer_exists = true;
        state.buffer_lookup_fails = true;
    });
    let client = client(&cluster);
    let payer = keypair(1);
    let mut submission = uploading(&payer);
    assert!(matches!(
        submission.send(&client, &payer, &[]).await,
        Err(RingError::Client(_))
    ));
    let settlement = cluster.last_signature();
    assert_eq!(cluster.sent_tags().last(), Some(&tag::SETTLE_BUFFERED));
    assert!(submission.pending_transaction().is_some());

    cluster.set(|state| state.buffer_lookup_fails = false);
    assert_eq!(
        submission.send(&client, &payer, &[]).await.unwrap(),
        SubmissionStatus::Settled(SettledSubmission::Failed {
            signature: settlement,
            error: TransactionError::AccountNotFound,
        })
    );
    assert_eq!(cluster.sent_tags().last(), Some(&tag::CLOSE_FRAME_BUFFER));
    assert_eq!(submission.attempts(), 1);
}

#[tokio::test]
async fn an_unknown_write_holds_the_next_chunk() {
    let cluster = Cluster::default();
    cluster.set(|state| state.write = Status::Absent);
    let client = client(&cluster);
    let payer = keypair(1);
    let mut submission = uploading(&payer);
    for _ in 0..2 {
        assert_eq!(
            submission.send(&client, &payer, &[]).await.unwrap(),
            SubmissionStatus::Pending {
                signature: cluster.last_signature()
            }
        );
        assert_eq!(cluster.sent_tags(), [tag::WRITE_FRAME]);
    }
}
