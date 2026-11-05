use std::sync::{Arc, Mutex};

use custom_ring_interface::{
    credential::owner_member, RingMode, CREDENTIAL_PDA_SEED, REGISTER_KEY_CIPHERTEXT_LEN,
};
use solana_account::Account;
use solana_message::Hash;
use solana_transaction_status_client_types::{TransactionConfirmationStatus, TransactionStatus};
use spr_client::{AsyncProverClient, AsyncZolanaClient, ClientError};
use spr_keypair::ShieldedKeypair;
use spr_program::program::{NewAddress, PdaOwner};
use spr_user_registry_interface::{user_registry_program_id, MergeEncryptionScheme, UserRecord};
use zolana_ring_client::rpc::address_tree;

use super::*;
use crate::tests::support::{keypair, ring, Chain, RingSettings, SLOT, TREE_ID};

const OUTPUT_TREE: Address = Address::new_from_array([0x77; 32]);
const VALID_UNTIL: u64 = 500;

fn accounts(owner: Address, payer: Address) -> EnrollAccounts {
    EnrollAccounts {
        ring_program_id: ring().program_id(),
        owner,
        payer,
        output_tree: OUTPUT_TREE,
    }
}

fn instruction(owner: Address, payer: Address) -> EnrollInstruction {
    EnrollInstruction {
        accounts: accounts(owner, payer),
        data: vec![tag::ENROLL, 1, 2, 3],
        registration: None,
    }
}

fn sealed(seed: u8) -> EnrollIxData {
    EnrollIxData {
        nullifier_pk: [seed; 32].map(|byte| byte & 0x0f),
        list_tag: [2; 32],
        eph_u: [3; 32],
        ciphertext: [seed; REGISTER_KEY_CIPHERTEXT_LEN],
    }
}

async fn config() -> CustomRingConfig {
    let chain = Chain::ring(RingSettings::new(RingMode::Confidential));
    ring().require_config(&chain).await.unwrap()
}

fn enroll<'a>(owner: Address, key: &'a NullifierKey) -> Enroll<'a> {
    Enroll {
        ring: ring(),
        owner,
        payer: keypair(9).pubkey(),
        output_tree: OUTPUT_TREE,
        nullifier_key: key,
        list_salt: [5; 32],
        viewing_pubkey: keypair(1).viewing_pubkey(),
    }
}

#[test]
fn an_owner_and_a_separate_payer_sign_apart_and_the_credential_accounts_derive() {
    let (owner, payer) = (keypair(1).pubkey(), keypair(2).pubkey());
    let [built] = <[_; 1]>::try_from(instruction(owner, payer).instructions().unwrap()).unwrap();
    let credential = CredentialAccounts::derive(&ring().program_id(), &owner).unwrap();
    let (pda, _) = Address::find_program_address(&[CREDENTIAL_PDA_SEED], &ring().program_id());
    let signers: Vec<_> = built
        .accounts
        .iter()
        .filter(|meta| meta.is_signer)
        .map(|meta| meta.pubkey)
        .collect();

    assert_eq!(built.program_id, ring().program_id());
    assert_eq!(signers, [owner, payer]);
    assert!(!built.accounts[0].is_writable && built.accounts[2].is_writable);
    assert_eq!(
        built
            .accounts
            .iter()
            .map(|meta| meta.pubkey)
            .collect::<Vec<_>>()[1..],
        [
            ring().policy_pda(),
            payer,
            OUTPUT_TREE,
            Address::new_from_array(spr_interface::SHIELDED_POOL_PROGRAM_ID),
            custom_ring_interface::SYSTEM_PROGRAM_ID,
            address_tree(),
            credential.nullifier_pda,
            pda,
        ]
    );
    assert_ne!(pda, ring().ring_auth_pda());
}

/// A PDA owner is a signer meta, its program signs through `invoke_signed`.
#[test]
fn a_pda_owner_signs_its_meta_through_its_program() {
    let (pda_owner, _) =
        Address::find_program_address(&[b"vault"], &Address::new_from_array([8; 32]));
    let payer = keypair(2).pubkey();
    let [built] =
        <[_; 1]>::try_from(instruction(pda_owner, payer).instructions().unwrap()).unwrap();
    let wallet = CredentialAccounts::derive(&ring().program_id(), &keypair(1).pubkey()).unwrap();
    let owned = CredentialAccounts::derive(&ring().program_id(), &pda_owner).unwrap();

    assert!(!pda_owner.is_on_curve());
    assert_eq!(built.accounts[0].pubkey, pda_owner);
    assert!(built.accounts[0].is_signer);
    assert_eq!(built.accounts[7].pubkey, owned.nullifier_pda);
    assert_ne!(owned.address, wallet.address);
}

/// A second enrollment of one owner in one ring meets the first address.
#[tokio::test]
async fn the_credential_address_names_the_ring_and_owner_alone() {
    let config = config().await;
    let key = NullifierKey::from_secret([1; BLINDING_LEN]);
    let owner = keypair(1).pubkey();
    let one = enroll(owner, &key).credential(&config, &sealed(1)).unwrap();
    let other = enroll(owner, &key).credential(&config, &sealed(4)).unwrap();
    let credential = CredentialAccounts::derive(&ring().program_id(), &owner).unwrap();
    let program_address = NewAddress::derive(
        &PdaOwner::new(credential.owner.pda()).unwrap(),
        one.seed().unwrap(),
    )
    .unwrap();

    assert_eq!(one.seed().unwrap(), other.seed().unwrap());
    assert_eq!(*program_address.address(), credential.address);
    for (ring_program_id, member) in [
        (Address::new_from_array([3; 32]), owner),
        (ring().program_id(), keypair(2).pubkey()),
    ] {
        assert_ne!(
            CredentialAccounts::derive(&ring_program_id, &member)
                .unwrap()
                .address,
            credential.address
        );
    }
}

/// A RegisterKey proof over another ring, owner or auditor proves another statement.
#[tokio::test]
async fn the_register_key_statement_binds_the_ring_owner_and_auditor() {
    let config = config().await;
    let key = NullifierKey::from_secret([1; BLINDING_LEN]);
    let owner = keypair(1).pubkey();
    let ix = sealed(1);
    let built = enroll(owner, &key).credential(&config, &ix).unwrap();
    let rebuilt = Enrollment {
        ring_id: &ring().ring_id().unwrap(),
        auditor_pubkey: config.auditor_pubkey.as_bytes(),
        owner: &owner,
        ix: &ix,
    }
    .credential()
    .unwrap();
    assert_eq!(built, rebuilt);
    assert_eq!(rebuilt.member, owner_member(&owner).unwrap());

    let other_ring = Enroll {
        ring: CustomRing::new(Address::new_from_array([3; 32])),
        ..enroll(owner, &key)
    };
    let mut other_auditor = config.clone();
    other_auditor.auditor_pubkey = X25519Pubkey::from_u(UNSEALED_VIEWER_U).unwrap();
    for wrong in [
        other_ring.credential(&config, &ix).unwrap(),
        enroll(keypair(2).pubkey(), &key)
            .credential(&config, &ix)
            .unwrap(),
        enroll(owner, &key).credential(&other_auditor, &ix).unwrap(),
    ] {
        assert_ne!(
            wrong.register_key_hash().unwrap(),
            built.register_key_hash().unwrap()
        );
    }
}

/// A swapped ciphertext moves the RegisterKey statement and the credential output SPP checks.
#[tokio::test]
async fn a_substituted_ciphertext_moves_both_statements() {
    let config = config().await;
    let key = NullifierKey::from_secret([1; BLINDING_LEN]);
    let owner = keypair(1).pubkey();
    let honest = sealed(1);
    let mut substituted = honest;
    substituted.ciphertext[0] ^= 1;
    let accounts = CredentialAccounts::derive(&ring().program_id(), &owner).unwrap();
    let output = |ix: &EnrollIxData| {
        let credential = enroll(owner, &key).credential(&config, ix).unwrap();
        let data = CredentialCreation {
            credential: &credential,
            accounts: &accounts,
            output_tree_id: TREE_ID,
        }
        .program_data(0)
        .unwrap();
        (
            credential.register_key_hash().unwrap(),
            data.outputs,
            data.private_tx_hash,
        )
    };
    let (honest_statement, honest_outputs, honest_tx) = output(&honest);
    let (statement, outputs, tx) = output(&substituted);

    assert_ne!(statement, honest_statement);
    assert_ne!(outputs[0].utxo_hash, honest_outputs[0].utxo_hash);
    assert_ne!(tx, honest_tx);
}

/// The proof inputs reproduce the program's output and reserve the program's address.
#[tokio::test]
async fn the_proof_inputs_rebuild_the_program_output() {
    let config = config().await;
    let key = NullifierKey::from_secret([1; BLINDING_LEN]);
    let owner = keypair(1).pubkey();
    let credential = enroll(owner, &key).credential(&config, &sealed(1)).unwrap();
    let accounts = CredentialAccounts::derive(&ring().program_id(), &owner).unwrap();
    let creation = CredentialCreation {
        credential: &credential,
        accounts: &accounts,
        output_tree_id: TREE_ID,
    };
    let program = creation.program_data(3).unwrap();
    let inputs = creation.proof_inputs(keypair(9).pubkey()).unwrap();

    assert_eq!(
        inputs.output_utxos[0].hash(TREE_ID).unwrap(),
        program.outputs[0].utxo_hash
    );
    assert_eq!(inputs.input_utxos[0].nullifier, accounts.address);
    assert_eq!(program.inputs[0].nullifier_hash, accounts.address);
    assert_eq!(inputs.external_data.outputs, program.outputs);
    assert_eq!(
        program.tree_contexts,
        [TreeContext {
            utxo_tree_root_index: NO_UTXO_ROOT,
            nullifier_tree_root_index: 3,
        }]
    );
    assert!(inputs.input_utxos[1].compact && inputs.output_utxos[1].compact);
}

#[tokio::test]
async fn a_reserved_address_refuses_before_any_proof() {
    let key = NullifierKey::from_secret([1; BLINDING_LEN]);
    let owner = keypair(1).pubkey();
    let reserved = CredentialAccounts::derive(&ring().program_id(), &owner).unwrap();
    let client = Chain::ring(RingSettings::new(RingMode::Confidential))
        .with(reserved.nullifier_pda, Account::default())
        .client();

    assert!(matches!(
        enroll(owner, &key).prove(&client).await,
        Err(RingError::AlreadyEnrolled { owner: refused }) if refused == owner
    ));
}

fn user_record(owner: Address, nullifier_pubkey: [u8; 32]) -> Account {
    let record = UserRecord {
        owner,
        bump: user_record_pda(&owner).1,
        nullifier_pubkey,
        viewing_pubkey: *keypair(1).viewing_pubkey().as_bytes(),
        merge_encryption: MergeEncryptionScheme::Disabled,
    };
    let mut data = vec![UserRecord::DISCRIMINATOR];
    borsh::BorshSerialize::serialize(&record, &mut data).unwrap();
    Account {
        data,
        owner: user_registry_program_id(),
        ..Account::default()
    }
}

/// The record is never assumed, a missing one is created with the credential key.
#[tokio::test]
async fn an_owner_without_a_user_record_registers_it_ahead_of_enroll() {
    let key = NullifierKey::from_secret([1; BLINDING_LEN]);
    let owner = keypair(1).pubkey();
    let client = Chain::ring(RingSettings::new(RingMode::Confidential)).client();
    let registration = enroll(owner, &key).registration(&client).await.unwrap();
    let keys = UserRegistration {
        nullifier_pubkey: key.pubkey().unwrap(),
        viewing_pubkey: *keypair(1).viewing_pubkey().as_bytes(),
    };
    assert_eq!(registration, Some(keys));

    let payer = keypair(2).pubkey();
    let built = EnrollInstruction {
        registration,
        ..instruction(owner, payer)
    }
    .instructions()
    .unwrap();
    let [register, enroll] = <[_; 2]>::try_from(built).unwrap();
    assert_eq!(register.program_id, user_registry_program_id());
    assert_eq!(
        register.data,
        [
            &[spr_user_registry_interface::instruction::discriminator::REGISTER][..],
            &keys.nullifier_pubkey,
            &keys.viewing_pubkey,
        ]
        .concat()
    );
    assert_eq!(
        (
            register.accounts[0].pubkey,
            register.accounts[1].pubkey,
            register.accounts[2].pubkey
        ),
        (user_record_pda(&owner).0, owner, payer)
    );
    assert_eq!(enroll.program_id, ring().program_id());
}

#[tokio::test]
async fn a_user_record_under_the_credential_key_is_kept_and_another_key_refuses() {
    let key = NullifierKey::from_secret([1; BLINDING_LEN]);
    let owner = keypair(1).pubkey();
    let record = |nullifier_pubkey| {
        Chain::ring(RingSettings::new(RingMode::Confidential))
            .with(
                user_record_pda(&owner).0,
                user_record(owner, nullifier_pubkey),
            )
            .client()
    };
    assert_eq!(
        enroll(owner, &key)
            .registration(&record(key.pubkey().unwrap()))
            .await
            .unwrap(),
        None
    );
    assert!(matches!(
        enroll(owner, &key).registration(&record([7; 32])).await,
        Err(RingError::UserRecordKeyMismatch { owner: refused }) if refused == owner
    ));
}

/// The relay carries `Enroll` alone, an owner with no record refuses before any proof.
#[tokio::test]
async fn a_relayed_enrollment_without_a_user_record_refuses() {
    let key = NullifierKey::from_secret([1; BLINDING_LEN]);
    let owner = keypair(1);
    let enrolling = enroll(owner.pubkey(), &key);
    let quote = RelayQuote {
        fee_payer: enrolling.payer.into(),
        valid_until_slot: u64::MAX,
    };
    let client = Chain::ring(RingSettings::new(RingMode::Confidential)).client();

    assert!(matches!(
        enrolling.prepare_relay(&client, quote, &owner).await,
        Err(RingError::RelayNeedsUserRecord { .. })
    ));
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Landing {
    Landed,
    Failed,
    Absent,
}

struct LedgerState {
    sent: Vec<VersionedTransaction>,
    landing: Landing,
    reserved: bool,
    expired: bool,
    preflight_refuses: bool,
}

#[derive(Clone)]
struct Ledger(Arc<Mutex<LedgerState>>);

impl Ledger {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(LedgerState {
            sent: Vec::new(),
            landing: Landing::Absent,
            reserved: false,
            expired: false,
            preflight_refuses: false,
        })))
    }

    fn set(&self, change: impl FnOnce(&mut LedgerState)) {
        change(&mut self.0.lock().unwrap());
    }

    fn sent(&self) -> Vec<VersionedTransaction> {
        self.0.lock().unwrap().sent.clone()
    }

    fn client(&self) -> RingClient<Ledger, Chain> {
        let chain = Chain::ring(RingSettings::new(RingMode::Confidential));
        RingClient::new(
            AsyncZolanaClient::new(self.clone(), chain, AsyncProverClient::local()),
            AsyncProverClient::local(),
        )
    }
}

#[async_trait]
impl AsyncRpc for Ledger {
    async fn get_account(&self, _: Address) -> Result<Option<Account>, ClientError> {
        Ok(self.0.lock().unwrap().reserved.then(Account::default))
    }

    async fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        Ok((Hash::new_unique(), VALID_UNTIL))
    }

    async fn get_block_height(&self) -> Result<u64, ClientError> {
        Ok(VALID_UNTIL + u64::from(self.0.lock().unwrap().expired))
    }

    async fn get_signature_statuses(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        let state = self.0.lock().unwrap();
        let status = |err| TransactionStatus {
            slot: SLOT,
            confirmations: None,
            status: Ok(()),
            err,
            confirmation_status: Some(TransactionConfirmationStatus::Confirmed),
        };
        Ok(signatures
            .iter()
            .map(|_| match state.landing {
                Landing::Landed => Some(status(None)),
                Landing::Failed => Some(status(Some(TransactionError::AccountNotFound))),
                Landing::Absent => None,
            })
            .collect())
    }

    async fn get_signature_statuses_with_history(
        &self,
        signatures: Vec<Signature>,
    ) -> Result<Vec<Option<TransactionStatus>>, ClientError> {
        self.get_signature_statuses(signatures).await
    }

    async fn send_transaction_with_config(
        &self,
        transaction: &VersionedTransaction,
        _: RpcSendTransactionConfig,
    ) -> Result<Signature, ClientError> {
        let mut state = self.0.lock().unwrap();
        state.sent.push(transaction.clone());
        match state.preflight_refuses {
            true => Err(ClientError::UnsupportedRpcMethod("transport")),
            false => Ok(transaction.signatures[0]),
        }
    }
}

/// Each record keeps the ledger's sent count at that moment.
struct Journal {
    ledger: Ledger,
    recorded: Mutex<Vec<(Vec<u8>, usize)>>,
    fails: bool,
}

impl Journal {
    fn new(ledger: &Ledger) -> Self {
        Self {
            ledger: ledger.clone(),
            recorded: Mutex::new(Vec::new()),
            fails: false,
        }
    }

    fn last(&self) -> EnrollmentAttempt {
        let recorded = self.recorded.lock().unwrap();
        EnrollmentAttempt::decode(&recorded.last().unwrap().0).unwrap()
    }
}

#[async_trait]
impl EnrollmentJournal for Journal {
    async fn record(
        &self,
        attempt: &EnrollmentAttempt,
    ) -> Result<(), Box<dyn StdError + Send + Sync>> {
        if self.fails {
            return Err("disk full".into());
        }
        let encoded = attempt.encode()?;
        self.recorded
            .lock()
            .unwrap()
            .push((encoded, self.ledger.sent().len()));
        Ok(())
    }
}

fn wallets() -> (ShieldedKeypair, ShieldedKeypair) {
    (keypair(1), keypair(2))
}

#[tokio::test]
async fn an_attempt_is_recorded_before_its_broadcast_and_signed_by_owner_and_payer() {
    let ledger = Ledger::new();
    let journal = Journal::new(&ledger);
    let (owner, payer) = wallets();

    let attempt = instruction(owner.pubkey(), payer.pubkey())
        .submit(&ledger.client(), &[&payer, &owner], &journal)
        .await
        .unwrap();

    let recorded = journal.recorded.lock().unwrap().clone();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].1, 0, "nothing left before the record");
    assert_eq!(ledger.sent(), std::slice::from_ref(&attempt.transaction));
    assert_eq!(attempt.transaction.signatures.len(), 2);
    assert_eq!(
        attempt.transaction.message.static_account_keys()[0],
        payer.pubkey()
    );
}

#[tokio::test]
async fn an_unrecorded_attempt_sends_nothing() {
    let ledger = Ledger::new();
    let journal = Journal {
        fails: true,
        ..Journal::new(&ledger)
    };
    let (owner, payer) = wallets();

    let refused = instruction(owner.pubkey(), payer.pubkey())
        .submit(&ledger.client(), &[&payer, &owner], &journal)
        .await;

    assert!(matches!(refused, Err(RingError::AttemptNotRecorded(_))));
    assert!(ledger.sent().is_empty());
}

/// A transport error after the record leaves the outcome to reconciliation, never to a new send.
#[tokio::test]
async fn an_in_doubt_attempt_reconciles_from_its_record_after_a_restart() {
    let ledger = Ledger::new();
    ledger.set(|state| state.preflight_refuses = true);
    let journal = Journal::new(&ledger);
    let (owner, payer) = wallets();
    let client = ledger.client();
    let sent = instruction(owner.pubkey(), payer.pubkey())
        .submit(&client, &[&payer, &owner], &journal)
        .await;
    assert!(sent.is_ok(), "a lost answer is in doubt, not refused");
    let restored = journal.last();

    let outcome = || async { restored.reconcile(&client).await.unwrap() };
    assert_eq!(outcome().await, EnrollmentOutcome::Pending);
    assert!(matches!(
        restored
            .clone()
            .resubmit(&client, &[&payer, &owner], &journal)
            .await,
        Err(RingError::AttemptNotExpired(EnrollmentOutcome::Pending))
    ));
    ledger.set(|state| state.reserved = true);
    assert_eq!(outcome().await, EnrollmentOutcome::Reserved);
    ledger.set(|state| state.landing = Landing::Failed);
    assert_eq!(outcome().await, EnrollmentOutcome::Reserved);
    ledger.set(|state| state.reserved = false);
    assert_eq!(
        outcome().await,
        EnrollmentOutcome::Failed(TransactionError::AccountNotFound)
    );
    ledger.set(|state| state.landing = Landing::Landed);
    assert_eq!(outcome().await, EnrollmentOutcome::Landed { slot: SLOT });
    assert_eq!(ledger.sent().len(), 1);
}

#[tokio::test]
async fn only_an_expired_attempt_with_no_reservation_goes_again_with_the_same_request() {
    let ledger = Ledger::new();
    let journal = Journal::new(&ledger);
    let (owner, payer) = wallets();
    let client = ledger.client();
    let first = instruction(owner.pubkey(), payer.pubkey())
        .submit(&client, &[&payer, &owner], &journal)
        .await
        .unwrap();
    ledger.set(|state| {
        state.expired = true;
        state.reserved = true;
    });
    assert!(matches!(
        first
            .clone()
            .resubmit(&client, &[&payer, &owner], &journal)
            .await,
        Err(RingError::AttemptNotExpired(EnrollmentOutcome::Reserved))
    ));
    ledger.set(|state| state.reserved = false);
    assert_eq!(
        first.reconcile(&client).await.unwrap(),
        EnrollmentOutcome::Expired
    );

    let second = first
        .clone()
        .resubmit(&client, &[&payer, &owner], &journal)
        .await
        .unwrap();

    assert_eq!(second.instruction, first.instruction);
    assert_ne!(second.signature(), first.signature());
    assert_eq!(journal.recorded.lock().unwrap().len(), 2);
}

mod key_phase {
    //! Real RegisterKey and SPP proofs against a localnet that runs the ring program with `Enroll`.
    //! `ZOLANA_LOCALNET_URL`, `ZOLANA_INDEXER_URL`, `ZOLANA_PROVER_URL` and `RING_PROGRAM_ID`
    //! name the services and an initialized ring.

    use solana_rpc_client::nonblocking::rpc_client::RpcClient;
    use spr_client::{AsyncSolanaRpc, AsyncZolanaIndexer};

    use super::*;

    fn env(name: &str) -> String {
        std::env::var(name).unwrap_or_else(|_| panic!("{name} is unset"))
    }

    type Localnet = RingClient<AsyncSolanaRpc, AsyncZolanaIndexer>;

    async fn localnet(funded: &[&ShieldedKeypair]) -> (Localnet, CustomRing) {
        let rpc_url = env("ZOLANA_LOCALNET_URL");
        let airdrop = RpcClient::new(rpc_url.clone());
        for wallet in funded {
            let signature = airdrop
                .request_airdrop(&wallet.pubkey(), 1_000_000_000)
                .await
                .unwrap();
            while !airdrop.confirm_transaction(&signature).await.unwrap() {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }
        let prover = || AsyncProverClient::new(env("ZOLANA_PROVER_URL"));
        let client = RingClient::new(
            AsyncZolanaClient::new(
                AsyncSolanaRpc::new(rpc_url),
                AsyncZolanaIndexer::new(env("ZOLANA_INDEXER_URL")),
                prover(),
            ),
            prover(),
        );
        let ring = CustomRing::new(env("RING_PROGRAM_ID").parse().unwrap());
        (client, ring)
    }

    struct Memory(Mutex<Vec<EnrollmentAttempt>>);

    #[async_trait]
    impl EnrollmentJournal for Memory {
        async fn record(
            &self,
            attempt: &EnrollmentAttempt,
        ) -> Result<(), Box<dyn StdError + Send + Sync>> {
            self.0.lock().unwrap().push(attempt.clone());
            Ok(())
        }
    }

    async fn settle(attempt: &EnrollmentAttempt, client: &Localnet) -> EnrollmentOutcome {
        loop {
            match attempt.reconcile(client).await.unwrap() {
                EnrollmentOutcome::Pending => {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await
                }
                settled => return settled,
            }
        }
    }

    async fn proven(
        client: &Localnet,
        ring: CustomRing,
        owner: &ShieldedKeypair,
        payer: Address,
    ) -> ProvenEnrollment {
        Enroll {
            ring,
            owner: owner.pubkey(),
            payer,
            output_tree: spr_interface::pda::tree(TREE_ID),
            nullifier_key: &owner.nullifier_key,
            list_salt: [5; 32],
            viewing_pubkey: owner.viewing_pubkey(),
        }
        .prove(client)
        .await
        .unwrap()
    }

    #[tokio::test]
    #[ignore = "key phase, needs the ring Enroll program, RegisterKey and SPP 2x2 keys on localnet"]
    async fn an_owner_enrolls_with_a_separate_payer_once() {
        let (owner, payer) = (
            ShieldedKeypair::new_ed25519().unwrap(),
            ShieldedKeypair::new_ed25519().unwrap(),
        );
        let (client, ring) = localnet(&[&payer]).await;
        let journal = Memory(Mutex::new(Vec::new()));
        let enrolled = proven(&client, ring, &owner, payer.pubkey()).await;

        let attempt = enrolled
            .instruction
            .submit(&client, &[&payer, &owner], &journal)
            .await
            .unwrap();

        assert!(matches!(
            settle(&attempt, &client).await,
            EnrollmentOutcome::Landed { .. }
        ));
        assert_eq!(client.get_balance(owner.pubkey()).await.unwrap(), 0);
        let again = Enroll {
            ring,
            owner: owner.pubkey(),
            payer: payer.pubkey(),
            output_tree: spr_interface::pda::tree(TREE_ID),
            nullifier_key: &owner.nullifier_key,
            list_salt: [5; 32],
            viewing_pubkey: owner.viewing_pubkey(),
        }
        .prove(&client)
        .await;
        assert!(matches!(again, Err(RingError::AlreadyEnrolled { .. })));
        let replay = attempt.resubmit(&client, &[&payer, &owner], &journal).await;
        assert!(matches!(
            replay,
            Err(RingError::AttemptNotExpired(
                EnrollmentOutcome::Landed { .. }
            ))
        ));
    }

    /// The program rebuilds the credential from the request and the signing owner, both proofs bind
    /// the original.
    #[tokio::test]
    #[ignore = "key phase, needs the ring Enroll program, RegisterKey and SPP 2x2 keys on localnet"]
    async fn a_substituted_ciphertext_or_another_owner_fails_on_chain() {
        let (owner, other, payer) = (
            ShieldedKeypair::new_ed25519().unwrap(),
            ShieldedKeypair::new_ed25519().unwrap(),
            ShieldedKeypair::new_ed25519().unwrap(),
        );
        let (client, ring) = localnet(&[&payer]).await;
        let journal = Memory(Mutex::new(Vec::new()));
        let enrolled = proven(&client, ring, &owner, payer.pubkey()).await;
        let ciphertext_at = 1 + 3 * 32;
        let mut substituted = enrolled.instruction.clone();
        substituted.data[ciphertext_at] ^= 1;
        let mut swapped_owner = enrolled.instruction.clone();
        swapped_owner.accounts.owner = other.pubkey();

        for (forged, owner) in [(substituted, &owner), (swapped_owner, &other)] {
            let attempt = forged.submit(&client, &[&payer, owner], &journal).await;
            let refused = match attempt {
                Ok(attempt) => matches!(
                    settle(&attempt, &client).await,
                    EnrollmentOutcome::Failed(_)
                ),
                Err(RingError::EnrollmentRefused(_)) => true,
                Err(error) => panic!("{error}"),
            };
            assert!(refused);
        }
        let attempt = enrolled
            .instruction
            .submit(&client, &[&payer, &owner], &journal)
            .await
            .unwrap();
        assert!(matches!(
            settle(&attempt, &client).await,
            EnrollmentOutcome::Landed { .. }
        ));
    }
}
