use std::{collections::HashSet, num::NonZeroU32, sync::Arc, time::Duration};

use async_trait::async_trait;
use custom_ring_sdk::{select_merge_where, MAX_RING_MERGE_INPUTS};
use solana_address::Address;
use solana_message::VersionedMessage;
use spr_keypair::NullifierKey;
use spr_transaction::WalletUtxo;
use zolana_ring_client::rpc::{
    MergeSettings, MergeSettingsAttestation, RelayId, SetMergeSettingsRequest,
    SetMergeSettingsResponse,
};
use zolana_ring_transaction::RingAssets;

use crate::{
    audit::AuditService,
    authorize::WalletCheck,
    error::{redacted, RingRpcError},
    hub::Hub,
    keyed_tasks::{KeyedTasks, MAX_CONCURRENT_KEYED_TASKS},
    merge_inputs::HeldInput,
    merge_settings::{MergeSettingsBook, SignedMergeSettings, WalletMergeSettings},
    relay::{HeldMerge, Relay},
    relays::RelayPhase,
    replay::ReplayCheck,
    upstream::TransactionSource,
    utxos::SpendableNotes,
};

pub const MANAGED_MERGE_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MergeTarget {
    pub note_count: NonZeroU32,
    pub min_average_amount: u64,
}

/// The owner's nullifier secret lives only for the build.
#[must_use]
pub struct OwnerMerge<'a> {
    pub ring: Address,
    pub owner: Address,
    pub nullifier_key: &'a NullifierKey,
    pub inputs: Vec<WalletUtxo>,
}

/// The fee payer the message names signs at relay.
pub struct BuiltMerge {
    pub message: VersionedMessage,
    pub last_valid_block_height: u64,
}

#[async_trait]
pub trait MergeBuilder: Send + Sync {
    async fn build(&self, merge: OwnerMerge<'_>) -> Result<BuiltMerge, RingRpcError>;
}

#[must_use]
pub struct ManagedMergeInit<S> {
    pub hub: Arc<Hub<S>>,
    pub builder: Arc<dyn MergeBuilder>,
    pub relay: Arc<Relay>,
}

pub struct ManagedMerge<S> {
    hub: Arc<Hub<S>>,
    builder: Arc<dyn MergeBuilder>,
    relay: Arc<Relay>,
}

struct RingPass<S> {
    service: AuditService<S>,
    assets: RingAssets,
    held: HashSet<[u8; 32]>,
}

impl MergeTarget {
    /// `None` for a zero target, a later request revokes with it.
    pub fn of(settings: &MergeSettings) -> Option<Self> {
        Some(Self {
            note_count: NonZeroU32::new(settings.target_note_count)?,
            min_average_amount: settings.min_average_amount,
        })
    }

    /// The smallest notes of the fullest tree, at most as many as the target needs.
    pub fn plan(&self, notes: &[WalletUtxo]) -> Option<Vec<WalletUtxo>> {
        let asset = notes.first()?.utxo.asset.asset;
        let total: u128 = notes.iter().map(|note| u128::from(note.utxo.amount)).sum();
        let by_average = match self.min_average_amount {
            0 => notes.len(),
            least => usize::try_from(total / u128::from(least))
                .unwrap_or(usize::MAX)
                .max(1),
        };
        let keep = by_average.min(usize::try_from(self.note_count.get()).unwrap_or(usize::MAX));
        let inputs = notes.len().checked_sub(keep)?.checked_add(1)?;
        if inputs < 2 {
            return None;
        }
        select_merge_where(
            notes,
            asset,
            inputs.min(MAX_RING_MERGE_INPUTS),
            &HashSet::new(),
            |_| true,
        )
        .ok()
    }
}

impl<S> ManagedMergeInit<S> {
    pub fn build(self) -> ManagedMerge<S> {
        ManagedMerge {
            hub: self.hub,
            builder: self.builder,
            relay: self.relay,
        }
    }
}

impl<S: TransactionSource + 'static> ManagedMerge<S> {
    /// Every `interval`, the first at once, merges each wallet above its signed target.
    ///
    /// Each ring runs on its own task, a ring still merging sits out the tick.
    pub async fn run(self, interval: Duration) {
        let merge = Arc::new(self);
        let rings = KeyedTasks::new(MAX_CONCURRENT_KEYED_TASKS);
        let mut ticks = tokio::time::interval(interval);
        loop {
            ticks.tick().await;
            let due = match merge.due_rings().await {
                Ok(due) => due,
                Err(error) => {
                    log::warn!("managed merge failed because {}", redacted(&error));
                    continue;
                }
            };
            rings.spawn_idle(due, |ring| {
                let merge = merge.clone();
                async move {
                    merge.merge_ring_logged(ring).await;
                }
            });
        }
    }
}

impl<S: TransactionSource> ManagedMerge<S> {
    /// At most one merge for each wallet and mint, a failed ring or wallet only logs.
    pub async fn merge_due(&self) -> Result<Vec<RelayId>, RingRpcError> {
        let mut sent = Vec::new();
        for ring in self.due_rings().await? {
            sent.extend(self.merge_ring_logged(ring).await);
        }
        Ok(sent)
    }

    async fn due_rings(&self) -> Result<Vec<Address>, RingRpcError> {
        self.hub.shared().merge_settings()?.rings().await
    }

    async fn merge_ring_logged(&self, ring: Address) -> Vec<RelayId> {
        let merged = match self.hub.shared().merge_settings() {
            Ok(book) => self.merge_ring(&book, ring).await,
            Err(error) => Err(error),
        };
        merged.unwrap_or_else(|error| {
            log::warn!(
                "managed merge of ring {ring} failed because {}",
                redacted(&error)
            );
            Vec::new()
        })
    }

    /// An enrolled wallet's secret opens from its credential on every ring.
    async fn merge_ring(
        &self,
        book: &MergeSettingsBook<'_>,
        ring: Address,
    ) -> Result<Vec<RelayId>, RingRpcError> {
        let service = self.hub.service(Some(ring))?;
        let shared = self.hub.shared();
        if service.served_config().await?.is_none() {
            return Ok(Vec::new());
        }
        let pass = RingPass {
            service,
            assets: shared.due_assets().await,
            held: self.held_inputs(ring).await?,
        };
        let mut sent = Vec::new();
        for wallet in book.active(ring).await? {
            match self.merge_wallet(&pass, wallet).await {
                Ok(Some(relay_id)) => sent.push(relay_id),
                Ok(None) => {}
                Err(error) => log::warn!(
                    "managed merge of {} on ring {ring} failed because {}",
                    wallet.owner,
                    redacted(&error)
                ),
            }
        }
        Ok(sent)
    }

    /// A failed merge frees its inputs, a confirmed one once the ring history spends them.
    async fn held_inputs(&self, ring: Address) -> Result<HashSet<[u8; 32]>, RingRpcError> {
        let synced = self.hub.shared().store(ring);
        let inputs = self.relay.merge_inputs();
        let (settled, held): (Vec<HeldInput>, Vec<HeldInput>) = inputs
            .held(&ring)
            .await?
            .into_iter()
            .partition(|input| match input.phase {
                RelayPhase::Pending => false,
                RelayPhase::Confirmed => synced.is_spent(&input.nullifier),
                RelayPhase::Failed => true,
            });
        let settled: Vec<[u8; 32]> = settled.iter().map(|input| input.nullifier).collect();
        inputs.release(&settled).await?;
        Ok(held.iter().map(|input| input.nullifier).collect())
    }

    async fn merge_wallet(
        &self,
        pass: &RingPass<S>,
        wallet: WalletMergeSettings,
    ) -> Result<Option<RelayId>, RingRpcError> {
        let Some(target) = MergeTarget::of(&wallet.settings) else {
            return Ok(None);
        };
        let ring = pass.service.ring();
        let owner_key = wallet.owner.to_bytes();
        // 1. The secret opens to the nullifier key the registry record binds.
        let Some(nullifier_key) = pass.service.held_nullifier_key(&owner_key)? else {
            return Ok(None);
        };
        let notes = self
            .hub
            .shared()
            .store(ring)
            .spendable(SpendableNotes {
                ring,
                owner_key,
                mint: pass.assets.registry().mint(&wallet.settings.mint.0)?,
                nullifier_key: &nullifier_key,
            })
            .await?;
        // 2. Each candidate is unspent and held by no merge in the store.
        let notes: Vec<WalletUtxo> = notes
            .into_iter()
            .filter(|note| !pass.held.contains(&note.nullifier))
            .collect();
        let Some(inputs) = target.plan(&notes) else {
            return Ok(None);
        };
        // 3. The secret leaves memory once the merge is proven.
        let nullifiers: Vec<[u8; 32]> = inputs.iter().map(|input| input.nullifier).collect();
        let built = self
            .builder
            .build(OwnerMerge {
                ring,
                owner: wallet.owner,
                nullifier_key: &nullifier_key,
                inputs,
            })
            .await?;
        drop(nullifier_key);
        // 4. A merge demands no co-signer, the inputs stay held until the relay fails or the ring history spends them.
        let relay_id = self
            .relay
            .send_merge(HeldMerge {
                ring,
                message: built.message,
                last_valid_block_height: built.last_valid_block_height,
                co_signature: None,
                nullifiers,
            })
            .await?;
        Ok(Some(relay_id))
    }
}

impl<S: TransactionSource> Hub<S> {
    /// A replay or a request not later than the stored one fails.
    pub async fn set_merge_settings(
        &self,
        request: &SetMergeSettingsRequest,
    ) -> Result<SetMergeSettingsResponse, RingRpcError> {
        let shared = self.shared();
        let book = shared.merge_settings()?;
        let ring = request.ring.0;
        let owner = request.owner.0;
        let attestation = MergeSettingsAttestation {
            target: self.service(Some(ring))?.read_target(),
            owner,
            settings: request.settings,
        };
        let now = shared.clock.now()?;
        let nonce = WalletCheck {
            wallet: owner,
            signature: &request.signature,
            timestamp: request.timestamp,
            nonce: &request.nonce,
            attestation: &attestation,
            now,
        }
        .decide()?;
        shared
            .replay
            .accept(ReplayCheck {
                ring,
                nonce,
                timestamp: request.timestamp,
                now,
            })
            .await?;
        let saved = book
            .save(SignedMergeSettings {
                ring,
                owner,
                settings: &request.settings,
                signed_at: request.timestamp,
            })
            .await?;
        if !saved {
            return Err(RingRpcError::StaleMergeSettings);
        }
        Ok(request.settings)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use custom_ring_interface::RingMode;
    use solana_hash::Hash;
    use solana_keypair::Keypair;
    use solana_signature::Signature;
    use solana_signer::Signer;
    use solana_transaction::versioned::VersionedTransaction;
    use spr_client::{
        compile_message, ClientError, ComputeBudgetConfig, GetShieldedTransactionsByTagsResponse,
    };
    use spr_keypair::X25519Keypair;
    use spr_transaction::{Data, Mint, Utxo};
    use zolana_ring_client::{
        rpc::{unix_now, MergeSettingsRequest, ReadTarget, RingChainStatus, SignedRequest},
        AuditError, CreatedUtxo, KnownUtxo, MergeAuditPage, RingIndexerError, RingOrigin,
        UtxoOwner,
    };
    use zolana_ring_indexer::rpc::{
        GetStorageMemberOpeningsRequest, GetStorageMemberOpeningsResponse,
        GetStorageMemberRecordsRequest, GetStorageMemberRecordsResponse,
    };

    use spr_indexer_api::{Context, TransactionEvents};
    use spr_transaction::ShieldedTransaction;

    use super::*;
    use crate::{
        credentials::HeldCredential,
        credentials::{fixture::Enrollment, CredentialPda},
        database::Store,
        hub::ServiceIdentity,
        landing::{ChainOutcome, ChainSubmit, LatestBlockhash},
        relay::RelayParts,
        relay_prover::{DelegateSeal, ProvenRelay, RelayParties, RelayProofRequest, RelayProver},
        upstream::{
            DepositHistory, DepositPage, MergeAuditRequest, RecordsTip, RingConfiguration,
            RingFrame, RingHistoryPage, TransactionPage,
        },
        utxos::CreatedIn,
    };

    pub(crate) const RING: Address = Address::new_from_array([8; 32]);
    pub(crate) const GENESIS: [u8; 32] = [3; 32];
    pub(crate) const MINT: Address = Address::new_from_array([6; 32]);
    pub(crate) fn fee_payer() -> Keypair {
        Keypair::new_from_array([5; 32])
    }
    const LAST_VALID_BLOCK_HEIGHT: u64 = 100;

    pub(crate) struct EscrowRingSource {
        config: RingConfiguration,
        pub(crate) origins: Mutex<HashMap<Signature, RingOrigin>>,
        /// Enroll events under the credential tag, each with its owner account.
        pub(crate) enrollments: Mutex<Vec<(ShieldedTransaction, Address)>>,
    }

    fn unused<T>() -> Result<T, ClientError> {
        Err(ClientError::Rpc("unused source".to_owned()))
    }

    impl TransactionSource for EscrowRingSource {
        async fn salted_list_writers(&self, _ring: Address) -> Result<Vec<Address>, ClientError> {
            Ok(vec![list_writer().pubkey()])
        }

        /// One terminal page of the enrollments after the position.
        async fn transactions_by_tag(
            &self,
            request: TransactionPage,
        ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
            if request.tag != CredentialPda::of(&RING).expect("pda").view_tag() {
                return unused();
            }
            let filters = request.position.filters();
            let data = self
                .enrollments
                .lock()
                .expect("enrollments")
                .iter()
                .filter(|(event, _)| filters.slot.contains(event.slot))
                .map(|(event, _)| TransactionEvents {
                    slot: event.slot,
                    signature: event.tx_signature,
                    events: vec![event.clone()],
                })
                .collect();
            Ok(GetShieldedTransactionsByTagsResponse {
                context: Context {
                    slot: 1_000,
                    block_time: 0,
                },
                output_tree_id: None,
                data,
                pagination_token: None,
            })
        }

        async fn transaction_accounts(
            &self,
            signature: Signature,
        ) -> Result<Vec<Address>, ClientError> {
            let enrollments = self.enrollments.lock().expect("enrollments");
            Ok(enrollments
                .iter()
                .filter(|(event, _)| event.tx_signature == signature)
                .map(|(_, owner)| *owner)
                .collect())
        }

        async fn ring_frame(
            &self,
            _frame: RingFrame,
        ) -> Result<Vec<spr_transaction::ShieldedTransaction>, ClientError> {
            unused()
        }

        async fn ring_history(
            &self,
            _request: RingHistoryPage,
        ) -> Result<GetShieldedTransactionsByTagsResponse, ClientError> {
            unused()
        }

        async fn merge_audit_page(
            &self,
            _request: MergeAuditRequest<'_>,
        ) -> Result<MergeAuditPage, AuditError> {
            Err(AuditError::InvalidMemberRegistry)
        }

        async fn transaction_origin(
            &self,
            signature: Signature,
            _event_index: u16,
            _ring: Address,
        ) -> Result<RingOrigin, AuditError> {
            let origins = self.origins.lock().expect("origins");
            origins
                .get(&signature)
                .cloned()
                .ok_or_else(|| AuditError::Unavailable {
                    signature,
                    message: "unused source".to_owned(),
                })
        }

        async fn ring_deposits(&self, _page: DepositPage) -> Result<DepositHistory, ClientError> {
            unused()
        }

        async fn ring_config(
            &self,
            _ring: Address,
        ) -> Result<Option<RingConfiguration>, ClientError> {
            Ok(Some(self.config))
        }

        async fn ring_chain_status(&self, _ring: Address) -> Result<RingChainStatus, ClientError> {
            unused()
        }

        async fn slot(&self) -> Result<u64, ClientError> {
            unused()
        }

        async fn records_root(&self, _ring: Address) -> Result<RecordsTip, ClientError> {
            unused()
        }

        async fn storage_member_openings(
            &self,
            _request: GetStorageMemberOpeningsRequest,
        ) -> Result<GetStorageMemberOpeningsResponse, RingIndexerError> {
            Ok(unused()?)
        }

        async fn storage_member_records(
            &self,
            _request: GetStorageMemberRecordsRequest,
        ) -> Result<GetStorageMemberRecordsResponse, RingIndexerError> {
            Ok(unused()?)
        }

        async fn upgrade_authority(
            &self,
            _program: Address,
        ) -> Result<Option<Address>, ClientError> {
            unused()
        }

        async fn health(&self) -> Result<(), ClientError> {
            Ok(())
        }

        async fn genesis_hash(&self) -> Result<[u8; 32], ClientError> {
            Ok(GENESIS)
        }

        async fn tree_id(&self, _tree: Address) -> Result<u16, custom_ring_sdk::RingError> {
            Ok(1)
        }

        async fn ring_assets(&self) -> Result<RingAssets, ClientError> {
            Ok(assets())
        }
    }

    #[derive(Default)]
    struct RecordingBuilder {
        owners: Mutex<Vec<(Address, usize)>>,
    }

    #[async_trait]
    impl MergeBuilder for RecordingBuilder {
        async fn build(&self, merge: OwnerMerge<'_>) -> Result<BuiltMerge, RingRpcError> {
            let mut owners = self.owners.lock().expect("owners");
            owners.push((merge.owner, merge.inputs.len()));
            let blockhash = Hash::new_from_array([u8::try_from(owners.len()).expect("builds"); 32]);
            Ok(BuiltMerge {
                message: compile_message(
                    &fee_payer().pubkey(),
                    &[],
                    blockhash,
                    ComputeBudgetConfig::new(400_000),
                )?,
                last_valid_block_height: LAST_VALID_BLOCK_HEIGHT,
            })
        }
    }

    /// No outcome until a test sets one, a send fails while `down`.
    pub(crate) struct ScriptedChain {
        height: Mutex<u64>,
        pub(crate) outcome: Mutex<Option<ChainOutcome>>,
        sent: Mutex<usize>,
        pub(crate) down: Mutex<bool>,
    }

    impl Default for ScriptedChain {
        fn default() -> Self {
            Self {
                height: Mutex::new(1),
                outcome: Mutex::new(None),
                sent: Mutex::new(0),
                down: Mutex::new(false),
            }
        }
    }

    #[async_trait]
    impl ChainSubmit for ScriptedChain {
        async fn simulate(
            &self,
            _message: &solana_message::VersionedMessage,
        ) -> Result<crate::landing::Simulation, RingRpcError> {
            Ok(crate::landing::Simulation::Passed)
        }

        async fn account_data(
            &self,
            _address: solana_address::Address,
        ) -> Result<Option<Vec<u8>>, RingRpcError> {
            Ok(None)
        }

        async fn rent_exempt_lamports(&self, _data_len: usize) -> Result<u64, RingRpcError> {
            Ok(0)
        }

        async fn slot(&self) -> Result<u64, RingRpcError> {
            Ok(1)
        }

        async fn latest_blockhash(&self) -> Result<LatestBlockhash, RingRpcError> {
            Ok((Hash::new_from_array([4; 32]), LAST_VALID_BLOCK_HEIGHT).into())
        }

        async fn block_height(&self) -> Result<u64, RingRpcError> {
            Ok(*self.height.lock().expect("height"))
        }

        async fn send(&self, _transaction: &VersionedTransaction) -> Result<(), RingRpcError> {
            if *self.down.lock().expect("down") {
                return Err(RingRpcError::Upstream(ClientError::Rpc("down".to_owned())));
            }
            *self.sent.lock().expect("sent") += 1;
            Ok(())
        }

        async fn outcome(
            &self,
            _signature: Signature,
        ) -> Result<Option<ChainOutcome>, RingRpcError> {
            Ok(self.outcome.lock().expect("outcome").clone())
        }
    }

    struct UnusedProver;

    #[async_trait]
    impl RelayProver for UnusedProver {
        async fn check_enrollment(
            &self,
            _enrollment: &zolana_ring_client::rpc::RelayEnrollInputs,
        ) -> Result<(), RingRpcError> {
            Err(RingRpcError::StateUnavailable)
        }

        async fn prove(
            &self,
            _request: RelayProofRequest<'_>,
        ) -> Result<ProvenRelay, RingRpcError> {
            Err(RingRpcError::StateUnavailable)
        }

        async fn seal_delegate(
            &self,
            _seal: DelegateSeal<'_>,
            _parties: RelayParties,
        ) -> Result<zolana_ring_client::rpc::RelayProofInputs, RingRpcError> {
            Err(RingRpcError::StateUnavailable)
        }
    }

    fn assets() -> RingAssets {
        RingAssets::new([Mint::new(MINT, 7)]).expect("assets")
    }

    pub(crate) fn list_writer() -> Keypair {
        Keypair::new_from_array([23; 32])
    }

    /// A zero lead byte as `RegisterKey` proves.
    pub(crate) const LIST_SALT: [u8; 32] = {
        let mut salt = [9; 32];
        salt[0] = 0;
        salt
    };

    pub(crate) struct Fixture {
        pub(crate) hub: Arc<Hub<EscrowRingSource>>,
        builder: Arc<RecordingBuilder>,
        chain: Arc<ScriptedChain>,
    }

    impl Fixture {
        async fn new() -> Self {
            Self::on(Store::open("sqlite::memory:", 1).await.expect("store")).await
        }

        async fn on(store: Store) -> Self {
            let chain = Arc::new(ScriptedChain::default());
            let parts = RelayParts {
                store,
                prover: Arc::new(UnusedProver),
                fee_payer: fee_payer(),
                chain: chain.clone(),
            };
            Self {
                chain,
                ..Self::serving(None, Some(parts)).await
            }
        }

        pub(crate) async fn serving(delegate: Option<Address>, relay: Option<RelayParts>) -> Self {
            let auditor = X25519Keypair::new();
            let source = EscrowRingSource {
                config: RingConfiguration {
                    auditor_pubkey: auditor.pubkey(),
                    roles: custom_ring_interface::RingRoles {
                        policy: Address::new_from_array([2; 32]),
                        ..bytemuck::Zeroable::zeroed()
                    },
                    mode: RingMode::Confidential,
                    delegate,
                },
                origins: Mutex::default(),
                enrollments: Mutex::default(),
            };
            let store = match &relay {
                Some(relay) => relay.store.clone(),
                None => Store::open("sqlite::memory:", 1).await.expect("store"),
            };
            let identity = ServiceIdentity {
                genesis_hash: GENESIS,
                service: Keypair::new(),
            };
            let mut builder = Hub::builder(source, identity)
                .with_store(store)
                .with_co_signer(Keypair::new())
                .with_co_signer_approval(crate::cosign::CoSignerApproval::new([
                    crate::cosign::ApproveClass::Transfers,
                ]));
            if let Some(relay) = relay {
                builder = builder.with_relay(relay).with_relay_budget(
                    crate::relay_reservations::RelayBudget {
                        total_lamports: 1_000_000,
                        signer_lamports: 1_000_000,
                    },
                );
            }
            let hub = builder.local(RING, auditor).expect("hub");
            Self {
                hub: Arc::new(hub),
                builder: Arc::default(),
                chain: Arc::default(),
            }
        }

        /// A finalized Enroll of `wallet` at `slot`, sealed to the served auditor.
        pub(crate) fn enroll(
            &self,
            wallet: &Keypair,
            key: &NullifierKey,
            slot: u8,
        ) -> HeldCredential {
            let auditor = self
                .hub
                .service(Some(RING))
                .expect("service")
                .auditor_pubkey();
            let enrollment = Enrollment {
                ring: RING,
                owner: wallet.pubkey(),
                key,
                list_salt: LIST_SALT,
                auditor: &auditor,
                signature: Signature::from([slot; 64]),
                slot: u64::from(slot),
            };
            let credential = enrollment.credential();
            let event = enrollment.event_of(&credential);
            self.hub
                .shared()
                .source
                .enrollments
                .lock()
                .expect("enrollments")
                .push((event, wallet.pubkey()));
            enrollment.held(credential)
        }

        pub(crate) async fn escrow_notes(&self, wallet: &Keypair, notes: u8) -> NullifierKey {
            self.escrow_wallets(&[(wallet, notes)]).await.remove(0)
        }

        /// Held before any scan, a merge pass opens only held credentials.
        pub(crate) async fn escrow_wallets(&self, wallets: &[(&Keypair, u8)]) -> Vec<NullifierKey> {
            let store = self.hub.shared().store(RING);
            let mut keys = Vec::with_capacity(wallets.len());
            for (wallet, notes) in wallets {
                let key = NullifierKey::from_secret([wallet.pubkey().to_bytes()[0]; 31]);
                // Slots rise in enrollment order, a scan refuses a page out of order.
                let enrolled = self
                    .hub
                    .shared()
                    .source
                    .enrollments
                    .lock()
                    .expect("enrollments")
                    .len();
                let slot = u8::try_from(enrolled + 1).expect("few enrollments");
                let held = self.enroll(wallet, &key, slot);
                store
                    .admit_credentials(vec![held])
                    .expect("held credential");
                self.record_notes(wallet, &key, *notes).await;
                keys.push(key);
            }
            keys
        }

        async fn record_notes(&self, wallet: &Keypair, key: &NullifierKey, notes: u8) {
            let store = self.hub.shared().store(RING);
            let owner_key = wallet.pubkey().to_bytes();
            let nullifier_pk = key.pubkey().expect("nullifier pk");
            let asset = *assets().fields().next().expect("field");
            // The delegate path rebuilds each opening's hash, a stand in commitment would fail it.
            let commitment = |index: u8| {
                Utxo {
                    owner: spr_keypair::PublicKey::from_ed25519(&owner_key),
                    asset: Mint::new(MINT, 7),
                    amount: 10,
                    blinding: [index; 32],
                    ring_program_id: Some(RING),
                    data: Data::default(),
                }
                .hash(&nullifier_pk, &[0; 32], &[0; 32], 1)
                .expect("commitment")
            };
            store
                .record(
                    CreatedIn {
                        slot: 1,
                        tx_signature: Signature::from([7; 64]),
                        event_index: 0,
                    },
                    (0..notes).map(|index| CreatedUtxo {
                        commitment: commitment(index),
                        slot_index: u32::from(index),
                        leaf_index: u64::from(index),
                        utxo: KnownUtxo {
                            owner_key,
                            owner: UtxoOwner::Keyed { nullifier_pk },
                            asset: asset.0,
                            mint: Some(MINT),
                            amount: 10,
                            blinding: [index; 32],
                            data_hash: [0; 32],
                            ring_data_hash: [0; 32],
                            tree_id: 1,
                        },
                        ring_note: true,
                    }),
                )
                .await;
        }

        async fn settle(&self, wallet: &Keypair, target_note_count: u32) {
            let target = ReadTarget {
                cluster: GENESIS,
                service: self.hub.service_pubkey(),
                ring: RING,
            };
            let request: MergeSettingsRequest = SignedRequest::new(MergeSettingsAttestation {
                target,
                owner: wallet.pubkey(),
                settings: MergeSettings {
                    mint: MINT.into(),
                    target_note_count,
                    min_average_amount: 0,
                },
            });
            let signed = request
                .at(unix_now().expect("clock"))
                .sign(wallet)
                .expect("signed settings");
            self.hub
                .set_merge_settings(&signed)
                .await
                .expect("stored settings");
        }

        async fn merge_due(&self) -> Vec<RelayId> {
            ManagedMergeInit {
                hub: self.hub.clone(),
                builder: self.builder.clone(),
                relay: self.relay().clone(),
            }
            .build()
            .merge_due()
            .await
            .expect("merge pass")
        }

        fn relay(&self) -> &Arc<Relay> {
            self.hub.relay().expect("relay")
        }

        async fn track(&self) {
            self.relay().track().await.expect("tracked relays");
        }

        async fn held(&self) -> Vec<HeldInput> {
            self.relay()
                .merge_inputs()
                .held(&RING)
                .await
                .expect("held inputs")
        }
    }

    #[tokio::test]
    async fn a_wallet_above_its_target_count_is_merged() {
        let fixture = Fixture::new().await;
        let wallet = Keypair::new_from_array([11; 32]);
        fixture.escrow_notes(&wallet, 3).await;
        fixture.settle(&wallet, 1).await;

        assert_eq!(fixture.merge_due().await.len(), 1);
        assert_eq!(*fixture.chain.sent.lock().expect("sent"), 1);
        assert_eq!(
            *fixture.builder.owners.lock().expect("owners"),
            vec![(wallet.pubkey(), 3)]
        );
    }

    #[tokio::test]
    async fn a_wallet_without_settings_is_left_alone() {
        let fixture = Fixture::new().await;
        let settled = Keypair::new_from_array([11; 32]);
        let unsettled = Keypair::new_from_array([12; 32]);
        fixture.escrow_notes(&settled, 1).await;
        fixture.escrow_notes(&unsettled, 3).await;
        fixture.settle(&settled, 1).await;

        assert!(fixture.merge_due().await.is_empty());
        assert_eq!(*fixture.chain.sent.lock().expect("sent"), 0);
    }

    #[tokio::test]
    async fn a_dropped_merge_frees_its_notes_after_expiry() {
        let fixture = Fixture::new().await;
        let wallet = Keypair::new_from_array([11; 32]);
        fixture.escrow_notes(&wallet, 3).await;
        fixture.settle(&wallet, 1).await;
        assert_eq!(fixture.merge_due().await.len(), 1);
        assert!(fixture.merge_due().await.is_empty());

        *fixture.chain.height.lock().expect("height") = LAST_VALID_BLOCK_HEIGHT + 1;
        fixture.track().await;

        assert_eq!(fixture.merge_due().await.len(), 1);
        assert_eq!(*fixture.chain.sent.lock().expect("sent"), 2);
    }

    #[tokio::test]
    async fn a_confirmed_merge_holds_nothing_once_its_spend_syncs() {
        let fixture = Fixture::new().await;
        let wallet = Keypair::new_from_array([11; 32]);
        fixture.escrow_notes(&wallet, 3).await;
        fixture.settle(&wallet, 1).await;
        assert_eq!(fixture.merge_due().await.len(), 1);
        *fixture.chain.outcome.lock().expect("outcome") = Some(ChainOutcome::Confirmed { slot: 5 });
        fixture.track().await;
        // The backfill has not seen the spend, the notes still read as spendable.
        assert!(fixture.merge_due().await.is_empty());

        let spent: Vec<[u8; 32]> = fixture
            .held()
            .await
            .iter()
            .map(|input| input.nullifier)
            .collect();
        assert_eq!(spent.len(), 3);
        fixture.hub.shared().store(RING).spend(spent).await;

        assert!(fixture.merge_due().await.is_empty());
        assert!(fixture.held().await.is_empty());
    }

    #[tokio::test]
    async fn a_restart_resends_the_stored_merge_and_builds_no_second_one() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let before = Fixture::on(store.clone()).await;
        let wallet = Keypair::new_from_array([11; 32]);
        before.escrow_notes(&wallet, 3).await;
        before.settle(&wallet, 1).await;
        *before.chain.down.lock().expect("down") = true;
        assert!(before.merge_due().await.is_empty());

        let after = Fixture::on(store).await;
        after.escrow_notes(&wallet, 3).await;
        assert!(after.merge_due().await.is_empty());
        after.track().await;

        assert!(after.builder.owners.lock().expect("owners").is_empty());
        assert_eq!(*after.chain.sent.lock().expect("sent"), 1);
    }

    #[tokio::test]
    async fn a_restart_releases_orphaned_merge_inputs_after_finalized_expiry() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let before = Fixture::on(store.clone()).await;
        let wallet = Keypair::new_from_array([11; 32]);
        before.escrow_notes(&wallet, 3).await;
        before.settle(&wallet, 1).await;
        assert_eq!(before.merge_due().await.len(), 1);
        drop(before);

        let after = Fixture::on(store).await;
        *after.chain.height.lock().expect("height") = LAST_VALID_BLOCK_HEIGHT;
        after.track().await;
        let held = after.held().await;
        assert_eq!(held.len(), 3);
        assert!(held.iter().all(|input| input.phase == RelayPhase::Pending));

        *after.chain.height.lock().expect("height") = LAST_VALID_BLOCK_HEIGHT + 1;
        after.track().await;
        let managed = ManagedMergeInit {
            hub: after.hub.clone(),
            builder: after.builder.clone(),
            relay: after.relay().clone(),
        }
        .build();
        assert!(managed
            .held_inputs(RING)
            .await
            .expect("held inputs")
            .is_empty());
        assert!(after.held().await.is_empty());
    }
}
