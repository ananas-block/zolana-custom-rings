use async_trait::async_trait;
use custom_ring_sdk::{DelegatePayment, DelegateSourceError, ResolvedSource, SourceEnrollment};
use jsonrpsee::types::ErrorObjectOwned;
use solana_address::Address;
use spr_indexer_api::Hash;
use spr_keypair::{NullifierKey, ShieldedAddress};
use thiserror::Error;
use zolana_ring_client::rpc::{
    AuthorityTransferAttestation, DelegateNotesAttestation, GetDelegateNotesRequest,
    GetDelegateNotesResponse, GetListSaltRequest, GetListSaltResponse, ListSaltAttestation,
    PrepareAuthorityTransferRequest, RelayStep,
};

use crate::{
    audit::{AuditService, WALLET_NOTE_PAGE_LIMIT},
    authorize::WalletCheck,
    error::RingRpcError,
    hub::Hub,
    relay_prover::{DelegateSeal, SealedSource},
    replay::ReplayCheck,
    upstream::TransactionSource,
    utxos::{SpendableNotes, WalletStatusQuery},
};

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
#[repr(i32)]
pub enum AuthorityTransferError {
    #[error("the signer is not the ring delegate")]
    NotDelegate = -32220,
    #[error("the ring seals its keys to another auditor")]
    ForeignAuditor = -32221,
    #[error("the source wallet has no enrolled nullifier key")]
    SourceUnescrowed = -32222,
    #[error("the source address names another nullifier key")]
    SourceKey = -32223,
    #[error("the service runs no relay")]
    RelayUnavailable = -32224,
    #[error("the transaction key is not a clamped X25519 secret")]
    TxViewingKey = -32225,
    #[error("the signer writes no salted list of the ring")]
    NotListWriter = -32226,
    #[error("a stored note of the source belongs to another owner or key")]
    SourceNote = -32227,
}

impl AuthorityTransferError {
    pub const fn code(self) -> i32 {
        self as i32
    }
}

impl From<AuthorityTransferError> for ErrorObjectOwned {
    fn from(error: AuthorityTransferError) -> Self {
        Self::owned(error.code(), error.to_string(), None::<()>)
    }
}

impl From<DelegateSourceError> for RingRpcError {
    fn from(error: DelegateSourceError) -> Self {
        match error {
            DelegateSourceError::Unenrolled => AuthorityTransferError::SourceUnescrowed.into(),
            DelegateSourceError::KeyMismatch => AuthorityTransferError::SourceKey.into(),
            DelegateSourceError::ForeignNote { .. } => AuthorityTransferError::SourceNote.into(),
            DelegateSourceError::SealMismatch => Self::TrackedKey,
            DelegateSourceError::Keypair(error) => error.into(),
            DelegateSourceError::Client(error) => error.into(),
            DelegateSourceError::Seal(error) => error.into(),
        }
    }
}

struct TrackedEnrollment<'a, S> {
    service: &'a AuditService<S>,
}

#[async_trait]
impl<S: TransactionSource> SourceEnrollment for TrackedEnrollment<'_, S> {
    type Error = RingRpcError;

    async fn escrowed_key(
        &self,
        source: &ShieldedAddress,
    ) -> Result<Option<NullifierKey>, RingRpcError> {
        let owner_key = source
            .solana_address()
            .map_err(|_| AuthorityTransferError::SourceUnescrowed)?
            .to_bytes();
        self.service.held_nullifier_key(&owner_key)
    }
}

impl<S: TransactionSource> Hub<S> {
    /// The chain names the delegate, only its signature reads a victim's secret and openings.
    pub async fn delegate_notes(
        &self,
        request: &GetDelegateNotesRequest,
    ) -> Result<GetDelegateNotesResponse, RingRpcError> {
        let (ring, delegate, owner) = (request.ring.0, request.delegate.0, request.owner.0);
        let cursor = request
            .cursor
            .as_ref()
            .map(|cursor| <[u8; 32]>::try_from(cursor.0.as_slice()))
            .transpose()
            .map_err(|_| RingRpcError::InvalidCursor)?;
        let service = self.service(Some(ring))?;
        let shared = self.shared();
        let now = shared.clock.now()?;
        // 1. The named key signed the read for the service and ring.
        let nonce = WalletCheck {
            wallet: delegate,
            signature: &request.signature,
            timestamp: request.timestamp,
            nonce: &request.nonce,
            attestation: &DelegateNotesAttestation {
                target: service.read_target(),
                delegate,
                owner,
                cursor: request.cursor.clone(),
            },
            now,
        }
        .decide()?;
        // 2. The config names the key its delegate under the auditor key held here.
        let config = shared
            .source
            .ring_config(ring)
            .await?
            .filter(|config| config.delegate == Some(delegate))
            .ok_or(AuthorityTransferError::NotDelegate)?;
        if config.auditor_pubkey != service.auditor_pubkey() {
            return Err(AuthorityTransferError::ForeignAuditor.into());
        }
        shared
            .replay
            .accept(ReplayCheck {
                ring,
                nonce,
                timestamp: request.timestamp,
                now,
            })
            .await?;
        // 3. The secret opens to the key the owner's record binds, it stays out of the store.
        let nullifier_secret = service
            .held_nullifier_key(&owner.to_bytes())?
            .map(|key| spr_hasher::primitives::right_align(&key.secret()).into());
        let enrollment = shared.source.tracking_enrollment(ring, owner).await?;
        Ok(GetDelegateNotesResponse {
            nullifier_secret,
            status: shared.store(ring).wallet_status(WalletStatusQuery {
                enrollment,
                wallet: owner,
                after: cursor,
                limit: WALLET_NOTE_PAGE_LIMIT,
            }),
        })
    }

    /// An owner dodging a block need not hand over an address.
    pub async fn list_salt(
        &self,
        request: &GetListSaltRequest,
    ) -> Result<GetListSaltResponse, RingRpcError> {
        let (ring, writer, owner) = (request.ring.0, request.writer.0, request.owner.0);
        let service = self.service(Some(ring))?;
        let shared = self.shared();
        let now = shared.clock.now()?;
        // 1. The named key signed the read for the service and ring.
        let nonce = WalletCheck {
            wallet: writer,
            signature: &request.signature,
            timestamp: request.timestamp,
            nonce: &request.nonce,
            attestation: &ListSaltAttestation {
                target: service.read_target(),
                writer,
                owner,
            },
            now,
        }
        .decide()?;
        // 2. The policy authority or the authority of a salted list's registry, under the auditor key held here.
        let config = shared
            .source
            .ring_config(ring)
            .await?
            .ok_or(AuthorityTransferError::NotListWriter)?;
        let writes = config.roles.policy == writer
            || shared
                .source
                .salted_list_writers(ring)
                .await?
                .contains(&writer);
        if !writes {
            return Err(AuthorityTransferError::NotListWriter.into());
        }
        if config.auditor_pubkey != service.auditor_pubkey() {
            return Err(AuthorityTransferError::ForeignAuditor.into());
        }
        shared
            .replay
            .accept(ReplayCheck {
                ring,
                nonce,
                timestamp: request.timestamp,
                now,
            })
            .await?;
        Ok(GetListSaltResponse {
            list_salt: service
                .credential_list_salt(&owner.to_bytes())
                .await?
                .map(Hash),
        })
    }

    /// A repeated request returns the stored relay step.
    pub async fn prepare_authority_transfer(
        &self,
        request: &PrepareAuthorityTransferRequest,
    ) -> Result<RelayStep, RingRpcError> {
        let relay = self
            .relay()
            .ok_or(AuthorityTransferError::RelayUnavailable)?;
        let (ring, delegate) = (request.ring.0, request.delegate.0);
        let transfer = &request.transfer;
        let service = self.service(Some(ring))?;
        let shared = self.shared();
        let now = shared.clock.now()?;
        // 1. The named key signed the transfer for the service and ring.
        let nonce = WalletCheck {
            wallet: delegate,
            signature: &request.signature,
            timestamp: request.timestamp,
            nonce: &request.nonce,
            attestation: &AuthorityTransferAttestation {
                target: service.read_target(),
                delegate,
                transfer: transfer.clone(),
            },
            now,
        }
        .decide()?;
        let tx_viewing_key = request
            .tx_viewing_key
            .key()
            .map_err(|_| AuthorityTransferError::TxViewingKey)?;
        let relay_id = request
            .relay_id()
            .map_err(|_| RingRpcError::StateUnavailable)?;
        if let Some(step) = relay.stored(&relay_id).await? {
            return Ok(step);
        }
        // 2. The config names the key its delegate and the auditor key held here.
        let config = shared.source.ring_config(ring).await?;
        let config = config
            .filter(|config| config.delegate == Some(delegate))
            .ok_or(AuthorityTransferError::NotDelegate)?;
        if config.auditor_pubkey != service.auditor_pubkey() {
            return Err(AuthorityTransferError::ForeignAuditor.into());
        }
        if !relay.holds(&relay_id).await? {
            shared
                .replay
                .accept(ReplayCheck {
                    ring,
                    nonce,
                    timestamp: request.timestamp,
                    now,
                })
                .await?;
        }
        // 3. Each source key is the public zero key or its escrowed key, and only its own notes follow.
        let assets = shared.due_assets().await;
        let mut mints: Vec<Address> = Vec::new();
        for payment in &transfer.payments {
            if !mints.contains(&payment.mint.0) {
                mints.push(payment.mint.0);
            }
        }
        let enrollment = TrackedEnrollment { service: &service };
        let mut sources = Vec::with_capacity(transfer.sources.len());
        for source in &transfer.sources {
            let source = source.0;
            let owner_key = source
                .solana_address()
                .map_err(|_| AuthorityTransferError::SourceUnescrowed)?
                .to_bytes();
            let resolved = ResolvedSource::resolve(source, &enrollment).await?;
            let mut notes = Vec::new();
            for mint in &mints {
                notes.extend(shared.store(ring).spendable(SpendableNotes {
                    ring,
                    owner_key,
                    mint: assets.registry().mint(mint)?,
                    nullifier_key: resolved.nullifier_key(),
                })?);
            }
            resolved.check_notes(&notes)?;
            sources.push(SealedSource {
                address: source,
                nullifier_key: resolved.into_nullifier_key(),
                notes,
            });
        }
        relay
            .prepare_delegated(
                relay_id,
                DelegateSeal {
                    ring,
                    delegate,
                    sources: &sources,
                    tx_viewing_key,
                    payments: transfer
                        .payments
                        .iter()
                        .map(|payment| DelegatePayment {
                            recipient: payment.recipient.0,
                            mint: payment.mint.0,
                            amount: payment.amount,
                        })
                        .collect(),
                    assets: assets.registry(),
                },
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use solana_instruction::{AccountMeta, Instruction};
    use solana_keypair::Keypair;
    use solana_message::VersionedMessage;
    use solana_signer::Signer;
    use spr_client::ComputeBudgetConfig;
    use spr_keypair::{NullifierKey, PublicKey, ShieldedAddress, ViewingKey, X25519Keypair};
    use spr_transaction::instructions::transact::ExternalData;
    use zolana_ring_client::rpc::{
        unix_now, AuthorityPayment, AuthorityTransfer, AuthorityTransferAttestation,
        AuthorityTransferRequest, ReadTarget, RelayProofInputs, RelayRail, SignedRequest,
    };

    use super::*;
    use crate::{
        database::Store,
        managed_merge::tests::{
            fee_payer, list_writer, Fixture, ScriptedChain, GENESIS, LIST_SALT, MINT, RING,
        },
        relay::{RelayParts, RelayPayload},
        relay_prover::{DelegateSeal, ProvenRelay, RelayParties, RelayProofRequest, RelayProver},
        relay_reservations::RelayReservations,
    };

    #[derive(Default)]
    struct SealingProver {
        sealed: Mutex<Vec<Sealed>>,
        proven: Mutex<Vec<(Address, [u8; 31])>>,
        frame: Mutex<Option<Vec<u8>>>,
    }

    struct Sealed {
        delegate: Address,
        /// One per source, in the request's order.
        secrets: Vec<[u8; 31]>,
        nullifiers: Vec<[u8; 32]>,
    }

    #[async_trait]
    impl RelayProver for SealingProver {
        async fn check_enrollment(
            &self,
            _enrollment: &zolana_ring_client::rpc::RelayEnrollInputs,
        ) -> Result<(), RingRpcError> {
            Err(RingRpcError::StateUnavailable)
        }

        async fn prove(&self, request: RelayProofRequest<'_>) -> Result<ProvenRelay, RingRpcError> {
            let RelayPayload::Transfer(proof_inputs) = request.payload else {
                panic!("an authority transfer proves a transfer");
            };
            let RelayRail::Delegate { delegate, .. } = proof_inputs.rail else {
                panic!("an authority transfer proves on the delegate rail");
            };
            self.proven
                .lock()
                .expect("proven")
                .push((delegate, *proof_inputs.nullifier_key.secret()));
            Ok(ProvenRelay {
                instruction: Instruction {
                    program_id: request.ring,
                    accounts: vec![
                        AccountMeta::new(request.parties.fee_payer, true),
                        AccountMeta::new_readonly(delegate, true),
                    ],
                    data: self
                        .frame
                        .lock()
                        .expect("frame")
                        .clone()
                        .unwrap_or_else(|| vec![21]),
                },
                budget: ComputeBudgetConfig::new(400_000),
                co_signers: Vec::new(),
                signers: vec![delegate],
            })
        }

        async fn seal_delegate(
            &self,
            seal: DelegateSeal<'_>,
            _parties: RelayParties,
        ) -> Result<RelayProofInputs, RingRpcError> {
            self.sealed.lock().expect("sealed").push(Sealed {
                delegate: seal.delegate,
                secrets: seal
                    .sources
                    .iter()
                    .map(|source| *source.nullifier_key.secret())
                    .collect(),
                nullifiers: seal
                    .sources
                    .iter()
                    .flat_map(|source| source.notes.iter().map(|note| note.nullifier))
                    .collect(),
            });
            let tx_viewing_key = seal.tx_viewing_key;
            Ok(RelayProofInputs {
                rail: RelayRail::Delegate {
                    delegate: seal.delegate,
                    plan: None,
                },
                ring_program_id: seal.ring,
                sender: seal.sources[0].address,
                nullifier_key: seal.sources[0].nullifier_key.clone(),
                co_owners: Vec::new(),
                approval_blinder: None,
                external_data: ExternalData::new(
                    *tx_viewing_key.pubkey().as_bytes(),
                    [0; 16],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
                tx_viewing_key,
                inputs: Vec::new(),
                outputs: Vec::new(),
                interface_transfer_accounts: Vec::new(),
                blinding_seed: [0; 32],
                output_tree_id: 1,
                list_salts: Vec::new(),
                wide_owners: false,
            })
        }
    }

    async fn served(delegate: Address) -> (Fixture, Arc<SealingProver>) {
        let prover = Arc::new(SealingProver::default());
        let relay = RelayParts {
            store: Store::open("sqlite::memory:", 1).await.expect("store"),
            prover: prover.clone(),
            fee_payer: fee_payer(),
            chain: Arc::new(ScriptedChain::default()),
        };
        (Fixture::serving(Some(delegate), Some(relay)).await, prover)
    }

    fn address(signing: &Keypair, nullifier_key: &NullifierKey) -> ShieldedAddress {
        ShieldedAddress {
            signing_pubkey: PublicKey::from_ed25519(signing.pubkey().as_array()),
            nullifier_pubkey: nullifier_key.pubkey().expect("nullifier pk"),
            viewing_pubkey: X25519Keypair::new().pubkey(),
        }
    }

    fn request(
        fixture: &Fixture,
        signer: &Keypair,
        source: ShieldedAddress,
    ) -> PrepareAuthorityTransferRequest {
        request_from(fixture, signer, &[source])
    }

    fn request_from(
        fixture: &Fixture,
        signer: &Keypair,
        sources: &[ShieldedAddress],
    ) -> PrepareAuthorityTransferRequest {
        let recipient = address(
            &Keypair::new_from_array([13; 32]),
            &NullifierKey::from_secret([13; 31]),
        );
        let request: AuthorityTransferRequest = SignedRequest::new(AuthorityTransferAttestation {
            target: ReadTarget {
                cluster: GENESIS,
                service: fixture.hub.service_pubkey(),
                ring: RING,
            },
            delegate: signer.pubkey(),
            transfer: AuthorityTransfer {
                sources: sources.iter().map(|source| (*source).into()).collect(),
                payments: vec![AuthorityPayment {
                    recipient: recipient.into(),
                    mint: MINT.into(),
                    amount: 15,
                }],
            },
        });
        request
            .at(unix_now().expect("clock"))
            .sign(signer, &ViewingKey::new())
            .expect("signed request")
    }

    #[tokio::test]
    async fn a_delegate_request_spends_the_source_notes_under_the_escrowed_key() {
        let delegate = Keypair::new_from_array([21; 32]);
        let (fixture, prover) = served(delegate.pubkey()).await;
        let wallet = Keypair::new_from_array([11; 32]);
        let escrowed = fixture.escrow_notes(&wallet, 2);

        let step = fixture
            .hub
            .prepare_authority_transfer(&request(&fixture, &delegate, address(&wallet, &escrowed)))
            .await
            .expect("prepared transfer");

        let RelayStep::SignMessage { message, .. } = step else {
            panic!("the delegate signs the authority transfer, got {step:?}");
        };
        let message: VersionedMessage = wincode::deserialize(&message.0).expect("message");
        assert!(message.static_account_keys().contains(&delegate.pubkey()));
        let [sealed] = std::mem::take(&mut *prover.sealed.lock().expect("sealed"))
            .try_into()
            .unwrap_or_else(|_| panic!("one seal"));
        assert_eq!(
            (sealed.delegate, sealed.secrets),
            (delegate.pubkey(), vec![*escrowed.secret()])
        );
        assert_eq!(sealed.nullifiers.len(), 2);
        assert_eq!(
            *prover.proven.lock().expect("proven"),
            [(delegate.pubkey(), *escrowed.secret())]
        );
    }

    /// The delegate's own wallet and another member's stand alike, each under its escrowed key.
    #[tokio::test]
    async fn a_delegate_request_names_its_own_and_another_members_notes() {
        let delegate = Keypair::new_from_array([21; 32]);
        let (fixture, prover) = served(delegate.pubkey()).await;
        let wallet = Keypair::new_from_array([11; 32]);
        let keys = fixture.escrow_wallets(&[(&delegate, 1), (&wallet, 2)]);
        let (own, other) = (&keys[0], &keys[1]);
        let sources = [address(&delegate, own), address(&wallet, other)];

        fixture
            .hub
            .prepare_authority_transfer(&request_from(&fixture, &delegate, &sources))
            .await
            .expect("prepared transfer");

        let [sealed] = std::mem::take(&mut *prover.sealed.lock().expect("sealed"))
            .try_into()
            .unwrap_or_else(|_| panic!("one seal"));
        assert_eq!(sealed.secrets, [*own.secret(), *other.secret()]);
        assert_eq!(sealed.nullifiers.len(), 3);

        let unescrowed = Keypair::new_from_array([12; 32]);
        let missing = address(&unescrowed, &NullifierKey::from_secret([12; 31]));
        assert!(fixture
            .hub
            .prepare_authority_transfer(&request_from(&fixture, &delegate, &[missing]))
            .await
            .is_err());
    }

    /// A retry of the signed request passes its own nonce, proves nothing and resumes the upload.
    #[tokio::test]
    async fn a_wide_delegate_frame_reserves_under_the_delegate_and_a_retry_resumes() {
        let delegate = Keypair::new_from_array([21; 32]);
        let prover = Arc::new(SealingProver::default());
        *prover.frame.lock().expect("frame") = Some(crate::relay::wide_frame::wide_frame(
            custom_ring_interface::tag::AUTHORITY_TRANSFER,
        ));
        let chain = Arc::new(ScriptedChain::default());
        *chain.outcome.lock().expect("outcome") =
            Some(crate::landing::ChainOutcome::Confirmed { slot: 1 });
        *chain.down.lock().expect("down") = true;
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let relay = RelayParts {
            store: store.clone(),
            prover: prover.clone(),
            fee_payer: fee_payer(),
            chain: chain.clone(),
        };
        let fixture = Fixture::serving(Some(delegate.pubkey()), Some(relay)).await;
        let wallet = Keypair::new_from_array([11; 32]);
        let escrowed = fixture.escrow_notes(&wallet, 2);
        let reservations = RelayReservations::new(store.connection());

        let stranger = Keypair::new_from_array([22; 32]);
        let foreign = request(&fixture, &stranger, address(&wallet, &escrowed));
        assert!(fixture
            .hub
            .prepare_authority_transfer(&foreign)
            .await
            .is_err());
        let foreign_id = foreign.relay_id().expect("relay id");
        assert!(reservations
            .by_relay(&foreign_id)
            .await
            .expect("read")
            .is_none());

        let signed = request(&fixture, &delegate, address(&wallet, &escrowed));
        let relay_id = signed.relay_id().expect("relay id");
        assert!(fixture
            .hub
            .prepare_authority_transfer(&signed)
            .await
            .is_err());
        let held = reservations
            .by_relay(&relay_id)
            .await
            .expect("read")
            .expect("reservation");
        assert_eq!(held.signer, delegate.pubkey());

        *chain.down.lock().expect("down") = false;
        let step = fixture
            .hub
            .prepare_authority_transfer(&signed)
            .await
            .expect("the retry");
        assert!(matches!(step, RelayStep::SignMessage { .. }), "{step:?}");
        assert_eq!(prover.proven.lock().expect("proven").len(), 1);
    }

    fn notes_request(
        fixture: &Fixture,
        signer: &Keypair,
        owner: Address,
    ) -> GetDelegateNotesRequest {
        SignedRequest::new(DelegateNotesAttestation {
            target: ReadTarget {
                cluster: GENESIS,
                service: fixture.hub.service_pubkey(),
                ring: RING,
            },
            delegate: signer.pubkey(),
            owner,
            cursor: None,
        })
        .at(unix_now().expect("clock"))
        .sign(signer)
        .expect("signed request")
    }

    #[tokio::test]
    async fn the_delegate_reads_the_secret_and_openings_and_another_key_nothing() {
        let delegate = Keypair::new_from_array([21; 32]);
        let (fixture, _prover) = served(delegate.pubkey()).await;
        let wallet = Keypair::new_from_array([11; 32]);
        let escrowed = fixture.escrow_notes(&wallet, 2);
        let read = fixture
            .hub
            .delegate_notes(&notes_request(&fixture, &delegate, wallet.pubkey()))
            .await
            .expect("delegate read");
        assert_eq!(
            read.nullifier_secret.expect("secret").0[1..],
            *escrowed.secret()
        );
        let impostor = Keypair::new_from_array([22; 32]);
        let refused = fixture
            .hub
            .delegate_notes(&notes_request(&fixture, &impostor, wallet.pubkey()))
            .await
            .expect_err("only the configured delegate reads");
        assert_eq!(ErrorObjectOwned::from(refused).code(), -32220);
    }

    fn salt_request(fixture: &Fixture, signer: &Keypair, owner: Address) -> GetListSaltRequest {
        SignedRequest::new(ListSaltAttestation {
            target: ReadTarget {
                cluster: GENESIS,
                service: fixture.hub.service_pubkey(),
                ring: RING,
            },
            writer: signer.pubkey(),
            owner,
        })
        .at(unix_now().expect("clock"))
        .sign(signer)
        .expect("signed request")
    }

    #[tokio::test]
    async fn a_list_writer_reads_the_credential_salt_and_another_key_nothing() {
        let (fixture, _prover) = served(Keypair::new_from_array([21; 32]).pubkey()).await;
        let wallet = Keypair::new_from_array([11; 32]);
        fixture.enroll(&wallet, &NullifierKey::from_secret([11; 31]), 1);
        let writer = list_writer();
        let read = fixture
            .hub
            .list_salt(&salt_request(&fixture, &writer, wallet.pubkey()))
            .await
            .expect("the writer reads");
        assert_eq!(read.list_salt.expect("salt").0, LIST_SALT);
        let impostor = Keypair::new_from_array([22; 32]);
        let refused = fixture
            .hub
            .list_salt(&salt_request(&fixture, &impostor, wallet.pubkey()))
            .await
            .expect_err("only a writer reads");
        assert_eq!(ErrorObjectOwned::from(refused).code(), -32226);
        // An owner held only by a tracking row has no credential, the salt reads nothing.
        let tracked = Keypair::new_from_array([12; 32]);
        fixture.escrow_notes(&tracked, 1);
        let none = fixture
            .hub
            .list_salt(&salt_request(&fixture, &writer, tracked.pubkey()))
            .await
            .expect("a complete scan without the credential reads nothing");
        assert_eq!(none.list_salt, None);
    }

    #[tokio::test]
    async fn a_request_signed_by_another_key_is_refused() {
        let delegate = Keypair::new_from_array([21; 32]);
        let (fixture, prover) = served(delegate.pubkey()).await;
        let wallet = Keypair::new_from_array([11; 32]);
        let escrowed = fixture.escrow_notes(&wallet, 2);
        let impostor = Keypair::new_from_array([22; 32]);

        let refused = fixture
            .hub
            .prepare_authority_transfer(&request(&fixture, &impostor, address(&wallet, &escrowed)))
            .await
            .expect_err("a key other than the delegate is refused");

        assert_eq!(ErrorObjectOwned::from(refused).code(), -32220);
        assert!(prover.sealed.lock().expect("sealed").is_empty());
    }
}
