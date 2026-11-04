//! Relayed transfers against a stub Ring RPC.

use std::sync::Mutex;

use async_trait::async_trait;
use custom_ring_interface::RingMode;
use solana_address::Address;
use spr_indexer_api::SerializablePubkey;
use spr_transaction::{instructions::transact::ConfidentialTransaction, Mint};
use zolana_ring_client::rpc::{
    GetRelayQuoteRequest, GetRelayStatusRequest, PrepareAuthorityTransferRequest,
    PrepareRelayRequest, RelayIntent, RelayProofInputs, RelayQuote, RelayStatus, RelayStep,
    SubmitRelayRequest, TokenAccountSetup,
};
use zolana_ring_keys::RingAddress;

use crate::tests::{
    pipeline_rules,
    support::{keypair, ring, ring_utxo, Chain, Registry, RingSettings},
};
use crate::{AnonymousPayment, CustomRingTransfer, CustomRingTransferInput, RingError, RingRelay};

#[derive(Default)]
struct StubRelay {
    prepared: Mutex<Vec<PrepareRelayRequest>>,
    asks_signature: bool,
    /// What a relay that asks returns, a garbled message unset.
    message: Vec<u8>,
    submitted: Mutex<Vec<SubmitRelayRequest>>,
}

#[async_trait]
impl RingRelay for StubRelay {
    async fn get_relay_quote(
        &self,
        _request: GetRelayQuoteRequest,
    ) -> Result<RelayQuote, RingError> {
        unreachable!("the test holds its quote")
    }

    async fn prepare_relay(&self, request: PrepareRelayRequest) -> Result<RelayStep, RingError> {
        let relay_id = request.relay_id()?;
        self.prepared.lock().unwrap().push(request);
        Ok(match self.asks_signature {
            true => RelayStep::SignMessage {
                relay_id,
                message: match self.message.is_empty() {
                    true => vec![1].into(),
                    false => self.message.clone().into(),
                },
            },
            false => RelayStep::Submitted { relay_id },
        })
    }

    async fn prepare_authority_transfer(
        &self,
        _request: PrepareAuthorityTransferRequest,
    ) -> Result<RelayStep, RingError> {
        unreachable!("the wallet names no delegate")
    }

    async fn submit_relay(&self, request: SubmitRelayRequest) -> Result<RelayStatus, RingError> {
        let signature = request.signature;
        self.submitted.lock().unwrap().push(request);
        Ok(RelayStatus::Sent { signature })
    }

    async fn get_relay_status(
        &self,
        _request: GetRelayStatusRequest,
    ) -> Result<RelayStatus, RingError> {
        unreachable!("the test reads no status")
    }
}

#[tokio::test]
async fn an_anonymous_relay_sends_no_path_or_record_request_and_signs_the_message_hash() {
    let sender = keypair(1);
    let recipient = keypair(2);
    let fee_payer = Address::new_from_array([0x44; 32]);
    let chain = Chain::ring(RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::Anonymous)
    })
    .with_registry(
        Registry::new(&[(&sender, 1), (&recipient, 1)]),
        &pipeline_rules(),
    );
    let transaction = ConfidentialTransaction::new_with_ring(
        vec![ring_utxo(&sender, Mint::SOL, 10, 0)],
        fee_payer,
        ring().program_id(),
    )
    .unwrap();
    let transfer = CustomRingTransfer::new(CustomRingTransferInput {
        ring: ring(),
        sender: &sender,
        nullifier_key: Some(&sender.nullifier_key),
        transaction,
    })
    .with_anonymous_signer(&sender.signing_key)
    .with_payment(AnonymousPayment {
        to: RingAddress {
            recipient: recipient.shielded_address().unwrap(),
            ring_program_id: ring().program_id(),
            list_salt: [7; 32],
        },
        asset: Mint::SOL,
        amount: 4,
        reply: None,
        data: crate::NoteData::default(),
    })
    .unwrap();
    let quote = RelayQuote {
        fee_payer: SerializablePubkey(fee_payer),
        valid_until_slot: u64::MAX,
    };
    let relay = StubRelay::default();
    let relay_id = transfer
        .prepare_relay(&chain, quote)
        .await
        .unwrap()
        .send(&relay)
        .await
        .unwrap()
        .submitted()
        .unwrap();

    assert!(chain.proof_requests.lock().unwrap().is_empty());
    assert!(chain.witness_requests.lock().unwrap().is_empty());
    assert!(chain.record_requests.lock().unwrap().is_empty());
    let request = {
        let prepared = relay.prepared.lock().unwrap();
        let [request] = prepared.as_slice() else {
            panic!("one prepareRelay call");
        };
        request.clone()
    };
    assert_eq!(request.relay_id().unwrap(), relay_id);
    let RelayIntent::Anonymous {
        proof_inputs,
        owner_signature,
        ..
    } = &request.intent
    else {
        panic!("the anonymous intent");
    };
    let sent = RelayProofInputs::decode(proof_inputs.as_bytes()).unwrap();
    let message_hash = sent.spp_proof_inputs(fee_payer).message_hash().unwrap();
    assert!(sender
        .signing_pubkey()
        .verify_message(&message_hash, owner_signature.0.as_array()));

    // A signature the wallet never expected has nothing to check against.
    let asking = StubRelay {
        asks_signature: true,
        ..StubRelay::default()
    };
    let crate::RelaySent::SignMessage(pending) = crate::PreparedRelay::new(request)
        .send(&asking)
        .await
        .unwrap()
    else {
        panic!("the relay asks a signature");
    };
    assert!(matches!(
        pending.verify(Address::new_from_array(
            sender.signing_pubkey().as_ed25519().unwrap()
        )),
        Err(RingError::RelayMessage(crate::MessageMismatch::Unrequested))
    ));
}

#[tokio::test]
async fn a_confidential_relay_carries_its_token_account_setup() {
    let sender = keypair(1);
    let recipient = keypair(2);
    let fee_payer = Address::new_from_array([0x44; 32]);
    let chain = Chain::ring(RingSettings::new(RingMode::Confidential));
    let mut transaction = ConfidentialTransaction::new_with_ring(
        vec![ring_utxo(&sender, Mint::SOL, 10, 0)],
        fee_payer,
        ring().program_id(),
    )
    .unwrap();
    transaction
        .transfer_sol(&recipient.shielded_address().unwrap(), 4)
        .unwrap();
    let setup = vec![TokenAccountSetup {
        owner: SerializablePubkey(Address::new_from_array([0x55; 32])),
        mint: SerializablePubkey(Address::new_from_array([0x66; 32])),
    }];
    let transfer = CustomRingTransfer::new(CustomRingTransferInput {
        ring: ring(),
        sender: &sender,
        nullifier_key: Some(&sender.nullifier_key),
        transaction,
    })
    .with_in_proof_owner(&sender.signing_key)
    .with_token_account_setup(setup.clone());
    let quote = RelayQuote {
        fee_payer: SerializablePubkey(fee_payer),
        valid_until_slot: u64::MAX,
    };

    let relay = StubRelay::default();
    transfer
        .prepare_relay(&chain, quote)
        .await
        .unwrap()
        .send(&relay)
        .await
        .unwrap()
        .submitted()
        .unwrap();

    let prepared = relay.prepared.lock().unwrap();
    let [PrepareRelayRequest {
        intent:
            RelayIntent::Confidential {
                token_account_setup,
                ..
            },
        ..
    }] = prepared.as_slice()
    else {
        panic!("one confidential prepareRelay call");
    };
    assert_eq!(token_account_setup, &setup);
}

/// The Go golden test solves the relayed tail.
#[tokio::test]
async fn a_relayed_spend_proves_on_the_key_its_owner_sealed() {
    use custom_ring_interface::key_catalog::RingCircuit;
    use spr_transaction::SppProofOutputUtxo;

    use crate::{RelayedTransferInput, RingTransfer};

    let sender = keypair(1);
    let recipient = keypair(2);
    let fee_payer = Address::new_from_array([0x44; 32]);
    let client = Chain::ring(RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::Confidential)
    })
    .with_registry(
        Registry::new(&[(&sender, 1), (&recipient, 1)]),
        &pipeline_rules(),
    )
    .client();
    let relayed = |notes: u64, data: Option<[u8; 32]>| {
        let client = &client;
        let (sender, recipient) = (&sender, &recipient);
        async move {
            let utxos = (0..notes)
                .map(|leaf| ring_utxo(sender, Mint::SOL, 1, leaf))
                .collect();
            let mut transaction =
                ConfidentialTransaction::new_with_ring(utxos, fee_payer, ring().program_id())
                    .unwrap();
            transaction
                .add_output_utxo(SppProofOutputUtxo {
                    owner_address: Some(recipient.shielded_address().unwrap()),
                    asset: Mint::SOL,
                    amount: notes,
                    ring_program_id: Some(ring().program_id()),
                    ring_data_hash: data,
                    ..Default::default()
                })
                .unwrap();
            let relay = StubRelay::default();
            CustomRingTransfer::new(CustomRingTransferInput {
                ring: ring(),
                sender,
                nullifier_key: Some(&sender.nullifier_key),
                transaction,
            })
            .with_in_proof_owner(&sender.signing_key)
            .prepare_relay(
                client.zolana(),
                RelayQuote {
                    fee_payer: SerializablePubkey(fee_payer),
                    valid_until_slot: u64::MAX,
                },
            )
            .await
            .unwrap()
            .send(&relay)
            .await
            .unwrap()
            .submitted()
            .unwrap();
            let (inputs, signature) = {
                let prepared = relay.prepared.lock().unwrap();
                let [PrepareRelayRequest {
                    intent:
                        RelayIntent::Confidential {
                            proof_inputs,
                            owner_signature,
                            ..
                        },
                    ..
                }] = prepared.as_slice()
                else {
                    panic!("one confidential prepareRelay call");
                };
                (
                    RelayProofInputs::decode(proof_inputs.as_bytes()).unwrap(),
                    owner_signature.0,
                )
            };
            let assembled = RingTransfer::relayed(RelayedTransferInput {
                ring: ring(),
                proof_inputs: &inputs,
                fee_payer,
            })
            .with_owner_signature(signature.into())
            .assemble(client)
            .await
            .unwrap();
            assert_eq!(assembled.frame.parts.wide_owners, inputs.wide_owners);
            let request = assembled.request().unwrap();
            let body = serde_json::to_value(
                crate::prover::RequestBody::new(request.circuit, &request.body).unwrap(),
            )
            .unwrap();
            (inputs.wide_owners, request.circuit, body)
        }
    };
    let shape = |circuit| match circuit {
        RingCircuit::Transfer {
            outputs,
            inputs,
            wide,
            ..
        } => (outputs, inputs, wide),
        _ => panic!("a transfer key"),
    };

    let (wide, circuit, _) = relayed(2, None).await;
    assert_eq!((wide, shape(circuit)), (false, (2, 24, false)));
    let (wide, circuit, _) = relayed(25, None).await;
    assert_eq!((wide, shape(circuit)), (true, (2, 49, true)));
    let (wide, circuit, built) = relayed(2, Some([3; 32])).await;
    assert_eq!((wide, shape(circuit)), (true, (8, 24, true)));

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/custom-ring-transfer-relayed-wide-data.json");
    if std::env::var_os("UPDATE_PROVER_JSON").is_some() {
        std::fs::write(&path, serde_json::to_string_pretty(&built).unwrap() + "\n").unwrap();
    }
    assert!(path.exists());
}

mod delegate_message {
    //! The transfer a delegate signs, refused when it pays an unnamed owner or charges the delegate.

    use std::sync::Mutex;

    use custom_ring_interface::{
        compute_unit_limit, tag, FrameBufferHeader, InstructionTag, RingRail, RingTransactData,
    };
    use solana_instruction::Instruction;
    use solana_signer::Signer;
    use spr_indexer_api::{Base64String, SerializableSignature};
    use spr_keypair::{ShieldedAddress, ShieldedKeypair, ViewingKey};
    use spr_transaction::{AssetRegistry, WalletUtxo};
    use zolana_ring_client::rpc::{
        AuthorityPayment, AuthorityTransfer, SerializableShieldedAddress, TxViewingSecret,
    };

    use super::*;
    use crate::{
        relay_message::ExpectedDelegate,
        tests::support::{pinned_vector, relay_message, verdict, MessageCase, MessageVector},
        DelegateMove, DelegateOutput, DelegatePayment, DelegateSource, DelegateWithdrawal,
        MessageMismatch, PreparedAuthorityTransfer, RelaySent, RelayedTransferInput, RingTransfer,
    };

    const FEE_PAYER: Address = Address::new_from_array([0x44; 32]);
    const UNITS: u32 = compute_unit_limit(InstructionTag::AuthorityTransfer);
    const MOVED: u64 = 4;
    const USDC: Mint = Mint {
        asset: Address::new_from_array([0x31; 32]),
        asset_id: 2,
    };
    const EURC: Mint = Mint {
        asset: Address::new_from_array([0x32; 32]),
        asset_id: 3,
    };

    #[derive(Clone, Copy)]
    enum Answer {
        Honest,
        SwappedRecipient,
        DelegateWritable,
        ExtraSystemTransfer,
        DelegatePaysFee,
    }

    impl Answer {
        const ALL: [Self; 5] = [
            Self::Honest,
            Self::SwappedRecipient,
            Self::DelegateWritable,
            Self::ExtraSystemTransfer,
            Self::DelegatePaysFee,
        ];

        /// Fixed here, never read back from the check.
        fn case(self) -> (&'static str, &'static str) {
            match self {
                Self::Honest => ("honest", "Accepted"),
                Self::SwappedRecipient => ("swappedRecipient", "Recipients"),
                Self::DelegateWritable => ("delegateWritable", "Accounts"),
                Self::ExtraSystemTransfer => ("extraSystemTransfer", "Instructions"),
                Self::DelegatePaysFee => ("delegatePaysFee", "FeePayer"),
            }
        }

        fn message(self, honest: &Instruction, delegate: Address) -> Base64String {
            let stranger = stranger();
            let send = |instruction: Instruction| relay_message(&FEE_PAYER, &[instruction], UNITS);
            match self {
                Self::Honest => send(honest.clone()),
                Self::SwappedRecipient => send(paying(honest, 0, stranger)),
                Self::DelegateWritable => {
                    let mut widened = honest.clone();
                    widened
                        .accounts
                        .iter_mut()
                        .filter(|meta| meta.pubkey == delegate)
                        .for_each(|meta| meta.is_writable = true);
                    send(widened)
                }
                Self::ExtraSystemTransfer => relay_message(
                    &FEE_PAYER,
                    &[
                        honest.clone(),
                        solana_system_interface::instruction::transfer(
                            &delegate,
                            &Address::new_from_array([0x63; 32]),
                            1_000,
                        ),
                    ],
                    UNITS,
                ),
                Self::DelegatePaysFee => {
                    relay_message(&delegate, std::slice::from_ref(honest), UNITS)
                }
            }
        }
    }

    fn stranger() -> [u8; 32] {
        keypair(3)
            .shielded_address()
            .unwrap()
            .signing_pubkey
            .owner_proof_input_hash()
            .unwrap()
    }

    const ZERO_TAIL: [u8; custom_ring_interface::DATA_TAIL_LEN] =
        [0; custom_ring_interface::DATA_TAIL_LEN];

    fn rewritten(
        honest: &Instruction,
        rail: RingRail,
        change: impl for<'a> FnOnce(&mut custom_ring_interface::RingTransactData<'a>),
    ) -> Instruction {
        let parsed = RingTransactData::parse(&honest.data[1..], rail).unwrap();
        let mut data = parsed.into_data();
        change(&mut data);
        Instruction {
            data: [vec![tag::AUTHORITY_TRANSFER], data.encode().unwrap()].concat(),
            ..honest.clone()
        }
    }

    /// The honest data with output `slot` published under `owner_tag`.
    fn paying(honest: &Instruction, slot: usize, owner_tag: [u8; 32]) -> Instruction {
        let parsed = RingTransactData::parse(&honest.data[1..], RingRail::Delegate).unwrap();
        let mut data = parsed.into_data();
        data.outputs[slot].owner_tag = custom_ring_interface::stream::slot_tag(owner_tag);
        Instruction {
            data: [vec![tag::AUTHORITY_TRANSFER], data.encode().unwrap()].concat(),
            ..honest.clone()
        }
    }

    /// Ring RPC's authority transfer path without its proof, answering with one `Answer`.
    struct DelegateRelay {
        client: crate::RingClient<Chain, Chain>,
        /// Every member with the notes the service opened for it.
        members: Vec<(ShieldedKeypair, Vec<WalletUtxo>)>,
        delegate: Address,
        answer: Answer,
        honest: Mutex<Option<Instruction>>,
        submitted: Mutex<Vec<SubmitRelayRequest>>,
    }

    impl DelegateRelay {
        fn new(answer: Answer, delegate: Address) -> Self {
            Self::on_mode(answer, delegate, RingMode::Confidential)
        }

        fn on_mode(answer: Answer, delegate: Address, mode: RingMode) -> Self {
            let member = keypair(1);
            let own = keypair(7);
            let other = keypair(3);
            let chain = Chain::ring(RingSettings {
                has_policy: true,
                delegate: Some(delegate),
                ..RingSettings::new(mode)
            })
            .with_registry(
                Registry::new(&[(&member, 1), (&keypair(2), 1), (&other, 1), (&own, 1)]),
                &pipeline_rules(),
            );
            Self {
                client: chain.client(),
                members: vec![
                    (member.clone(), vec![ring_utxo(&member, Mint::SOL, 10, 0)]),
                    (other.clone(), vec![ring_utxo(&other, Mint::SOL, 10, 1)]),
                    (own.clone(), vec![ring_utxo(&own, Mint::SOL, 10, 2)]),
                ],
                delegate,
                answer,
                honest: Mutex::new(None),
                submitted: Mutex::new(Vec::new()),
            }
        }

        /// `seal_delegate` then `prove` as `SdkRelayProver` runs them, the proofs zeroed.
        async fn build(
            &self,
            transfer: &AuthorityTransfer,
            tx_viewing_key: &TxViewingSecret,
        ) -> Result<Instruction, RingError> {
            let mut assets = AssetRegistry::default();
            assets.insert(USDC.asset_id, USDC.asset).unwrap();
            assets.insert(EURC.asset_id, EURC.asset).unwrap();
            let proof_inputs = DelegateMove {
                ring: ring(),
                delegate: self.delegate,
                payer: FEE_PAYER,
                sources: transfer
                    .sources
                    .iter()
                    .map(|source| {
                        let (member, notes) = self
                            .members
                            .iter()
                            .find(|(member, _)| member.shielded_address().unwrap() == source.0)
                            .unwrap();
                        DelegateSource {
                            address: source.0,
                            nullifier_key: &member.nullifier_key,
                            utxos: notes,
                        }
                    })
                    .collect(),
                payments: transfer
                    .payments
                    .iter()
                    .map(|payment| DelegatePayment {
                        recipient: payment.recipient.0,
                        mint: payment.mint.0,
                        amount: payment.amount,
                    })
                    .collect(),
                assets: &assets,
                wide_frames: crate::WideFrames::Refuse,
                tx_viewing_key: tx_viewing_key.key()?,
            }
            .select(&self.client)
            .await?
            .relay_proof_inputs(self.client.zolana())
            .await?;
            let assembled = RingTransfer::relayed(RelayedTransferInput {
                ring: ring(),
                proof_inputs: &proof_inputs,
                fee_payer: FEE_PAYER,
            })
            .assemble(&self.client)
            .await?;
            let frame = &assembled.frame;
            frame
                .accounts
                .instruction(frame.ring, &assembled.config, &frame.parts)
        }

        /// A move the request never named, built on the member's note.
        async fn moved(
            &self,
            tx_viewing_key: &TxViewingSecret,
            shape: spr_client::Shape,
            change: impl FnOnce(crate::DelegateTransfer<'_>) -> crate::DelegateTransfer<'_>,
        ) -> Instruction {
            let assets = AssetRegistry::default();
            let (member, notes) = &self.members[0];
            let source = member.shielded_address().unwrap();
            let transfer = change(
                crate::DelegateTransfer::new(crate::DelegateTransferInput {
                    ring: ring(),
                    delegate: self.delegate,
                    payer: FEE_PAYER,
                    source,
                    source_nullifier_key: &member.nullifier_key,
                    inputs: notes.clone(),
                    outputs: Vec::new(),
                })
                .with_assets(&assets)
                .with_tx_viewing_key(tx_viewing_key.key().unwrap())
                .with_shape(shape)
                .unwrap(),
            );
            // The exit keys are absent from the catalog here, the frame needs no witness.
            let framed = transfer.frame(&self.client).await.ok().unwrap();
            let frame = &framed.frame;
            frame
                .accounts
                .instruction(frame.ring, framed.config.account(), &frame.parts)
                .unwrap()
        }
    }

    #[async_trait]
    impl RingRelay for DelegateRelay {
        async fn get_relay_quote(
            &self,
            _request: GetRelayQuoteRequest,
        ) -> Result<RelayQuote, RingError> {
            unreachable!("the test holds its quote")
        }

        async fn prepare_relay(
            &self,
            _request: PrepareRelayRequest,
        ) -> Result<RelayStep, RingError> {
            unreachable!("the delegate prepares an authority transfer")
        }

        async fn prepare_authority_transfer(
            &self,
            request: PrepareAuthorityTransferRequest,
        ) -> Result<RelayStep, RingError> {
            let honest = self
                .build(&request.transfer, &request.tx_viewing_key)
                .await?;
            let message = self.answer.message(&honest, self.delegate);
            *self.honest.lock().unwrap() = Some(honest);
            Ok(RelayStep::SignMessage {
                relay_id: request.relay_id()?,
                message,
            })
        }

        async fn submit_relay(
            &self,
            request: SubmitRelayRequest,
        ) -> Result<RelayStatus, RingError> {
            let signature = request.signature;
            self.submitted.lock().unwrap().push(request);
            Ok(RelayStatus::Sent { signature })
        }

        async fn get_relay_status(
            &self,
            _request: GetRelayStatusRequest,
        ) -> Result<RelayStatus, RingError> {
            unreachable!("the test reads no status")
        }
    }

    fn quote() -> RelayQuote {
        RelayQuote {
            fee_payer: SerializablePubkey(FEE_PAYER),
            valid_until_slot: 0,
        }
    }

    /// The delegate's signature over the request is Ring RPC's to check, the message check reads none.
    fn request(delegate: Address) -> PrepareAuthorityTransferRequest {
        PrepareAuthorityTransferRequest {
            ring: SerializablePubkey(ring().program_id()),
            delegate: SerializablePubkey(delegate),
            transfer: AuthorityTransfer {
                sources: vec![SerializableShieldedAddress(
                    keypair(1).shielded_address().unwrap(),
                )],
                payments: vec![AuthorityPayment {
                    recipient: SerializableShieldedAddress(keypair(2).shielded_address().unwrap()),
                    mint: SerializablePubkey(Mint::SOL.asset),
                    amount: MOVED,
                }],
            },
            tx_viewing_key: TxViewingSecret::from(&ViewingKey::from_bytes(&[9; 32])),
            timestamp: 0,
            nonce: Base64String(vec![4; 32]),
            signature: SerializableSignature(Default::default()),
        }
    }

    async fn relayed_signature(answer: Answer) -> (DelegateRelay, Result<RelayStatus, RingError>) {
        let delegate = keypair(7);
        let relay = DelegateRelay::new(answer, delegate.pubkey());
        let config = ring().require_config(relay.client.zolana()).await.unwrap();
        let prepared =
            PreparedAuthorityTransfer::new(request(delegate.pubkey()), &quote(), &config).unwrap();
        let RelaySent::SignMessage(pending) = prepared.send(&relay).await.unwrap() else {
            panic!("the delegate signs the move");
        };
        let signed = pending.sign(&relay, &delegate).await;
        (relay, signed)
    }

    #[tokio::test]
    async fn a_delegate_message_with_a_swapped_recipient_is_refused() {
        let (relay, signed) = relayed_signature(Answer::SwappedRecipient).await;
        assert!(matches!(
            signed,
            Err(RingError::RelayMessage(MessageMismatch::Recipients))
        ));
        assert!(relay.submitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_authority_transfer_the_relay_builds_is_signed() {
        let (relay, signed) = relayed_signature(Answer::Honest).await;
        signed.unwrap();
        let honest = relay.honest.lock().unwrap().clone().unwrap();
        let message = Answer::Honest.message(&honest, relay.delegate);
        let submitted = relay.submitted.lock().unwrap();
        let [submitted] = submitted.as_slice() else {
            panic!("one signature");
        };
        assert_eq!(submitted.signer.0, relay.delegate);
        assert!(submitted
            .signature
            .0
            .verify(relay.delegate.as_ref(), &message.0));
    }

    fn thief() -> ShieldedAddress {
        keypair(3).shielded_address().unwrap()
    }

    fn payee() -> ShieldedAddress {
        keypair(2).shielded_address().unwrap()
    }

    /// The frame keeps the payee's tag while its note pays another owner.
    async fn thief_under_payee_tag(
        relay: &DelegateRelay,
        asked: &PrepareAuthorityTransferRequest,
    ) -> Instruction {
        let mut stolen = asked.transfer.clone();
        stolen.payments[0].recipient = SerializableShieldedAddress(thief());
        let frame = relay.build(&stolen, &asked.tx_viewing_key).await.unwrap();
        match RingTransactData::parse(&frame.data[1..], RingRail::Delegate) {
            Ok(_) => paying(&frame, 0, payee().viewing_pubkey.u()),
            Err(_) => frame,
        }
    }

    /// Each slot's owner in frame order, opened under the request's transaction key.
    fn slot_owners(
        frame: &Instruction,
        rail: RingRail,
        expected: &ExpectedDelegate,
    ) -> Vec<[u8; 32]> {
        let parsed = RingTransactData::parse(&frame.data[1..], rail).unwrap();
        let data = parsed.data();
        let opened = zolana_ring_client::AuditEnvelope {
            eph_u: *data.tx_viewing_u,
            salt: data.salt,
            ciphertext: data.envelope,
        }
        .open_sealed(
            &expected.tx_viewing_key.key().unwrap(),
            &expected.auditor,
            parsed.audit_stream(),
        )
        .unwrap();
        data.outputs
            .iter()
            .enumerate()
            .map(|(slot, output)| opened.record(slot, output.record).unwrap().owner_key)
            .collect()
    }

    /// An unproved tag binds nothing, the proven records name every owner, mint and amount.
    #[tokio::test]
    async fn a_delegate_signs_only_the_move_the_proven_records_show_on_both_rails() {
        for mode in [RingMode::Confidential, RingMode::Anonymous] {
            let delegate = keypair(7);
            let relay = DelegateRelay::on_mode(Answer::Honest, delegate.pubkey(), mode);
            let asked = request(delegate.pubkey());
            let config = ring().require_config(relay.client.zolana()).await.unwrap();
            let expected = ExpectedDelegate::new(&asked, &quote(), &config).unwrap();
            let verdict_of = |frame: Instruction| {
                expected
                    .check(&relay_message(&FEE_PAYER, &[frame], UNITS).0)
                    .map(drop)
            };
            let build = |transfer: AuthorityTransfer, key: TxViewingSecret| {
                let relay = &relay;
                async move { relay.build(&transfer, &key).await.unwrap() }
            };

            let honest = build(asked.transfer.clone(), asked.tx_viewing_key.clone()).await;
            assert_eq!(verdict_of(honest.clone()), Ok(()), "{mode:?}");
            let source = keypair(1).shielded_address().unwrap();
            let owner =
                |address: ShieldedAddress| address.signing_pubkey.confidential_view_tag().unwrap();
            let order = match mode {
                RingMode::Confidential => [owner(payee()), owner(source)],
                RingMode::Anonymous => [owner(source), owner(payee())],
            };
            assert_eq!(
                slot_owners(&honest, expected.rail, &expected)[..2],
                order,
                "{mode:?}"
            );

            assert_eq!(
                verdict_of(thief_under_payee_tag(&relay, &asked).await),
                Err(MessageMismatch::Recipients),
                "{mode:?}"
            );

            let mut more = asked.transfer.clone();
            more.payments[0].amount = MOVED + 1;
            assert_eq!(
                verdict_of(build(more, asked.tx_viewing_key.clone()).await),
                Err(MessageMismatch::Recipients),
                "{mode:?}"
            );

            let mut extra = asked.transfer.clone();
            extra.payments.push(AuthorityPayment {
                recipient: SerializableShieldedAddress(thief()),
                mint: SerializablePubkey(Mint::SOL.asset),
                amount: 1,
            });
            assert_eq!(
                verdict_of(build(extra, asked.tx_viewing_key.clone()).await),
                Err(MessageMismatch::Recipients),
                "{mode:?}"
            );

            let mut other_mint = asked.clone();
            other_mint.transfer.payments[0].mint = SerializablePubkey(USDC.asset);
            assert_eq!(
                ExpectedDelegate::new(&other_mint, &quote(), &config)
                    .unwrap()
                    .check(&relay_message(&FEE_PAYER, std::slice::from_ref(&honest), UNITS).0)
                    .map(drop),
                Err(MessageMismatch::Recipients),
                "{mode:?}"
            );

            let parsed = RingTransactData::parse(&honest.data[1..], expected.rail).unwrap();
            let shape = spr_client::Shape::new(
                usize::from(parsed.data().n_in),
                usize::from(parsed.data().n_out),
            );
            let exit = relay
                .moved(&asked.tx_viewing_key, shape, |transfer| {
                    transfer.with_exit(DelegateOutput {
                        recipient: payee(),
                        asset: Mint::SOL.asset,
                        amount: MOVED,
                    })
                })
                .await;
            assert_eq!(
                verdict_of(exit),
                Err(MessageMismatch::Recipients),
                "{mode:?}"
            );

            let leg = relay
                .moved(&asked.tx_viewing_key, shape, |transfer| {
                    transfer.with_withdrawal(DelegateWithdrawal {
                        asset: Mint::SOL.asset,
                        amount: 1,
                        recipient: Address::new_from_array([0x62; 32]),
                        token_program: None,
                    })
                })
                .await;
            assert_eq!(verdict_of(leg), Err(MessageMismatch::Data), "{mode:?}");

            let tails = rewritten(&honest, expected.rail, |data| {
                data.has_data = true;
                for output in &mut data.outputs {
                    output.tail = Some(&ZERO_TAIL);
                }
            });
            assert_eq!(verdict_of(tails), Err(MessageMismatch::Data), "{mode:?}");

            let mut unclamped = asked.clone();
            unclamped.tx_viewing_key =
                serde_json::from_value(serde_json::json!(Base64String(vec![1; 32]))).unwrap();
            assert_eq!(
                ExpectedDelegate::new(&unclamped, &quote(), &config)
                    .unwrap()
                    .check(&relay_message(&FEE_PAYER, std::slice::from_ref(&honest), UNITS).0)
                    .map(drop),
                Err(MessageMismatch::TransactionKey),
                "{mode:?}"
            );

            let other_key = TxViewingSecret::from(&ViewingKey::from_bytes(&[8; 32]));
            assert_eq!(
                verdict_of(build(asked.transfer.clone(), other_key).await),
                Err(MessageMismatch::TransactionKey),
                "{mode:?}"
            );
        }
    }

    /// Owner against delegate is no rule, change returns to an input's owner.
    #[tokio::test]
    async fn a_delegate_moves_its_own_another_and_several_members_notes_on_both_rails() {
        let delegate = keypair(7);
        let member = keypair(1);
        let other = keypair(3);
        for mode in [RingMode::Confidential, RingMode::Anonymous] {
            for (sources, moved) in [
                (vec![&delegate], MOVED),
                (vec![&member], MOVED),
                (vec![&member, &other], 15),
            ] {
                let relay = DelegateRelay::on_mode(Answer::Honest, delegate.pubkey(), mode);
                let mut asked = request(delegate.pubkey());
                asked.transfer.sources = sources
                    .iter()
                    .map(|source| SerializableShieldedAddress(source.shielded_address().unwrap()))
                    .collect();
                asked.transfer.payments[0].amount = moved;
                let frame = relay
                    .build(&asked.transfer, &asked.tx_viewing_key)
                    .await
                    .unwrap();
                let config = ring().require_config(relay.client.zolana()).await.unwrap();
                let expected = ExpectedDelegate::new(&asked, &quote(), &config).unwrap();
                expected
                    .check(&relay_message(&FEE_PAYER, std::slice::from_ref(&frame), UNITS).0)
                    .map(drop)
                    .unwrap();

                // The auditor's own key opens every published slot.
                let parsed = RingTransactData::parse(&frame.data[1..], expected.rail).unwrap();
                let data = parsed.data();
                let opened = zolana_ring_client::AuditEnvelope {
                    eph_u: *data.tx_viewing_u,
                    salt: data.salt,
                    ciphertext: data.envelope,
                }
                .open(&crate::tests::support::auditor(), parsed.audit_stream())
                .unwrap();
                let records: Vec<_> = data
                    .outputs
                    .iter()
                    .enumerate()
                    .map(|(slot, output)| opened.record(slot, output.record).unwrap())
                    .collect();
                let spent = u64::try_from(sources.len()).unwrap() * 10;
                let total: u64 = records.iter().map(|record| record.amount).sum();
                assert_eq!(total, spent, "{mode:?} {}", sources.len());
                let owner_key = |owner: &ShieldedKeypair| {
                    owner
                        .shielded_address()
                        .unwrap()
                        .signing_pubkey
                        .confidential_view_tag()
                        .unwrap()
                };
                let payee_key = owner_key(&keypair(2));
                assert!(records
                    .iter()
                    .filter(|record| record.kind == custom_ring_interface::RecordKind::Ring)
                    .all(|record| record.owner_key == payee_key
                        || sources
                            .iter()
                            .any(|source| owner_key(source) == record.owner_key)));
            }
        }
    }

    fn payment_of(mint: Mint, amount: u64) -> AuthorityPayment {
        AuthorityPayment {
            recipient: SerializableShieldedAddress(payee()),
            mint: SerializablePubkey(mint.asset),
            amount,
        }
    }

    /// Each mint's change returns to the owner of the note it came from.
    #[tokio::test]
    async fn a_move_across_owners_and_mints_returns_each_change_to_its_owner() {
        let delegate = keypair(7);
        for mode in [RingMode::Confidential, RingMode::Anonymous] {
            let mut relay = DelegateRelay::on_mode(Answer::Honest, delegate.pubkey(), mode);
            let (member, other) = (keypair(1), keypair(3));
            relay.members[1].1 = vec![ring_utxo(&other, USDC, 10, 1)];
            let mut asked = request(delegate.pubkey());
            asked.transfer.sources = [&member, &other]
                .map(|source| SerializableShieldedAddress(source.shielded_address().unwrap()))
                .into();
            asked.transfer.payments = vec![payment_of(Mint::SOL, 4), payment_of(USDC, 3)];
            let frame = relay
                .build(&asked.transfer, &asked.tx_viewing_key)
                .await
                .unwrap();
            let config = ring().require_config(relay.client.zolana()).await.unwrap();
            let expected = ExpectedDelegate::new(&asked, &quote(), &config).unwrap();
            expected
                .check(&relay_message(&FEE_PAYER, std::slice::from_ref(&frame), UNITS).0)
                .map(drop)
                .unwrap();
            let parsed = RingTransactData::parse(&frame.data[1..], expected.rail).unwrap();
            let data = parsed.data();
            let opened = zolana_ring_client::AuditEnvelope {
                eph_u: *data.tx_viewing_u,
                salt: data.salt,
                ciphertext: data.envelope,
            }
            .open(&crate::tests::support::auditor(), parsed.audit_stream())
            .unwrap();
            let moved: Vec<([u8; 32], [u8; 32], u64)> = data
                .outputs
                .iter()
                .enumerate()
                .map(|(slot, output)| opened.record(slot, output.record).unwrap())
                .filter(|record| record.kind == custom_ring_interface::RecordKind::Ring)
                .map(|record| (record.owner_key, record.mint, record.amount))
                .filter(|(_, _, amount)| *amount > 0)
                .collect();
            let key =
                |address: ShieldedAddress| address.signing_pubkey.confidential_view_tag().unwrap();
            let (sol, usdc) = (Mint::SOL.asset.to_bytes(), USDC.asset.to_bytes());
            for held in [
                (key(payee()), sol, 4),
                (key(payee()), usdc, 3),
                (key(member.shielded_address().unwrap()), sol, 6),
                (key(other.shielded_address().unwrap()), usdc, 7),
            ] {
                assert!(moved.contains(&held), "{mode:?} {moved:?}");
            }
            assert_eq!(moved.len(), 4, "{mode:?}");
        }
    }

    /// The anonymous frame's bundle holds one SPL change and the SOL change of its sender.
    #[tokio::test]
    async fn one_owners_change_on_two_spl_mints_needs_the_confidential_frame() {
        let delegate = keypair(7);
        for (mode, fits) in [(RingMode::Confidential, true), (RingMode::Anonymous, false)] {
            let mut relay = DelegateRelay::on_mode(Answer::Honest, delegate.pubkey(), mode);
            let member = keypair(1);
            relay.members[0].1 = vec![
                ring_utxo(&member, USDC, 10, 0),
                ring_utxo(&member, EURC, 10, 3),
            ];
            let mut asked = request(delegate.pubkey());
            asked.transfer.payments = vec![payment_of(USDC, 3), payment_of(EURC, 3)];
            let built = relay.build(&asked.transfer, &asked.tx_viewing_key).await;
            match fits {
                true => {
                    built.unwrap();
                }
                false => assert!(
                    matches!(
                        built,
                        Err(RingError::Rail(
                            zolana_ring_transaction::RingRailError::AnonymousChangeCount
                        ))
                    ),
                    "{:?}",
                    built.err()
                ),
            }
        }
    }

    #[tokio::test]
    async fn a_move_past_its_sources_value_is_refused() {
        let delegate = keypair(7);
        let relay = DelegateRelay::new(Answer::Honest, delegate.pubkey());
        let mut asked = request(delegate.pubkey());
        asked.transfer.payments[0].amount = 11;
        assert!(relay
            .build(&asked.transfer, &asked.tx_viewing_key)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn a_source_named_twice_is_refused() {
        let delegate = keypair(7);
        let relay = DelegateRelay::new(Answer::Honest, delegate.pubkey());
        let mut asked = request(delegate.pubkey());
        let source = asked.transfer.sources[0];
        asked.transfer.sources.push(source);
        assert!(matches!(
            relay.build(&asked.transfer, &asked.tx_viewing_key).await,
            Err(RingError::RepeatedDelegateSource)
        ));
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct DelegateRequest {
        prepare: PrepareAuthorityTransferRequest,
        fee_payer: SerializablePubkey,
        /// The ring account's key, the stream a delegate reads seals to it.
        auditor: Base64String,
    }

    /// The TypeScript check reads the same file and reaches the same verdicts.
    #[tokio::test]
    async fn the_shared_delegate_messages_keep_their_verdicts() {
        let (relay, signed) = relayed_signature(Answer::Honest).await;
        signed.unwrap();
        let honest = relay.honest.lock().unwrap().clone().unwrap();
        let config = ring().require_config(relay.client.zolana()).await.unwrap();
        let asked = request(relay.delegate);
        let stolen = thief_under_payee_tag(&relay, &asked).await;
        let fresh = MessageVector {
            description: "One authority transfer the ring delegate asks Ring RPC for, moving 4 \
                          of the member's SOL to a second member with the change back, and the \
                          messages Ring RPC could answer with. The honest message is the relay's \
                          delegate path with zeroed proofs, each other case changes one thing. \
                          verdict names the MessageMismatch the Rust ExpectedDelegate::check and \
                          the TypeScript checkDelegateMessage return."
                .to_owned(),
            request: DelegateRequest {
                prepare: asked.clone(),
                fee_payer: SerializablePubkey(FEE_PAYER),
                auditor: Base64String(config.auditor_pubkey.as_bytes().to_vec()),
            },
            cases: Answer::ALL
                .map(|answer| {
                    let (name, verdict) = answer.case();
                    MessageCase {
                        name: name.to_owned(),
                        message: answer.message(&honest, relay.delegate),
                        verdict: verdict.to_owned(),
                    }
                })
                .into_iter()
                .chain([MessageCase {
                    name: "thiefUnderPayeeTag".to_owned(),
                    message: relay_message(&FEE_PAYER, &[stolen], UNITS),
                    verdict: "Recipients".to_owned(),
                }])
                .collect(),
        };
        let buffered = crate::BufferedFrame::for_writer(&honest, FEE_PAYER).unwrap();
        let settle = relay_message(
            &FEE_PAYER,
            &[buffered.settle()],
            compute_unit_limit(InstructionTag::SettleBuffered),
        );
        let held = |frame: &[u8]| {
            let header = FrameBufferHeader::new(FEE_PAYER);
            [bytemuck::bytes_of(&header), frame].concat()
        };
        let vector = pinned_vector("relay_delegate_messages.json", fresh);
        let quote = RelayQuote {
            fee_payer: vector.request.fee_payer,
            valid_until_slot: 0,
        };
        assert_eq!(vector.request.auditor.0, config.auditor_pubkey.as_bytes());
        let expected = ExpectedDelegate::new(&vector.request.prepare, &quote, &config).unwrap();
        assert_eq!(vector.cases.len(), Answer::ALL.len() + 1);
        for case in &vector.cases {
            assert_eq!(
                verdict(expected.check(&case.message.0)),
                case.verdict,
                "{}",
                case.name
            );
        }
        assert_eq!(
            expected.check(&settle.0).unwrap_err(),
            MessageMismatch::SettlesBuffer
        );
        assert_eq!(
            expected.settled_buffer(&settle.0).unwrap(),
            Some(buffered.buffer())
        );
        assert!(expected
            .check_settled(&settle.0, &held(&honest.data))
            .is_ok());
        let mut rewritten = honest.data.clone();
        *rewritten.last_mut().unwrap() ^= 1;
        assert_eq!(
            expected
                .check_settled(&settle.0, &held(&rewritten))
                .unwrap_err(),
            MessageMismatch::Data
        );
        let stranger_frame =
            crate::BufferedFrame::for_writer(&paying(&honest, 0, stranger()), FEE_PAYER)
                .unwrap()
                .settle();
        let swapped = relay_message(
            &FEE_PAYER,
            &[stranger_frame],
            compute_unit_limit(InstructionTag::SettleBuffered),
        );
        assert_eq!(
            expected
                .check_settled(&swapped.0, &held(&paying(&honest, 0, stranger()).data))
                .unwrap_err(),
            MessageMismatch::Recipients
        );
    }
}

mod public_signers {
    //! The public owners of a relayed transfer, each rebuilds its own slots against the frame.

    use custom_ring_interface::{
        cosign::ApprovalMask, tag, CoSignScope, InstructionTag, RingRail, RingTransactData,
    };
    use solana_instruction::Instruction;
    use spr_keypair::ShieldedKeypair;
    use spr_transaction::WalletUtxo;
    use zolana_ring_client::rpc::RelayId;

    use super::*;
    use crate::{
        tests::support::relay_message, ApplicationData, ApprovalLimit, ApprovalOpening, CoOwner,
        CoSignerApproval, CoSignerRule, CustomRingConfig, ExactApproval, MessageMismatch, NoteData,
        OwnerApproval, PendingSignature, PreparedRelay, RelaySent, RelayTransferTerms,
        RingTransfer, SlotOpening,
    };

    const FEE_PAYER: Address = Address::new_from_array([0x44; 32]);
    const UNITS: u32 = custom_ring_interface::compute_unit_limit(InstructionTag::Transfer);

    fn address(owner: &ShieldedKeypair) -> Address {
        Address::new_from_array(owner.signing_pubkey().as_ed25519().unwrap())
    }

    fn chain(mode: RingMode, co_signer: Option<Address>, owners: &[&ShieldedKeypair]) -> Chain {
        let owners: Vec<(&ShieldedKeypair, u64)> = owners.iter().map(|owner| (*owner, 1)).collect();
        Chain::ring(RingSettings {
            has_policy: true,
            co_signer: co_signer.map(|signer| (signer, CoSignScope::TRANSFERS)),
            ..RingSettings::new(mode)
        })
        .with_registry(Registry::new(&owners), &pipeline_rules())
    }

    fn transfer<'a>(sender: &'a ShieldedKeypair, notes: Vec<WalletUtxo>) -> CustomRingTransfer<'a> {
        CustomRingTransfer::new(CustomRingTransferInput {
            ring: ring(),
            sender,
            nullifier_key: Some(&sender.nullifier_key),
            transaction: ConfidentialTransaction::new_with_ring(
                notes,
                FEE_PAYER,
                ring().program_id(),
            )
            .unwrap(),
        })
    }

    fn pay(to: &ShieldedKeypair, amount: u64) -> AnonymousPayment {
        AnonymousPayment {
            to: RingAddress {
                recipient: to.shielded_address().unwrap(),
                ring_program_id: ring().program_id(),
                list_salt: [7; 32],
            },
            asset: Mint::SOL,
            amount,
            reply: None,
            data: NoteData::default(),
        }
    }

    fn quote() -> RelayQuote {
        RelayQuote {
            fee_payer: SerializablePubkey(FEE_PAYER),
            valid_until_slot: u64::MAX,
        }
    }

    struct Sent {
        request: PrepareRelayRequest,
        relay_id: RelayId,
        pending: PendingSignature,
    }

    /// `prepare_relay` sets the expectation, a relay that asks reaches a wallet holding terms.
    async fn sent(prepared: PreparedRelay) -> Sent {
        let relay = StubRelay {
            asks_signature: true,
            ..StubRelay::default()
        };
        let RelaySent::SignMessage(pending) = prepared.send(&relay).await.unwrap() else {
            panic!("the relay asks a signature");
        };
        let request = relay.prepared.lock().unwrap().pop().unwrap();
        Sent {
            relay_id: pending.relay_id().clone(),
            pending,
            request,
        }
    }

    /// `SdkRelayProver` over the wire bytes, the proofs zeroed.
    async fn frame(
        client: &crate::RingClient<Chain, Chain>,
        request: &PrepareRelayRequest,
    ) -> Instruction {
        let (RelayIntent::Anonymous {
            proof_inputs,
            owner_signature,
            ..
        }
        | RelayIntent::Confidential {
            proof_inputs,
            owner_signature,
            ..
        }) = &request.intent
        else {
            panic!("a wallet relay");
        };
        let inputs = RelayProofInputs::decode(proof_inputs.as_bytes()).unwrap();
        let mut relayed = RingTransfer::relayed(crate::RelayedTransferInput {
            ring: ring(),
            proof_inputs: &inputs,
            fee_payer: FEE_PAYER,
        })
        .with_owner_signature(<[u8; 64]>::from(owner_signature.0));
        for co_signer in &request.co_signers {
            relayed = relayed.with_co_signer(co_signer.0);
        }
        let assembled = relayed.assemble(client).await.unwrap();
        let frame = &assembled.frame;
        frame
            .accounts
            .instruction(frame.ring, &assembled.config, &frame.parts)
            .unwrap()
    }

    /// The terms cross to the signer's wallet as JSON.
    fn pending_for(
        relay_id: &RelayId,
        message: Vec<u8>,
        terms: &RelayTransferTerms,
        config: &CustomRingConfig,
    ) -> PendingSignature {
        approval(relay_id, message, terms, config, &[])
    }

    fn approval(
        relay_id: &RelayId,
        message: Vec<u8>,
        terms: &RelayTransferTerms,
        config: &CustomRingConfig,
        known_notes: &[WalletUtxo],
    ) -> PendingSignature {
        OwnerApproval {
            relay_id: relay_id.clone(),
            message,
            terms: serde_json::from_str(&serde_json::to_string(terms).unwrap()).unwrap(),
            config,
            known_notes,
        }
        .pending()
    }

    async fn signs(pending: &PendingSignature, signer: &ShieldedKeypair) {
        let relay = StubRelay::default();
        pending.sign(&relay, signer).await.unwrap();
        let submitted = relay.submitted.lock().unwrap();
        assert_eq!(submitted[0].signer.0, address(signer));
    }

    fn refused(pending: &PendingSignature, signer: &ShieldedKeypair, mismatch: MessageMismatch) {
        let verdict = pending.verify(address(signer));
        assert!(
            matches!(&verdict, Err(RingError::RelayMessage(found)) if *found == mismatch),
            "{:?}",
            verdict.map(drop)
        );
    }

    fn data_payment(to: &ShieldedKeypair) -> AnonymousPayment {
        pay(to, 4).with_data(NoteData {
            ring_data_hash: None,
            application: Some(ApplicationData {
                hash: [4; 32],
                bytes: b"app".to_vec(),
            }),
        })
    }

    #[tokio::test]
    async fn a_data_recipient_opens_its_own_slot_and_signs() {
        let (sender, payee, thief) = (keypair(1), keypair(2), keypair(3));
        let client = chain(RingMode::Anonymous, None, &[&sender, &payee, &thief]).client();
        let config = ring().require_config(client.zolana()).await.unwrap();
        let paying = |to: &ShieldedKeypair| {
            transfer(&sender, vec![ring_utxo(&sender, Mint::SOL, 10, 0)])
                .with_anonymous_signer(&sender.signing_key)
                .with_payment(data_payment(to))
                .unwrap()
        };
        let honest = paying(&payee);
        let asked = sent(
            honest
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap(),
        )
        .await;
        let terms = asked
            .pending
            .transfer_terms(address(&payee))
            .unwrap()
            .clone();
        let [opening] = terms.slots.as_slice() else {
            panic!("one slot of its own");
        };
        assert!(terms.nullifiers.is_empty());
        assert_eq!(opening.owner.0, address(&payee));
        let built = frame(&client, &asked.request).await;
        let message = relay_message(&FEE_PAYER, core::slice::from_ref(&built), UNITS).0;
        let pending = pending_for(&asked.relay_id, message.clone(), &terms, &config);
        signs(&pending, &payee).await;
        refused(&pending, &sender, MessageMismatch::Unrequested);

        let false_opening = RelayTransferTerms {
            slots: vec![SlotOpening {
                amount: opening.amount + 1,
                ..opening.clone()
            }],
            ..terms.clone()
        };
        refused(
            &pending_for(&asked.relay_id, message.clone(), &false_opening, &config),
            &payee,
            MessageMismatch::Recipients,
        );

        let another_slot = RelayTransferTerms {
            slots: vec![SlotOpening {
                slot: opening.slot + 1,
                ..opening.clone()
            }],
            ..terms.clone()
        };
        refused(
            &pending_for(&asked.relay_id, message.clone(), &another_slot, &config),
            &payee,
            MessageMismatch::Recipients,
        );

        let another_owner = RelayTransferTerms {
            slots: vec![SlotOpening {
                owner: SerializablePubkey(address(&thief)),
                ..opening.clone()
            }],
            ..terms.clone()
        };
        refused(
            &pending_for(&asked.relay_id, message, &another_owner, &config),
            &payee,
            MessageMismatch::Recipients,
        );

        let stolen = paying(&thief);
        let forged = sent(
            stolen
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap(),
        )
        .await;
        let forged_frame = frame(&client, &forged.request).await;
        refused(
            &pending_for(
                &asked.relay_id,
                relay_message(&FEE_PAYER, &[forged_frame], UNITS).0,
                &terms,
                &config,
            ),
            &payee,
            MessageMismatch::Recipients,
        );
    }

    #[tokio::test]
    async fn a_public_co_owner_crosses_the_wire_with_its_key_and_signs_for_its_notes() {
        let (sender, payee, co_owner) = (keypair(1), keypair(2), keypair(3));
        let client = chain(RingMode::Anonymous, None, &[&sender, &payee, &co_owner]).client();
        let config = ring().require_config(client.zolana()).await.unwrap();
        let spent = ring_utxo(&co_owner, Mint::SOL, 10, 1);
        let kept = ring_utxo(&co_owner, Mint::SOL, 10, 2);
        let transaction = transfer(
            &sender,
            vec![ring_utxo(&sender, Mint::SOL, 10, 0), spent.clone()],
        )
        .with_anonymous_signer(&sender.signing_key)
        .with_co_owner(CoOwner {
            owner: address(&co_owner),
            nullifier_key: &co_owner.nullifier_key,
        })
        .with_payment(pay(&payee, 4))
        .unwrap();
        let asked = sent(
            transaction
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap(),
        )
        .await;
        let terms = asked
            .pending
            .transfer_terms(address(&co_owner))
            .unwrap()
            .clone();
        assert_eq!(terms.nullifiers.len(), 1);
        let built = frame(&client, &asked.request).await;
        let message = relay_message(&FEE_PAYER, core::slice::from_ref(&built), UNITS).0;
        let known = [spent.clone(), kept.clone()];
        signs(
            &approval(&asked.relay_id, message.clone(), &terms, &config, &known),
            &co_owner,
        )
        .await;

        // No list stands behind the check, the note the terms name is not the wallet's.
        refused(
            &approval(&asked.relay_id, message, &terms, &config, &[]),
            &co_owner,
            MessageMismatch::Data,
        );

        // The relay holds the key, its frame spends a second note the terms do not name.
        let rewritten = |nullifiers: &[[u8; 32]]| {
            let parsed = RingTransactData::parse(&built.data[1..], RingRail::Anonymous).unwrap();
            let mut data = parsed.into_data();
            data.nullifiers = nullifiers;
            relay_message(
                &FEE_PAYER,
                &[Instruction {
                    data: [vec![tag::TRANSFER], data.encode().unwrap()].concat(),
                    ..built.clone()
                }],
                UNITS,
            )
            .0
        };
        let also_kept = [kept.nullifier, spent.nullifier];
        refused(
            &approval(
                &asked.relay_id,
                rewritten(&also_kept),
                &terms,
                &config,
                &known,
            ),
            &co_owner,
            MessageMismatch::SpendsUnnamedNote,
        );
        let others = [[9; 32], [8; 32]];
        refused(
            &approval(&asked.relay_id, rewritten(&others), &terms, &config, &known),
            &co_owner,
            MessageMismatch::Data,
        );
    }

    #[tokio::test]
    async fn a_data_recipient_of_a_relayed_in_proof_transfer_signs() {
        let (sender, payee) = (keypair(1), keypair(2));
        let client = chain(RingMode::Confidential, None, &[&sender, &payee]).client();
        let config = ring().require_config(client.zolana()).await.unwrap();
        let mut transaction = ConfidentialTransaction::new_with_ring(
            vec![ring_utxo(&sender, Mint::SOL, 10, 0)],
            FEE_PAYER,
            ring().program_id(),
        )
        .unwrap();
        transaction
            .add_output_utxo(
                spr_transaction::SppProofOutputUtxo::new(
                    Mint::SOL,
                    4,
                    payee.shielded_address().unwrap(),
                )
                .unwrap()
                .with_ring_program_id(ring().program_id())
                .with_utxo_data(b"app".to_vec(), [4; 32]),
            )
            .unwrap();
        let in_proof = CustomRingTransfer::new(CustomRingTransferInput {
            ring: ring(),
            sender: &sender,
            nullifier_key: Some(&sender.nullifier_key),
            transaction,
        })
        .with_in_proof_owner(&sender.signing_key);
        let asked = sent(
            in_proof
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap(),
        )
        .await;
        let terms = asked
            .pending
            .transfer_terms(address(&payee))
            .unwrap()
            .clone();
        let built = frame(&client, &asked.request).await;
        let pending = pending_for(
            &asked.relay_id,
            relay_message(&FEE_PAYER, &[built], UNITS).0,
            &terms,
            &config,
        );
        signs(&pending, &payee).await;
        refused(&pending, &sender, MessageMismatch::Unrequested);
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct OwnerCase {
        name: String,
        terms: RelayTransferTerms,
        known_nullifiers: Vec<spr_indexer_api::Hash>,
        message: spr_indexer_api::Base64String,
        verdict: String,
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct OwnerMessages {
        description: String,
        cases: Vec<OwnerCase>,
    }

    fn owner_case(
        name: &str,
        terms: &RelayTransferTerms,
        known: &[[u8; 32]],
        message: &[u8],
        verdict: &str,
    ) -> OwnerCase {
        OwnerCase {
            name: name.to_owned(),
            terms: terms.clone(),
            known_nullifiers: known.iter().copied().map(spr_indexer_api::Hash).collect(),
            message: message.to_vec().into(),
            verdict: verdict.to_owned(),
        }
    }

    /// The TypeScript check reads the same frames and reaches the same verdicts, `UPDATE_RELAY_MESSAGES=1` rewrites them.
    #[tokio::test]
    async fn the_shared_owner_messages_keep_their_verdicts() {
        let (sender, payee, thief, co_owner) = (keypair(1), keypair(2), keypair(4), keypair(3));
        let client = chain(
            RingMode::Anonymous,
            None,
            &[&sender, &payee, &thief, &co_owner],
        )
        .client();
        let paying = |to: &ShieldedKeypair| {
            transfer(&sender, vec![ring_utxo(&sender, Mint::SOL, 10, 0)])
                .with_anonymous_signer(&sender.signing_key)
                .with_payment(data_payment(to))
                .unwrap()
        };
        let honest = paying(&payee);
        let asked = sent(
            honest
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap(),
        )
        .await;
        let terms = asked
            .pending
            .transfer_terms(address(&payee))
            .unwrap()
            .clone();
        let message = relay_message(&FEE_PAYER, &[frame(&client, &asked.request).await], UNITS).0;
        let stolen = paying(&thief);
        let forged = sent(
            stolen
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap(),
        )
        .await;
        let forged_message =
            relay_message(&FEE_PAYER, &[frame(&client, &forged.request).await], UNITS).0;
        let false_opening = RelayTransferTerms {
            slots: vec![SlotOpening {
                amount: terms.slots[0].amount + 1,
                ..terms.slots[0].clone()
            }],
            ..terms.clone()
        };

        let spent = ring_utxo(&co_owner, Mint::SOL, 10, 1);
        let kept = ring_utxo(&co_owner, Mint::SOL, 10, 2);
        let shared = transfer(
            &sender,
            vec![ring_utxo(&sender, Mint::SOL, 10, 0), spent.clone()],
        )
        .with_anonymous_signer(&sender.signing_key)
        .with_co_owner(CoOwner {
            owner: address(&co_owner),
            nullifier_key: &co_owner.nullifier_key,
        })
        .with_payment(pay(&payee, 4))
        .unwrap();
        let co_asked = sent(
            shared
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap(),
        )
        .await;
        let co_terms = co_asked
            .pending
            .transfer_terms(address(&co_owner))
            .unwrap()
            .clone();
        let built = frame(&client, &co_asked.request).await;
        let co_message = relay_message(&FEE_PAYER, core::slice::from_ref(&built), UNITS).0;
        let parsed = RingTransactData::parse(&built.data[1..], RingRail::Anonymous).unwrap();
        let mut data = parsed.into_data();
        let also_kept = [kept.nullifier, spent.nullifier];
        data.nullifiers = &also_kept;
        let unnamed = relay_message(
            &FEE_PAYER,
            &[Instruction {
                data: [vec![tag::TRANSFER], data.encode().unwrap()].concat(),
                ..built.clone()
            }],
            UNITS,
        )
        .0;
        let known = [spent.nullifier, kept.nullifier];

        let fresh = OwnerMessages {
            description: "Relayed anonymous transfers a public owner signs. A data recipient \
                          opens its own slot, a co-owner names its notes against the notes its \
                          wallet holds. Each case holds the owner's terms, what its wallet knows, \
                          the message Ring RPC answers with, and the MessageMismatch the Rust \
                          ExpectedPublicOwner and the TypeScript check return. Frames carry \
                          zeroed proofs."
                .to_owned(),
            cases: vec![
                owner_case("recipientHonest", &terms, &[], &message, "Accepted"),
                owner_case("thief", &terms, &[], &forged_message, "Recipients"),
                owner_case("falseOpening", &false_opening, &[], &message, "Recipients"),
                owner_case("coOwnerHonest", &co_terms, &known, &co_message, "Accepted"),
                owner_case(
                    "unnamedNote",
                    &co_terms,
                    &known,
                    &unnamed,
                    "SpendsUnnamedNote",
                ),
                owner_case("noList", &co_terms, &[], &co_message, "Data"),
            ],
        };
        let vector = crate::tests::support::pinned_vector("relay_transfer_messages.json", fresh);
        for case in &vector.cases {
            let expected = crate::relay_message::ExpectedPublicOwner::new(
                case.terms.clone(),
                RingMode::Anonymous,
                case.known_nullifiers.iter().map(|hash| hash.0).collect(),
            );
            let checked = crate::relay_message::ExpectedMessage::PublicOwner(expected)
                .check(&case.message.0, case.terms.signer.0);
            assert_eq!(
                crate::tests::support::verdict(checked),
                case.verdict,
                "{}",
                case.name
            );
        }
    }

    /// The terms name each create, one with no withdrawal to pay has none.
    #[tokio::test]
    async fn an_owners_terms_refuse_a_setup_naming_no_withdrawal() {
        let (sender, payee) = (keypair(1), keypair(2));
        let client = chain(RingMode::Anonymous, None, &[&sender, &payee]).client();
        let transaction = transfer(&sender, vec![ring_utxo(&sender, Mint::SOL, 10, 0)])
            .with_token_account_setup(vec![TokenAccountSetup {
                owner: SerializablePubkey(Address::new_from_array([0x55; 32])),
                mint: SerializablePubkey(Address::new_from_array([0x66; 32])),
            }])
            .with_anonymous_signer(&sender.signing_key)
            .with_payment(data_payment(&payee))
            .unwrap();
        assert!(matches!(
            transaction.prepare_relay(client.zolana(), quote()).await,
            Err(RingError::TokenAccountSetup(_))
        ));
    }

    /// No sender slot is opened, and the plain wallet check names no terms for a co-signer.
    #[tokio::test]
    async fn an_outside_co_signer_holds_no_owner_terms() {
        let (sender, payee, co_signer) = (keypair(1), keypair(2), keypair(6));
        let client = chain(
            RingMode::Anonymous,
            Some(address(&co_signer)),
            &[&sender, &payee],
        )
        .client();
        let transaction = transfer(&sender, vec![ring_utxo(&sender, Mint::SOL, 10, 0)])
            .with_co_signer(address(&co_signer))
            .with_anonymous_signer(&sender.signing_key)
            .with_payment(pay(&payee, 4))
            .unwrap();
        let asked = sent(
            transaction
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap(),
        )
        .await;
        assert!(asked.pending.transfer_terms(address(&co_signer)).is_none());
        assert!(asked.pending.approval_opening().is_none());
        refused(&asked.pending, &co_signer, MessageMismatch::Unrequested);
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct LimitCase {
        mint: SerializablePubkey,
        peak: String,
        outflow: String,
    }

    /// `opening` unset is the threshold rule, `accepts` then names its bits.
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct CoSignerCase {
        name: String,
        accepts: u8,
        opening: Option<ApprovalOpening>,
        limits: Vec<LimitCase>,
        seen_blinders: Vec<spr_indexer_api::Hash>,
        message: spr_indexer_api::Base64String,
        verdict: String,
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct CoSignerMessages {
        description: String,
        ring: SerializablePubkey,
        fee_payer: SerializablePubkey,
        signer: SerializablePubkey,
        cases: Vec<CoSignerCase>,
    }

    fn limit(mint: Mint, peak: u128, outflow: u128) -> LimitCase {
        LimitCase {
            mint: SerializablePubkey(mint.asset),
            peak: peak.to_string(),
            outflow: outflow.to_string(),
        }
    }

    impl CoSignerCase {
        fn rule(&self) -> CoSignerRule {
            match &self.opening {
                None => CoSignerRule::Threshold {
                    accepts: ApprovalMask::new(self.accepts).unwrap(),
                },
                Some(opening) => CoSignerRule::Exact(ExactApproval {
                    opening: opening.clone(),
                    limits: self
                        .limits
                        .iter()
                        .map(|limit| ApprovalLimit {
                            mint: limit.mint.0,
                            peak: limit.peak.parse().unwrap(),
                            outflow: limit.outflow.parse().unwrap(),
                        })
                        .collect(),
                    seen_blinders: self.seen_blinders.clone(),
                }),
            }
        }
    }

    fn co_signer_pending(
        relay_id: &RelayId,
        message: Vec<u8>,
        signer: Address,
        rule: CoSignerRule,
        config: &CustomRingConfig,
    ) -> PendingSignature {
        CoSignerApproval {
            relay_id: relay_id.clone(),
            message,
            ring: ring().program_id(),
            fee_payer: FEE_PAYER,
            signer,
            config,
            setup: Vec::new(),
            rule,
        }
        .pending()
    }

    /// The TypeScript check reads the same frames, neither rule opens a slot.
    #[tokio::test]
    async fn the_shared_co_signer_messages_keep_their_verdicts() {
        let (sender, payee, co_signer) = (keypair(1), keypair(2), keypair(6));
        let client = chain(
            RingMode::Anonymous,
            Some(address(&co_signer)),
            &[&sender, &payee],
        )
        .client();
        let config = ring().require_config(client.zolana()).await.unwrap();
        let build = || {
            transfer(&sender, vec![ring_utxo(&sender, Mint::SOL, 10, 0)])
                .with_co_signer(address(&co_signer))
                .with_anonymous_signer(&sender.signing_key)
                .with_payment(pay(&payee, 4))
                .unwrap()
        };
        let exact = build().with_exact_approval();
        let disclosed = sent(exact.prepare_relay(client.zolana(), quote()).await.unwrap()).await;
        let opening = disclosed.pending.approval_opening().unwrap().clone();
        let digested = frame(&client, &disclosed.request).await;
        let message = relay_message(&FEE_PAYER, core::slice::from_ref(&digested), UNITS).0;
        let plain_transfer = build();
        let plain = sent(
            plain_transfer
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap(),
        )
        .await;
        assert!(plain.pending.approval_opening().is_none());
        let plain_message =
            relay_message(&FEE_PAYER, &[frame(&client, &plain.request).await], UNITS).0;

        // The extension stays out of what SPP hashes.
        let parsed = RingTransactData::parse(&digested.data[1..], RingRail::Anonymous).unwrap();
        let mut stripped = parsed.into_data();
        let with_digest = stripped.external_data_hash(config.account(), &[]).unwrap();
        assert!(stripped.extensions.approval_totals.is_some());
        stripped.extensions.approval_totals = None;
        assert_eq!(
            with_digest,
            stripped.external_data_hash(config.account(), &[]).unwrap()
        );

        // A frame over a mask the co-signer does not accept.
        let parsed = RingTransactData::parse(&digested.data[1..], RingRail::Anonymous).unwrap();
        let mut masked = parsed.into_data();
        masked.approval = ApprovalMask::OUTFLOW;
        let masked_message = relay_message(
            &FEE_PAYER,
            &[Instruction {
                data: [vec![tag::TRANSFER], masked.encode().unwrap()].concat(),
                ..digested.clone()
            }],
            UNITS,
        )
        .0;

        let mut false_opening = opening.clone();
        false_opening.outputs[0].outflow = "1".to_owned();
        let bounds = vec![limit(Mint::SOL, 4, 4)];
        let exact_case =
            |name: &str, opening: &ApprovalOpening, limits, seen, verdict: &str| CoSignerCase {
                name: name.to_owned(),
                accepts: 0,
                opening: Some(opening.clone()),
                limits,
                seen_blinders: seen,
                message: message.clone().into(),
                verdict: verdict.to_owned(),
            };
        let threshold_case =
            |name: &str, accepts: u8, message: &[u8], verdict: &str| CoSignerCase {
                name: name.to_owned(),
                accepts,
                opening: None,
                limits: Vec::new(),
                seen_blinders: Vec::new(),
                message: message.to_vec().into(),
                verdict: verdict.to_owned(),
            };
        let fresh = CoSignerMessages {
            description: "One relayed anonymous transfer an outside co-signer signs, read by \
                          proven bits or by an opening of the frame's approval digest. Each \
                          verdict names the MessageMismatch the Rust and TypeScript checks \
                          return, no case opens a slot. Frames carry zeroed proofs."
                .to_owned(),
            ring: SerializablePubkey(ring().program_id()),
            fee_payer: SerializablePubkey(FEE_PAYER),
            signer: SerializablePubkey(address(&co_signer)),
            cases: vec![
                exact_case("exactHonest", &opening, bounds, Vec::new(), "Accepted"),
                exact_case(
                    "falseOpening",
                    &false_opening,
                    vec![limit(Mint::SOL, 4, 4)],
                    Vec::new(),
                    "FalseApprovalOpening",
                ),
                exact_case(
                    "reusedBlinder",
                    &opening,
                    vec![limit(Mint::SOL, 4, 4)],
                    vec![opening.blinder.clone()],
                    "ReusedApprovalBlinder",
                ),
                exact_case(
                    "peakOverLimit",
                    &opening,
                    vec![limit(Mint::SOL, 3, 4)],
                    Vec::new(),
                    "ApprovalOverLimit",
                ),
                exact_case(
                    "outflowOverLimit",
                    &opening,
                    vec![limit(Mint::SOL, 4, 3)],
                    Vec::new(),
                    "ApprovalOverLimit",
                ),
                exact_case(
                    "noLimit",
                    &opening,
                    Vec::new(),
                    Vec::new(),
                    "ApprovalOverLimit",
                ),
                CoSignerCase {
                    message: plain_message.clone().into(),
                    ..exact_case(
                        "missingDigest",
                        &opening,
                        vec![limit(Mint::SOL, 4, 4)],
                        Vec::new(),
                        "MissingApprovalDigest",
                    )
                },
                threshold_case("thresholdHonest", 0, &plain_message, "Accepted"),
                threshold_case("thresholdWithDigest", 0, &message, "Accepted"),
                threshold_case(
                    "maskUnaccepted",
                    0,
                    &masked_message,
                    "ApprovalMaskUnaccepted",
                ),
                threshold_case(
                    "maskAccepted",
                    ApprovalMask::OUTFLOW.bits(),
                    &masked_message,
                    "Accepted",
                ),
            ],
        };
        let vector = crate::tests::support::pinned_vector("relay_co_signer_messages.json", fresh);
        for case in &vector.cases {
            let pending = co_signer_pending(
                &disclosed.relay_id,
                case.message.0.clone(),
                vector.signer.0,
                case.rule(),
                &config,
            );
            let checked = match pending.verify(vector.signer.0) {
                Ok(verified) => Ok(verified),
                Err(RingError::RelayMessage(mismatch)) => Err(mismatch),
                Err(other) => panic!("{}: {other:?}", case.name),
            };
            assert_eq!(
                crate::tests::support::verdict(checked),
                case.verdict,
                "{}",
                case.name
            );
        }

        let rule = vector.cases[0].rule();
        let pending = co_signer_pending(
            &disclosed.relay_id,
            vector.cases[0].message.0.clone(),
            vector.signer.0,
            rule,
            &config,
        );
        signs(&pending, &co_signer).await;
        refused(&pending, &sender, MessageMismatch::Unrequested);
    }

    #[tokio::test]
    async fn an_exact_co_signer_of_a_relayed_in_proof_transfer_signs_and_each_attempt_draws_afresh()
    {
        let (sender, payee, co_signer) = (keypair(1), keypair(2), keypair(6));
        let client = chain(
            RingMode::Confidential,
            Some(address(&co_signer)),
            &[&sender, &payee],
        )
        .client();
        let config = ring().require_config(client.zolana()).await.unwrap();
        let attempt = || {
            let mut transaction = ConfidentialTransaction::new_with_ring(
                vec![ring_utxo(&sender, Mint::SOL, 10, 0)],
                FEE_PAYER,
                ring().program_id(),
            )
            .unwrap();
            transaction
                .transfer_with_ring(
                    &payee.shielded_address().unwrap(),
                    Mint::SOL,
                    4,
                    Some(ring().program_id()),
                )
                .unwrap();
            CustomRingTransfer::new(CustomRingTransferInput {
                ring: ring(),
                sender: &sender,
                nullifier_key: Some(&sender.nullifier_key),
                transaction,
            })
            .with_co_signer(address(&co_signer))
            .with_exact_approval()
            .with_in_proof_owner(&sender.signing_key)
        };
        let first = attempt();
        let asked = sent(first.prepare_relay(client.zolana(), quote()).await.unwrap()).await;
        let opening = asked.pending.approval_opening().unwrap().clone();
        let again = attempt();
        let retried = sent(again.prepare_relay(client.zolana(), quote()).await.unwrap()).await;
        assert_ne!(
            opening.blinder,
            retried.pending.approval_opening().unwrap().blinder
        );
        let built = frame(&client, &asked.request).await;
        let rule = CoSignerRule::Exact(ExactApproval {
            opening: opening.clone(),
            limits: vec![ApprovalLimit {
                mint: Mint::SOL.asset,
                peak: 4,
                outflow: 4,
            }],
            seen_blinders: Vec::new(),
        });
        signs(
            &co_signer_pending(
                &asked.relay_id,
                relay_message(&FEE_PAYER, &[built], UNITS).0,
                address(&co_signer),
                rule,
                &config,
            ),
            &co_signer,
        )
        .await;
    }

    async fn request_json(
        client: &crate::RingClient<Chain, Chain>,
        transfer: crate::AnonymousTransfer<'_>,
    ) -> (serde_json::Value, Option<ApprovalOpening>) {
        let assembled = transfer.assemble(client).await.unwrap();
        let request = assembled.request().unwrap();
        (
            serde_json::to_value(&*request.body).unwrap(),
            assembled.frame.approval_opening.clone(),
        )
    }

    /// `prover/ring/params.go` reads both fields, a plain frame sends neither.
    #[tokio::test]
    async fn the_prover_request_names_the_digest_only_when_the_frame_discloses() {
        let (sender, payee) = (keypair(1), keypair(2));
        let client = chain(RingMode::Anonymous, None, &[&sender, &payee]).client();
        let build = || {
            transfer(&sender, vec![ring_utxo(&sender, Mint::SOL, 10, 0)])
                .with_anonymous_signer(&sender.signing_key)
                .with_payment(pay(&payee, 4))
                .unwrap()
        };
        let (plain, none) = request_json(&client, build()).await;
        assert!(none.is_none());
        assert!(plain.get("approvalTotals").is_none());
        assert!(plain.get("approvalBlinder").is_none());
        let (disclosed, opening) = request_json(&client, build().with_exact_approval()).await;
        let opening = opening.unwrap();
        assert!(disclosed["approvalTotals"].is_string());
        assert_eq!(
            disclosed["approvalBlinder"].as_str().unwrap(),
            format!("0x{}", hex::encode(opening.blinder.0))
        );
    }

    /// Padding and repeats in the rows reach no total, the frame commits one layout.
    #[tokio::test]
    async fn the_totals_read_the_same_past_padded_rows() {
        let (sender, payee) = (keypair(1), keypair(2));
        let client = chain(RingMode::Anonymous, None, &[&sender, &payee]).client();
        let transaction = transfer(&sender, vec![ring_utxo(&sender, Mint::SOL, 10, 0)])
            .with_anonymous_signer(&sender.signing_key)
            .with_payment(pay(&payee, 4))
            .unwrap();
        let asked = sent(
            transaction
                .with_exact_approval()
                .prepare_relay(client.zolana(), quote())
                .await
                .unwrap(),
        )
        .await;
        let RelayIntent::Anonymous { proof_inputs, .. } = &asked.request.intent else {
            panic!("the anonymous intent");
        };
        let inputs = RelayProofInputs::decode(proof_inputs.as_bytes()).unwrap();
        let owner = sender.signing_pubkey().owner_proof_input_hash().unwrap();
        let assets = [[0; 32]; spr_interface::N_PUBLIC_SLOTS];
        let gross = [0; spr_interface::N_PUBLIC_SLOTS];
        let totals = |senders: &[[u8; 32]]| {
            crate::limits::Outflows {
                senders,
                inputs: &inputs.inputs,
                outputs: &inputs.outputs,
                public_assets: &assets,
                public_gross: &gross,
            }
            .approval_totals(inputs.outputs.len())
            .unwrap()
        };
        assert_eq!(
            totals(&[owner]).commitment(&[7; 32]).unwrap(),
            totals(&[owner, [0; 32], owner, [0; 32]])
                .commitment(&[7; 32])
                .unwrap()
        );
    }
}

mod enroll_message {
    //! The enrollment an owner with no SOL signs, read against what it proved.

    use solana_instruction::Instruction;
    use solana_signer::Signer;
    use zolana_ring_client::rpc::{RelayEnrollInputs, ENROLL_COMPUTE_UNITS};

    use super::*;
    use crate::{
        tests::support::{pinned_vector, relay_message, verdict, MessageCase, MessageVector},
        EnrollInstruction, EnrollRelay, MessageMismatch, RelaySent,
    };

    const FEE_PAYER: Address = Address::new_from_array([0x44; 32]);
    const REGISTRY: Address = Address::new_from_array([0x55; 32]);

    fn inputs(owner: Address) -> RelayEnrollInputs {
        RelayEnrollInputs {
            ring_program_id: ring().program_id(),
            owner,
            tracking_registry: REGISTRY,
            instruction_data: vec![
                custom_ring_interface::storage_instruction::tag::ENROLL,
                1,
                2,
            ],
        }
    }

    async fn signed(answer: Instruction) -> Result<RelayStatus, RingError> {
        let owner = keypair(1);
        let quote = RelayQuote {
            fee_payer: SerializablePubkey(FEE_PAYER),
            valid_until_slot: u64::MAX,
        };
        let relay = StubRelay {
            asks_signature: true,
            message: relay_message(&FEE_PAYER, &[answer], ENROLL_COMPUTE_UNITS).0,
            ..StubRelay::default()
        };
        let prepared = EnrollRelay {
            inputs: inputs(owner.pubkey()),
            owner: &owner,
        }
        .prepare(quote)
        .unwrap();
        let RelaySent::SignMessage(pending) = prepared.send(&relay).await.unwrap() else {
            panic!("the owner signs the enrollment");
        };
        pending.sign(&relay, &owner).await
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct EnrollRequest {
        ring_program_id: SerializablePubkey,
        owner: SerializablePubkey,
        tracking_registry: SerializablePubkey,
        instruction_data: spr_indexer_api::Base64String,
        fee_payer: SerializablePubkey,
    }

    /// The TypeScript check reads the same file and reaches the same verdicts.
    #[test]
    fn the_shared_enroll_messages_keep_their_verdicts() {
        let owner = keypair(1).pubkey();
        let asked = inputs(owner);
        let honest = asked.instruction(FEE_PAYER);
        let mut swapped = honest.clone();
        swapped.accounts[2].pubkey = Address::new_from_array([0x56; 32]);
        let mut rewritten = honest.clone();
        rewritten.data[1] ^= 1;
        let case = |name: &str, payer: &Address, answer: Instruction, verdict: &str| MessageCase {
            name: name.to_owned(),
            message: relay_message(payer, &[answer], ENROLL_COMPUTE_UNITS),
            verdict: verdict.to_owned(),
        };
        let fresh = MessageVector {
            description: "One relayed enrollment the owner proved and signed, and the messages \
                          Ring RPC could answer with. Each verdict names the MessageMismatch the \
                          Rust ExpectedEnroll and the TypeScript check return."
                .to_owned(),
            request: EnrollRequest {
                ring_program_id: SerializablePubkey(asked.ring_program_id),
                owner: SerializablePubkey(asked.owner),
                tracking_registry: SerializablePubkey(asked.tracking_registry),
                instruction_data: asked.instruction_data.clone().into(),
                fee_payer: SerializablePubkey(FEE_PAYER),
            },
            cases: vec![
                case("honest", &FEE_PAYER, honest.clone(), "Accepted"),
                case("swappedRegistry", &FEE_PAYER, swapped, "Accounts"),
                case("rewrittenData", &FEE_PAYER, rewritten, "Data"),
                case("ownerPaysFee", &owner, honest, "FeePayer"),
            ],
        };
        let vector = pinned_vector("relay_enroll_messages.json", fresh);
        let expected = crate::relay_message::ExpectedEnroll {
            fee_payer: vector.request.fee_payer.0,
            inputs: RelayEnrollInputs {
                ring_program_id: vector.request.ring_program_id.0,
                owner: vector.request.owner.0,
                tracking_registry: vector.request.tracking_registry.0,
                instruction_data: vector.request.instruction_data.0.clone(),
            },
        };
        assert_eq!(vector.cases.len(), 4);
        for case in &vector.cases {
            assert_eq!(
                verdict(expected.check(&case.message.0)),
                case.verdict,
                "{}",
                case.name
            );
        }
    }

    #[tokio::test]
    async fn the_enrollment_the_owner_proved_is_signed() {
        let honest = inputs(keypair(1).pubkey()).instruction(FEE_PAYER);
        assert!(matches!(
            signed(honest.clone()).await,
            Ok(RelayStatus::Sent { .. })
        ));
        let built = EnrollInstruction {
            payer: FEE_PAYER,
            owner: keypair(1).pubkey(),
            tracking_registry: REGISTRY,
            data: bytemuck::Zeroable::zeroed(),
            proof: None,
        }
        .instruction();
        assert_eq!(honest.accounts, built.accounts);
        assert_eq!(honest.program_id, built.program_id);
    }

    #[tokio::test]
    async fn a_relay_that_swaps_an_account_or_a_byte_is_refused() {
        let honest = inputs(keypair(1).pubkey()).instruction(FEE_PAYER);
        let mut swapped = honest.clone();
        swapped.accounts[2].pubkey = Address::new_from_array([0x56; 32]);
        assert!(matches!(
            signed(swapped).await,
            Err(RingError::RelayMessage(MessageMismatch::Accounts))
        ));
        let mut rewritten = honest;
        rewritten.data[1] ^= 1;
        assert!(matches!(
            signed(rewritten).await,
            Err(RingError::RelayMessage(MessageMismatch::Data))
        ));
    }
}
