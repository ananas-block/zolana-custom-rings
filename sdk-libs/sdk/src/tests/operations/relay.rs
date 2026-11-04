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
                message: vec![1].into(),
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

    async fn submit_relay(&self, _request: SubmitRelayRequest) -> Result<RelayStatus, RingError> {
        unreachable!("a wallet relay signs inside the proof")
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
        pending.verify(),
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
        DelegateMove, DelegatePayment, MessageMismatch, PreparedAuthorityTransfer, RelaySent,
        RelayedTransferInput, RingTransfer,
    };

    const FEE_PAYER: Address = Address::new_from_array([0x44; 32]);
    const UNITS: u32 = compute_unit_limit(InstructionTag::AuthorityTransfer);
    const MOVED: u64 = 4;

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
        member: ShieldedKeypair,
        delegate: Address,
        notes: Vec<WalletUtxo>,
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
            let chain = Chain::ring(RingSettings {
                has_policy: true,
                delegate: Some(delegate),
                ..RingSettings::new(mode)
            })
            .with_registry(
                Registry::new(&[(&member, 1), (&keypair(2), 1), (&keypair(3), 1)]),
                &pipeline_rules(),
            );
            Self {
                client: chain.client(),
                notes: vec![ring_utxo(&member, Mint::SOL, 10, 0)],
                member,
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
            let assets = AssetRegistry::default();
            let proof_inputs = DelegateMove {
                ring: ring(),
                delegate: self.delegate,
                payer: FEE_PAYER,
                source: transfer.source.0,
                source_nullifier_key: &self.member.nullifier_key,
                utxos: &self.notes,
                mint: transfer.mint.0,
                payments: transfer
                    .payments
                    .iter()
                    .map(|payment| DelegatePayment {
                        recipient: payment.recipient.0,
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
                source: SerializableShieldedAddress(keypair(1).shielded_address().unwrap()),
                mint: SerializablePubkey(Mint::SOL.asset),
                payments: vec![AuthorityPayment {
                    recipient: SerializableShieldedAddress(keypair(2).shielded_address().unwrap()),
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
                amount: 1,
            });
            assert_eq!(
                verdict_of(build(extra, asked.tx_viewing_key.clone()).await),
                Err(MessageMismatch::Recipients),
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
