use custom_ring_interface::{CoSignScope, CustomRingError, RingMode};
use solana_address::Address;
use spr_interface::pda;
use zolana_ring_keys::RingAddress;

use crate::{
    tests::support::{history, keypair, ring, Chain, RingSettings, TREE_ID},
    DepositAsset, DepositRecipient, RingDeposit, RingError,
};

fn deposit<'a>(
    payer: &'a (dyn solana_signer::Signer + Sync),
    recipient: DepositRecipient<'a>,
) -> RingDeposit<'a> {
    RingDeposit {
        ring: ring(),
        payer,
        recipient,
        tree: pda::tree(TREE_ID),
        asset: DepositAsset::Sol,
        amount: 5,
        cosigner: None,
        list_salt: None,
    }
}

#[tokio::test]
async fn an_anonymous_ring_takes_deposits_only_for_the_depositors_hidden_owner() {
    let member = keypair(1);
    let payer = keypair(9);
    let anonymous = Chain::ring(RingSettings::new(RingMode::Anonymous));
    let confidential = Chain::ring(RingSettings::new(RingMode::Confidential));
    let address = member.shielded_address().unwrap();
    let history = history(&member);
    let hidden = DepositRecipient::Anonymous {
        keys: &member,
        history: &history,
    };
    assert!(matches!(
        deposit(&payer, DepositRecipient::Confidential(address))
            .prepare(&anonymous)
            .await,
        Err(RingError::AnonymousDepositUntagged)
    ));
    assert!(matches!(
        deposit(&payer, hidden).prepare(&confidential).await,
        Err(RingError::NotAnonymousRing)
    ));
    assert!(matches!(
        deposit(&member, hidden).prepare(&anonymous).await,
        Err(RingError::AnonymousPublicSignerLinksOwner)
    ));
    let prepared = deposit(&payer, hidden).prepare(&anonymous).await.unwrap();
    assert_eq!(
        (prepared.utxos()[0].owner, prepared.utxos()[0].amount),
        (member.signing_pubkey(), 5)
    );
}

/// A keyed note needs its owner's credential under the same key.
#[tokio::test]
async fn a_deposit_takes_the_owners_credential_key_before_any_proof() {
    let (stranger, payer) = (keypair(2), keypair(9));
    let keyed = stranger.shielded_address().unwrap();
    let unenrolled = Chain::ring(RingSettings::new(RingMode::Confidential)).with_credentials(&[]);
    let refused = deposit(&payer, DepositRecipient::Confidential(keyed))
        .prepare(&unenrolled)
        .await
        .unwrap();
    assert!(matches!(
        refused.prove_bound(&unenrolled.client()).await,
        Err(RingError::RecipientNotEnrolled { slot_index: 0 })
    ));
    let other_key = custom_ring_interface::AuditCredential {
        nullifier_pk: keypair(3).shielded_address().unwrap().nullifier_pubkey,
        ..crate::tests::support::credential_of(&keyed, [0x06; 32])
    };
    let rekeyed =
        Chain::ring(RingSettings::new(RingMode::Confidential)).with_enrolled(&[other_key]);
    let mismatched = deposit(&payer, DepositRecipient::Confidential(keyed))
        .prepare(&rekeyed)
        .await
        .unwrap();
    assert!(matches!(
        mismatched.prove_bound(&rekeyed.client()).await,
        Err(RingError::RecipientKeyMismatch { slot_index: 0 })
    ));
}

/// A note sealed to a viewing key the recipient's user record no longer names stays unread.
#[tokio::test]
async fn a_deposit_refuses_a_viewing_key_its_recipients_record_replaced() {
    let (member, payer) = (keypair(2), keypair(9));
    let enrolled = member.shielded_address().unwrap();
    let rotated = spr_keypair::ShieldedAddress {
        viewing_pubkey: keypair(3).shielded_address().unwrap().viewing_pubkey,
        ..enrolled
    };
    let chain = Chain::ring(RingSettings::new(RingMode::Confidential)).with_user_record(&enrolled);
    let stale = deposit(&payer, DepositRecipient::Confidential(rotated))
        .prepare(&chain)
        .await
        .unwrap();
    assert!(matches!(
        stale.prove_bound(&chain.clone().client()).await,
        Err(RingError::RecipientViewingKeyStale { slot_index: 0 })
    ));
}

#[tokio::test]
async fn a_deposit_names_the_co_signer_a_deposit_scope_demands() {
    let member = keypair(1);
    let payer = keypair(9);
    let co_signer = keypair(8);
    let chain = Chain::ring(RingSettings {
        co_signer: Some((
            solana_signer::Signer::pubkey(&co_signer),
            CoSignScope::DEPOSITS,
        )),
        ..RingSettings::new(RingMode::Confidential)
    });
    let recipient = DepositRecipient::Confidential(member.shielded_address().unwrap());
    assert!(matches!(
        deposit(&payer, recipient).prepare(&chain).await,
        Err(RingError::Program(CustomRingError::MissingCoSigner))
    ));
    let named = RingDeposit {
        cosigner: Some(&co_signer),
        ..deposit(&payer, recipient)
    };
    assert!(named.prepare(&chain).await.is_ok());
    let stranger = keypair(7);
    let wrong = RingDeposit {
        cosigner: Some(&stranger),
        ..deposit(&payer, recipient)
    };
    assert!(matches!(
        wrong.prepare(&chain).await,
        Err(RingError::Program(CustomRingError::InvalidCoSignerRecord))
    ));
}

#[tokio::test]
async fn a_co_signer_outside_the_deposit_scope_does_not_sign() {
    let member = keypair(1);
    let payer = keypair(9);
    let co_signer = keypair(8);
    let recipient = DepositRecipient::Confidential(member.shielded_address().unwrap());
    for (scope, signs) in [
        (CoSignScope::WITHDRAWALS, false),
        (CoSignScope::DEPOSITS, true),
    ] {
        let chain = Chain::ring(RingSettings {
            co_signer: Some((solana_signer::Signer::pubkey(&co_signer), scope)),
            ..RingSettings::new(RingMode::Confidential)
        });
        let named = RingDeposit {
            cosigner: Some(&co_signer),
            ..deposit(&payer, recipient)
        };
        let prepared = named.prepare(&chain).await.unwrap();
        assert_eq!(
            named.batch().signers(&prepared).len(),
            1 + usize::from(signs)
        );
    }
}

fn publishes(prepared: &crate::PreparedRingDeposit, tag: &[u8; 32]) -> bool {
    prepared
        .spp
        .data
        .windows(tag.len())
        .any(|bytes| bytes == tag)
}

#[tokio::test]
async fn an_own_deposit_takes_the_sender_tag_at_tx_count_and_advances_it() {
    let member = keypair(1);
    let payer = keypair(9);
    let chain = Chain::ring(RingSettings::new(RingMode::Anonymous));
    let history = history(&member);
    let hidden = deposit(
        &payer,
        DepositRecipient::Anonymous {
            keys: &member,
            history: &history,
        },
    );
    let prepared = hidden.prepare(&chain).await.unwrap();
    assert!(publishes(
        &prepared,
        &member.get_sender_view_tag(0).unwrap()
    ));
    let advanced = prepared.viewing_history().unwrap();
    assert_eq!(advanced.current().tx_count(), 1);
    assert_eq!(hidden.viewing_history().unwrap().as_ref(), Some(advanced));
}

#[tokio::test]
async fn a_deposit_from_the_stored_history_takes_the_next_sender_tag() {
    let member = keypair(1);
    let payer = keypair(9);
    let chain = Chain::ring(RingSettings::new(RingMode::Anonymous));
    let history = history(&member);
    let own = |history| {
        deposit(
            &payer,
            DepositRecipient::Anonymous {
                keys: &member,
                history,
            },
        )
    };
    let stored = own(&history).viewing_history().unwrap().unwrap();
    let next = own(&stored).prepare(&chain).await.unwrap();
    assert!(publishes(&next, &member.get_sender_view_tag(1).unwrap()));
    assert!(!publishes(&next, &member.get_sender_view_tag(0).unwrap()));
    assert_eq!(next.viewing_history().unwrap().current().tx_count(), 2);
}

#[tokio::test]
async fn a_deposit_to_another_member_takes_its_request_tag_or_its_viewing_key() {
    let recipient = keypair(2);
    let payer = keypair(9);
    let chain = Chain::ring(RingSettings::new(RingMode::Anonymous));
    let to = RingAddress {
        recipient: recipient.shielded_address().unwrap(),
        ring_program_id: ring().program_id(),
        list_salt: [7; 32],
    };
    let request = recipient.get_recipient_request_view_tag(0).unwrap();
    let paid = |deposit_tag| {
        deposit(
            &payer,
            DepositRecipient::AnonymousPayment {
                to: &to,
                deposit_tag,
            },
        )
    };
    assert!(matches!(
        paid(None).prepare(&chain).await,
        Err(RingError::DepositBootstrapTag)
    ));
    let requested = paid(Some(request)).prepare(&chain).await.unwrap();
    assert!(publishes(&requested, &request));
}

/// Identical deposit bytes yield one commitment, and the second note could never spend.
#[tokio::test]
async fn a_retry_draws_a_new_note_and_a_frame_proves_once() {
    let registered = keypair(1);
    let payer = keypair(9);
    let chain = Chain::ring(RingSettings {
        has_policy: true,
        ..RingSettings::new(RingMode::Confidential)
    })
    .with_registry(
        crate::tests::support::Registry::new(&[]),
        &crate::tests::pipeline_rules(),
    );
    let client = chain.client();
    let prepared = deposit(
        &payer,
        DepositRecipient::Confidential(registered.shielded_address().unwrap()),
    )
    .prepare(client.zolana())
    .await
    .unwrap();
    let retried = prepared.fresh_attempt().unwrap();
    assert_ne!(retried.utxos()[0].blinding, prepared.utxos()[0].blinding);
    assert_eq!(retried.utxos()[0].amount, prepared.utxos()[0].amount);
    assert_ne!(retried.spp.data, prepared.spp.data);
    assert_ne!(
        retried.disclosure.context_hash,
        prepared.disclosure.context_hash
    );
    let _first_attempt = prepared.prove(&client).await;
    assert!(matches!(
        prepared.prove(&client).await,
        Err(RingError::DepositFrameReused)
    ));
    assert!(!matches!(
        retried.prove(&client).await,
        Err(RingError::DepositFrameReused)
    ));
}

#[tokio::test]
async fn a_deposit_refuses_an_address_of_another_ring() {
    let payer = keypair(9);
    let chain = Chain::ring(RingSettings::new(RingMode::Anonymous));
    let other = Address::new_from_array([0x47; 32]);
    let to = RingAddress {
        recipient: keypair(2).shielded_address().unwrap(),
        ring_program_id: other,
        list_salt: [7; 32],
    };
    let paid = DepositRecipient::AnonymousPayment {
        to: &to,
        deposit_tag: None,
    };
    assert!(matches!(
        deposit(&payer, paid).prepare(&chain).await,
        Err(RingError::ForeignRingAddress { address, ring: paid })
            if address == other && paid == ring().program_id()
    ));
}

mod relay_message {
    //! The deposit message a depositor signs, refused when it moves more than the request.

    use std::sync::Mutex;

    use async_trait::async_trait;
    use bytemuck::Zeroable;
    use custom_ring_interface::{compute_unit_limit, CustomRingProof, InstructionTag};
    use solana_instruction::{AccountMeta, Instruction};
    use solana_message::{legacy, VersionedMessage};
    use solana_signer::Signer;
    use spr_event::EncryptedRingDepositData;
    use spr_indexer_api::{Base64String, SerializablePubkey};
    use spr_keypair::ShieldedKeypair;
    use spr_program::instruction::{DepositAsset, RingAssetDeposit};
    use zolana_ring_client::rpc::{
        GetRelayQuoteRequest, GetRelayStatusRequest, PrepareAuthorityTransferRequest,
        PrepareRelayRequest, RelayDepositInputs, RelayQuote, RelayStatus, RelayStep,
        SubmitRelayRequest,
    };

    use super::*;
    use crate::{
        relay_message::ExpectedDeposit,
        tests::support::{pinned_vector, relay_message, verdict, MessageCase, MessageVector},
        CustomRing, MessageMismatch, RelaySent, RelayedDeposit, RingRelay,
    };

    const FEE_PAYER: Address = Address::new_from_array([0x44; 32]);
    const UNITS: u32 = compute_unit_limit(InstructionTag::Deposit);

    #[derive(Clone, Copy)]
    enum Answer {
        Honest,
        ExtraSplTransfer,
        ExtraSystemTransfer,
        DepositorPaysFee,
        AlteredDeposit,
        DepositorInRingPrefix,
        BudgetAboveDeposit,
        ForeignProgram,
        Legacy,
        TrailingByte,
        DuplicateAddress,
        ReadonlyFeePayer,
    }

    impl Answer {
        const ALL: [Self; 12] = [
            Self::Honest,
            Self::ExtraSplTransfer,
            Self::ExtraSystemTransfer,
            Self::DepositorPaysFee,
            Self::AlteredDeposit,
            Self::DepositorInRingPrefix,
            Self::BudgetAboveDeposit,
            Self::ForeignProgram,
            Self::Legacy,
            Self::TrailingByte,
            Self::DuplicateAddress,
            Self::ReadonlyFeePayer,
        ];

        /// Fixed here, never read back from the check.
        fn case(self) -> (&'static str, &'static str) {
            match self {
                Self::Honest => ("honest", "Accepted"),
                Self::ExtraSplTransfer => ("extraSplTransfer", "Instructions"),
                Self::ExtraSystemTransfer => ("extraSystemTransfer", "Instructions"),
                Self::DepositorPaysFee => ("depositorPaysFee", "FeePayer"),
                Self::AlteredDeposit => ("alteredDeposit", "Data"),
                Self::DepositorInRingPrefix => ("depositorInRingPrefix", "Accounts"),
                Self::BudgetAboveDeposit => ("budgetAboveDeposit", "Budget"),
                Self::ForeignProgram => ("foreignProgram", "Program"),
                Self::Legacy => ("legacy", "NotV1"),
                Self::TrailingByte => ("trailingByte", "Undecodable"),
                Self::DuplicateAddress => ("duplicateAddress", "Undecodable"),
                Self::ReadonlyFeePayer => ("readonlyFeePayer", "Undecodable"),
            }
        }

        fn message(self, honest: &Instruction, depositor: Address) -> Base64String {
            let taken = Address::new_from_array([0x63; 32]);
            let with =
                |extra: Instruction| relay_message(&FEE_PAYER, &[honest.clone(), extra], UNITS);
            match self {
                Self::Honest => relay_message(&FEE_PAYER, std::slice::from_ref(honest), UNITS),
                Self::ExtraSplTransfer => with(
                    spl_token_2022_interface::instruction::transfer_checked(
                        &spl_token_2022_interface::ID,
                        &Address::new_from_array([0x61; 32]),
                        &Address::new_from_array([0x62; 32]),
                        &taken,
                        &depositor,
                        &[],
                        1_000,
                        6,
                    )
                    .unwrap(),
                ),
                Self::ExtraSystemTransfer => with(solana_system_interface::instruction::transfer(
                    &depositor, &taken, 1_000,
                )),
                Self::DepositorPaysFee => {
                    relay_message(&depositor, std::slice::from_ref(honest), UNITS)
                }
                Self::AlteredDeposit => {
                    let mut altered = honest.clone();
                    *altered.data.last_mut().unwrap() ^= 1;
                    relay_message(&FEE_PAYER, &[altered], UNITS)
                }
                Self::DepositorInRingPrefix => {
                    let mut widened = honest.clone();
                    widened
                        .accounts
                        .insert(1, AccountMeta::new_readonly(depositor, false));
                    relay_message(&FEE_PAYER, &[widened], UNITS)
                }
                Self::BudgetAboveDeposit => {
                    relay_message(&FEE_PAYER, std::slice::from_ref(honest), UNITS + 1)
                }
                Self::ForeignProgram => {
                    let foreign = Instruction {
                        program_id: Address::new_from_array([0x64; 32]),
                        ..honest.clone()
                    };
                    relay_message(&FEE_PAYER, &[foreign], UNITS)
                }
                Self::Legacy => VersionedMessage::Legacy(legacy::Message::new(
                    std::slice::from_ref(honest),
                    Some(&FEE_PAYER),
                ))
                .serialize()
                .into(),
                Self::TrailingByte => {
                    let mut bytes =
                        relay_message(&FEE_PAYER, std::slice::from_ref(honest), UNITS).0;
                    bytes.push(0);
                    bytes.into()
                }
                Self::DuplicateAddress | Self::ReadonlyFeePayer => {
                    let honest = relay_message(&FEE_PAYER, std::slice::from_ref(honest), UNITS);
                    let Ok(VersionedMessage::V1(mut message)) = wincode::deserialize(&honest.0)
                    else {
                        unreachable!("the relay compiles v1 messages");
                    };
                    match self {
                        Self::DuplicateAddress => message.account_keys.push(depositor),
                        _ => {
                            message.header.num_readonly_signed_accounts =
                                message.header.num_required_signatures
                        }
                    }
                    message.serialize().into()
                }
            }
        }
    }

    /// Ring RPC's deposit path without its proof, answering with one `Answer`.
    struct DepositRelay {
        chain: Chain,
        answer: Answer,
        honest: Mutex<Option<(Instruction, RelayDepositInputs)>>,
        submitted: Mutex<Vec<SubmitRelayRequest>>,
    }

    impl DepositRelay {
        fn new(answer: Answer) -> Self {
            Self {
                chain: Chain::ring(RingSettings::new(RingMode::Confidential)),
                answer,
                honest: Mutex::new(None),
                submitted: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl RingRelay for DepositRelay {
        async fn get_relay_quote(
            &self,
            _request: GetRelayQuoteRequest,
        ) -> Result<RelayQuote, RingError> {
            unreachable!("the test holds its quote")
        }

        async fn prepare_relay(
            &self,
            request: PrepareRelayRequest,
        ) -> Result<RelayStep, RingError> {
            let inputs = RelayDepositInputs::decode(request.intent.proof_inputs().as_bytes())?;
            let honest = RelayedDeposit {
                ring: ring(),
                inputs: &inputs,
                fee_payer: FEE_PAYER,
                co_signer: None,
            }
            .prepare(&self.chain)
            .await?
            .instruction(
                CustomRingProof::zeroed(),
                &crate::deposit::DepositFrame {
                    roots: crate::deposit::DepositRoots {
                        own: None,
                        curator: None,
                    },
                    key_capacity: 1,
                    credential_read: custom_ring_interface::CredentialRead::new(0, &[0])?,
                    credential_trees: crate::CredentialTrees::new(
                        [crate::tests::support::CREDENTIAL_TREE_ID],
                        1,
                    )?,
                },
            )?;
            let message = self.answer.message(&honest, inputs.depositor);
            *self.honest.lock().unwrap() = Some((honest, inputs));
            Ok(RelayStep::SignMessage {
                relay_id: request.relay_id()?,
                message,
            })
        }

        async fn prepare_authority_transfer(
            &self,
            _request: PrepareAuthorityTransferRequest,
        ) -> Result<RelayStep, RingError> {
            unreachable!("a deposit names no delegate")
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

    async fn relayed_signature(
        relay: &DepositRelay,
        depositor: &ShieldedKeypair,
    ) -> Result<RelayStatus, RingError> {
        let recipient = DepositRecipient::Confidential(keypair(1).shielded_address().unwrap());
        let quote = RelayQuote {
            fee_payer: FEE_PAYER.into(),
            valid_until_slot: 0,
        };
        let prepared = deposit(depositor, recipient)
            .prepare_relay(&relay.chain, quote)
            .await
            .unwrap();
        let RelaySent::SignMessage(pending) = prepared.send(relay).await.unwrap() else {
            panic!("a relayed deposit waits for the depositor");
        };
        pending.sign(relay, depositor).await
    }

    #[tokio::test]
    async fn a_deposit_message_with_an_extra_spl_transfer_from_the_depositor_is_refused() {
        let relay = DepositRelay::new(Answer::ExtraSplTransfer);
        assert!(matches!(
            relayed_signature(&relay, &keypair(9)).await,
            Err(RingError::RelayMessage(MessageMismatch::Instructions))
        ));
        assert!(relay.submitted.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn the_deposit_message_the_relay_builds_is_signed() {
        let relay = DepositRelay::new(Answer::Honest);
        let depositor = keypair(9);
        relayed_signature(&relay, &depositor).await.unwrap();
        let honest = relay.honest.lock().unwrap().as_ref().unwrap().0.clone();
        let message = Answer::Honest.message(&honest, depositor.pubkey());
        let [submitted] = <[SubmitRelayRequest; 1]>::try_from(std::mem::take(
            &mut *relay.submitted.lock().unwrap(),
        ))
        .unwrap();
        assert_eq!(submitted.signer.0, depositor.pubkey());
        assert!(submitted
            .signature
            .0
            .verify(depositor.pubkey().as_ref(), &message.0));
    }

    /// A SOL deposit request, every field the depositor's own.
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields, rename_all = "camelCase")]
    struct DepositRequest {
        ring: SerializablePubkey,
        fee_payer: SerializablePubkey,
        tree: SerializablePubkey,
        depositor: SerializablePubkey,
        view_tag: String,
        owner_utxo_hash: String,
        amount: u64,
        ring_data_hash: String,
        tx_viewing_pk: String,
        salt: String,
        ciphertext: Base64String,
    }

    impl DepositRequest {
        fn of(inputs: &RelayDepositInputs, owner_utxo_hash: [u8; 32]) -> Self {
            Self {
                ring: inputs.ring_program_id.into(),
                fee_payer: FEE_PAYER.into(),
                tree: inputs.tree.into(),
                depositor: inputs.depositor.into(),
                view_tag: hex::encode(inputs.view_tag),
                owner_utxo_hash: hex::encode(owner_utxo_hash),
                amount: inputs.amount,
                ring_data_hash: hex::encode([0u8; 32]),
                tx_viewing_pk: hex::encode(inputs.encrypted.tx_viewing_pk),
                salt: hex::encode(inputs.encrypted.salt),
                ciphertext: inputs.encrypted.ciphertext.clone().into(),
            }
        }

        fn expected(&self) -> ExpectedDeposit {
            let bytes = |text: &str| hex::decode(text).unwrap().try_into().unwrap();
            let deposit = RingAssetDeposit {
                asset: DepositAsset::Sol,
                view_tag: bytes(&self.view_tag),
                owner_utxo_hash: bytes(&self.owner_utxo_hash),
                amount: self.amount,
                ring_data_hash: bytes(&self.ring_data_hash),
                encrypted: EncryptedRingDepositData {
                    tx_viewing_pk: hex::decode(&self.tx_viewing_pk)
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    salt: bytes16(&self.salt),
                    ciphertext: self.ciphertext.0.clone(),
                },
            };
            ExpectedDeposit {
                ring: CustomRing::new(self.ring.0),
                fee_payer: self.fee_payer.0,
                depositor: self.depositor.0,
                spp: spr_program::instruction::RingDeposit {
                    tree: self.tree.0,
                    depositor: self.depositor.0,
                    ring_program_id: self.ring.0,
                    deposits: vec![deposit],
                }
                .instruction()
                .unwrap(),
            }
        }
    }

    fn bytes16(text: &str) -> [u8; 16] {
        hex::decode(text).unwrap().try_into().unwrap()
    }

    /// The TypeScript check reads the same file and reaches the same verdicts.
    #[tokio::test]
    async fn the_shared_deposit_messages_keep_their_verdicts() {
        let relay = DepositRelay::new(Answer::Honest);
        relayed_signature(&relay, &keypair(9)).await.unwrap();
        let (honest, inputs) = relay.honest.lock().unwrap().take().unwrap();
        let owner_utxo_hash = spr_transaction::owner_utxo_hash(
            &inputs.recipient.owner_hash().unwrap(),
            &custom_ring_interface::domain::deposit_blinding(&inputs.blinding_secret).unwrap(),
        )
        .unwrap();
        let fresh = MessageVector {
            description: "One relayed SOL deposit of 5 into a confidential ring and the messages \
                          Ring RPC could answer with. The honest message is the relay's deposit \
                          path with a zeroed proof, each other case changes one thing. verdict \
                          names the MessageMismatch the Rust ExpectedDeposit::check and the \
                          TypeScript checkDepositMessage return."
                .to_owned(),
            request: DepositRequest::of(&inputs, owner_utxo_hash),
            cases: Answer::ALL
                .map(|answer| {
                    let (name, verdict) = answer.case();
                    MessageCase {
                        name: name.to_owned(),
                        message: answer.message(&honest, inputs.depositor),
                        verdict: verdict.to_owned(),
                    }
                })
                .into(),
        };
        let vector = pinned_vector("relay_deposit_messages.json", fresh);
        let expected = vector.request.expected();
        assert_eq!(vector.cases.len(), Answer::ALL.len());
        for case in &vector.cases {
            assert_eq!(
                verdict(expected.check(&case.message.0)),
                case.verdict,
                "{}",
                case.name
            );
        }
    }
}

#[tokio::test]
async fn a_deposit_request_carries_the_go_fields_at_the_key_capacity() {
    let member = keypair(1);
    let payer = keypair(9);
    let chain = Chain::ring(RingSettings::new(RingMode::Confidential));
    let recipient = DepositRecipient::Confidential(member.shielded_address().unwrap());
    let prepared = deposit(&payer, recipient).prepare(&chain).await.unwrap();
    let records = prepared.disclosure.records(ring(), &chain).await.unwrap();
    assert_eq!(records.key_capacity, 1);
    let body = serde_json::to_value(prepared.disclosure.body(&records).unwrap()).unwrap();
    let mut keys: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "addressRoot",
            "amounts",
            "assetEntries",
            "assets",
            "auditorPk",
            "blindingSecrets",
            "contextHash",
            "count",
            "credentialOpenings",
            "credentialOwner",
            "curatorProof",
            "curatorRecords",
            "curatorRoot",
            "curatorSubjects",
            "ephSk",
            "mintChunks",
            "nullifierPks",
            "outputEntries",
            "ownProof",
            "ownRecords",
            "ownRoot",
            "ownSubjects",
            "ownerEntries",
            "ownerKeys",
            "ownerPkHashes",
            "policyHash",
            "policyLen",
            "publicAmounts",
            "publicAssetEntries",
            "publicAssets",
            "publicGross",
            "publicInputHash",
            "ringId",
            "rowEntries",
            "rules",
            "salted",
            "senderEntries",
            "sources",
            "stateRoots",
            "withdrawalCount",
            "withdrawalHash",
            "withdrawals",
        ]
    );
}

#[tokio::test]
async fn own_notes_of_one_batch_take_consecutive_sender_tags() {
    let member = keypair(1);
    let payer = keypair(9);
    let chain = Chain::ring(RingSettings::new(RingMode::Anonymous));
    let history = history(&member);
    let own = crate::DepositOutput {
        recipient: DepositRecipient::Anonymous {
            keys: &member,
            history: &history,
        },
        asset: DepositAsset::Sol,
        amount: 5,
        list_salt: None,
    };
    let prepared = crate::RingDepositBatch {
        ring: ring(),
        payer: &payer,
        tree: pda::tree(TREE_ID),
        outputs: vec![own, own],
        cosigner: None,
    }
    .prepare(&chain)
    .await
    .unwrap();
    for tx_count in [0, 1] {
        assert!(publishes(
            &prepared,
            &member.get_sender_view_tag(tx_count).unwrap()
        ));
    }
    assert_eq!(prepared.viewing_history().unwrap().current().tx_count(), 2);
}

/// A deposit proves no signature, a PDA recipient sits beside a wallet and no public signer may name either.
#[tokio::test]
async fn an_anonymous_batch_funds_a_pda_beside_a_wallet() {
    use solana_signer::Signer;
    use spr_keypair::{PublicKey, ShieldedAddress};
    let (member, holder, payer) = (keypair(2), keypair(3), keypair(9));
    let program_owner = Address::new_from_array([0x51; 32]);
    let wallet = member.shielded_address().unwrap();
    let program_address = ShieldedAddress {
        signing_pubkey: PublicKey::from_pda(&program_owner),
        ..holder.shielded_address().unwrap()
    };
    let chain = Chain::ring(RingSettings::new(RingMode::Anonymous))
        .with_credentials(&[wallet, program_address]);
    let to = |recipient| RingAddress {
        recipient,
        ring_program_id: ring().program_id(),
        list_salt: [7; 32],
    };
    let (to_wallet, to_program) = (to(wallet), to(program_address));
    let paid = |to, requester: &spr_keypair::ShieldedKeypair| crate::DepositOutput {
        recipient: DepositRecipient::AnonymousPayment {
            to,
            deposit_tag: Some(requester.get_recipient_request_view_tag(0).unwrap()),
        },
        asset: DepositAsset::Sol,
        amount: 5,
        list_salt: None,
    };
    let prepared = crate::RingDepositBatch {
        ring: ring(),
        payer: &payer,
        tree: pda::tree(TREE_ID),
        outputs: vec![paid(&to_wallet, &member), paid(&to_program, &holder)],
        cosigner: None,
    }
    .prepare(&chain)
    .await
    .unwrap();
    assert_eq!(prepared.utxos()[1].owner, program_address.signing_pubkey);
    let slot = &prepared.disclosure.slots[1];
    assert_eq!(slot.owner.key(), program_owner.to_bytes());
    assert_eq!(
        slot.owner_pk_hash,
        spr_hasher::primitives::solana_owner_identity(program_owner.as_array()).unwrap()
    );
    prepared.disclosure.records(ring(), &chain).await.unwrap();
    assert!(prepared.check_public_signers([payer.pubkey()]).is_ok());
    for named in [program_owner, wallet.solana_address().unwrap()] {
        assert!(matches!(
            prepared.check_public_signers([payer.pubkey(), named]),
            Err(RingError::AnonymousPublicSignerLinksOwner)
        ));
    }
}

mod capacities {
    use bytemuck::Zeroable;
    use custom_ring_interface::{
        domain, CustomRingProof, DepositPrefix, DepositSubjects, RingDepositAuditCapsule,
    };
    use spr_interface::{
        instruction::instruction_data::deposit::RingDepositIxDataRef,
        state::{discriminator::SPL_ASSET_REGISTRY, SplAssetRegistry},
        PROGRAM_ID_PUBKEY,
    };
    use spr_keypair::ShieldedKeypair;
    use zolana_ring_policy::{ListId, Rule, RuleTable, Subject};

    use super::*;
    use crate::{
        deposit::DepositFrame,
        tests::support::{account, Registry},
        DepositOutput, DepositSplAccounts, RingDepositBatch,
    };

    const SALT: [u8; 32] = [7; 32];
    const MINT: Address = Address::new_from_array([0x3c; 32]);

    fn output(owner: &ShieldedKeypair, asset: DepositAsset) -> DepositOutput<'static> {
        DepositOutput {
            recipient: DepositRecipient::Confidential(owner.shielded_address().unwrap()),
            asset,
            amount: 5,
            list_salt: Some(SALT),
        }
    }

    fn spl() -> DepositAsset {
        DepositAsset::Spl(DepositSplAccounts {
            mint: MINT,
            user_token: Address::new_from_array([0x3d; 32]),
            token_program: pda::spl_token_program_id(),
        })
    }

    fn policy_ring(list: ListId, enrolled: &[&ShieldedKeypair]) -> Chain {
        let rules = RuleTable::builder()
            .rule(Rule::forbid(Subject::OutputOwner, list))
            .build();
        let addresses: Vec<_> = enrolled
            .iter()
            .map(|owner| owner.shielded_address().unwrap())
            .collect();
        Chain::ring(RingSettings {
            has_policy: true,
            ..RingSettings::new(RingMode::Confidential)
        })
        .with_registry(Registry::new(&[]), &rules)
        .with_credential_tag(&addresses, domain::list_tag(&SALT).unwrap())
        .with(
            pda::spl_asset_registry(&MINT),
            account(
                PROGRAM_ID_PUBKEY,
                &SplAssetRegistry {
                    discriminator: SPL_ASSET_REGISTRY,
                    reserved: [0; 7],
                    mint: MINT,
                    asset_id: 2,
                },
            ),
        )
    }

    /// The key the records select, after the witness and the frame the program parses agree on it.
    async fn key(chain: &Chain, outputs: Vec<DepositOutput<'_>>) -> u8 {
        let payer = keypair(9);
        let count = outputs.len();
        let prepared = RingDepositBatch {
            ring: ring(),
            payer: &payer,
            tree: pda::tree(TREE_ID),
            outputs,
            cosigner: None,
        }
        .prepare(chain)
        .await
        .unwrap();
        let records = prepared.disclosure.records(ring(), chain).await.unwrap();
        let key = records.key_capacity;
        let capacity = usize::from(key);
        // 1. The witness fills the key's slots and pools, padding past the notes.
        let body = serde_json::to_value(prepared.disclosure.body(&records).unwrap()).unwrap();
        let length = |field: &str| body[field].as_array().unwrap().len();
        assert_eq!(body["count"], count);
        for field in ["ownerPkHashes", "assets", "outputEntries", "ownerEntries"] {
            assert_eq!(length(field), capacity, "{field}");
        }
        assert_eq!(length("ownRecords"), DepositSubjects::pool_width(key));
        assert_eq!(length("credentialOpenings"), capacity);
        assert_eq!(length("stateRoots"), capacity);
        // 2. The frame names the key and fits a transaction, each capsule at its slot under one ephemeral key.
        let frame = DepositFrame {
            roots: records.roots(),
            key_capacity: key,
            credential_read: records.credentials.read().unwrap(),
            credential_trees: records.credentials.trees(capacity).unwrap(),
        };
        prepared.check_size(&frame).unwrap();
        let instruction = prepared
            .instruction(CustomRingProof::zeroed(), &frame)
            .unwrap();
        let mut spp = instruction.data.as_slice();
        assert_eq!(DepositPrefix::parse(&mut spp).unwrap().key_capacity, key);
        let deposit = RingDepositIxDataRef::from_bytes(&spp[1..]).unwrap();
        assert_eq!(deposit.deposits.len(), count);
        let capsules: Vec<_> = deposit
            .deposits
            .iter()
            .map(|entry| {
                RingDepositAuditCapsule::parse(entry.encrypted.ciphertext)
                    .unwrap()
                    .unwrap()
            })
            .collect();
        for (slot, capsule) in capsules.iter().enumerate() {
            assert_eq!(usize::from(capsule.slot_index), slot);
            assert_eq!(capsule.eph_pk, capsules[0].eph_pk);
        }
        assert_eq!(prepared.utxos().len(), count);
        key
    }

    #[tokio::test]
    async fn two_recipients_of_two_assets_take_key_two() {
        let (first, second) = (keypair(1), keypair(2));
        let chain = policy_ring(ListId::Block, &[&first, &second]);
        let outputs = vec![output(&first, DepositAsset::Sol), output(&second, spl())];
        assert_eq!(key(&chain, outputs).await, 2);
    }

    /// Two recipients, two assets and two salted keys need six records, key 2 holds four.
    #[tokio::test]
    async fn two_salted_recipients_of_two_assets_take_key_four() {
        let (first, second) = (keypair(1), keypair(2));
        let chain = policy_ring(ListId::PrivateBlock, &[&first, &second]);
        let outputs = vec![output(&first, DepositAsset::Sol), output(&second, spl())];
        assert_eq!(key(&chain, outputs).await, 4);
    }

    /// Four salted recipients need nine records past key 4's eight, five notes exceed its slots.
    #[tokio::test]
    async fn nine_records_or_five_notes_take_key_eight() {
        let owners: Vec<_> = (1..=5).map(keypair).collect();
        let enrolled: Vec<_> = owners.iter().collect();
        let salted = policy_ring(ListId::PrivateBlock, &enrolled);
        let four = owners[..4]
            .iter()
            .map(|owner| output(owner, DepositAsset::Sol))
            .collect();
        assert_eq!(key(&salted, four).await, 8);
        let plain = policy_ring(ListId::Block, &enrolled);
        let five = owners
            .iter()
            .map(|owner| output(owner, DepositAsset::Sol))
            .collect();
        assert_eq!(key(&plain, five).await, 8);
    }

    /// No key holds nine slots, the batch is refused before a secret is drawn.
    #[tokio::test]
    async fn a_batch_past_the_widest_key_is_refused() {
        let payer = keypair(9);
        let recipient = keypair(1);
        let chain = Chain::ring(RingSettings::new(RingMode::Confidential));
        let batch = RingDepositBatch {
            ring: ring(),
            payer: &payer,
            tree: pda::tree(TREE_ID),
            outputs: vec![output(&recipient, DepositAsset::Sol); 9],
            cosigner: None,
        };
        assert!(matches!(
            batch.prepare(&chain).await,
            Err(RingError::DepositUnkeyed)
        ));
    }
}
