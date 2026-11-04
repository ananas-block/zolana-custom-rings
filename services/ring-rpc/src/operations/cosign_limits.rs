use std::{collections::BTreeSet, future::Future, sync::Arc};

use async_trait::async_trait;
use sea_orm::TransactionTrait;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_message::VersionedMessage;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_ring_policy::{
    ApprovalInputs, ApprovalMask, Member, MintPolicy, OwnerDebit, PublicGross,
};

use crate::{
    cosign::{
        ApproveClass, AssetFlow, CoSignDecision, CoSignError, CoSignFlows, CoSignPolicy,
        CoSignRefusal, CoSignRequest, CoSignSettlement, CoSignerApproval, OwnerFlow,
    },
    cosign_usage::{Reservation, Reserve, UsageLedger, UsageWindow},
    database::Store,
    error::RingRpcError,
    hub::Shared,
    transfer_debits::TransferDebits,
    upstream::{RecordsTip, TransactionSource, VerifiedOpenings},
};

pub trait AssetLimitSource: Send + Sync {
    fn current_slot(&self) -> impl Future<Output = Result<u64, RingRpcError>> + Send;

    /// In `assets` order, `None` for an asset without a record.
    fn asset_policies(
        &self,
        ring: Address,
        assets: &[Address],
    ) -> impl Future<Output = Result<Vec<Option<MintPolicy>>, RingRpcError>> + Send;

    /// One flow per owner and asset of the transfer `message` carries, refused on an unknown input.
    fn transfer_flows(
        &self,
        ring: Address,
        message: &VersionedMessage,
    ) -> impl Future<Output = Result<FrameRead, RingRpcError>> + Send;
}

/// What the frame a co-signer signs moves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameRead {
    /// The delegate rail demands no class and no limit reads it.
    Delegate,
    Transfer(TransferRead),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRead {
    pub flows: Vec<OwnerFlow>,
    /// Clear on a frame of public legs alone.
    pub spends_note: bool,
    /// The frame's proven mask, `None` on a frame that carries none.
    pub approval_bits: Option<u8>,
}

/// Reads each asset record under the newest root of the ring's records registry.
pub(crate) struct RecordLimits<S>(pub(crate) Arc<Shared<S>>);

pub struct LimitedCoSignerInit<L> {
    pub signer: Keypair,
    pub limits: L,
    pub store: Arc<Store>,
    pub approval: CoSignerApproval,
}

pub struct LimitedCoSigner<L> {
    signer: Keypair,
    limits: L,
    store: Arc<Store>,
    approval: CoSignerApproval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssetCheck {
    pub asset: Address,
    pub policy: MintPolicy,
}

/// Windows end at the current `slot`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowUsage {
    pub slot: u64,
    pub reservations: Vec<Reservation>,
}

#[must_use]
pub struct LimitDecision<'a> {
    pub flows: &'a [OwnerFlow],
    pub assets: &'a [AssetCheck],
    pub usage: &'a WindowUsage,
}

#[derive(Clone, Copy)]
enum Measure {
    Outflow,
    Volume,
    Deposited,
    Withdrawn,
}

#[derive(Clone, Copy)]
enum Scope {
    Owner,
    Ring,
}

struct WindowCap {
    cap: u64,
    window_slots: u64,
    measure: Measure,
    scope: Scope,
}

impl<L> LimitedCoSignerInit<L> {
    pub fn build(self) -> LimitedCoSigner<L> {
        LimitedCoSigner {
            signer: self.signer,
            limits: self.limits,
            store: self.store,
            approval: self.approval,
        }
    }
}

#[async_trait]
impl<L: AssetLimitSource> CoSignPolicy for LimitedCoSigner<L> {
    fn signer(&self) -> Option<Address> {
        Some(self.signer.pubkey())
    }

    async fn decide(&self, request: &CoSignRequest) -> Result<CoSignDecision, RingRpcError> {
        // 1. The frame names every transfer outflow, an owner and asset appears once.
        let (flows, operation) = match &request.flows {
            CoSignFlows::Frame => {
                match self
                    .limits
                    .transfer_flows(request.ring, &request.message)
                    .await?
                {
                    // A delegate transfer demands no class, no limit reads it and nothing reserves.
                    FrameRead::Delegate => {
                        return Ok(CoSignDecision::Signed(
                            self.signer.sign_message(&request.message.serialize()),
                        ))
                    }
                    FrameRead::Transfer(read) => {
                        (read.flows, Operation::Transfer(read.spends_note))
                    }
                }
            }
            CoSignFlows::Published(flows) => (flows.clone(), Operation::Published),
        };
        let rows: BTreeSet<_> = flows
            .iter()
            .map(|flow| (*flow.owner.as_bytes(), flow.flow.asset))
            .collect();
        if rows.len() != flows.len() {
            return Err(CoSignError::RepeatedAsset.into());
        }
        // 2. Each asset has a record in the ring's registry.
        let assets: Vec<Address> = flows
            .iter()
            .map(|flow| flow.flow.asset)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let slot = self.limits.current_slot().await?;
        let policies = self.limits.asset_policies(request.ring, &assets).await?;
        if policies.len() != assets.len() {
            return Err(CoSignError::LimitsUnavailable.into());
        }
        let checks: Vec<AssetCheck> = assets
            .iter()
            .zip(policies)
            .map(|(asset, recorded)| {
                recorded.map(|policy| AssetCheck {
                    asset: *asset,
                    policy,
                })
            })
            .collect::<Option<_>>()
            .ok_or(CoSignError::UnrecordedAsset)?;
        // 3. No explicit approval of a demanded class, no signature, whatever the caps say.
        if !self.approval.covers_any(&operation.demand(&flows, &checks)) {
            return Ok(CoSignDecision::Refused(CoSignRefusal::NotApproved));
        }
        let signature = self.signer.sign_message(&request.message.serialize());

        // 4. Co-signers sharing the store decide one at a time for each asset.
        let transaction = self.store.connection().begin().await?;
        let ledger = UsageLedger { conn: &transaction };
        ledger.admit(&request.ring, &assets).await?;

        // 5. A repeated message keeps its rows.
        if ledger.reserved(&signature).await? {
            return Ok(CoSignDecision::Signed(signature));
        }

        // 6. The window read and the reservation commit in one database transaction.
        let usage = WindowUsage {
            slot,
            reservations: ledger
                .window(UsageWindow {
                    ring: &request.ring,
                    assets: &assets,
                    since_slot: slot.saturating_sub(longest_window(&checks)),
                })
                .await?,
        };
        let decision = LimitDecision {
            flows: &flows,
            assets: &checks,
            usage: &usage,
        }
        .decide(signature);
        if let CoSignDecision::Signed(_) = decision {
            ledger
                .reserve(Reserve {
                    signature: &signature,
                    ring: &request.ring,
                    slot,
                    flows: &flows,
                })
                .await?;
        }
        transaction.commit().await?;
        Ok(decision)
    }

    async fn settle(&self, settlement: CoSignSettlement) -> Result<(), RingRpcError> {
        let ledger = UsageLedger {
            conn: self.store.connection(),
        };
        match settlement {
            CoSignSettlement::Confirmed(signature) => ledger.confirm(&signature).await?,
            CoSignSettlement::Failed(signature) => ledger.free(&signature).await?,
        }
        Ok(())
    }
}

impl<S: TransactionSource + 'static> AssetLimitSource for RecordLimits<S> {
    async fn current_slot(&self) -> Result<u64, RingRpcError> {
        Ok(self.0.source.slot().await?)
    }

    /// No record without a ring policy, refused without a records registry.
    async fn asset_policies(
        &self,
        ring: Address,
        assets: &[Address],
    ) -> Result<Vec<Option<MintPolicy>>, RingRpcError> {
        if assets.is_empty() {
            return Ok(Vec::new());
        }
        let source = &self.0.source;
        let tip = match source.records_root(ring).await? {
            RecordsTip::NoPolicy => return Ok(vec![None; assets.len()]),
            RecordsTip::NoRegistry => return Err(CoSignError::LimitsUnavailable.into()),
            RecordsTip::Newest(tip) => tip,
        };
        let members = assets
            .iter()
            .map(|asset| Member::asset(asset).map(|member| *member.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CoSignError::LimitsUnavailable)?;
        Ok(source
            .verified_openings(&tip, &members)
            .await?
            .iter()
            .map(|opening| opening.record().map(|record| record.mint_policy))
            .collect())
    }

    async fn transfer_flows(
        &self,
        ring: Address,
        message: &VersionedMessage,
    ) -> Result<FrameRead, RingRpcError> {
        TransferDebits {
            shared: &self.0,
            ring,
            message,
        }
        .flows()
        .await
    }
}

#[derive(Clone, Copy)]
enum Operation {
    Transfer {
        spends_note: bool,
        approval_bits: Option<u8>,
    },
    /// A deposit's public leg, or a merge's nothing.
    Published,
}

/// The shared formula over the flows a reservation holds, the mint stands for its asset.
fn approval_mask(flows: &[OwnerFlow], checks: &[AssetCheck]) -> ApprovalMask {
    let debits: Vec<OwnerDebit> = flows
        .iter()
        .map(|flow| OwnerDebit {
            owner: *flow.owner.as_bytes(),
            asset: flow.flow.asset.to_bytes(),
            debit: flow.flow.outflow.into(),
            kept: 0,
            charge: 0,
            outflow: flow.flow.outflow.into(),
        })
        .collect();
    let public_gross: Vec<PublicGross> = flows
        .iter()
        .map(|flow| PublicGross {
            asset: flow.flow.asset.to_bytes(),
            gross: flow.flow.withdrawn.into(),
        })
        .collect();
    ApprovalInputs {
        flows: &debits,
        public_gross: &public_gross,
    }
    .mask(|asset| {
        checks
            .iter()
            .find(|check| check.asset.as_array() == asset)
            .map_or(MintPolicy::EMPTY, |check| check.policy)
    })
}

impl Operation {
    /// A frame's proven bits meet the thresholds this service reads, or it signs nothing.
    fn frame_holds(self, mask: ApprovalMask) -> bool {
        match self {
            Self::Transfer {
                approval_bits: Some(bits),
                ..
            } => bits == mask.bits(),
            Self::Transfer { .. } | Self::Published => true,
        }
    }

    /// The classes the ring's rule demands of this operation.
    fn demand(self, flows: &[OwnerFlow], mask: ApprovalMask) -> BTreeSet<ApproveClass> {
        let mut demand = BTreeSet::new();
        for moved in flows.iter().map(|flow| flow.flow) {
            if moved.deposited != 0 {
                demand.insert(ApproveClass::Deposits);
            }
            if moved.withdrawn != 0 {
                demand.insert(ApproveClass::Withdrawals);
            }
        }
        if mask.contains(ApprovalMask::OUTFLOW) {
            demand.insert(ApproveClass::Outflow);
        }
        if mask.contains(ApprovalMask::WITHDRAWAL) {
            demand.insert(ApproveClass::Withdrawal);
        }
        let spends_note = match self {
            Self::Transfer { spends_note, .. } => spends_note,
            Self::Published => !demand.contains(&ApproveClass::Deposits),
        };
        if spends_note {
            demand.insert(ApproveClass::Transfers);
        }
        demand
    }
}

impl LimitDecision<'_> {
    /// `signature` is the co-signature over the request message.
    pub fn decide(self, signature: Signature) -> CoSignDecision {
        let within = self.assets.iter().all(|check| {
            window_caps(&check.policy.limits)
                .iter()
                .all(|cap| self.within(check.asset, cap))
        });
        match within {
            true => CoSignDecision::Signed(signature),
            false => CoSignDecision::Refused(CoSignRefusal::OverLimit),
        }
    }

    fn within(&self, asset: Address, cap: &WindowCap) -> bool {
        // A zero cap sets no window limit, the approval decided the signature.
        if cap.cap == 0 {
            return true;
        }
        let of_asset = || self.flows.iter().filter(|flow| flow.flow.asset == asset);
        match cap.scope {
            // Credits never move between owners, each answers for its own debit.
            Scope::Owner => of_asset().all(|flow| {
                self.window_total(asset, cap, Some(flow.owner.as_bytes()))
                    + cap.measure.of(&flow.flow)
                    <= u128::from(cap.cap)
            }),
            Scope::Ring => {
                let moved: u128 = of_asset().map(|flow| cap.measure.of(&flow.flow)).sum();
                self.window_total(asset, cap, None) + moved <= u128::from(cap.cap)
            }
        }
    }

    fn window_total(&self, asset: Address, cap: &WindowCap, owner: Option<&[u8; 32]>) -> u128 {
        self.usage
            .reservations
            .iter()
            .filter(|reservation| {
                reservation.flow.asset == asset
                    && self.usage.slot.saturating_sub(reservation.slot) < cap.window_slots
                    && owner.is_none_or(|owner| reservation.owner == *owner)
            })
            .map(|reservation| cap.measure.of(&reservation.flow))
            .sum()
    }
}

impl Measure {
    fn of(self, flow: &AssetFlow) -> u128 {
        let [outflow, deposited, withdrawn] =
            [flow.outflow, flow.deposited, flow.withdrawn].map(u128::from);
        match self {
            Self::Outflow => outflow,
            Self::Volume => outflow + deposited,
            Self::Deposited => deposited,
            Self::Withdrawn => withdrawn,
        }
    }
}

/// A zero window counts the checked transaction alone.
fn window_caps(limits: &zolana_ring_policy::AssetLimits) -> [WindowCap; 4] {
    let ring = |cap, window_slots, measure| WindowCap {
        cap,
        window_slots,
        measure,
        scope: Scope::Ring,
    };
    [
        WindowCap {
            cap: limits.sender_cap,
            window_slots: limits.sender_window_slots,
            measure: Measure::Outflow,
            scope: Scope::Owner,
        },
        ring(
            limits.volume_cap,
            limits.volume_window_slots,
            Measure::Volume,
        ),
        ring(
            limits.deposit_cap,
            limits.deposit_window_slots,
            Measure::Deposited,
        ),
        ring(
            limits.withdrawal_cap,
            limits.withdrawal_window_slots,
            Measure::Withdrawn,
        ),
    ]
}

fn longest_window(checks: &[AssetCheck]) -> u64 {
    checks
        .iter()
        .flat_map(|check| window_caps(&check.policy.limits))
        .map(|cap| cap.window_slots)
        .max()
        .unwrap_or_default()
}

#[cfg(test)]
#[path = "cosign_window_tests.rs"]
mod cosign_window_tests;

#[cfg(test)]
mod tests {
    use sea_orm::ConnectionTrait;
    use solana_message::Message;
    use zolana_ring_policy::AssetLimits;

    use super::*;

    const ASSET: Address = Address::new_from_array([3; 32]);
    const SENDER_LIMITS: AssetLimits = AssetLimits {
        sender_cap: 100,
        sender_window_slots: 50,
        ..AssetLimits::EMPTY
    };

    fn member(byte: u8) -> Member {
        Member::from_bytes([byte; 32]).expect("member")
    }

    fn debit(owner: u8, amount: u64) -> OwnerFlow {
        OwnerFlow {
            owner: member(owner),
            flow: AssetFlow {
                asset: ASSET,
                outflow: amount,
                deposited: 0,
                withdrawn: 0,
            },
        }
    }

    fn window(slot: u64, owner: u8, amount: u64) -> WindowUsage {
        WindowUsage {
            slot,
            reservations: vec![Reservation {
                owner: [owner; 32],
                slot: 1_000,
                flow: debit(owner, amount).flow,
            }],
        }
    }

    fn policy(limits: AssetLimits) -> MintPolicy {
        MintPolicy {
            limits,
            ..MintPolicy::EMPTY
        }
    }

    fn sender_check() -> [AssetCheck; 1] {
        [AssetCheck {
            asset: ASSET,
            policy: policy(SENDER_LIMITS),
        }]
    }

    #[test]
    fn a_second_transfer_over_the_owner_window_cap_is_refused() {
        let signature = Signature::from([1; 64]);
        let decide = |owner: u8, usage: &WindowUsage| {
            LimitDecision {
                flows: &[debit(owner, 60)],
                assets: &sender_check(),
                usage,
            }
            .decide(signature)
        };

        assert_eq!(
            decide(7, &window(1_049, 7, 60)),
            CoSignDecision::Refused(CoSignRefusal::OverLimit)
        );
        assert_eq!(
            decide(7, &window(1_050, 7, 60)),
            CoSignDecision::Signed(signature)
        );
        assert_eq!(
            decide(8, &window(1_049, 7, 60)),
            CoSignDecision::Signed(signature)
        );
    }

    #[test]
    fn each_owner_of_a_mixed_transfer_answers_for_its_own_window() {
        let signature = Signature::from([1; 64]);
        let usage = window(1_010, 7, 60);
        let decide = |flows: &[OwnerFlow]| {
            LimitDecision {
                flows,
                assets: &sender_check(),
                usage: &usage,
            }
            .decide(signature)
        };
        assert_eq!(
            decide(&[debit(7, 40), debit(8, 100)]),
            CoSignDecision::Signed(signature),
            "each owner stays at its own cap"
        );
        assert_eq!(
            decide(&[debit(7, 41), debit(8, 1)]),
            CoSignDecision::Refused(CoSignRefusal::OverLimit),
            "a credit of one owner never pays for another"
        );
    }

    #[test]
    fn a_ring_cap_sums_every_owner_of_the_transfer() {
        let signature = Signature::from([1; 64]);
        let check = [AssetCheck {
            asset: ASSET,
            policy: policy(AssetLimits {
                volume_cap: 100,
                volume_window_slots: 50,
                ..AssetLimits::EMPTY
            }),
        }];
        let usage = WindowUsage {
            slot: 1_000,
            reservations: Vec::new(),
        };
        let decide = |flows: &[OwnerFlow]| {
            LimitDecision {
                flows,
                assets: &check,
                usage: &usage,
            }
            .decide(signature)
        };
        assert_eq!(
            decide(&[debit(7, 60), debit(8, 40)]),
            CoSignDecision::Signed(signature)
        );
        assert_eq!(
            decide(&[debit(7, 60), debit(8, 41)]),
            CoSignDecision::Refused(CoSignRefusal::OverLimit)
        );
    }

    struct FixedLimits {
        limits: Option<MintPolicy>,
        flows: Result<FrameRead, CoSignError>,
    }

    impl AssetLimitSource for FixedLimits {
        async fn current_slot(&self) -> Result<u64, RingRpcError> {
            Ok(1_000)
        }

        async fn asset_policies(
            &self,
            _ring: Address,
            assets: &[Address],
        ) -> Result<Vec<Option<MintPolicy>>, RingRpcError> {
            Ok(vec![self.limits; assets.len()])
        }

        async fn transfer_flows(
            &self,
            _ring: Address,
            _message: &VersionedMessage,
        ) -> Result<FrameRead, RingRpcError> {
            self.flows.clone().map_err(Into::into)
        }
    }

    fn message(nonce: u8) -> VersionedMessage {
        VersionedMessage::Legacy(Message {
            account_keys: vec![Address::new_from_array([nonce; 32])],
            ..Message::default()
        })
    }

    fn request(nonce: u8, amount: u64) -> CoSignRequest {
        CoSignRequest {
            ring: Address::new_from_array([9; 32]),
            message: message(nonce),
            flows: CoSignFlows::Published(vec![debit(7, amount)]),
        }
    }

    async fn store_rows(store: &Store) -> usize {
        store
            .connection()
            .query_all(sea_orm::Statement::from_string(
                store.connection().get_database_backend(),
                "SELECT owner FROM cosign_usage",
            ))
            .await
            .expect("rows")
            .len()
    }

    fn all_classes() -> CoSignerApproval {
        CoSignerApproval::new([
            ApproveClass::Outflow,
            ApproveClass::Withdrawal,
            ApproveClass::Transfers,
            ApproveClass::Deposits,
            ApproveClass::Withdrawals,
        ])
    }

    fn signer_over(store: Store, limits: FixedLimits) -> LimitedCoSigner<FixedLimits> {
        approving(store, limits, all_classes())
    }

    fn approving(
        store: Store,
        limits: FixedLimits,
        approval: CoSignerApproval,
    ) -> LimitedCoSigner<FixedLimits> {
        LimitedCoSignerInit {
            signer: Keypair::new_from_array([5; 32]),
            limits,
            store: Arc::new(store),
            approval,
        }
        .build()
    }

    fn frame(flows: Vec<OwnerFlow>) -> FrameRead {
        FrameRead::Transfer(TransferRead {
            flows,
            spends_note: true,
            approval_bits: None,
        })
    }

    fn frame_request() -> CoSignRequest {
        CoSignRequest {
            ring: Address::new_from_array([9; 32]),
            message: message(1),
            flows: CoSignFlows::Frame,
        }
    }

    async fn decided(
        limits: MintPolicy,
        read: FrameRead,
        approval: CoSignerApproval,
    ) -> CoSignDecision {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        approving(
            store,
            FixedLimits {
                limits: Some(limits),
                flows: Ok(read),
            },
            approval,
        )
        .decide(&frame_request())
        .await
        .expect("decision")
    }

    #[tokio::test]
    async fn zero_caps_with_no_approval_refuse() {
        assert_eq!(
            decided(
                MintPolicy::EMPTY,
                frame(vec![debit(7, 1_000_000)]),
                CoSignerApproval::default()
            )
            .await,
            CoSignDecision::Refused(CoSignRefusal::NotApproved)
        );
    }

    #[tokio::test]
    async fn an_approved_class_signs_and_an_undemanded_one_does_not() {
        let transfer = frame(vec![debit(7, 10)]);
        assert!(matches!(
            decided(
                MintPolicy::EMPTY,
                transfer.clone(),
                CoSignerApproval::new([ApproveClass::Transfers])
            )
            .await,
            CoSignDecision::Signed(_)
        ));
        assert_eq!(
            decided(
                MintPolicy::EMPTY,
                transfer,
                CoSignerApproval::new([ApproveClass::Deposits])
            )
            .await,
            CoSignDecision::Refused(CoSignRefusal::NotApproved)
        );
    }

    #[tokio::test]
    async fn a_threshold_passes_demand_its_approval_class() {
        let over = MintPolicy {
            cosign_above: 100,
            withdrawal_threshold: 100,
            ..MintPolicy::EMPTY
        };
        let moved = |outflow, withdrawn| {
            FrameRead::Transfer(TransferRead {
                flows: vec![OwnerFlow {
                    owner: member(7),
                    flow: AssetFlow {
                        asset: ASSET,
                        outflow,
                        deposited: 0,
                        withdrawn,
                    },
                }],
                spends_note: false,
                approval_bits: None,
            })
        };
        let outflow = CoSignerApproval::new([ApproveClass::Outflow]);
        let withdrawal = CoSignerApproval::new([ApproveClass::Withdrawal]);
        assert!(matches!(
            decided(over, moved(101, 0), outflow.clone()).await,
            CoSignDecision::Signed(_)
        ));
        assert_eq!(
            decided(over, moved(100, 0), outflow.clone()).await,
            CoSignDecision::Refused(CoSignRefusal::NotApproved),
            "at the threshold no approval is demanded"
        );
        assert_eq!(
            decided(over, moved(101, 0), withdrawal.clone()).await,
            CoSignDecision::Refused(CoSignRefusal::NotApproved),
            "an approver of the other class does not count"
        );
        assert!(matches!(
            decided(over, moved(0, 101), withdrawal).await,
            CoSignDecision::Signed(_)
        ));
    }

    #[tokio::test]
    async fn a_delegate_frame_reads_no_limit_and_reserves_nothing() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let reader = store.clone();
        let co_signer = approving(
            store,
            FixedLimits {
                limits: None,
                flows: Ok(FrameRead::Delegate),
            },
            CoSignerApproval::default(),
        );
        assert!(matches!(
            co_signer.decide(&frame_request()).await.expect("decision"),
            CoSignDecision::Signed(_)
        ));
        assert_eq!(store_rows(&reader).await, 0);
    }

    fn within_limits() -> FixedLimits {
        FixedLimits {
            limits: Some(policy(SENDER_LIMITS)),
            flows: Ok(frame(Vec::new())),
        }
    }

    #[tokio::test]
    async fn a_failed_transfer_frees_its_usage() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let co_signer = signer_over(store, within_limits());
        let CoSignDecision::Signed(first) = co_signer.decide(&request(1, 60)).await.expect("first")
        else {
            panic!("the first transfer is within the cap");
        };
        assert_eq!(
            co_signer.decide(&request(2, 60)).await.expect("second"),
            CoSignDecision::Refused(CoSignRefusal::OverLimit)
        );

        for _ in 0..2 {
            co_signer
                .settle(CoSignSettlement::Failed(first))
                .await
                .expect("settle");
        }
        assert!(matches!(
            co_signer.decide(&request(2, 60)).await.expect("retry"),
            CoSignDecision::Signed(_)
        ));
    }

    #[tokio::test]
    async fn a_transfer_of_an_unrecorded_asset_is_refused() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let co_signer = signer_over(
            store,
            FixedLimits {
                limits: None,
                flows: Ok(frame(Vec::new())),
            },
        );

        assert!(matches!(
            co_signer.decide(&request(1, 1)).await,
            Err(RingRpcError::CoSign(CoSignError::UnrecordedAsset))
        ));
    }

    #[tokio::test]
    async fn a_transfer_reserves_what_its_frame_names_and_never_a_caller_total() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let co_signer = signer_over(
            store,
            FixedLimits {
                limits: Some(policy(SENDER_LIMITS)),
                flows: Ok(frame(vec![debit(7, 101)])),
            },
        );
        let decision = co_signer
            .decide(&CoSignRequest {
                ring: Address::new_from_array([9; 32]),
                message: message(1),
                flows: CoSignFlows::Frame,
            })
            .await
            .expect("decision");
        assert_eq!(decision, CoSignDecision::Refused(CoSignRefusal::OverLimit));
    }

    #[tokio::test]
    async fn an_unknown_input_refuses_until_the_wallet_retries_after_ingestion() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let co_signer = signer_over(
            store,
            FixedLimits {
                limits: Some(policy(SENDER_LIMITS)),
                flows: Err(CoSignError::LimitsUnavailable),
            },
        );
        assert!(matches!(
            co_signer
                .decide(&CoSignRequest {
                    ring: Address::new_from_array([9; 32]),
                    message: message(1),
                    flows: CoSignFlows::Frame,
                })
                .await,
            Err(RingRpcError::CoSign(CoSignError::LimitsUnavailable))
        ));
    }

    #[tokio::test]
    async fn a_repeated_message_keeps_its_rows_and_settles_each_at_once() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let reader = store.clone();
        let co_signer = signer_over(store, within_limits());
        let mixed = || CoSignRequest {
            ring: Address::new_from_array([9; 32]),
            message: message(1),
            flows: CoSignFlows::Published(vec![debit(7, 10), debit(8, 20)]),
        };
        let CoSignDecision::Signed(signature) = co_signer.decide(&mixed()).await.expect("first")
        else {
            panic!("within the cap");
        };
        assert_eq!(store_rows(&reader).await, 2);
        assert_eq!(
            co_signer.decide(&mixed()).await.expect("retry"),
            CoSignDecision::Signed(signature)
        );
        assert_eq!(store_rows(&reader).await, 2, "a retry adds no row");
        co_signer
            .settle(CoSignSettlement::Failed(signature))
            .await
            .expect("settle");
        assert_eq!(store_rows(&reader).await, 0, "every row releases together");
    }

    #[tokio::test]
    async fn a_confirmed_message_keeps_every_row_through_a_late_failure() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let reader = store.clone();
        let co_signer = signer_over(store, within_limits());
        let CoSignDecision::Signed(signature) = co_signer
            .decide(&CoSignRequest {
                ring: Address::new_from_array([9; 32]),
                message: message(1),
                flows: CoSignFlows::Published(vec![debit(7, 10), debit(8, 20)]),
            })
            .await
            .expect("decision")
        else {
            panic!("within the cap");
        };
        co_signer
            .settle(CoSignSettlement::Confirmed(signature))
            .await
            .expect("confirm");
        co_signer
            .settle(CoSignSettlement::Failed(signature))
            .await
            .expect("late failure");
        assert_eq!(store_rows(&reader).await, 2);
    }

    #[tokio::test]
    async fn an_owner_and_asset_named_twice_is_refused() {
        let store = Store::open("sqlite::memory:", 1).await.expect("store");
        let co_signer = signer_over(store, within_limits());
        assert!(matches!(
            co_signer
                .decide(&CoSignRequest {
                    ring: Address::new_from_array([9; 32]),
                    message: message(1),
                    flows: CoSignFlows::Published(vec![debit(7, 10), debit(7, 20)]),
                })
                .await,
            Err(RingRpcError::CoSign(CoSignError::RepeatedAsset))
        ));
    }

    async fn co_signer(url: &str) -> Arc<LimitedCoSigner<FixedLimits>> {
        let store = Store::open(url, crate::database::STORE_CONNECTIONS)
            .await
            .expect("store");
        Arc::new(signer_over(store, within_limits()))
    }

    async fn assert_two_co_signers_share_one_allowance(url: &str) {
        let co_signers = [co_signer(url).await, co_signer(url).await];
        let mut decisions = tokio::task::JoinSet::new();
        for nonce in 0..24u8 {
            let co_signer = co_signers[usize::from(nonce % 2)].clone();
            decisions.spawn(async move { co_signer.decide(&request(nonce, 20)).await });
        }
        let mut signed = 0;
        while let Some(decision) = decisions.join_next().await {
            if let CoSignDecision::Signed(_) = decision.expect("task").expect("decision") {
                signed += 1;
            }
        }
        assert_eq!(signed, 5);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_co_signers_over_one_sqlite_file_grant_the_allowance_once() {
        let path = std::env::temp_dir().join(format!("cosign-{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert_two_co_signers_share_one_allowance(&format!("sqlite://{}?mode=rwc", path.display()))
            .await;
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs RING_RPC_TEST_POSTGRES_URL"]
    async fn two_co_signers_over_one_postgres_store_grant_the_allowance_once() {
        let url = std::env::var("RING_RPC_TEST_POSTGRES_URL").expect("postgres url");
        let store = Store::open(&url, 1).await.expect("store");
        store
            .connection()
            .execute_unprepared("DELETE FROM cosign_usage")
            .await
            .expect("empty usage");
        assert_two_co_signers_share_one_allowance(&url).await;
    }
}
