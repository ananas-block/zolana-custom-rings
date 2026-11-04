//! Each owner's outflow of the transfer a co-signer signs, read from the frame and the note index.

use custom_ring_interface::{
    ring_deposit_assets, settlement_mints, tag, DepositPrefix, InstructionTag, ParsedTransact,
    RingRail, RingTransactData, RING_DEPOSIT_RING_CONFIG_INDEX, RING_TRANSACT_RING_CONFIG_INDEX,
};
use solana_address::Address;
use solana_message::VersionedMessage;
use spr_hasher::primitives::hash_bytes;
use spr_interface::SOL_ASSET_FIELD;
use spr_interface::{
    instruction::{
        instruction_data::{deposit::RingDepositIxDataRef, settlement_accounts},
        tag::RING_DEPOSIT,
    },
    pda, PROGRAM_ID_PUBKEY,
};
use spr_transaction::SOL_MINT;
use zolana_ring_client::{
    AuditedTransaction, FramedRow, InputOpening, OutputOpening, TransactionAudit,
};
use zolana_ring_policy::{
    owner_debits, DebitInput, DebitOutput, DebitTransfer, Member, PublicGross,
};
use zolana_ring_transaction::RingAssets;

use crate::{
    cosign::{AssetFlow, CoSignError, OwnerFlow},
    cosign_limits::{FrameRead, TransferRead},
    error::RingRpcError,
    hub::Shared,
    upstream::TransactionSource,
    utxos::AuditStore,
};

/// The output tree's position in SPP's transact account list.
const TRANSACT_OUTPUT_TREE_INDEX: usize = 1;

/// A ring whose auditor key the service does not hold refuses the limited co-signer.
#[must_use]
pub(crate) struct TransferDebits<'a, S> {
    pub shared: &'a std::sync::Arc<Shared<S>>,
    pub ring: Address,
    pub message: &'a VersionedMessage,
}

/// The ring instruction of a message, the only one the co-signer's signature admits.
struct RingFrame<'m> {
    tag: u8,
    data: &'m [u8],
    accounts: Vec<Address>,
}

/// One asset's public legs, a deposit joins the volume and a withdrawal stays gross.
struct PublicFlow {
    mint: Address,
    /// The field the statement's gross and every note of the mint hash under.
    asset: [u8; 32],
    deposited: u64,
    withdrawn: u64,
}

/// Unknown input refuses, the wallet retries once the auditor ingested the note.
const fn unavailable() -> RingRpcError {
    RingRpcError::CoSign(CoSignError::LimitsUnavailable)
}

const fn scope() -> RingRpcError {
    RingRpcError::CoSign(CoSignError::MessageScope)
}

impl<S: TransactionSource + 'static> TransferDebits<'_, S> {
    pub async fn flows(self) -> Result<FrameRead, RingRpcError> {
        let frame = RingFrame::of(self.message, self.ring)?;
        self.read(frame).await
    }

    async fn read(&self, frame: RingFrame<'_>) -> Result<FrameRead, RingRpcError> {
        let service = self.shared.service(Some(self.ring))?;
        let config = service.served_config().await?.ok_or_else(unavailable)?;
        let assets = self.shared.cached_assets().await;
        match frame.tag {
            tag::AUTHORITY_TRANSFER => return Ok(FrameRead::Delegate),
            tag::DEPOSIT => {
                return deposit_read(&frame, self.ring, &assets).map(FrameRead::Transfer)
            }
            _ => {}
        }
        let store = self.shared.store(self.ring);
        let rail = InstructionTag::try_from(frame.tag)
            .and_then(|tag| RingRail::of(tag, config.mode))
            .map_err(|_| unavailable())?;
        let parsed = RingTransactData::parse(frame.data, rail).map_err(|_| unavailable())?;
        let spp = frame.spp_accounts(self.ring)?;
        let tree = *spp
            .get(TRANSACT_OUTPUT_TREE_INDEX)
            .ok_or_else(unavailable)?;
        let output_tree_id = self
            .shared
            .source
            .tree_id(tree)
            .await
            .map_err(|_| unavailable())?;
        let row = FramedRow {
            parsed: &parsed,
            ring: self.ring,
            auditor: &service.auditor_keypair().pubkey(),
            output_tree_id,
        }
        .row()
        .map_err(|_| unavailable())?;
        let audited = TransactionAudit::new(&row, parsed.audit_stream())
            .run(service.auditor_keypair(), &assets)
            .map_err(|_| unavailable())?;
        let public = public_flows(&parsed, spp)?;
        let window = settlement_accounts(
            &parsed.data().interface_transfers,
            parsed.data().circuit(),
            spp,
        )
        .ok_or_else(unavailable)?;
        let owner_signers = parsed
            .data()
            .owner_signers(spp, window.len())
            .map_err(|_| unavailable())?
            .iter()
            .map(|owner| identity(owner.as_array()))
            .collect::<Result<Vec<_>, _>>()?;
        FrameFlows {
            audited: &audited,
            store: &store,
            owner_signers,
            public,
            assets: &assets,
            ring: self.ring,
        }
        .read(parsed.data().co_sign.approval.bits())
        .map(FrameRead::Transfer)
    }
}

impl<'m> RingFrame<'m> {
    /// The signature covers the whole message, debits derive from all of it or it refuses.
    fn of(message: &'m VersionedMessage, ring: Address) -> Result<Self, RingRpcError> {
        // Version 1 carries no lookup table, one could hide the ring from the check.
        let VersionedMessage::V1(_) = message else {
            return Err(scope());
        };
        let keys = message.static_account_keys();
        let key = |index: u8| keys.get(usize::from(index)).copied().ok_or_else(scope);
        // A CPI target must sit in the invoking instruction's accounts.
        let names_ring_or_spp =
            |index: u8| key(index).map(|address| address == ring || address == PROGRAM_ID_PUBKEY);
        let mut holding = None;
        for instruction in message.instructions() {
            let mut relevant = names_ring_or_spp(instruction.program_id_index)?;
            for index in &instruction.accounts {
                relevant |= names_ring_or_spp(*index)?;
            }
            if relevant && holding.replace(instruction).is_some() {
                return Err(scope());
            }
        }
        let instruction = holding.ok_or_else(scope)?;
        let (tag, data) = instruction.data.split_first().ok_or_else(scope)?;
        if key(instruction.program_id_index)? != ring
            || !matches!(*tag, tag::TRANSFER | tag::AUTHORITY_TRANSFER | tag::DEPOSIT)
        {
            return Err(scope());
        }
        let accounts = instruction
            .accounts
            .iter()
            .map(|index| key(*index))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            tag: *tag,
            data,
            accounts,
        })
    }

    /// The ring's signed config opens SPP's list past the ring's own accounts.
    fn spp_accounts(&self, ring: Address) -> Result<&[Address], RingRpcError> {
        let ring_auth = pda::ring_auth(&ring).0;
        self.accounts
            .iter()
            .position(|account| *account == ring_auth)
            .and_then(|position| position.checked_sub(RING_TRANSACT_RING_CONFIG_INDEX))
            .and_then(|start| self.accounts.get(start..))
            .ok_or_else(unavailable)
    }
}

/// A deposit spends no note, its legs answer on the ring's own tag.
fn deposit_read(
    frame: &RingFrame<'_>,
    ring: Address,
    assets: &RingAssets,
) -> Result<TransferRead, RingRpcError> {
    let (_, spp_data) = frame
        .data
        .split_at_checked(DepositPrefix::SIZE - 1)
        .ok_or_else(unavailable)?;
    let body = match spp_data.split_first() {
        Some((&RING_DEPOSIT, body)) => body,
        _ => return Err(unavailable()),
    };
    let deposit = RingDepositIxDataRef::from_bytes(body).map_err(|_| unavailable())?;
    let start = frame
        .accounts
        .iter()
        .position(|account| *account == pda::ring_auth(&ring).0)
        .and_then(|position| position.checked_sub(RING_DEPOSIT_RING_CONFIG_INDEX))
        .ok_or_else(unavailable)?;
    let spp = frame.accounts.get(start..).ok_or_else(unavailable)?;
    let deposited = ring_deposit_assets(&deposit, |position| {
        spp.get(position).map(|address| address.to_bytes())
    })
    .map_err(|_| unavailable())?;
    let owner = Member::owner_tag(ring.as_array()).map_err(|_| unavailable())?;
    let mut flows: Vec<OwnerFlow> = Vec::new();
    for leg in deposited {
        let asset = assets.by_field(&leg.asset).ok_or_else(unavailable)?.asset;
        match flows.iter_mut().find(|flow| flow.flow.asset == asset) {
            Some(flow) => {
                flow.flow.deposited = flow
                    .flow
                    .deposited
                    .checked_add(leg.amount)
                    .ok_or_else(unavailable)?;
            }
            None => flows.push(OwnerFlow {
                owner,
                flow: AssetFlow {
                    asset,
                    outflow: 0,
                    deposited: leg.amount,
                    withdrawn: 0,
                },
            }),
        }
    }
    Ok(TransferRead {
        flows,
        spends_note: false,
        approval_bits: None,
    })
}

fn public_flows(
    parsed: &ParsedTransact<'_>,
    spp: &[Address],
) -> Result<Vec<PublicFlow>, RingRpcError> {
    let data = parsed.data();
    let window = settlement_accounts(&data.interface_transfers, data.circuit(), spp)
        .ok_or_else(unavailable)?;
    let mut flows: Vec<PublicFlow> = Vec::new();
    for (transfer, mint) in data
        .interface_transfers
        .iter()
        .zip(settlement_mints(&data.interface_transfers, window))
    {
        let named = mint.map_err(|_| unavailable())?.copied();
        let mint = named.unwrap_or(SOL_MINT);
        let asset = named.map_or(Ok(SOL_ASSET_FIELD), |mint| {
            hash_bytes(mint.as_array()).map_err(|_| unavailable())
        })?;
        let position = flows.iter().position(|flow| flow.mint == mint);
        let flow = match position {
            Some(position) => &mut flows[position],
            None => {
                flows.push(PublicFlow {
                    mint,
                    asset,
                    deposited: 0,
                    withdrawn: 0,
                });
                flows.last_mut().ok_or_else(unavailable)?
            }
        };
        let side = match transfer.is_deposit() {
            true => &mut flow.deposited,
            false => &mut flow.withdrawn,
        };
        *side = side
            .checked_add(transfer.amount())
            .ok_or_else(unavailable)?;
    }
    Ok(flows)
}

/// A public leg has no owner on the frame, it joins the first sender or a no-spend frame's ring tag.
struct OwnerFlows<'a> {
    inputs: &'a [DebitInput],
    outputs: &'a [DebitOutput],
    owner_signers: &'a [[u8; 32]],
    public: &'a [PublicFlow],
    /// Only ring caps read a public leg, the tag answers for no owner cap.
    no_spend_owner: Member,
}

impl OwnerFlows<'_> {
    /// One row per nonzero debit or public leg, each owner and asset once.
    fn rows(
        self,
        mint_of: impl Fn(&[u8; 32]) -> Result<Address, RingRpcError>,
    ) -> Result<Vec<OwnerFlow>, RingRpcError> {
        // Only an input owner holds a nonzero debit, the proof binds each to the rail's senders.
        let senders: Vec<[u8; 32]> = self
            .inputs
            .iter()
            .map(|input| input.owner)
            .chain(self.owner_signers.iter().copied())
            .collect();
        let public_gross: Vec<PublicGross> = self
            .public
            .iter()
            .map(|public| PublicGross {
                asset: public.asset,
                gross: public.withdrawn.into(),
            })
            .collect();
        let assets: Vec<[u8; 32]> = self
            .outputs
            .iter()
            .map(|output| output.asset)
            .chain(self.inputs.iter().map(|input| input.asset))
            .chain(public_gross.iter().map(|public| public.asset))
            .collect();
        let mut flows = owner_debits(&DebitTransfer {
            senders: &senders,
            assets: &assets,
            inputs: self.inputs,
            outputs: self.outputs,
            public_gross: &public_gross,
        })
        .iter()
        .map(|debit| {
            Ok(OwnerFlow {
                owner: member(debit.owner)?,
                flow: AssetFlow {
                    asset: mint_of(&debit.asset)?,
                    outflow: u64::try_from(debit.outflow).map_err(|_| unavailable())?,
                    deposited: 0,
                    withdrawn: 0,
                },
            })
        })
        .collect::<Result<Vec<_>, RingRpcError>>()?;
        for public in self.public {
            let owner = senders
                .first()
                .map_or(Ok(self.no_spend_owner), |sender| member(*sender))?;
            let joined = flows
                .iter()
                .position(|flow| flow.flow.asset == public.mint && flow.owner == owner);
            let row = match joined {
                Some(row) => row,
                None => {
                    flows.push(OwnerFlow {
                        owner,
                        flow: AssetFlow {
                            asset: public.mint,
                            outflow: 0,
                            deposited: 0,
                            withdrawn: 0,
                        },
                    });
                    flows.len() - 1
                }
            };
            flows[row].flow.deposited = public.deposited;
            flows[row].flow.withdrawn = public.withdrawn;
        }
        Ok(flows)
    }
}

struct FrameFlows<'a> {
    audited: &'a AuditedTransaction,
    store: &'a AuditStore,
    /// The public run a public-funded transfer screens, it spends no note.
    owner_signers: Vec<[u8; 32]>,
    public: Vec<PublicFlow>,
    assets: &'a RingAssets,
    ring: Address,
}

impl FrameFlows<'_> {
    fn read(&self, approval_bits: u8) -> Result<TransferRead, RingRpcError> {
        let inputs = self.inputs()?;
        Ok(TransferRead {
            flows: OwnerFlows {
                inputs: &inputs,
                outputs: &self.outputs()?,
                owner_signers: &self.owner_signers,
                public: &self.public,
                no_spend_owner: Member::owner_tag(self.ring.as_array())
                    .map_err(|_| unavailable())?,
            }
            .rows(|asset| self.mint_of(asset))?,
            spends_note: !inputs.is_empty(),
            approval_bits: Some(approval_bits),
        })
    }

    /// A real input the index cannot name refuses, as an unknown note does.
    fn inputs(&self) -> Result<Vec<DebitInput>, RingRpcError> {
        let mut inputs = Vec::new();
        for input in &self.audited.inputs {
            match &input.opening {
                InputOpening::Dummy => {}
                // The frame's proven entry evidence, a default-ring note holds no index row.
                InputOpening::External(external) => inputs.push(DebitInput {
                    owner: identity(&external.utxo.owner_key)?,
                    asset: external.utxo.asset,
                    amount: external.utxo.amount,
                }),
                InputOpening::Real => {
                    let (_, note) = self
                        .store
                        .note_of_nullifier(&input.nullifier)
                        .ok_or_else(unavailable)?;
                    inputs.push(DebitInput {
                        owner: identity(&note.utxo.owner_key)?,
                        asset: note.utxo.asset,
                        amount: note.utxo.amount,
                    });
                }
            }
        }
        Ok(inputs)
    }

    /// A slot that failed to open could return funds, the outflow stays unknown.
    fn outputs(&self) -> Result<Vec<DebitOutput>, RingRpcError> {
        if !self.audited.payload_errors.is_empty() {
            return Err(unavailable());
        }
        let mut outputs = Vec::new();
        for output in &self.audited.outputs {
            let (ring, utxo) = match &output.opening {
                OutputOpening::Dummy => continue,
                OutputOpening::Ring { utxo, .. } => (true, utxo),
                OutputOpening::Exit(utxo) => (false, utxo),
            };
            outputs.push(DebitOutput {
                ring,
                owner: identity(&utxo.owner_key)?,
                asset: utxo.asset,
                amount: utxo.amount,
            });
        }
        Ok(outputs)
    }

    fn mint_of(&self, asset: &[u8; 32]) -> Result<Address, RingRpcError> {
        self.assets
            .by_field(asset)
            .map(|mint| mint.asset)
            .ok_or_else(unavailable)
    }
}

fn identity(owner_key: &[u8; 32]) -> Result<[u8; 32], RingRpcError> {
    Member::owner_tag(owner_key)
        .map(|member| *member.as_bytes())
        .map_err(|_| unavailable())
}

fn member(owner: [u8; 32]) -> Result<Member, RingRpcError> {
    Member::from_bytes(owner).map_err(|_| unavailable())
}

#[cfg(test)]
#[path = "frame_flows_tests.rs"]
mod frame_flows_tests;

#[cfg(test)]
mod tests {
    use solana_instruction::{AccountMeta, Instruction};
    use spr_client::{compile_message, ComputeBudgetConfig};

    use super::*;

    const RING: Address = Address::new_from_array([0x11; 32]);
    const PAYER: Address = Address::new_from_array([0x22; 32]);
    const OTHER_PROGRAM: Address = Address::new_from_array([0x33; 32]);

    fn ring_instruction(tag: u8) -> Instruction {
        Instruction {
            program_id: RING,
            accounts: vec![AccountMeta::new(PAYER, true)],
            data: vec![tag, 1, 2],
        }
    }

    fn message(instructions: &[Instruction]) -> VersionedMessage {
        compile_message(
            &PAYER,
            instructions,
            solana_hash::Hash::default(),
            ComputeBudgetConfig::new(1),
        )
        .expect("message")
    }

    fn refuses_scope(instructions: &[Instruction]) {
        assert!(matches!(
            RingFrame::of(&message(instructions), RING).err(),
            Some(RingRpcError::CoSign(CoSignError::MessageScope))
        ));
    }

    #[test]
    fn alternating_public_legs_refuse_gross_overflow() {
        use custom_ring_interface::{CustomRingError, PublicLeg, PublicSlots};
        use spr_interface::instruction::InterfaceTransfer;

        let frame = hex::decode(
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../test-vectors/settlement/frame_v4.hex"
            ))
            .lines()
            .next()
            .expect("frame"),
        )
        .expect("hex");
        let base = RingTransactData::parse(&frame, RingRail::Confidential)
            .expect("frame")
            .into_data();
        let deposit = |amount| InterfaceTransfer::SolDeposit { amount };
        let withdrawal = |amount| InterfaceTransfer::SolWithdrawal { amount };
        for amount in [u64::MAX - 1, u64::MAX] {
            for transfers in [
                [withdrawal(amount), deposit(amount), withdrawal(1)],
                [deposit(amount), withdrawal(amount), deposit(1)],
            ] {
                let slots =
                    PublicSlots::fold::<CustomRingError>(transfers.iter().map(|transfer| {
                        Ok(PublicLeg {
                            transfer: *transfer,
                            mint: None,
                        })
                    }))
                    .expect("bounded public net");
                assert_eq!(slots.amounts()[0].unsigned_abs(), 1);
                let mut data = base.clone();
                data.interface_transfers = transfers.to_vec();
                let parsed = ParsedTransact::new(data).expect("frame");
                let flows = public_flows(&parsed, &[PAYER; 6]);
                if amount == u64::MAX {
                    assert!(matches!(
                        flows,
                        Err(RingRpcError::CoSign(CoSignError::LimitsUnavailable))
                    ));
                } else {
                    let flows = flows.expect("gross fits u64");
                    assert_eq!(flows.len(), 1);
                    let (deposited, withdrawn) = match transfers[0].is_deposit() {
                        true => (u64::MAX, amount),
                        false => (amount, u64::MAX),
                    };
                    assert_eq!(flows[0].deposited, deposited);
                    assert_eq!(flows[0].withdrawn, withdrawn);
                }
            }
        }
    }

    const VECTOR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../test-vectors/rpc/owner_debits.json"
    );

    /// Two rows of one owner aggregate, an exit leaves, a credit never moves, a public-funded transfer joins its signer.
    fn vector_cases() -> serde_json::Value {
        let field = |byte: u8| hex::encode(right_aligned(byte));
        let input = |owner: u8, asset: u8, amount: u64| serde_json::json!({"owner": field(owner), "asset": field(asset), "amount": amount});
        let output = |ring: bool, owner: u8, asset: u8, amount: u64| serde_json::json!({"ring": ring, "owner": field(owner), "asset": field(asset), "amount": amount});
        let public = |asset: u8, deposited: u64, withdrawn: u64| serde_json::json!({"mint": hex::encode(mint_of_field(asset)), "asset": field(asset), "deposited": deposited, "withdrawn": withdrawn});
        serde_json::json!([
            {"name": "one owner keeps change", "inputs": [input(1, 7, 30), input(1, 7, 20)], "outputs": [output(true, 2, 7, 15), output(true, 1, 7, 35)], "ownerSigners": [field(1)], "public": []},
            {"name": "an exit to the owner leaves the ring", "inputs": [input(1, 7, 30)], "outputs": [output(false, 1, 7, 30)], "ownerSigners": [field(1)], "public": [public(7, 0, 30)]},
            {"name": "a credit of another owner never moves", "inputs": [input(1, 7, 30), input(2, 7, 10)], "outputs": [output(true, 2, 7, 25), output(true, 3, 7, 15)], "ownerSigners": [field(1), field(2)], "public": []},
            {"name": "two assets of two owners", "inputs": [input(1, 7, 30), input(2, 8, 10)], "outputs": [output(true, 3, 7, 30), output(true, 3, 8, 10)], "ownerSigners": [field(1), field(2)], "public": []},
            {"name": "a public funded transfer joins its signer", "inputs": [], "outputs": [output(true, 3, 7, 40)], "ownerSigners": [field(1)], "public": [public(7, 40, 0)]}
        ])
    }

    fn right_aligned(byte: u8) -> [u8; 32] {
        let mut field = [0; 32];
        field[31] = byte;
        field
    }

    fn mint_of_field(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn bytes32(value: &serde_json::Value) -> [u8; 32] {
        hex::decode(value.as_str().expect("hex"))
            .expect("hex")
            .try_into()
            .expect("32 bytes")
    }

    fn rows_of(case: &serde_json::Value) -> Vec<serde_json::Value> {
        let inputs: Vec<DebitInput> = case["inputs"]
            .as_array()
            .expect("inputs")
            .iter()
            .map(|input| DebitInput {
                owner: bytes32(&input["owner"]),
                asset: bytes32(&input["asset"]),
                amount: input["amount"].as_u64().expect("amount"),
            })
            .collect();
        let outputs: Vec<DebitOutput> = case["outputs"]
            .as_array()
            .expect("outputs")
            .iter()
            .map(|output| DebitOutput {
                ring: output["ring"].as_bool().expect("ring"),
                owner: bytes32(&output["owner"]),
                asset: bytes32(&output["asset"]),
                amount: output["amount"].as_u64().expect("amount"),
            })
            .collect();
        let owner_signers: Vec<[u8; 32]> = case["ownerSigners"]
            .as_array()
            .expect("signers")
            .iter()
            .map(bytes32)
            .collect();
        let public: Vec<PublicFlow> = case["public"]
            .as_array()
            .expect("public")
            .iter()
            .map(|flow| PublicFlow {
                mint: Address::new_from_array(bytes32(&flow["mint"])),
                asset: bytes32(&flow["asset"]),
                deposited: flow["deposited"].as_u64().expect("deposited"),
                withdrawn: flow["withdrawn"].as_u64().expect("withdrawn"),
            })
            .collect();
        OwnerFlows {
            inputs: &inputs,
            outputs: &outputs,
            owner_signers: &owner_signers,
            public: &public,
            no_spend_owner: Member::from_bytes([0xee; 32]).expect("tag"),
        }
        .rows(|asset| Ok(Address::new_from_array([asset[31]; 32])))
        .expect("rows")
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "owner": hex::encode(row.owner.as_bytes()),
                "mint": hex::encode(row.flow.asset.to_bytes()),
                "debit": row.flow.outflow,
                "deposited": row.flow.deposited,
                "withdrawn": row.flow.withdrawn,
            })
        })
        .collect()
    }

    /// `UPDATE_RING_VECTORS=1` rewrites the file.
    #[test]
    fn the_owner_debits_vector_holds() {
        let cases: Vec<serde_json::Value> = vector_cases()
            .as_array()
            .expect("cases")
            .iter()
            .map(|case| {
                let mut case = case.clone();
                case["flows"] = serde_json::Value::Array(rows_of(&case));
                case
            })
            .collect();
        let built = serde_json::json!({ "cases": cases });
        if std::env::var_os("UPDATE_RING_VECTORS").is_some() {
            let pretty = serde_json::to_string_pretty(&built).expect("json");
            std::fs::write(VECTOR, pretty + "\n").expect("vector");
        }
        let pinned: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(VECTOR).expect("vector")).expect("json");
        assert_eq!(built, pinned);
    }

    #[test]
    fn one_transfer_alone_is_the_frame() {
        let transfer = ring_instruction(tag::TRANSFER);
        let unrelated = Instruction {
            program_id: OTHER_PROGRAM,
            accounts: vec![AccountMeta::new(PAYER, true)],
            data: vec![9],
        };
        for instructions in [
            vec![transfer.clone()],
            vec![unrelated.clone(), transfer.clone()],
            vec![transfer.clone(), unrelated],
        ] {
            let message = message(&instructions);
            let frame = RingFrame::of(&message, RING).expect("one transfer");
            assert_eq!(frame.tag, tag::TRANSFER);
            assert_eq!(frame.data, [1, 2]);
        }
    }

    #[test]
    fn a_second_transfer_refuses_in_either_order() {
        let transfer = ring_instruction(tag::TRANSFER);
        let authority = ring_instruction(tag::AUTHORITY_TRANSFER);
        refuses_scope(&[transfer.clone(), transfer.clone()]);
        refuses_scope(&[transfer.clone(), authority.clone()]);
        refuses_scope(&[authority, transfer]);
    }

    #[test]
    fn any_further_ring_or_spp_reach_refuses() {
        let transfer = ring_instruction(tag::TRANSFER);
        let merge = ring_instruction(tag::MERGE);
        refuses_scope(&[transfer.clone(), merge.clone()]);
        refuses_scope(&[merge, transfer.clone()]);
        let direct_spp = Instruction {
            program_id: PROGRAM_ID_PUBKEY,
            accounts: vec![AccountMeta::new(PAYER, true)],
            data: vec![0],
        };
        refuses_scope(&[transfer.clone(), direct_spp.clone()]);
        refuses_scope(&[direct_spp, transfer.clone()]);
        // A wrapper can invoke only what its accounts name.
        let wrapper = |target: Address| Instruction {
            program_id: OTHER_PROGRAM,
            accounts: vec![AccountMeta::new_readonly(target, false)],
            data: vec![],
        };
        refuses_scope(&[transfer.clone(), wrapper(RING)]);
        refuses_scope(&[wrapper(PROGRAM_ID_PUBKEY), transfer]);
    }

    /// A wrapper whose program reaches `hidden` through a lookup table, an index past the static keys.
    fn v0_with_a_table(hidden_slot: u8) -> VersionedMessage {
        use solana_message::{
            compiled_instruction::CompiledInstruction,
            v0::{self, MessageAddressTableLookup},
            MessageHeader,
        };
        let transfer = ring_instruction(tag::TRANSFER);
        VersionedMessage::V0(v0::Message {
            header: MessageHeader {
                num_required_signatures: 1,
                num_readonly_signed_accounts: 0,
                num_readonly_unsigned_accounts: 2,
            },
            account_keys: vec![PAYER, RING, OTHER_PROGRAM],
            recent_blockhash: solana_hash::Hash::default(),
            instructions: vec![
                CompiledInstruction {
                    program_id_index: 1,
                    accounts: vec![0],
                    data: transfer.data,
                },
                CompiledInstruction {
                    program_id_index: 2,
                    accounts: vec![3],
                    data: vec![],
                },
            ],
            address_table_lookups: vec![MessageAddressTableLookup {
                account_key: Address::new_from_array([0x44; 32]),
                writable_indexes: vec![],
                readonly_indexes: vec![hidden_slot],
            }],
        })
    }

    #[test]
    fn a_message_that_can_hide_an_account_refuses() {
        for hidden_slot in [0, 1] {
            assert!(matches!(
                RingFrame::of(&v0_with_a_table(hidden_slot), RING).err(),
                Some(RingRpcError::CoSign(CoSignError::MessageScope))
            ));
        }
        let legacy = VersionedMessage::Legacy(solana_message::legacy::Message::new(
            &[ring_instruction(tag::TRANSFER)],
            Some(&PAYER),
        ));
        assert!(matches!(
            RingFrame::of(&legacy, RING).err(),
            Some(RingRpcError::CoSign(CoSignError::MessageScope))
        ));
    }

    #[test]
    fn an_index_outside_the_account_list_refuses_and_never_reads_unrelated() {
        let unrelated = Instruction {
            program_id: OTHER_PROGRAM,
            accounts: vec![AccountMeta::new(PAYER, true)],
            data: vec![9],
        };
        let mut wrapper_account = message(&[ring_instruction(tag::TRANSFER), unrelated.clone()]);
        let VersionedMessage::V1(held) = &mut wrapper_account else {
            panic!("version 1");
        };
        held.instructions[1].accounts.push(200);
        assert!(matches!(
            RingFrame::of(&wrapper_account, RING).err(),
            Some(RingRpcError::CoSign(CoSignError::MessageScope))
        ));
        let mut wrapper_program = message(&[ring_instruction(tag::TRANSFER), unrelated]);
        let VersionedMessage::V1(held) = &mut wrapper_program else {
            panic!("version 1");
        };
        held.instructions[1].program_id_index = 200;
        assert!(matches!(
            RingFrame::of(&wrapper_program, RING).err(),
            Some(RingRpcError::CoSign(CoSignError::MessageScope))
        ));
    }

    #[test]
    fn a_message_with_no_transfer_refuses() {
        refuses_scope(&[ring_instruction(tag::MERGE)]);
        let unrelated = Instruction {
            program_id: OTHER_PROGRAM,
            accounts: vec![AccountMeta::new(PAYER, true)],
            data: vec![9],
        };
        refuses_scope(&[unrelated]);
    }
}
