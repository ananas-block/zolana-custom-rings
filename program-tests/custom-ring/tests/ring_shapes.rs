//! Every transfer shape of the five basic rails settles or is refused before proving as too large.
//! Registry sources and withdrawal/batch capacities have separate circuit and verifier tests.

use super::*;
use custom_ring_interface::{
    key_catalog::{
        RingCircuit, TransferShape, ANONYMOUS_TRANSFER_SHAPES, CONFIDENTIAL_TRANSFER_SHAPES,
        ENTRY_TRANSFER_SHAPES, RING_KEYS,
    },
    ParsedTransact, DELIVERED_AUDIT_CAPACITIES, MERGE_WIDTHS,
};
use custom_ring_test_validator::{
    policy::{EnrollAddresses, RingNotes},
    shared::restart_prover,
};
use spr_client::{Shape, SPP_SUPPORTED_SHAPES};
use spr_test_utils::wallet::create_associated_token_account;

const UTXO_AMOUNT: u64 = 1_000_000;
/// Rent-exempt before the first leg lands on it.
const DESTINATION_FUNDING: u64 = 1_000_000;
const LEG_AMOUNT: u64 = 1_000;

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sdk-libs/sdk/src/tests/operations/size_pins.rs"
));

fn pinned_bytes(rail: Measured, n_in: usize, n_out: usize) -> Option<usize> {
    let column = Measured::COLUMNS
        .iter()
        .position(|column| *column == rail)?;
    SIZE_PINS
        .iter()
        .find(|pin| (pin.n_in, pin.n_out) == (n_in, n_out))?
        .bytes[column]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Column {
    Confidential,
    ConfidentialPolicy,
    Anonymous,
    AnonymousPolicy,
    Delegate,
}

impl Column {
    fn tier(self) -> Tier {
        match self {
            Self::Confidential => Tier::AuditOnly,
            Self::ConfidentialPolicy | Self::Delegate => Tier::policy(&EMPTY),
            Self::Anonymous => Tier::AnonymousAuditOnly,
            Self::AnonymousPolicy => Tier::anonymous_policy(&EMPTY),
        }
    }

    fn rail(self) -> RingRail {
        match self {
            Self::Confidential | Self::ConfidentialPolicy => RingRail::Confidential,
            Self::Anonymous | Self::AnonymousPolicy => RingRail::Anonymous,
            Self::Delegate => RingRail::Delegate,
        }
    }

    /// The widest shapes a spend padded to its full published width still fits.
    const fn widest(self) -> &'static [Shape] {
        match self {
            Self::Anonymous => &[Shape::IN24_OUT2, Shape::IN16_OUT4, Shape::IN5_OUT8],
            Self::AnonymousPolicy => &[Shape::IN24_OUT2, Shape::IN16_OUT4],
            Self::Confidential => &[
                Shape::IN32_OUT2,
                Shape::IN24_OUT4,
                Shape::IN16_OUT8,
                Shape::IN5_OUT16,
            ],
            Self::ConfidentialPolicy | Self::Delegate => &[],
        }
    }

    fn keyed(self, shape: Shape) -> bool {
        custom_ring_sdk::shape_keyed(self.rail(), shape)
    }

    fn measured(self, spend: Spend, spends_default_ring: bool) -> Measured {
        match spend {
            Spend::Rail(RingRail::Delegate) => Measured::Delegate,
            Spend::Rail(RingRail::Anonymous) => match self {
                Self::AnonymousPolicy if spends_default_ring => Measured::AnonymousEntryPolicy,
                Self::AnonymousPolicy => Measured::AnonymousPolicy,
                _ if spends_default_ring => Measured::AnonymousEntry,
                _ => Measured::Anonymous,
            },
            Spend::Rail(RingRail::Confidential) => match self {
                Self::Delegate => Measured::ConfidentialEscrow,
                Self::ConfidentialPolicy => Measured::ConfidentialPolicy,
                _ => Measured::Confidential,
            },
            Spend::InProofOwner => match self {
                Self::Delegate => Measured::InProofOwnerEscrow,
                Self::ConfidentialPolicy => Measured::InProofOwnerPolicy,
                _ => Measured::InProofOwner,
            },
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum KeyFamily {
    ConfidentialSigner,
    ConfidentialInProof,
    Anonymous,
    AnonymousEntry,
}

impl KeyFamily {
    const fn shapes(self) -> &'static [TransferShape] {
        match self {
            Self::ConfidentialSigner | Self::ConfidentialInProof => &CONFIDENTIAL_TRANSFER_SHAPES,
            Self::Anonymous => &ANONYMOUS_TRANSFER_SHAPES,
            Self::AnonymousEntry => &ENTRY_TRANSFER_SHAPES,
        }
    }

    /// A policy ring alone keys the legs, sixteen outputs fit only under key escrow.
    const fn column(self, outputs: u8) -> Column {
        match self {
            Self::ConfidentialSigner | Self::ConfidentialInProof => match outputs {
                16 => Column::Delegate,
                _ => Column::ConfidentialPolicy,
            },
            Self::Anonymous | Self::AnonymousEntry => Column::AnonymousPolicy,
        }
    }

    const fn spend(self) -> Spend {
        match self {
            Self::ConfidentialSigner => Spend::Rail(RingRail::Confidential),
            Self::ConfidentialInProof => Spend::InProofOwner,
            Self::Anonymous | Self::AnonymousEntry => Spend::Rail(RingRail::Anonymous),
        }
    }

    fn keys(self, circuit: RingCircuit, column: Column) -> bool {
        match self {
            Self::ConfidentialSigner | Self::ConfidentialInProof => {
                matches!(circuit, RingCircuit::TransferConfidential { outputs, .. }
                    if self.column(outputs) == column)
            }
            Self::Anonymous => matches!(circuit, RingCircuit::TransferAnonymous { .. }),
            Self::AnonymousEntry => matches!(circuit, RingCircuit::TransferAnonymousEntry { .. }),
        }
    }
}

#[derive(Default)]
struct Coverage {
    circuits: Vec<RingCircuit>,
}

impl Coverage {
    fn cover(&mut self, circuit: RingCircuit) {
        if !self.circuits.contains(&circuit) {
            self.circuits.push(circuit);
        }
    }

    fn assert_keys(&self, owned: impl Fn(RingCircuit) -> bool) {
        let missing: Vec<RingCircuit> = RING_KEYS
            .iter()
            .map(|key| key.circuit)
            .filter(|circuit| owned(*circuit))
            .filter(|circuit| !self.circuits.contains(circuit))
            .collect();
        assert!(missing.is_empty(), "no landed operation proved {missing:?}");
    }

    fn assert_transfer_keys(&self, column: Column) {
        self.assert_keys(|circuit| key_owner(circuit) == Some(column));
        assert!(self
            .circuits
            .iter()
            .all(|circuit| RING_KEYS.iter().any(|key| key.circuit == *circuit)));
    }
}

/// The one sweep that proves the key, every transfer key has one.
fn key_owner(circuit: RingCircuit) -> Option<Column> {
    // A sweep without public legs proves the narrowest withdrawal key, a policy ring keys the legs.
    let wide = |family: &[TransferShape], outputs: u8, withdrawals: u8| {
        TransferShape::of(family, outputs.into())
            .is_some_and(|shape| shape.withdrawals[0] != withdrawals)
    };
    Some(match circuit {
        RingCircuit::TransferConfidential {
            outputs,
            withdrawals,
            ..
        } => match wide(&CONFIDENTIAL_TRANSFER_SHAPES, outputs, withdrawals) {
            true => Column::ConfidentialPolicy,
            false => Column::Confidential,
        },
        RingCircuit::TransferAnonymous {
            outputs,
            withdrawals,
            ..
        } => match wide(&ANONYMOUS_TRANSFER_SHAPES, outputs, withdrawals) {
            true => Column::AnonymousPolicy,
            false => Column::Anonymous,
        },
        RingCircuit::TransferAnonymousEntry { .. } | RingCircuit::Merge { .. } => Column::Anonymous,
        RingCircuit::Deposit { capacity: 1 } => Column::Confidential,
        RingCircuit::ApplyRecords { writes: 1 } => Column::ConfidentialPolicy,
        RingCircuit::ApplyRecords { writes: 2 } => Column::Delegate,
        RingCircuit::RegisterKey
        | RingCircuit::Deposit { .. }
        | RingCircuit::ApplyRecords { .. } => return None,
    })
}

/// The legs the program keys the transfer by, the policy withdrawals alone.
fn keyed_legs(data: &RingTransactData<'_>) -> usize {
    match data.policy {
        Some(_) => data
            .interface_transfers
            .iter()
            .filter(|transfer| !transfer.is_deposit())
            .count(),
        None => 0,
    }
}

fn funded_destinations(env: &TestEnv, count: usize) -> Result<Vec<Address>> {
    let destinations: Vec<Address> = (0..count).map(|_| Keypair::new().pubkey()).collect();
    for batch in destinations.chunks(16) {
        let transfers: Vec<Instruction> = batch
            .iter()
            .map(|destination| {
                solana_system_interface::instruction::transfer(
                    &env.payer.pubkey(),
                    destination,
                    DESTINATION_FUNDING,
                )
            })
            .collect();
        send(env.client.rpc(), &env.payer, &transfers)?;
    }
    Ok(destinations)
}

struct ShapeTransfer {
    shape: Shape,
    inputs: Vec<WalletUtxo>,
    spend: Spend,
    legs: Vec<Leg>,
}

/// One public withdrawal of `LEG_AMOUNT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Leg {
    Sol(Address),
    Spl {
        mint: Address,
        token_account: Address,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum LegKind {
    Sol,
    Spl,
}

/// The last target repeats, an anonymous exit names one.
struct LegTargets {
    destinations: Vec<Address>,
    mint: Address,
    token_accounts: Vec<Address>,
}

impl LegTargets {
    fn legs(&self, kind: LegKind, count: usize) -> Vec<Leg> {
        (0..count)
            .map(|index| match kind {
                LegKind::Sol => Leg::Sol(self.destinations[index.min(self.destinations.len() - 1)]),
                LegKind::Spl => Leg::Spl {
                    mint: self.mint,
                    token_account: self.token_accounts[index.min(self.token_accounts.len() - 1)],
                },
            })
            .collect()
    }
}

#[derive(Clone, Copy, Debug)]
enum Spend {
    Rail(RingRail),
    /// SPP's anonymous rail proves the confidential owner.
    InProofOwner,
}

impl Spend {
    fn rail(self) -> RingRail {
        match self {
            Self::Rail(rail) => rail,
            Self::InProofOwner => RingRail::Confidential,
        }
    }
}

enum Proven {
    Transfer(Box<ProvenRingTransfer>),
    /// Refused before any proof, the transaction fits no ceiling.
    Unfit(RingError),
}

enum Settlement {
    Settled,
    TooLarge,
}

#[must_use]
struct ColumnSetup<'a> {
    env: &'a TestEnv,
    column: Column,
    program: Address,
}

struct ShapeRing<'a> {
    env: &'a TestEnv,
    ring: CustomRing,
    column: Column,
    auditor: X25519Keypair,
    /// Signs and pays every move of the delegate rail.
    delegate: Keypair,
    mode: RingMode,
    escrowed: HashMap<[u8; 32], [u8; 32]>,
}

impl<'a> ColumnSetup<'a> {
    fn configure(self, coverage: &mut Coverage) -> Result<ShapeRing<'a>> {
        let env = self.env;
        let ring = CustomRing::new(self.program);
        let auditor = X25519Keypair::new();
        RegisterRing {
            ring,
            payer: &env.payer,
            auditor_pubkey: auditor.pubkey(),
            tier: self.column.tier(),
        }
        .send(&env.client)?;
        let delegate = env.funded_keypair()?;
        let members = [&env.sender.keypair, &env.recipient.keypair];
        let applied = match self.column {
            Column::ConfidentialPolicy => {
                register_keys(env, ring, &[&env.sender.keypair])?;
                Some(1)
            }
            Column::Delegate => {
                EscrowedDelegate {
                    ring,
                    delegate: &delegate,
                    members: &members,
                }
                .set(env)?;
                env.enable_authority_rail(ring)?;
                Some(members.len() as u64)
            }
            Column::Confidential | Column::Anonymous | Column::AnonymousPolicy => None,
        };
        if let Some(applied) = applied {
            coverage.cover(RingCircuit::apply_records(applied));
        }
        let config = env.run(ring.require_config(env.client.as_async()))?;
        let escrowed = match config.mode {
            RingMode::ConfidentialEscrow => members
                .into_iter()
                .map(|member| {
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
                    let nullifier_pk = loop {
                        match env
                            .member_record(ring, owner_member(member)?)
                            .and_then(|read| {
                                read.nullifier_pk
                                    .context("the member's record escrows no nullifier key")
                            }) {
                            Ok(key) => break key,
                            Err(error) if std::time::Instant::now() >= deadline => {
                                return Err(error).context("member escrow was not indexed in time")
                            }
                            Err(_) => std::thread::sleep(std::time::Duration::from_millis(500)),
                        }
                    };
                    Ok((
                        member.signing_pubkey().confidential_view_tag()?,
                        nullifier_pk,
                    ))
                })
                .collect::<Result<_>>()?,
            RingMode::Confidential | RingMode::Anonymous => HashMap::new(),
        };
        if config.mode == RingMode::Anonymous {
            EnrollAddresses {
                ring,
                owners: &[&env.sender.keypair],
                env,
            }
            .send()?;
        }
        Ok(ShapeRing {
            env,
            ring,
            column: self.column,
            auditor,
            delegate,
            mode: config.mode,
            escrowed,
        })
    }
}

impl ShapeRing<'_> {
    fn sweep(&self, coverage: &mut Coverage) -> Result<()> {
        let (mut settled, mut too_large) = (Vec::new(), Vec::new());
        for shape in SPP_SUPPORTED_SHAPES
            .into_iter()
            .filter(|shape| self.column.keyed(*shape))
        {
            restart_prover()?;
            let transfer = ShapeTransfer {
                shape,
                inputs: self.utxos(1, coverage)?,
                spend: Spend::Rail(self.column.rail()),
                legs: Vec::new(),
            };
            match self.settle(transfer, coverage)? {
                Settlement::Settled => settled.push(shape),
                Settlement::TooLarge => too_large.push(shape),
            }
        }
        println!("RING_SHAPES {:?} too_large={too_large:?}", self.column);
        let unfit: Vec<Shape> = self
            .column
            .widest()
            .iter()
            .copied()
            .filter(|shape| !settled.contains(shape))
            .collect();
        ensure!(
            unfit.is_empty(),
            "{:?} {unfit:?} must settle at full width",
            self.column
        );
        Ok(())
    }

    /// A spend of a default-ring note opens every input under the entry keys.
    fn entries(&self, coverage: &mut Coverage) -> Result<()> {
        let env = self.env;
        for shape in ENTRY_TRANSFER_SHAPES {
            restart_prover()?;
            let utxo = DefaultRingDeposit {
                depositor: &env.sender.keypair,
                tree: env.tree,
                asset: DepositAsset::Sol,
                amount: UTXO_AMOUNT,
            }
            .send(env.client.rpc(), env.client.indexer(), &env.assets)?;
            let transfer = ShapeTransfer {
                shape: Shape::new(1, shape.outputs.into()),
                inputs: vec![utxo.input_utxo(env)?],
                spend: Spend::Rail(RingRail::Anonymous),
                legs: Vec::new(),
            };
            self.settled(transfer, coverage)?;
        }
        Ok(())
    }

    /// Sixteen policy outputs fit only when key escrow keeps the nullifier keys out of the bodies.
    fn escrowed_owner_transfer(&self, coverage: &mut Coverage) -> Result<()> {
        restart_prover()?;
        let transfer = ShapeTransfer {
            shape: Shape::IN1_OUT16,
            inputs: self.utxos(1, coverage)?,
            spend: Spend::Rail(RingRail::Confidential),
            legs: Vec::new(),
        };
        self.settled(transfer, coverage)
    }

    /// Every wider withdrawal capacity of the column's family, selected by as many legs under the policy.
    fn wide_withdrawals(&self, coverage: &mut Coverage) -> Result<()> {
        let (family, rail): (&[TransferShape], RingRail) = match self.column.rail() {
            RingRail::Confidential => (&CONFIDENTIAL_TRANSFER_SHAPES, RingRail::Confidential),
            RingRail::Anonymous => (&ANONYMOUS_TRANSFER_SHAPES, RingRail::Anonymous),
            RingRail::Delegate => return Ok(()),
        };
        let widest = family
            .iter()
            .map(|shape| usize::from(shape.withdrawals[1]))
            .max()
            .unwrap_or(0);
        let destinations = funded_destinations(self.env, distinct_targets(rail, widest))?;
        for shape in family.iter().filter(|shape| shape.withdrawals[1] != 0) {
            // One leg past the narrow capacity selects the wide key, its capacity fills it.
            for legs in [shape.withdrawals[0] + 1, shape.withdrawals[1]].map(usize::from) {
                restart_prover()?;
                let transfer = ShapeTransfer {
                    shape: Shape::new(1, shape.outputs.into()),
                    inputs: self.utxos(1, coverage)?,
                    spend: Spend::Rail(rail),
                    legs: match rail {
                        RingRail::Anonymous => vec![Leg::Sol(destinations[0]); legs],
                        RingRail::Confidential | RingRail::Delegate => {
                            destinations[..legs].iter().copied().map(Leg::Sol).collect()
                        }
                    },
                };
                self.settled(transfer, coverage)?;
            }
        }
        Ok(())
    }

    /// The widest SPL leg count one transaction carries under the two output wide key.
    fn spl_withdrawals(&self, coverage: &mut Coverage) -> Result<()> {
        let (family, rail): (&[TransferShape], RingRail) = match self.column.rail() {
            RingRail::Confidential => (&CONFIDENTIAL_TRANSFER_SHAPES, RingRail::Confidential),
            RingRail::Anonymous => (&ANONYMOUS_TRANSFER_SHAPES, RingRail::Anonymous),
            RingRail::Delegate => return Ok(()),
        };
        let mint = self.env.usdc_mint;
        let widest = TransferShape::of(family, 2)
            .map(|shape| usize::from(shape.withdrawals[1]))
            .context("a two output key")?;
        let token_accounts = self.token_accounts(distinct_targets(rail, widest))?;
        let inputs = self.usdc_utxos(1, coverage)?;
        restart_prover()?;
        for legs in (1..=widest).rev() {
            let transfer = ShapeTransfer {
                shape: Shape::IN1_OUT2,
                inputs: inputs.clone(),
                spend: Spend::Rail(rail),
                legs: (0..legs)
                    .map(|index| Leg::Spl {
                        mint,
                        token_account: token_accounts[index.min(token_accounts.len() - 1)],
                    })
                    .collect(),
            };
            if let Settlement::Settled = self.settle(transfer, coverage)? {
                println!("RING_SPL_LEGS {:?} legs={legs}", self.column);
                return Ok(());
            }
        }
        Err(anyhow!("{:?} settles no SPL withdrawal", self.column))
    }

    /// Per key and leg kind, the most legs one transaction carries at one note and at the input class.
    fn widest_frames(&self, family: KeyFamily, coverage: &mut Coverage) -> Result<()> {
        let env = self.env;
        let spend = family.spend();
        let widest = family
            .shapes()
            .iter()
            .flat_map(|shape| shape.withdrawals)
            .max()
            .map_or(0, usize::from);
        let distinct = distinct_targets(spend.rail(), widest);
        let targets = LegTargets {
            destinations: funded_destinations(env, distinct)?,
            mint: env.usdc_mint,
            token_accounts: self.token_accounts(distinct)?,
        };
        for shape in family
            .shapes()
            .iter()
            .filter(|shape| family.column(shape.outputs) == self.column)
        {
            let [narrow, wide] = shape.withdrawals.map(usize::from);
            // A note count no wide frame fits keeps its notes for the narrow key.
            let mut unspent: HashMap<(LegKind, usize), Vec<WalletUtxo>> = HashMap::new();
            for (fewest, most) in [(narrow + 1, wide), (0, narrow)] {
                if fewest > most {
                    continue;
                }
                restart_prover()?;
                for kind in [LegKind::Sol, LegKind::Spl] {
                    let mut settled_legs = 0;
                    for count in [1, usize::from(shape.inputs)] {
                        let notes = match unspent.remove(&(kind, count)) {
                            Some(notes) => notes,
                            None => self.spendable(family, kind, count, coverage)?,
                        };
                        let mut settled = None;
                        for legs in (fewest..=most).rev() {
                            let transfer = ShapeTransfer {
                                shape: Shape::new(count, shape.outputs.into()),
                                inputs: notes.clone(),
                                spend,
                                legs: targets.legs(kind, legs),
                            };
                            if let Settlement::Settled = self.settle(transfer, coverage)? {
                                settled = Some(legs);
                                break;
                            }
                        }
                        println!(
                            "RING_WIDEST {family:?} {kind:?} {count}x{} capacity={most} legs={settled:?}",
                            shape.outputs
                        );
                        match settled {
                            Some(legs) => settled_legs = settled_legs.max(legs),
                            None => {
                                unspent.insert((kind, count), notes);
                            }
                        }
                    }
                    ensure!(
                        settled_legs != 0,
                        "{family:?} {kind:?} {} outputs capacity {most} settles no leg",
                        shape.outputs
                    );
                }
            }
        }
        coverage.assert_keys(|circuit| family.keys(circuit, self.column));
        Ok(())
    }

    /// Each delivered capacity holds the in-proof owner's spent note once.
    fn in_proof_owners(&self, coverage: &mut Coverage) -> Result<()> {
        for outputs in DELIVERED_AUDIT_CAPACITIES {
            restart_prover()?;
            let shape = Shape::new(1, outputs);
            let transfer = ShapeTransfer {
                shape,
                inputs: self.utxos(1, coverage)?,
                spend: Spend::InProofOwner,
                legs: Vec::new(),
            };
            // The policy bodies push only the sixteen output transfer past the size ceiling.
            if self.column == Column::ConfidentialPolicy && shape == Shape::IN1_OUT16 {
                self.settle(transfer, coverage)?;
            } else {
                self.settled(transfer, coverage)?;
            }
        }
        Ok(())
    }

    /// Each merge takes one note more than the next narrower width holds.
    fn merges(&self, coverage: &mut Coverage) -> Result<()> {
        let env = self.env;
        let tree_id = env.tree_id(env.tree)?;
        let mut count = 2;
        for width in MERGE_WIDTHS {
            restart_prover()?;
            let prepared = CustomRingMerge::new(self.ring, self.utxos(count, coverage)?, None)?
                .with_output_tree_id(tree_id)
                .encrypt(&env.sender.keypair)?;
            let proved = u8::try_from(prepared.inputs().len())?;
            assert_eq!(
                usize::from(proved),
                width,
                "{count} notes merge at width {width}"
            );
            let merge = env.run(prepared.prove(
                MergeProofInput {
                    nullifier_key: env.sender.keypair.nullifier_key.clone(),
                    input_tree: env.tree,
                    output_tree: env.tree,
                    co_signer: None,
                },
                env.payer.pubkey(),
                env.client.ring_client(),
            ))?;
            let instruction = merge.instruction(env.payer.pubkey())?;
            let view = custom_ring_interface::CustomRingMergeIxDataRef::from_bytes(
                &instruction.data[1..],
            )?;
            let offset =
                view.disclosure.ciphertext.as_ptr() as usize - instruction.data.as_ptr() as usize;
            let mut altered = instruction.clone();
            altered.data[offset] ^= 1;
            let before = fetch_account(env.client.rpc(), &env.tree)?;
            let rejected = send_expecting_rejection(env.client.rpc(), &env.payer, altered)?;
            Rejection::custom(CustomRingError::ProofVerificationFailed as u32)
                .at(0)
                .assert_client(&rejected);
            assert_account_unchanged(env.client.rpc(), &env.tree, &before)?;
            land(env, instruction, &env.payer, &[])?;
            println!("RING_MERGE_KEY width={width} mutation_refused=true settled=true");
            coverage.cover(RingCircuit::Merge { width: proved });
            count = width + 1;
        }
        Ok(())
    }

    fn token_accounts(&self, count: usize) -> Result<Vec<Address>> {
        let env = self.env;
        (0..count)
            .map(|_| {
                let owner = Keypair::new().pubkey();
                let (_, ata) = create_associated_token_account(
                    env.client.rpc(),
                    &env.payer,
                    &owner,
                    &env.usdc_mint,
                )?;
                Ok(ata)
            })
            .collect()
    }

    fn spendable(
        &self,
        family: KeyFamily,
        kind: LegKind,
        count: usize,
        coverage: &mut Coverage,
    ) -> Result<Vec<WalletUtxo>> {
        match (family, kind) {
            (KeyFamily::AnonymousEntry, _) => self.default_ring_notes(kind, count),
            (_, LegKind::Sol) => self.utxos(count, coverage),
            (_, LegKind::Spl) => self.usdc_utxos(count, coverage),
        }
    }

    fn default_ring_notes(&self, kind: LegKind, count: usize) -> Result<Vec<WalletUtxo>> {
        let env = self.env;
        let depositor = &env.sender.keypair;
        let asset = match kind {
            LegKind::Sol => DepositAsset::Sol,
            LegKind::Spl => self.usdc_asset(depositor.pubkey(), count)?,
        };
        (0..count)
            .map(|_| {
                DefaultRingDeposit {
                    depositor,
                    tree: env.tree,
                    asset,
                    amount: UTXO_AMOUNT,
                }
                .send(env.client.rpc(), env.client.indexer(), &env.assets)?
                .input_utxo(env)
            })
            .collect()
    }

    fn utxos(&self, count: usize, coverage: &mut Coverage) -> Result<Vec<WalletUtxo>> {
        self.notes(count, DepositAsset::Sol, coverage)
    }

    fn usdc_utxos(&self, count: usize, coverage: &mut Coverage) -> Result<Vec<WalletUtxo>> {
        let asset = self.usdc_asset(self.env.payer.pubkey(), count)?;
        self.notes(count, asset, coverage)
    }

    fn usdc_asset(&self, depositor: Address, count: usize) -> Result<DepositAsset> {
        let env = self.env;
        let rpc = env.client.rpc();
        let mint = env.usdc_mint;
        let user_token = create_token_account(rpc, &env.payer, &mint, &depositor)?;
        mint_to(
            rpc,
            &env.payer,
            &mint,
            &user_token,
            UTXO_AMOUNT * count as u64,
        )?;
        Ok(DepositAsset::Spl(DepositSplAccounts {
            mint,
            user_token,
            token_program: pda::spl_token_program_id(),
        }))
    }

    /// Each deposit proves under the deposit key.
    fn notes(
        &self,
        count: usize,
        asset: DepositAsset,
        coverage: &mut Coverage,
    ) -> Result<Vec<WalletUtxo>> {
        let env = self.env;
        let utxos = RingNotes {
            ring: self.ring,
            owner: &env.sender.keypair,
            amount: UTXO_AMOUNT,
            asset,
            count,
            env,
        };
        let deposited = match self.column.rail() {
            RingRail::Anonymous => utxos.deposit_hidden_from(&env.payer)?,
            RingRail::Confidential | RingRail::Delegate => utxos.deposit_from(&env.payer)?,
        };
        coverage.cover(RingCircuit::deposit(1));
        deposited
            .into_iter()
            .map(|utxo| indexed_note(utxo, &env.sender.keypair, env, env.tree))
            .collect()
    }

    fn settled(&self, transfer: ShapeTransfer, coverage: &mut Coverage) -> Result<()> {
        let shape = transfer.shape;
        let spend = transfer.spend;
        match self.settle(transfer, coverage)? {
            Settlement::Settled => Ok(()),
            Settlement::TooLarge => Err(anyhow!("{:?} {spend:?} {shape:?} must fit", self.column)),
        }
    }

    fn settle(&self, transfer: ShapeTransfer, coverage: &mut Coverage) -> Result<Settlement> {
        let env = self.env;
        let rpc = env.client.rpc();
        let spend = transfer.spend;
        let rail = spend.rail();
        let label = format!(
            "{:?} {spend:?} {}x{} inputs={} legs={}{}",
            self.column,
            transfer.shape.n_inputs(),
            transfer.shape.n_outputs(),
            transfer.inputs.len(),
            transfer.legs.len(),
            match transfer.legs.first() {
                Some(Leg::Spl { .. }) => " spl",
                Some(Leg::Sol(_)) | None => "",
            }
        );
        let pinned = transfer
            .legs
            .is_empty()
            .then(|| {
                let spends_default_ring = transfer
                    .inputs
                    .iter()
                    .any(|input| input.utxo.ring_program_id.is_none());
                pinned_bytes(
                    self.column.measured(spend, spends_default_ring),
                    transfer.shape.n_inputs(),
                    transfer.shape.n_outputs(),
                )
            })
            .flatten();
        let mut paid: HashMap<Leg, u64> = HashMap::new();
        for leg in &transfer.legs {
            *paid.entry(*leg).or_default() += LEG_AMOUNT;
        }
        let balance = |leg: &Leg| -> Result<u64> {
            Ok(match leg {
                Leg::Sol(destination) => fetch_account(rpc, destination)?.lamports,
                Leg::Spl { token_account, .. } => token_amount(&fetch_account(rpc, token_account)?),
            })
        };
        let proven = match self
            .prove(transfer)
            .with_context(|| format!("prove {label}"))?
        {
            Proven::Transfer(proven) => proven,
            Proven::Unfit(reason) => {
                println!("RING_TOO_LARGE {label} {reason}");
                if let RingError::TransferTooWide { bytes, .. } = reason {
                    assert!(
                        pinned.is_none_or(|pinned| pinned == bytes),
                        "{label} takes {bytes}, its pin {pinned:?}"
                    );
                }
                return Ok(Settlement::TooLarge);
            }
        };
        let instruction = proven.instruction()?;
        let parsed = ParsedTransact::new(frame(&instruction, rail)?)?;
        let data = parsed.data();
        let circuit = data.transfer_circuit(keyed_legs(data))?;
        let tag = instruction
            .data
            .first()
            .context("a tagged ring instruction")?;
        let budget = ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::try_from(*tag)?));
        let payer = self.payer(spend);
        let size = spr_client::transaction_size(
            &payer.pubkey(),
            std::slice::from_ref(&instruction),
            budget,
        )?;
        if let Some(pinned) = pinned {
            assert_eq!(pinned, size.bytes, "{label} takes its pinned size");
        }
        let before: HashMap<Leg, u64> = paid
            .keys()
            .map(|leg| Ok((*leg, balance(leg)?)))
            .collect::<Result<_>>()?;
        let tree_before = fetch_account(rpc, &env.tree)?;
        let mut salt = *data.salt;
        salt[0] ^= 1;
        let altered = reframed(
            &instruction,
            &RingTransactData {
                salt: &salt,
                ..data.clone()
            },
        )?;
        let rejection = send_expecting_rejection(rpc, payer, altered)?;
        Rejection::custom(CustomRingError::ProofVerificationFailed as u32)
            .at(0)
            .assert_client(&rejection);
        assert_account_unchanged(rpc, &env.tree, &tree_before)?;
        for leg in paid.keys() {
            assert_eq!(balance(leg)?, before[leg]);
        }
        let signature = match land(env, instruction.clone(), payer, &[]) {
            Ok(signature) => signature,
            Err(error) => {
                let logs = self.simulated_logs(&instruction, payer)?;
                return Err(error.context(format!("{label} logs {logs:#?}")));
            }
        };
        coverage.cover(circuit);
        println!("RING_TRANSFER_KEY {circuit:?} mutation_refused=true settled=true");
        for (leg, amount) in &paid {
            assert_eq!(balance(leg)?, before[leg] + amount, "{label} leg {leg:?}");
        }
        let units = assert_transaction_compute_units(
            rpc,
            &signature,
            &label,
            CUSTOM_RING_TRANSACT_CU_LIMIT,
        )?;
        let audited = AuditLookup {
            ring: self.ring.program_id(),
            scan: RingScan::new(self.ring.program_id(), self.auditor.pubkey())
                .with_mode(self.mode)
                .with_escrowed_keys(self.escrowed.clone()),
            auditor: &self.auditor,
            signature,
        }
        .run(env)?;
        assert_eq!(opened(&audited), ring_openings(&proven.outputs)?, "{label}");
        println!(
            "RING_SETTLEMENT {label} bytes={} addresses={} cu={units}",
            size.bytes, size.addresses
        );
        Ok(Settlement::Settled)
    }

    /// Anonymous payments go to fresh recipients, each a bootstrap payment.
    fn prove(&self, transfer: ShapeTransfer) -> Result<Proven> {
        let env = self.env;
        let client = env.client.ring_client();
        let sender = &env.sender.keypair;
        let program = self.ring.program_id();
        let ShapeTransfer {
            shape,
            inputs,
            spend,
            legs,
        } = transfer;
        let total: u64 = inputs.iter().map(|input| input.utxo.amount).sum();
        let withdrawn = LEG_AMOUNT * legs.len() as u64;
        let amount = (total - withdrawn) / (2 * shape.n_outputs() as u64);
        let asset = inputs
            .first()
            .map(|input| input.utxo.asset.asset)
            .context("a spent note")?;
        let payments = 1..shape.n_outputs();
        let transaction = |payer: Address| -> Result<_> {
            let mut transaction =
                ConfidentialTransaction::new_with_ring(inputs.clone(), payer, program)?;
            let settlements = legs
                .iter()
                .map(|leg| match *leg {
                    Leg::Sol(destination) => {
                        Ok(transaction.withdraw_to(SOL_MINT, LEG_AMOUNT, destination, None)?)
                    }
                    Leg::Spl {
                        mint,
                        token_account,
                    } => {
                        transaction.withdraw(mint, LEG_AMOUNT, token_account)?;
                        Ok(TransactInterfaceTransferAccounts::SplWithdrawal(
                            TransactSplWithdrawalAccounts {
                                mint,
                                spl_interface: pda::spl_interface(&mint),
                                user_token_account: token_account,
                                token_program: pda::spl_token_program_id(),
                            },
                        ))
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            Ok((transaction, settlements))
        };
        let owner_transfer = |(transaction, settlements)| {
            CustomRingTransfer::new(CustomRingTransferInput {
                ring: self.ring,
                sender,
                nullifier_key: Some(&sender.nullifier_key),
                transaction,
            })
            .with_interface_transfer_accounts(settlements)
        };
        let confidential = |spend: Spend| -> Result<_> {
            let recipient = env.recipient.keypair.shielded_address()?;
            let (mut transaction, settlements) = transaction(self.payer(spend).pubkey())?;
            for _ in payments.clone() {
                if asset == SOL_MINT {
                    transaction.transfer_sol(&recipient, amount)?;
                } else {
                    transaction.transfer(&recipient, asset, amount)?;
                }
            }
            Ok(owner_transfer((transaction, settlements)))
        };
        let proven = match spend {
            Spend::Rail(RingRail::Confidential) => {
                env.run(confidential(spend)?.with_shape(shape)?.prove(client))
            }
            Spend::InProofOwner => env.run(
                confidential(spend)?
                    .with_in_proof_owner(&sender.signing_key)
                    .with_shape(shape)?
                    .prove(client),
            ),
            Spend::Rail(RingRail::Anonymous) => {
                let recipients = payments
                    .map(|_| ShieldedKeypair::new_ed25519())
                    .collect::<Result<Vec<_>, _>>()?;
                EnrollAddresses {
                    ring: self.ring,
                    owners: &recipients.iter().collect::<Vec<_>>(),
                    env,
                }
                .send()?;
                let mut anonymous = owner_transfer(transaction(env.payer.pubkey())?)
                    .with_anonymous_signer(&sender.signing_key);
                for recipient in &recipients {
                    anonymous = anonymous.with_payment(custom_ring_sdk::AnonymousPayment {
                        to: ring_address(recipient, program)?,
                        asset: env.assets.mint(&asset)?,
                        amount,
                        reply: None,
                    })?;
                }
                env.run(anonymous.with_shape(shape)?.prove(client))
            }
            Spend::Rail(RingRail::Delegate) => {
                ensure!(legs.is_empty(), "the authority rail settles no public leg");
                let recipient = env.recipient.keypair.shielded_address()?;
                let delegated = DelegateTransfer::new(DelegateTransferInput {
                    ring: self.ring,
                    delegate: self.delegate.pubkey(),
                    payer: self.delegate.pubkey(),
                    source: sender.shielded_address()?,
                    source_nullifier_key: &sender.nullifier_key,
                    inputs,
                    outputs: payments
                        .map(|_| DelegateOutput {
                            recipient,
                            asset: SOL_MINT,
                            amount,
                        })
                        .collect(),
                })
                .with_assets(&env.assets)
                .with_shape(shape)?;
                env.run(delegated.prove(client))
            }
        };
        match proven {
            Ok(proven) => Ok(Proven::Transfer(Box::new(proven))),
            Err(
                reason @ (RingError::TransferTooWide { .. }
                | RingError::TooManySettlementAccounts { .. }),
            ) => Ok(Proven::Unfit(reason)),
            Err(error) => Err(error.into()),
        }
    }

    /// A refused settlement reports its program logs, the landing alone names the error.
    fn simulated_logs(&self, instruction: &Instruction, payer: &dyn Signer) -> Result<Vec<String>> {
        let rpc = self.env.client.rpc();
        let (blockhash, _) = rpc.get_latest_blockhash()?;
        let budget = ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::Transfer));
        let message = compile_message(
            &payer.pubkey(),
            std::slice::from_ref(instruction),
            blockhash,
            budget,
        )?;
        let transaction = sign_transaction(message, &[payer])?;
        let simulated = rpc.client().simulate_transaction(&transaction)?;
        Ok(simulated.value.logs.unwrap_or_default())
    }

    /// The owner on SPP's anonymous rail never signs, the payer alone does.
    fn payer(&self, spend: Spend) -> &(dyn Signer + Sync) {
        match spend {
            Spend::Rail(RingRail::Confidential) => &self.env.sender.keypair,
            Spend::Rail(RingRail::Anonymous) | Spend::InProofOwner => &self.env.payer,
            Spend::Rail(RingRail::Delegate) => &self.delegate,
        }
    }
}

/// The anonymous rail leaves to one target, the confidential rail pays distinct owners.
fn distinct_targets(rail: RingRail, widest: usize) -> usize {
    match rail {
        RingRail::Anonymous => 1,
        RingRail::Confidential | RingRail::Delegate => widest,
    }
}

/// What the auditor must open for every output the proof binds, padding left out.
fn ring_openings(outputs: &[SppProofOutputUtxo]) -> Result<Vec<Opened>> {
    outputs
        .iter()
        .enumerate()
        .filter_map(|(slot, output)| output.owner_address.map(|owner| (slot, output, owner)))
        .map(|(slot, output, owner)| {
            Ok(Opened {
                slot_index: u32::try_from(slot)?,
                exit: false,
                owner_key: owner.signing_pubkey.confidential_view_tag()?,
                mint: Some(output.asset.asset),
                amount: output.amount,
                blinding: output.blinding,
            })
        })
        .collect()
}

#[test]
fn anonymous_widest_eight_output_transfer_settles() -> Result<()> {
    let env = setup()?;
    let mut coverage = Coverage::default();
    let ring = ColumnSetup {
        env: &env,
        column: Column::Anonymous,
        program: custom_ring_program_id()?,
    }
    .configure(&mut coverage)?;
    ring.settled(
        ShapeTransfer {
            shape: Shape::IN5_OUT8,
            inputs: ring.utxos(5, &mut coverage)?,
            spend: Spend::Rail(RingRail::Anonymous),
            legs: Vec::new(),
        },
        &mut coverage,
    )
}

#[test]
fn wide_anonymous_policy_withdrawals_settle() -> Result<()> {
    wide_withdrawals(Column::AnonymousPolicy)
}

#[test]
fn wide_confidential_policy_withdrawals_settle() -> Result<()> {
    wide_withdrawals(Column::ConfidentialPolicy)
}

#[test]
fn spl_anonymous_policy_withdrawals_settle() -> Result<()> {
    spl_withdrawals(Column::AnonymousPolicy)
}

#[test]
fn spl_confidential_policy_withdrawals_settle() -> Result<()> {
    spl_withdrawals(Column::ConfidentialPolicy)
}

#[test]
fn sweep_widest_frames_confidential_signer() -> Result<()> {
    widest_frames(KeyFamily::ConfidentialSigner, Column::ConfidentialPolicy)
}

#[test]
fn sweep_widest_frames_confidential_signer_escrowed() -> Result<()> {
    widest_frames(KeyFamily::ConfidentialSigner, Column::Delegate)
}

#[test]
fn sweep_widest_frames_confidential_in_proof() -> Result<()> {
    widest_frames(KeyFamily::ConfidentialInProof, Column::ConfidentialPolicy)
}

#[test]
fn sweep_widest_frames_confidential_in_proof_escrowed() -> Result<()> {
    widest_frames(KeyFamily::ConfidentialInProof, Column::Delegate)
}

#[test]
fn sweep_widest_frames_anonymous() -> Result<()> {
    widest_frames(KeyFamily::Anonymous, Column::AnonymousPolicy)
}

#[test]
fn sweep_widest_frames_anonymous_entry() -> Result<()> {
    widest_frames(KeyFamily::AnonymousEntry, Column::AnonymousPolicy)
}

fn widest_frames(family: KeyFamily, column: Column) -> Result<()> {
    configured(column, |ring, coverage| {
        ring.widest_frames(family, coverage)
    })
}

/// The wide withdrawal keys of one policy column alone, the sweep proves them beside every shape.
fn wide_withdrawals(column: Column) -> Result<()> {
    configured(column, |ring, coverage| ring.wide_withdrawals(coverage))
}

fn spl_withdrawals(column: Column) -> Result<()> {
    configured(column, |ring, coverage| ring.spl_withdrawals(coverage))
}

fn configured(
    column: Column,
    run: impl FnOnce(&ShapeRing<'_>, &mut Coverage) -> Result<()>,
) -> Result<()> {
    let env = setup()?;
    let mut coverage = Coverage::default();
    let ring = ColumnSetup {
        env: &env,
        column,
        program: custom_ring_program_id()?,
    }
    .configure(&mut coverage)?;
    run(&ring, &mut coverage)
}

#[test]
fn sweep_confidential() -> Result<()> {
    sweep(Column::Confidential)
}

#[test]
fn sweep_confidential_policy() -> Result<()> {
    sweep(Column::ConfidentialPolicy)
}

#[test]
fn sweep_anonymous() -> Result<()> {
    sweep(Column::Anonymous)
}

#[test]
fn sweep_anonymous_policy() -> Result<()> {
    sweep(Column::AnonymousPolicy)
}

#[test]
fn sweep_delegate() -> Result<()> {
    sweep(Column::Delegate)
}

fn sweep(column: Column) -> Result<()> {
    let env = setup()?;
    let mut coverage = Coverage::default();
    let ring = ColumnSetup {
        env: &env,
        column,
        program: custom_ring_program_id()?,
    }
    .configure(&mut coverage)?;
    ring.sweep(&mut coverage)?;
    match column {
        Column::Anonymous => ring.entries(&mut coverage)?,
        Column::Delegate => ring.escrowed_owner_transfer(&mut coverage)?,
        Column::Confidential => ring.in_proof_owners(&mut coverage)?,
        Column::ConfidentialPolicy => {
            ring.in_proof_owners(&mut coverage)?;
            ring.wide_withdrawals(&mut coverage)?;
            ring.spl_withdrawals(&mut coverage)?;
        }
        Column::AnonymousPolicy => {
            ring.wide_withdrawals(&mut coverage)?;
            ring.spl_withdrawals(&mut coverage)?;
        }
    }
    // One column per rail proves the merges, the delegate one also opens the key escrow record.
    if matches!(
        column,
        Column::Anonymous | Column::Confidential | Column::Delegate
    ) {
        ring.merges(&mut coverage)?;
    }
    coverage.assert_transfer_keys(column);
    Ok(())
}

#[test]
fn sanity_confidential_keys() -> Result<()> {
    sanity_keys(Column::Confidential)
}

#[test]
fn sanity_confidential_wide_keys() -> Result<()> {
    sanity_keys(Column::ConfidentialPolicy)
}

#[test]
fn sanity_anonymous_and_entry_keys() -> Result<()> {
    sanity_keys(Column::Anonymous)
}

#[test]
fn sanity_anonymous_wide_keys() -> Result<()> {
    sanity_keys(Column::AnonymousPolicy)
}

fn sanity_keys(column: Column) -> Result<()> {
    configured(column, |ring, coverage| {
        let family = match column.rail() {
            RingRail::Anonymous => &ANONYMOUS_TRANSFER_SHAPES[..],
            _ => &CONFIDENTIAL_TRANSFER_SHAPES[..],
        };
        let wide = matches!(column, Column::ConfidentialPolicy | Column::AnonymousPolicy);
        let destinations = funded_destinations(ring.env, 5)?;
        for shape in family {
            if wide && shape.withdrawals[1] == 0 {
                continue;
            }
            let legs = if wide {
                usize::from(shape.withdrawals[0]) + 1
            } else {
                0
            };
            ring.settled(
                ShapeTransfer {
                    shape: Shape::new(1, shape.outputs.into()),
                    inputs: ring.utxos(1, coverage)?,
                    spend: Spend::Rail(column.rail()),
                    legs: (0..legs)
                        .map(|index| {
                            Leg::Sol(
                                destinations[if column.rail() == RingRail::Anonymous {
                                    0
                                } else {
                                    index.min(4)
                                }],
                            )
                        })
                        .collect(),
                },
                coverage,
            )?;
        }
        if column == Column::Anonymous {
            ring.entries(coverage)?;
            ring.merges(coverage)?;
        }
        coverage.assert_transfer_keys(column);
        Ok(())
    })
}

#[test]
fn sanity_in_proof_and_delegate_modes() -> Result<()> {
    configured(Column::Delegate, |ring, coverage| {
        for spend in [Spend::InProofOwner, Spend::Rail(RingRail::Delegate)] {
            ring.settled(
                ShapeTransfer {
                    shape: Shape::IN2_OUT2,
                    inputs: ring.utxos(1, coverage)?,
                    spend,
                    legs: Vec::new(),
                },
                coverage,
            )?;
        }
        Ok(())
    })
}

#[test]
fn sanity_wide_withdrawal_heap_sentinel() -> Result<()> {
    configured(Column::AnonymousPolicy, |ring, coverage| {
        let destination = funded_destinations(ring.env, 1)?[0];
        ring.settled(
            ShapeTransfer {
                shape: Shape::IN1_OUT4,
                inputs: ring.utxos(1, coverage)?,
                spend: Spend::Rail(RingRail::Anonymous),
                legs: vec![Leg::Sol(destination); 32],
            },
            coverage,
        )
    })
}
