//! Pins every transfer key's credential pool to the most distinct subjects a spend on that key opens.
//!
//! A live row opens its owner's credential, a delegate row only for a nonzero-key note. A salted
//! policy read also opens every output owner and every withdrawal owner, and each subject may need
//! state inclusion or address absence. The SDK admits rows and legs by
//! `TransferAddresses::owner_rows`, and the catalog then selects the key by the subject count.
//! `go_vectors.rs` holds `credential_capacity` to the Go circuit's pool size.

use std::collections::BTreeMap;

use custom_ring_interface::{
    key_catalog::{RecordPools, RingCircuit, TransferAddresses, TransferSpend, RING_KEYS},
    RingRail,
};
use spr_interface::{shape::SPP_SUPPORTED_SHAPES, MAX_INTERFACE_TRANSFERS};

/// Who authorizes a spend's rows and where its withdrawals may pay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Signing {
    /// Every row signs in the run, as on the signer and public owner rails.
    Run,
    /// One row signs inside SPP's proof, the SDK refuses its default-ring inputs.
    InProof,
    /// One row hides and every withdrawal pays one destination.
    Hidden,
    /// No row signs and no policy reads a credential.
    Delegate,
}

/// `rows` counts distinct live input owners, never past what the addresses admit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Spend {
    signing: Signing,
    inputs: usize,
    outputs: usize,
    legs: usize,
    rows: usize,
    entry: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct Shortfall {
    spend: Spend,
    subjects: usize,
    key: &'static str,
    capacity: usize,
}

impl Signing {
    const ALL: [Self; 4] = [Self::Run, Self::InProof, Self::Hidden, Self::Delegate];

    const fn rail(self) -> RingRail {
        match self {
            Self::Run | Self::InProof => RingRail::Confidential,
            Self::Hidden => RingRail::Anonymous,
            Self::Delegate => RingRail::Delegate,
        }
    }

    /// An in-proof owner settles on SPP's anonymous selector.
    const fn spp_rail(self) -> RingRail {
        match self {
            Self::InProof => RingRail::Anonymous,
            signing => signing.rail(),
        }
    }

    const fn enters(self) -> bool {
        matches!(self, Self::Run | Self::Hidden)
    }

    /// The delegate's policy bypass reads no leg.
    fn legs(self) -> std::ops::RangeInclusive<usize> {
        match self {
            Self::Delegate => 0..=0,
            _ => 0..=MAX_INTERFACE_TRANSFERS,
        }
    }

    /// Every input may have its own owner, a row outside the run takes only its nullifier PDA.
    fn most_rows(self, inputs: usize, legs: usize) -> usize {
        let run = TransferAddresses {
            n_inputs: inputs,
            co_signers: 0,
            legs,
            credential_accounts: 0,
        }
        .owner_signers();
        match self {
            Self::Run => run.min(inputs),
            Self::InProof | Self::Hidden => (run + 1).min(inputs),
            Self::Delegate => inputs,
        }
    }
}

impl Spend {
    /// Every subject distinct and every output owner read, the salted worst case.
    fn subjects(self) -> usize {
        let leg_owners = match self.signing {
            Signing::Run | Signing::InProof => self.legs,
            Signing::Hidden => self.legs.min(1),
            Signing::Delegate => 0,
        };
        self.rows + self.outputs + leg_owners
    }

    fn catalog(self, credentials: usize, wide: bool) -> TransferSpend {
        TransferSpend {
            rail: self.signing.rail(),
            inputs: self.inputs,
            outputs: self.outputs,
            spends_default_ring: self.entry,
            legs: self.legs,
            owners: self.rows,
            pools: RecordPools {
                credentials,
                ..RecordPools::default()
            },
            wide,
        }
    }

    /// The selected key and `true`, else the wide key with no credential demand and `false`.
    fn key(self) -> Option<(RingCircuit, bool)> {
        match RingCircuit::transfer(self.catalog(self.subjects(), false).fitted()) {
            Some(circuit) => Some((circuit, true)),
            None => RingCircuit::transfer(self.catalog(0, true)).map(|circuit| (circuit, false)),
        }
    }
}

fn spends() -> impl Iterator<Item = Spend> {
    Signing::ALL.into_iter().flat_map(|signing| {
        [false, true]
            .into_iter()
            .filter(move |entry| !entry || signing.enters())
            .flat_map(move |entry| {
                SPP_SUPPORTED_SHAPES
                    .into_iter()
                    .filter(move |shape| signing.spp_rail().supports(*shape))
                    .flat_map(move |shape| {
                        signing.legs().flat_map(move |legs| {
                            let (inputs, outputs) = (shape.n_inputs(), shape.n_outputs());
                            (0..=signing.most_rows(inputs, legs)).map(move |rows| Spend {
                                signing,
                                inputs,
                                outputs,
                                legs,
                                rows,
                                entry,
                            })
                        })
                    })
            })
    })
}

fn name(circuit: RingCircuit) -> &'static str {
    RING_KEYS
        .iter()
        .find(|key| key.circuit == circuit)
        .map(|key| key.name)
        .expect("a selected key is in the catalog")
}

fn capacity(circuit: RingCircuit) -> usize {
    circuit
        .credential_capacity()
        .expect("a transfer key has a credential pool")
}

/// The most subjects any spend of `signings` opens per key, landed or short.
fn worst(signings: &[Signing]) -> BTreeMap<&'static str, usize> {
    let mut worst = BTreeMap::new();
    for spend in spends().filter(|spend| signings.contains(&spend.signing)) {
        if let Some((circuit, _)) = spend.key() {
            let seen = worst.entry(name(circuit)).or_insert(0);
            *seen = (*seen).max(spend.subjects());
        }
    }
    worst
}

/// Name, credential capacity, worst over every rail, worst over the run rail alone.
const BOUNDS: [(&str, usize, usize, usize); 12] = [
    ("custom-ring-transfer-2-in24-w4-s4", 6, 6, 6),
    ("custom-ring-transfer-4-in24-w4-s4", 8, 8, 8),
    ("custom-ring-transfer-8-in16-w4-s4", 12, 12, 12),
    ("custom-ring-transfer-16-in5-w8-s5", 21, 21, 21),
    ("custom-ring-transfer-wide-8-in24-w32-s24", 52, 52, 51),
    ("custom-ring-transfer-wide-16-in5-w8-s5", 29, 29, 29),
    ("custom-ring-transfer-wide-16-in8-w8-s8", 32, 32, 32),
    ("custom-ring-transfer-wide-2-in49-w4-s12", 18, 18, 18),
    ("custom-ring-transfer-entry-4-in8-w4-s8", 16, 16, 16),
    ("custom-ring-transfer-entry-8-in2-w4-s2", 14, 14, 14),
    ("custom-ring-transfer-entry-8-in4-w4-s4", 16, 16, 16),
    ("custom-ring-transfer-entry-2-in24-w32-s12", 45, 45, 45),
];

#[test]
fn each_key_pins_its_worst_subject_count() {
    let every_rail = worst(&Signing::ALL);
    let run = worst(&[Signing::Run]);
    for (key, pool, any, signed) in BOUNDS {
        let circuit = RING_KEYS
            .iter()
            .find(|ring_key| ring_key.name == key)
            .map(|ring_key| ring_key.circuit)
            .unwrap_or_else(|| panic!("{key} is no catalog key"));
        assert_eq!(capacity(circuit), pool, "{key} capacity");
        assert_eq!(every_rail.get(key), Some(&any), "{key} over every rail");
        assert_eq!(run.get(key), Some(&signed), "{key} on the run rail");
    }
    assert_eq!(every_rail.len(), BOUNDS.len());
}

/// Under a salted block list each run or in-proof subject can read absent or present, a row spending
/// zero-key notes, a zero-key recipient and a leg owner alike, so either kind alone can fill each pool.
#[test]
fn the_signing_rails_fill_every_pool() {
    let signing = worst(&[Signing::Run, Signing::InProof]);
    for key in RING_KEYS
        .iter()
        .filter(|key| matches!(key.circuit, RingCircuit::Transfer { .. }))
    {
        assert_eq!(
            signing.get(key.name),
            Some(&capacity(key.circuit)),
            "{}",
            key.name
        );
    }
}

/// An in-proof row takes its nullifier PDA alone, so twelve rows, eight outputs and thirty two legs name
/// 52 subjects.
#[test]
fn every_admitted_spend_fits_its_pool() {
    let shortfalls: Vec<Shortfall> = spends()
        .filter_map(|spend| match spend.key() {
            Some((circuit, false)) => Some(Shortfall {
                spend,
                subjects: spend.subjects(),
                key: name(circuit),
                capacity: capacity(circuit),
            }),
            _ => None,
        })
        .collect();
    assert_eq!(shortfalls, []);
    let in_proof = Spend {
        signing: Signing::InProof,
        inputs: 12,
        outputs: 8,
        legs: 32,
        rows: 12,
        entry: false,
    };
    assert_eq!(in_proof.subjects(), 52);
    assert_eq!(
        in_proof
            .key()
            .map(|(circuit, landed)| (name(circuit), landed)),
        Some(("custom-ring-transfer-wide-8-in24-w32-s24", true))
    );
}
