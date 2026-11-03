//! Prefix evidence of statement version 2, a prefix never repairs a spend link alone.

use std::collections::HashMap;

use spr_hasher::primitives::{is_canonical_bn254_scalar_be, BN254_SCALAR_MODULUS_BE};

/// The first bytes of a spent hash the historical evidence discloses.
pub const INPUT_PREFIX_BYTES: usize = 16;

/// `prefix16(input_hash)`, the first bytes of the big-endian hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InputPrefix(u128);

/// A prefix no canonical hash has.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("not the prefix of a canonical input hash")]
pub struct InvalidInputPrefix;

impl InputPrefix {
    /// No canonical hash has a larger prefix.
    const MAX: u128 = halves(&BN254_SCALAR_MODULUS_BE)[0];

    /// `None` for a hash at or above the modulus or below 2^128, a zero prefix names no input.
    pub fn of(hash: &[u8; 32]) -> Option<Self> {
        let [prefix, _] = halves(hash);
        (is_canonical_bn254_scalar_be(hash) && prefix != 0).then_some(Self(prefix))
    }

    pub const fn get(self) -> u128 {
        self.0
    }

    pub const fn to_bytes(self) -> [u8; INPUT_PREFIX_BYTES] {
        self.0.to_be_bytes()
    }

    /// `None` for the zero bytes of a published dummy, refuses a prefix no canonical hash has.
    pub fn from_bytes(
        bytes: &[u8; INPUT_PREFIX_BYTES],
    ) -> Result<Option<Self>, InvalidInputPrefix> {
        match u128::from_be_bytes(*bytes) {
            0 => Ok(None),
            prefix if prefix <= Self::MAX => Ok(Some(Self(prefix))),
            _ => Err(InvalidInputPrefix),
        }
    }
}

const fn halves(field: &[u8; 32]) -> [u128; 2] {
    let (chunks, _) = field.as_chunks::<INPUT_PREFIX_BYTES>();
    [
        u128::from_be_bytes(chunks[0]),
        u128::from_be_bytes(chunks[1]),
    ]
}

/// The notes an auditor opened, by spent-hash prefix with or without their owner.
#[derive(Clone, Debug, Default)]
pub struct PrefixIndex {
    owned: HashMap<([u8; 32], InputPrefix), Vec<[u8; 32]>>,
    prefixes: HashMap<InputPrefix, Vec<[u8; 32]>>,
}

impl PrefixIndex {
    /// A commitment with no prefix of its own stays out of the index.
    pub fn insert(&mut self, owner_key: [u8; 32], commitment: [u8; 32]) {
        if let Some(prefix) = InputPrefix::of(&commitment) {
            self.owned
                .entry((owner_key, prefix))
                .or_default()
                .push(commitment);
            self.prefixes.entry(prefix).or_default().push(commitment);
        }
    }

    pub fn owned(&self, owner_key: &[u8; 32], prefix: InputPrefix) -> &[[u8; 32]] {
        self.owned
            .get(&(*owner_key, prefix))
            .map_or(&[], Vec::as_slice)
    }

    /// The authority rail names no owner for its inputs.
    pub fn of_anyone(&self, prefix: InputPrefix) -> &[[u8; 32]] {
        self.prefixes.get(&prefix).map_or(&[], Vec::as_slice)
    }
}

/// One position of a prefix group, exact only for one note in one position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrefixAssignment {
    Dummy,
    Exact([u8; 32]),
    /// More notes carry the disclosed prefix than inputs name it.
    Ambiguous {
        candidates: Vec<[u8; 32]>,
    },
    /// Too few opened notes carry the disclosed prefix.
    Unseen {
        prefix: InputPrefix,
    },
}

/// The notes of one prefix in store order.
pub struct PrefixNotes {
    pub prefix: InputPrefix,
    pub notes: Vec<[u8; 32]>,
}

impl PrefixNotes {
    pub fn assign(self, inputs: usize) -> Vec<PrefixAssignment> {
        match self.notes[..] {
            _ if self.notes.len() < inputs => vec![
                PrefixAssignment::Unseen {
                    prefix: self.prefix,
                };
                inputs
            ],
            [commitment] => vec![PrefixAssignment::Exact(commitment)],
            _ => vec![
                PrefixAssignment::Ambiguous {
                    candidates: self.notes,
                };
                inputs
            ],
        }
    }
}

/// Groups equal prefixes, `notes` reads a group's candidates once.
pub fn assign_prefixed_inputs(
    prefixes: &[Option<InputPrefix>],
    notes: impl Fn(InputPrefix) -> Vec<[u8; 32]>,
) -> Vec<PrefixAssignment> {
    let mut groups: Vec<(InputPrefix, Vec<usize>)> = Vec::new();
    for (position, prefix) in prefixes.iter().enumerate() {
        let Some(prefix) = *prefix else {
            continue;
        };
        match groups.iter_mut().find(|(group, _)| *group == prefix) {
            Some((_, positions)) => positions.push(position),
            None => groups.push((prefix, vec![position])),
        }
    }
    let mut assigned = vec![PrefixAssignment::Dummy; prefixes.len()];
    for (prefix, positions) in groups {
        let opened = PrefixNotes {
            prefix,
            notes: notes(prefix),
        }
        .assign(positions.len());
        for (position, assignment) in positions.into_iter().zip(opened) {
            assigned[position] = assignment;
        }
    }
    assigned
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(prefix: u8, tail: u8) -> [u8; 32] {
        let mut hash = [tail; 32];
        hash[..16].fill(prefix);
        hash[0] = 1;
        hash
    }

    #[test]
    fn input_prefixes_read_back_and_refuse_a_prefix_above_the_modulus() {
        let mut below = BN254_SCALAR_MODULUS_BE;
        below[31] -= 1;
        let top = InputPrefix::of(&below).unwrap();
        assert_eq!(top.get(), InputPrefix::MAX);
        assert_eq!(InputPrefix::of(&BN254_SCALAR_MODULUS_BE), None);
        let mut short = [0; 32];
        short[16] = 1;
        assert_eq!(InputPrefix::of(&short), None);
        assert_eq!(InputPrefix::from_bytes(&top.to_bytes()), Ok(Some(top)));
        assert_eq!(InputPrefix::from_bytes(&[0; 16]), Ok(None));
        let over = (InputPrefix::MAX + 1).to_be_bytes();
        assert_eq!(InputPrefix::from_bytes(&over), Err(InvalidInputPrefix));
    }

    /// Reads the shared vector `PrefixNotes::assign` and TS `assignPrefixedInputs` both pin.
    #[test]
    fn prefix_assignment_matches_the_shared_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/audit/prefix-assignment.json"
        ))
        .unwrap();
        for case in vector["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let hash_of = |value: &serde_json::Value| -> [u8; 32] {
                hex::decode(value.as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap()
            };
            let notes: Vec<[u8; 32]> = case["notes"]
                .as_array()
                .unwrap()
                .iter()
                .map(hash_of)
                .collect();
            let inputs = case["inputs"].as_u64().unwrap() as usize;
            let assigned = PrefixNotes {
                prefix: InputPrefix::of(&notes[0]).unwrap(),
                notes: notes.clone(),
            }
            .assign(inputs);
            match case["expected"].as_str() {
                Some("ambiguous") => assert!(
                    assigned.iter().all(
                        |one| matches!(one, PrefixAssignment::Ambiguous { candidates } if *candidates == notes)
                    ),
                    "{name}"
                ),
                Some("unseen") => assert!(
                    assigned
                        .iter()
                        .all(|one| matches!(one, PrefixAssignment::Unseen { .. })),
                    "{name}"
                ),
                Some("opened") => {
                    assert_eq!(assigned, [PrefixAssignment::Exact(notes[0])], "{name}")
                }
                _ => panic!("{name} names no outcome"),
            }
        }
    }

    #[test]
    fn notes_sharing_a_prefix_fit_any_of_its_positions() {
        let (first, second) = (hash(7, 1), hash(7, 2));
        let prefix = InputPrefix::of(&first).unwrap();
        assert_eq!(InputPrefix::of(&second), Some(prefix));
        let assigned =
            assign_prefixed_inputs(&[Some(prefix), None, Some(prefix)], |_| vec![first, second]);
        let ambiguous = PrefixAssignment::Ambiguous {
            candidates: vec![first, second],
        };
        assert_eq!(
            assigned,
            [ambiguous.clone(), PrefixAssignment::Dummy, ambiguous]
        );
    }

    #[test]
    fn the_index_scopes_a_prefix_to_its_owner() {
        let mut index = PrefixIndex::default();
        let commitment = hash(7, 1);
        index.insert([1; 32], commitment);
        let prefix = InputPrefix::of(&commitment).unwrap();
        assert_eq!(index.owned(&[1; 32], prefix), [commitment]);
        assert!(index.owned(&[2; 32], prefix).is_empty());
        assert_eq!(index.of_anyone(prefix), [commitment]);
    }
}
