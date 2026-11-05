use custom_ring_interface::{
    credential::credential_owner, AddressCheckpoint, AddressRootSelection, CredentialRootSelection,
    CredentialRoots, CredentialStateRoot,
};
use solana_address::Address;
use spr_program::ADDRESS_TREE_ID;
use spr_tree::nullifier_tree::layout::NullifierTreeLayout;

pub struct CredentialFields<'a> {
    pub ring_program: &'a [u8; 32],
    pub fields: &'a [[u8; 32]],
}

pub struct CredentialFixture<'a> {
    pub ring_program: [u8; 32],
    pub address_root: [u8; 32],
    pub state_roots: &'a [CredentialStateRoot],
    pub capacity: usize,
}

impl CredentialFixture<'_> {
    pub fn roots(self) -> CredentialRoots {
        CredentialRootSelection {
            ring_program: &Address::new_from_array(self.ring_program),
            address_checkpoint: checkpoint(self.address_root),
            state_roots: self.state_roots,
            capacity: self.capacity,
        }
        .roots()
        .unwrap()
    }
}

impl CredentialFields<'_> {
    pub fn roots(self) -> CredentialRoots {
        assert!(self.fields.len() >= 4 && self.fields.len().is_multiple_of(2));
        let capacity = (self.fields.len() - 2) / 2;
        if self.fields.iter().all(|field| *field == [0; 32]) {
            return CredentialRoots::empty(capacity).unwrap();
        }
        let ring_program = Address::new_from_array(*self.ring_program);
        assert_eq!(self.fields[0], credential_owner(&ring_program).unwrap());
        let states: Vec<_> = self.fields[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                assert_eq!(&pair[0][..30], &[0; 30]);
                CredentialStateRoot {
                    tree_id: u16::from_be_bytes(pair[0][30..].try_into().unwrap()),
                    root: pair[1],
                }
            })
            .collect();
        let roots = if self.fields[1] == [0; 32] {
            assert_eq!(capacity, 1);
            CredentialRoots::state_only(&ring_program, states[0]).unwrap()
        } else {
            let distinct = states[1..]
                .iter()
                .position(|state| *state == states[0])
                .map_or(states.len(), |index| index + 1);
            CredentialFixture {
                ring_program: ring_program.to_bytes(),
                address_root: self.fields[1],
                state_roots: &states[..distinct],
                capacity,
            }
            .roots()
        };
        assert_eq!(roots.elements().collect::<Vec<_>>(), self.fields);
        roots
    }
}

fn checkpoint(root: [u8; 32]) -> AddressCheckpoint {
    let bytes = vec![0; core::mem::size_of::<NullifierTreeLayout<1>>()];
    let mut history: NullifierTreeLayout<1> = wincode::deserialize(&bytes).unwrap();
    history.sequence_number = 1;
    history.root_history.roots[0] = root;
    AddressRootSelection {
        tree_id: ADDRESS_TREE_ID,
        root_index: 0,
        history: &history,
    }
    .checkpoint()
    .unwrap()
}
