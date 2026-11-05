use std::{collections::VecDeque, sync::Mutex};

use custom_ring_interface::CREDENTIAL_PDA_SEED;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use spr_hasher::{Hasher, Poseidon};
use spr_interface::instruction::TreeContext;
use spr_keypair::{NullifierKey, X25519Keypair};
use spr_program::program::{PdaOwner, UniqueDataUtxo, UtxoMeta};

use super::*;
use crate::credentials::fixture::{Enrollment, TREE_ID};

const RING: Address = Address::new_from_array([8; 32]);
const SALT: [u8; 32] = {
    let mut salt = [5; 32];
    salt[0] = 0;
    salt
};
const ROOT: [u8; 32] = [3; 32];
const STATE_ROOT: [u8; 32] = [4; 32];

/// Answers each address read with the next queued snapshot, the last one repeats.
struct Tree0 {
    snapshots: Mutex<VecDeque<(u64, bool)>>,
    reads: Mutex<u32>,
}

#[async_trait]
impl CredentialEvidence for Tree0 {
    async fn address_snapshot(
        &self,
        addresses: &[[u8; 32]],
    ) -> Result<AddressSnapshot, RingRpcError> {
        *self.reads.lock().expect("reads") += 1;
        let mut snapshots = self.snapshots.lock().expect("snapshots");
        let (sequence, active) = match snapshots.len() {
            1 => snapshots[0],
            _ => snapshots.pop_front().expect("snapshot"),
        };
        let leaf = AddressLeaf {
            next: [0; 32],
            index: 1,
            path: [[0; 32]; ADDRESS_TREE_HEIGHT],
        };
        Ok(AddressSnapshot {
            root: ROOT,
            sequence,
            leaves: addresses.iter().map(|_| active.then_some(leaf)).collect(),
        })
    }

    async fn state_opening(&self, held: &HeldCredential) -> Result<StateOpening, RingRpcError> {
        Ok(StateOpening {
            tree_id: held.leaf.tree_id,
            root: STATE_ROOT,
            leaf_index: held.leaf.leaf_index,
            path: [[0; 32]; UTXO_TREE_HEIGHT],
        })
    }
}

impl Tree0 {
    fn new(snapshots: &[(u64, bool)]) -> Self {
        Self {
            snapshots: Mutex::new(snapshots.iter().copied().collect()),
            reads: Mutex::new(0),
        }
    }
}

fn owner(seed: u8, list_salt: [u8; 32]) -> HeldCredential {
    let key = NullifierKey::from_secret([seed; 31]);
    let auditor = X25519Keypair::new().pubkey();
    let enrollment = Enrollment {
        ring: RING,
        owner: Keypair::new_from_array([seed; 32]).pubkey(),
        key: &key,
        list_salt,
        auditor: &auditor,
        signature: Signature::from([seed; 64]),
        slot: u64::from(seed),
    };
    enrollment.held(enrollment.credential())
}

fn write(write_index: u8, owner: HeldCredential, list_salt: [u8; 32]) -> SaltedOwnerWrite {
    let member = Member::from_bytes(owner.credential.member).expect("member");
    SaltedOwnerWrite {
        write_index,
        written_key: *Member::salted(&member, &list_salt)
            .expect("list key")
            .as_bytes(),
        owner,
        list_salt,
    }
}

fn batch(writes: Vec<SaltedOwnerWrite>, absence_floor: u64, attempts: u32) -> CredentialWriteBatch {
    CredentialWriteBatch {
        ring: RING,
        writes,
        width: 4,
        absence_floor,
        wait: ActivationWait {
            attempts: NonZeroU32::new(attempts).expect("attempts"),
            interval: Duration::from_millis(10),
        },
    }
}

fn refusal(result: Result<CredentialWritePlan, RingRpcError>) -> CredentialWriteRefusal {
    match result {
        Err(RingRpcError::CredentialWrite(refusal)) => refusal,
        other => panic!("expected a credential write refusal, got {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn a_write_waits_for_activation_then_binds_its_key_and_raises_the_floor() {
    let target = owner(31, SALT);
    let tree0 = Tree0::new(&[(6, false), (9, true)]);

    let plan = batch(vec![write(2, target, SALT)], 5, 3)
        .plan(&tree0)
        .await
        .expect("plan");

    let pda = CredentialPda::of(&RING).expect("pda");
    assert_eq!(*tree0.reads.lock().expect("reads"), 2);
    assert_eq!(plan.credential_writes, 0b100);
    assert_eq!(plan.absence_floor, 9);
    assert_eq!(plan.address_root, ROOT);
    assert_eq!(plan.private_ring_id, pda.ring_id());
    assert_eq!(plan.credential_owner, pda.owner_hash());
    assert_eq!(
        plan.state_roots,
        vec![
            CredentialStateRoot {
                tree_id: TREE_ID,
                root: STATE_ROOT,
            };
            4
        ]
    );
    let input = &plan.credentials[0];
    assert_eq!((input.write_index, input.tree_slot), (2, 0));
    assert_eq!(input.credential, target.credential);
    assert_eq!(input.state_index, target.leaf.leaf_index);
    // The circuit's UTXO rebuilt under the planned blinding is the credential's confirmed leaf.
    let owner = PdaOwner::new(&Address::find_program_address(&[CREDENTIAL_PDA_SEED], &RING).0)
        .expect("owner");
    let meta = UtxoMeta {
        address: target.address,
        blinding: input.blinding,
        tree_context: TreeContext {
            utxo_tree_root_index: 0,
            nullifier_tree_root_index: 0,
        },
    };
    let spent = UniqueDataUtxo::new_mut(&owner, &meta, target.credential, TREE_ID).expect("utxo");
    assert_eq!(
        *spent.input_nullifier(),
        Poseidon::hashv(&[&target.leaf.utxo_hash, &input.blinding, &[0; 32]]).expect("nullifier")
    );
}

#[tokio::test(start_paused = true)]
async fn a_write_before_activation_is_refused_when_the_wait_ends() {
    let tree0 = Tree0::new(&[(6, false)]);

    let refused = batch(vec![write(1, owner(32, SALT), SALT)], 0, 3)
        .plan(&tree0)
        .await;

    assert_eq!(refusal(refused), CredentialWriteRefusal::NotActive(1));
    assert_eq!(*tree0.reads.lock().expect("reads"), 3);
}

#[tokio::test(start_paused = true)]
async fn the_floor_never_moves_below_the_registry_floor() {
    let tree0 = Tree0::new(&[(9, true)]);

    let plan = batch(vec![write(0, owner(33, SALT), SALT)], 12, 1)
        .plan(&tree0)
        .await
        .expect("plan");

    assert_eq!(plan.absence_floor, 12);
}

#[tokio::test(start_paused = true)]
async fn an_unbound_key_another_salt_or_a_repeated_index_is_refused_before_any_read() {
    let target = owner(34, SALT);
    let mut other_salt = SALT;
    other_salt[31] ^= 1;
    let mut unbound = write(0, target, SALT);
    unbound.written_key[31] ^= 1;
    let cases = [
        (vec![unbound], CredentialWriteRefusal::UnboundListKey(0)),
        (
            vec![write(1, target, other_salt)],
            CredentialWriteRefusal::ListTag(1),
        ),
        (
            vec![write(3, target, SALT), write(3, owner(35, SALT), SALT)],
            CredentialWriteRefusal::WriteIndex(3),
        ),
        (Vec::new(), CredentialWriteRefusal::Width),
    ];
    for (writes, expected) in cases {
        let tree0 = Tree0::new(&[(9, true)]);
        assert_eq!(refusal(batch(writes, 0, 1).plan(&tree0).await), expected);
        assert_eq!(*tree0.reads.lock().expect("reads"), 0);
    }
}
