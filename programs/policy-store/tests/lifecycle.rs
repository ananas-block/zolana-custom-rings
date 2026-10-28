use bytemuck::bytes_of;
use custom_ring_interface::{
    ApplyRecordsIxData, AuthorityWriteRecordsIxData, CustomRingError, CustomRingProof,
    PlainGroth16Proof, RecordWriteData, WriteRecordsIxData,
};
use litesvm::LiteSVM;
use policy_store_program::{
    tag, InitializeIxData, StoreError, VerifyPolicyIxData, REGISTRY_PDA_SEED,
};
use serde_json::Value;
use solana_address::Address;
use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_keypair::{Keypair, Signer};
use solana_transaction_error::TransactionError;
use spr_client::{
    compile_message,
    prover::{Proof, ProofCompressed},
    sign_transaction, ComputeBudgetConfig,
};
use spr_hasher::primitives::right_align;
use zolana_ring_policy::TableParts;

const PROGRAM: Address = Address::new_from_array([0x53; 32]);
const GRACE: u64 = 10;

struct Store {
    svm: LiteSVM,
    writer: Keypair,
    reader: Keypair,
    registry: Address,
    proofs: Value,
}

impl Store {
    fn new() -> Self {
        let mut svm = LiteSVM::new();
        svm.warp_to_slot(0);
        let program = std::env::var_os("SBF_OUT_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy").into())
            .join("policy_store_program.so");
        svm.add_program(PROGRAM, &std::fs::read(program).unwrap())
            .unwrap();
        let writer = Keypair::new_from_array([9; 32]);
        svm.airdrop(&writer.pubkey(), 1_000_000_000).unwrap();
        let registry =
            Address::find_program_address(&[REGISTRY_PDA_SEED, writer.pubkey().as_ref()], &PROGRAM)
                .0;
        Self {
            svm,
            writer,
            reader: Keypair::new(),
            registry,
            proofs: serde_json::from_str(include_str!("proofs.json")).unwrap(),
        }
    }

    fn update(&self, revision: u64) -> Instruction {
        let vector = &self.proofs[format!("update{revision}")];
        let writes = vector["writes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| RecordWriteData {
                member: field(&entry["member"]),
                lists: WriteRecordsIxData {
                    mask: entry["mask"].as_u64().unwrap().to_le_bytes(),
                    value: entry["value"].as_u64().unwrap().to_le_bytes(),
                },
                ..RecordWriteData::default()
            })
            .collect::<Vec<_>>();
        let apply = ApplyRecordsIxData {
            proof: proof(vector),
            new_root: field(&vector["root"]),
            new_next_index: u32::try_from(vector["nextIndex"].as_u64().unwrap())
                .unwrap()
                .to_le_bytes(),
        };
        self.instruction(
            tag::UPDATE,
            &[
                revision.to_le_bytes().as_slice(),
                &AuthorityWriteRecordsIxData {
                    writes: &writes,
                    apply: &apply,
                }
                .encode()
                .unwrap(),
            ]
            .concat(),
        )
    }

    fn verify(&self) -> Instruction {
        let vector = &self.proofs["reader"];
        let rows = vector["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(field)
            .collect::<Vec<_>>();
        let ix = VerifyPolicyIxData {
            revision: 1.into(),
            table: TableParts { rows: &rows }.encode().unwrap(),
            action: field(&vector["action"]),
            sender: right_align(&1001u64.to_be_bytes()),
            proof: proof(vector),
        };
        self.instruction(tag::VERIFY_POLICY, bytes_of(&ix))
    }

    fn instruction(&self, opcode: u8, data: &[u8]) -> Instruction {
        let mut accounts = vec![AccountMeta {
            pubkey: self.registry,
            is_signer: false,
            is_writable: opcode != tag::VERIFY_POLICY,
        }];
        if opcode != tag::VERIFY_POLICY {
            accounts.insert(
                0,
                AccountMeta {
                    pubkey: self.writer.pubkey(),
                    is_signer: true,
                    is_writable: opcode == tag::INITIALIZE,
                },
            );
        }
        if opcode == tag::INITIALIZE {
            accounts.push(AccountMeta::new_readonly(
                Address::new_from_array([0; 32]),
                false,
            ));
        }
        Instruction {
            program_id: PROGRAM,
            accounts,
            data: [&[opcode], data].concat(),
        }
    }

    fn send(&mut self, instruction: Instruction) -> Result<(), TransactionError> {
        self.svm.expire_blockhash();
        let mut signers: Vec<&dyn Signer> = vec![&self.reader];
        if instruction
            .accounts
            .iter()
            .any(|account| account.is_signer && account.pubkey == self.writer.pubkey())
        {
            signers.push(&self.writer);
        }
        let message = compile_message(
            &self.reader.pubkey(),
            &[instruction],
            self.svm.latest_blockhash(),
            ComputeBudgetConfig::new(1_400_000),
        )
        .unwrap();
        let transaction = sign_transaction(message, &signers).unwrap();
        self.svm
            .send_transaction(transaction)
            .map(|_| ())
            .map_err(|failed| failed.err)
    }
}

fn refusal(code: u32) -> Result<(), TransactionError> {
    Err(TransactionError::InstructionError(
        0,
        InstructionError::Custom(code),
    ))
}

fn field(value: &Value) -> [u8; 32] {
    hex::decode(value.as_str().unwrap().strip_prefix("0x").unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn proof(vector: &Value) -> CustomRingProof {
    let compressed =
        ProofCompressed::try_from(Proof::from_gnark_json(&vector["proof"].to_string()).unwrap())
            .unwrap();
    let commitment = compressed.commitment.unwrap();
    CustomRingProof {
        groth16: PlainGroth16Proof {
            proof_a: compressed.a,
            proof_b: compressed.compressed_b().unwrap(),
            proof_c: compressed.c,
        },
        commitment: commitment.commitment,
        commitment_pok: commitment.commitment_pok,
    }
}

#[test]
fn writer_updates_and_readers_verify_retained_roots() {
    let mut store = Store::new();
    store
        .svm
        .airdrop(&store.reader.pubkey(), 1_000_000_000)
        .unwrap();
    store
        .send(store.instruction(
            tag::INITIALIZE,
            bytes_of(&InitializeIxData {
                grace_slots: GRACE.to_le_bytes(),
            }),
        ))
        .unwrap();
    let mut wrong_writer = store.update(0);
    wrong_writer.accounts[0].pubkey = store.reader.pubkey();
    assert_eq!(
        store.send(wrong_writer),
        refusal(StoreError::Unauthorized as u32)
    );
    let mut forged = store.update(0);
    *forged.data.last_mut().unwrap() ^= 1;
    assert_eq!(
        store.send(forged),
        refusal(CustomRingError::ProofVerificationFailed as u32)
    );
    store.send(store.update(0)).unwrap();
    assert_eq!(
        store.send(store.update(0)),
        refusal(StoreError::RevisionChanged as u32)
    );
    for _ in 0..2 {
        store.reader = Keypair::new();
        store
            .svm
            .airdrop(&store.reader.pubkey(), 1_000_000_000)
            .unwrap();
        store.send(store.verify()).unwrap();
    }
    let mut wrong_action = store.verify();
    bytemuck::from_bytes_mut::<VerifyPolicyIxData>(&mut wrong_action.data[1..]).action[31] ^= 1;
    assert_eq!(
        store.send(wrong_action),
        refusal(CustomRingError::ProofVerificationFailed as u32)
    );

    let seeded = store.svm.clone();
    for mode in [tag::UPDATE, tag::UPDATE_IMMEDIATE] {
        store.svm = seeded.clone();
        let mut update = store.update(1);
        update.data[0] = mode;
        store.send(update).unwrap();
        if mode == tag::UPDATE {
            store.svm.warp_to_slot(GRACE - 1);
            store.send(store.verify()).unwrap();
            store.svm.warp_to_slot(GRACE);
        }
        assert_eq!(
            store.send(store.verify()),
            refusal(StoreError::RootExpired as u32)
        );
        store.send(store.update(2)).unwrap();
        assert_eq!(
            store.send(store.verify()),
            refusal(StoreError::RootExpired as u32)
        );
        let mut current = store.verify();
        bytemuck::from_bytes_mut::<VerifyPolicyIxData>(&mut current.data[1..]).revision = 3.into();
        store.send(current).unwrap();
    }
}
