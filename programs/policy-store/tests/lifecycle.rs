use bytemuck::bytes_of;
use custom_ring_interface::{
    ApplyRecordsIxData, AuthorityWriteRecordsIxData, CustomRingError, CustomRingProof,
    PlainGroth16Proof, RecordWriteData, WriteRecordsIxData, ROOT_HISTORY,
};
use litesvm::LiteSVM;
use policy_store_program::{
    InitializeIxData, Instruction as Tag, Registry, StoreError, VerifyPolicyIxData,
    REGISTRY_PDA_SEED,
};
use serde_json::Value;
use solana_address::Address;
use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_keypair::{Keypair, Signer};
use solana_transaction_error::TransactionError;
use zolana_client::{
    compile_message,
    prover::{Proof, ProofCompressed},
    sign_transaction, ComputeBudgetConfig,
};
use zolana_hasher::primitives::right_align;
use zolana_ring_policy::{ListId, ListSet, Rule, RuleTable, Subject};

const PROGRAM: Address = Address::new_from_array([0x53; 32]);
const GRACE: u64 = 10;

struct Fixtures {
    writer: Address,
    registry: Address,
    proofs: Value,
}

struct Chain<'a> {
    svm: LiteSVM,
    signers: [&'a Keypair; 3],
    payer: usize,
}

#[test]
fn writer_updates_and_readers_verify_retained_roots() {
    let mut svm = LiteSVM::new();
    let program = std::env::var_os("SBF_OUT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy").into())
        .join("policy_store_program.so");
    svm.add_program(PROGRAM, &std::fs::read(program).unwrap())
        .unwrap();
    let writer = Keypair::new_from_array([9; 32]);
    let readers = [Keypair::new(), Keypair::new()];
    for signer in [&writer, &readers[0], &readers[1]] {
        svm.airdrop(&signer.pubkey(), 1_000_000_000).unwrap();
    }
    let mut chain = Chain {
        svm,
        signers: [&writer, &readers[0], &readers[1]],
        payer: 0,
    };
    let fixture = Fixtures::new(writer.pubkey());
    chain.svm.warp_to_slot(100);
    chain.send(fixture.initialize()).unwrap();
    let initial = chain.svm.get_account(&fixture.registry).unwrap();

    let mut wrong_writer = fixture.update(0);
    wrong_writer.accounts[0].pubkey = readers[0].pubkey();
    assert_eq!(
        chain.send(wrong_writer),
        refusal(StoreError::Unauthorized as u32)
    );
    let mut forged = fixture.update(0);
    *forged.data.last_mut().unwrap() ^= 1;
    assert!(chain.send(forged).is_err());
    assert_eq!(chain.svm.get_account(&fixture.registry).unwrap(), initial);

    let mut invalid_delta = Fixtures::new(writer.pubkey());
    invalid_delta.proofs["update0"]["writes"][0]["value"] = Value::from(4);
    assert_eq!(
        chain.send(invalid_delta.update(0)),
        refusal(CustomRingError::ValueOutsideMask as u32)
    );

    chain.send(fixture.update(0)).unwrap();
    let seeded = chain.svm.get_account(&fixture.registry).unwrap();
    for i in 0..readers.len() {
        chain.payer = i + 1;
        chain.send(fixture.verify(i)).unwrap();
    }
    for change in 0..3 {
        let mut invalid = fixture.verify(0);
        let ix = bytemuck::from_bytes_mut::<VerifyPolicyIxData>(&mut invalid.data[1..]);
        match change {
            0 => ix.action[31] ^= 1,
            1 => ix.sender[31] ^= 1,
            _ => ix.table = RuleTable::builder().build().encode(),
        }
        assert_eq!(
            chain.send(invalid),
            refusal(CustomRingError::ProofVerificationFailed as u32)
        );
    }
    assert_eq!(chain.svm.get_account(&fixture.registry).unwrap(), seeded);
    assert_eq!(
        chain.send(fixture.update(0)),
        refusal(StoreError::RevisionChanged as u32)
    );

    let other = Fixtures::new(readers[0].pubkey());
    chain.send(other.initialize()).unwrap();
    assert_eq!(
        chain.send(other.update(0)),
        refusal(CustomRingError::ProofVerificationFailed as u32)
    );

    chain.svm.warp_to_slot(101);
    chain.send(fixture.update(1)).unwrap();
    let before_last = chain.svm.get_account(&fixture.registry).unwrap();
    chain.svm.warp_to_slot(110);
    for i in 0..readers.len() {
        chain.payer = i + 1;
        chain.send(fixture.verify(i)).unwrap();
    }
    chain.svm.warp_to_slot(111);
    assert_eq!(
        chain.send(fixture.verify(0)),
        refusal(StoreError::RootExpired as u32)
    );
    chain.send(fixture.update(2)).unwrap();
    assert_eq!(
        chain.send(fixture.verify(0)),
        refusal(StoreError::RootExpired as u32)
    );
    let mut current = fixture.verify(0);
    bytemuck::from_bytes_mut::<VerifyPolicyIxData>(&mut current.data[1..]).revision = 3.into();
    chain.send(current).unwrap();

    let mut full = before_last;
    let state = bytemuck::from_bytes_mut::<Registry>(&mut full.data);
    let next = (usize::from(state.cursor) + 1) % ROOT_HISTORY;
    state.roots[next] = state.roots[0];
    state.roots[next].expires_at = 112u64.to_le_bytes();
    chain
        .svm
        .set_account(fixture.registry, full.clone())
        .unwrap();
    assert_eq!(
        chain.send(fixture.update(2)),
        refusal(StoreError::HistoryFull as u32)
    );
    assert_eq!(chain.svm.get_account(&fixture.registry).unwrap(), full);
    chain.svm.warp_to_slot(112);
    chain.send(fixture.update(2)).unwrap();
    chain.svm.set_account(fixture.registry, seeded).unwrap();
    let mut immediate = fixture.update(1);
    immediate.data[0] = Tag::UpdateImmediate as u8;
    chain.send(immediate).unwrap();
    let after = chain.svm.get_account(&fixture.registry).unwrap();
    let state = bytemuck::from_bytes::<Registry>(&after.data);
    assert_eq!(state.current().revision.value(), 2);
    assert_eq!(
        state
            .roots
            .iter()
            .filter(|root| root.hash != [0; 32])
            .count(),
        1
    );
    assert_eq!(
        chain.send(fixture.verify(0)),
        refusal(StoreError::RootExpired as u32)
    );
    chain.send(fixture.update(2)).unwrap();
    assert_eq!(
        chain.send(fixture.verify(0)),
        refusal(StoreError::RootExpired as u32)
    );
    let after = chain.svm.get_account(&fixture.registry).unwrap();
    assert_eq!(
        bytemuck::from_bytes::<Registry>(&after.data)
            .current()
            .revision
            .value(),
        3
    );
}

impl Fixtures {
    fn new(writer: Address) -> Self {
        Self {
            writer,
            registry: Address::find_program_address(
                &[REGISTRY_PDA_SEED, writer.as_ref()],
                &PROGRAM,
            )
            .0,
            proofs: serde_json::from_str(include_str!("proofs.json")).unwrap(),
        }
    }

    fn initialize(&self) -> Instruction {
        Instruction {
            program_id: PROGRAM,
            accounts: vec![
                AccountMeta::new(self.writer, true),
                AccountMeta::new(self.registry, false),
                AccountMeta::new_readonly(Address::new_from_array([0; 32]), false),
            ],
            data: [
                &[Tag::Initialize as u8],
                bytes_of(&InitializeIxData {
                    grace_slots: GRACE.to_le_bytes(),
                }),
            ]
            .concat(),
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
        Instruction {
            program_id: PROGRAM,
            accounts: vec![
                AccountMeta::new_readonly(self.writer, true),
                AccountMeta::new(self.registry, false),
            ],
            data: [
                &[Tag::Update as u8],
                revision.to_le_bytes().as_slice(),
                &AuthorityWriteRecordsIxData {
                    writes: &writes,
                    apply: &apply,
                }
                .encode()
                .unwrap(),
            ]
            .concat(),
        }
    }

    fn verify(&self, reader: usize) -> Instruction {
        assert_eq!(
            hex::encode(self.registry),
            self.proofs["registry"].as_str().unwrap()
        );
        let vector = &self.proofs[format!("reader{reader}")];
        let ix = VerifyPolicyIxData {
            revision: 1.into(),
            table: RuleTable::builder()
                .rule(Rule::require_any(
                    Subject::OutputOwner,
                    ListSet::single(ListId::Allow),
                ))
                .rule(Rule::forbid_all(
                    Subject::Sender,
                    ListSet::single(ListId::Frozen),
                ))
                .build()
                .encode(),
            action: field(&vector["action"]),
            sender: right_align(&1001u64.to_be_bytes()),
            proof: proof(vector),
        };
        Instruction {
            program_id: PROGRAM,
            accounts: vec![AccountMeta::new_readonly(self.registry, false)],
            data: [&[Tag::VerifyPolicy as u8], bytes_of(&ix)].concat(),
        }
    }
}

impl Chain<'_> {
    fn send(&mut self, instruction: Instruction) -> Result<(), TransactionError> {
        self.svm.expire_blockhash();
        let message = compile_message(
            &self.signers[self.payer].pubkey(),
            &[instruction],
            self.svm.latest_blockhash(),
            ComputeBudgetConfig::new(1_400_000),
        )
        .unwrap();
        let keys =
            &message.static_account_keys()[..usize::from(message.header().num_required_signatures)];
        let signers = keys
            .iter()
            .map(|key| {
                *self
                    .signers
                    .iter()
                    .find(|signer| signer.pubkey() == *key)
                    .unwrap() as &dyn Signer
            })
            .collect::<Vec<_>>();
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
