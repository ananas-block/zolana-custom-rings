use super::*;
use custom_ring_interface::key_catalog::RING_KEYS;
use custom_ring_interface::{
    domain::deposit_blinding, key_catalog::RingCircuit, ring_deposit_assets, DepositContext,
    DepositPrefix, DepositPublicInput, RingDepositAuditCapsule, PROVING_KEY_SHA256S,
};
use custom_ring_sdk::secret_json_body;
use solana_instruction::AccountMeta;
use spr_client::{
    prover::{verify_proof_statement, ExpectedProvingKey, ProveRequest},
    ClientError, ProofCompressed,
};
use spr_hasher::primitives::right_align;
use spr_interface::instruction::instruction_data::deposit::RingDepositIxDataRef;
use spr_program::instruction::{RingAssetDeposit, RingDeposit as SppRingDeposit};
use spr_transaction::owner_utxo_hash;
use zeroize::Zeroizing;
use zolana_ring_client::{seal_deposits, DepositOpening};
use zolana_ring_transaction::RingDepositPlaintext;

struct BatchRequest {
    body: serde_json::Value,
    key: ExpectedProvingKey,
}

impl ProveRequest for BatchRequest {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        secret_json_body(&self.body)
    }

    fn proving_key(&self) -> Result<ExpectedProvingKey, ClientError> {
        Ok(self.key.clone())
    }
}

fn field(bytes: impl AsRef<[u8]>) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[test]
fn every_batch_deposit_capacity_settles_and_refuses_a_changed_amount() -> Result<()> {
    let env = setup()?;
    let ring = CustomRing::new(custom_ring_program_id()?);
    let auditor = X25519Keypair::new();
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: auditor.pubkey(),
        tier: Tier::AuditOnly,
    }
    .send(&env.client)?;
    let address = env.sender.keypair.shielded_address()?;
    let owner_key = address.signing_pubkey.confidential_view_tag()?;
    let owner_identity = address.signing_pubkey.owner_proof_input_hash()?;
    let owner_hash = address.owner_hash()?;
    let rpc = env.client.rpc();
    let prover = AsyncProverClient::new(prover_url());

    for count in [1_u8, 2, 4, 8] {
        let capacity = usize::from(count);
        let secrets: Vec<_> = (0..capacity)
            .map(|_| Zeroizing::new(random_blinding()))
            .collect();
        let openings = secrets
            .iter()
            .map(|secret| {
                Ok(DepositOpening {
                    owner_hash,
                    blinding: Zeroizing::new(deposit_blinding(secret)?),
                    owner_key,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let encryption = seal_deposits(&openings, &auditor.pubkey())?;
        let deposits = openings
            .iter()
            .enumerate()
            .map(|(slot, opening)| {
                let mut encrypted = RingDepositPlaintext {
                    blinding: *opening.blinding,
                    utxo_data: None,
                    memo: None,
                    ring_data: Vec::new(),
                }
                .encrypt(&address.viewing_pubkey)?;
                encrypted.ciphertext = RingDepositAuditCapsule {
                    slot_index: u8::try_from(slot)?,
                    eph_pk: encryption.ephemeral_pk.as_bytes(),
                    ciphertext: &encryption.ciphertexts[slot],
                    recipient_ciphertext: &encrypted.ciphertext,
                }
                .encode();
                Ok(RingAssetDeposit {
                    asset: DepositAsset::Sol,
                    view_tag: address.viewing_pubkey.u(),
                    owner_utxo_hash: owner_utxo_hash(&owner_hash, &opening.blinding)?,
                    amount: 10_000_000,
                    ring_data_hash: [0; 32],
                    encrypted,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let builder = SppRingDeposit {
            tree: env.tree,
            depositor: env.payer.pubkey(),
            ring_program_id: ring.program_id(),
            deposits,
        };
        let spp = builder.clone().instruction()?;
        let context = DepositContext {
            program_id: ring.program_id().as_array(),
            tree: env.tree.as_array(),
            spp_data: &spp.data,
        }
        .hash()?;
        let parsed = RingDepositIxDataRef::from_bytes(&spp.data[1..])?;
        let assets = ring_deposit_assets(&parsed, |index| {
            spp.accounts.get(index).map(|meta| meta.pubkey.to_bytes())
        })?;
        let commitments: Vec<_> = builder
            .deposits
            .iter()
            .map(|deposit| deposit.owner_utxo_hash)
            .collect();
        let statement = DepositPublicInput {
            context_hash: &context,
            anonymous: false,
            owner_utxo_hashes: &commitments,
            ciphertexts: &encryption.ciphertexts,
            assets: &assets,
            auditor_pk: auditor.pubkey().as_bytes(),
            eph_pk: encryption.ephemeral_pk.as_bytes(),
            registry: None,
        }
        .hash()?;
        let circuit = RingCircuit::deposit(count);
        let key = RING_KEYS
            .iter()
            .find(|key| key.circuit == circuit)
            .context("deposit key")?;
        let file = key.file_name();
        let sha256 = PROVING_KEY_SHA256S
            .iter()
            .find(|(name, _)| *name == file)
            .context("deposit checksum")?
            .1;
        let request = BatchRequest {
            key: ExpectedProvingKey { name: file, sha256 },
            body: serde_json::json!({
                "circuitType": key.name,
                "publicInputHash": field(statement),
                "contextHash": field(context),
                "count": count,
                "anonymous": false,
                "ownerPkHashes": vec![field(owner_identity); capacity],
                "ownerKeys": vec![field(owner_key); capacity],
                "nullifierPks": vec![field(address.nullifier_pubkey); capacity],
                "blindingSecrets": secrets.iter().map(|secret| field(secret.as_slice())).collect::<Vec<_>>(),
                "ctHashes": vec![field([0; 32]); capacity],
                "members": vec![serde_json::Value::Null; capacity],
                "ephSk": field(encryption.ephemeral_sk.as_slice()),
                "auditorPk": field(auditor.pubkey().u()),
                "keyEscrow": false,
                "memberRegistryRoot": field([0; 32]),
                "curatorRoot": field([0; 32]),
                "policyHash": field([0; 32]),
                "assets": assets.iter().map(|asset| field(asset.asset)).collect::<Vec<_>>(),
                "amounts": assets.iter().map(|asset| field(right_align(&asset.amount.to_be_bytes()))).collect::<Vec<_>>(),
                "assetRecords": vec![serde_json::Value::Null; capacity],
                "curatorAssetRecords": vec![serde_json::Value::Null; capacity],
            }),
        };
        let proof = env.run(async { Ok(prover.prove(&request).await?) })?;
        verify_proof_statement(
            &proof,
            statement,
            custom_ring_interface::verifying_key(circuit).context("deposit verifier")?,
        )?;
        let compressed = ProofCompressed::try_from(proof)?;
        let commitment = compressed.commitment.context("deposit commitment")?;
        let prefix = DepositPrefix {
            tag: custom_ring_interface::tag::DEPOSIT,
            proof: custom_ring_interface::CustomRingProof {
                groth16: custom_ring_interface::PlainGroth16Proof {
                    proof_a: compressed.a,
                    proof_b: compressed.compressed_b()?,
                    proof_c: compressed.c,
                },
                commitment: commitment.commitment,
                commitment_pok: commitment.commitment_pok,
            },
            own_revision: Default::default(),
            curator_revision: Default::default(),
        };
        let wrap = |mut instruction: Instruction| {
            instruction.data = [bytemuck::bytes_of(&prefix), &instruction.data].concat();
            instruction
                .accounts
                .insert(0, AccountMeta::new_readonly(ring.policy_pda(), false));
            instruction
        };
        let mut altered = builder.clone();
        altered.deposits[0].amount += 1;
        let tree_before = fetch_account(rpc, &env.tree)?;
        let error = send_expecting_rejection(rpc, &env.payer, wrap(altered.instruction()?))?;
        Rejection::custom(CustomRingError::ProofVerificationFailed as u32)
            .at(0)
            .assert_client(&error);
        assert_account_unchanged(rpc, &env.tree, &tree_before)?;
        let instruction = wrap(spp);
        let budget = ComputeBudgetConfig::new(compute_unit_limit(InstructionTag::Transfer));
        let size = spr_client::transaction_size(
            &env.payer.pubkey(),
            std::slice::from_ref(&instruction),
            budget,
        )?;
        ensure!(
            size.bytes <= MAX_TRANSACTION_SIZE,
            "deposit frame exceeds the transaction limit"
        );
        let signature = send(rpc, &env.payer, &[instruction])?;
        let units = assert_transaction_compute_units(
            rpc,
            &signature,
            &format!("deposit capacity {count}"),
            u64::from(budget.cu_limit),
        )?;
        ensure!(
            fetch_account(rpc, &env.tree)?.data != tree_before.data,
            "deposit did not change the tree"
        );
        println!(
            "deposit capacity {count} settled {signature}, measured {} bytes and {units} CU, and refused the changed amount",
            size.bytes
        );
    }
    Ok(())
}
