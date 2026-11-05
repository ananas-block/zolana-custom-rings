use super::*;
use custom_ring_interface::key_catalog::RING_KEYS;
use custom_ring_interface::{
    audit_stream::{AuditRecord, OpeningRecord, RecordKind},
    domain::deposit_blinding,
    key_catalog::RingCircuit,
    ring_deposit_assets, CredentialRead, CredentialRootSelection, CredentialRoots,
    CredentialStateRoot, CredentialTreeRead, DepositContext, DepositPrefix, DepositPublicInput,
    DepositSubjects, RingDepositAuditCapsule, PROVING_KEY_SHA256S,
};
use custom_ring_sdk::secret_json_body;
use solana_instruction::AccountMeta;
use spr_client::{
    prover::{verify_proof_statement, ExpectedProvingKey, ProveRequest},
    ClientError, ProofCompressed,
};
use spr_hasher::primitives::{pack_be, right_align};
use spr_interface::instruction::instruction_data::deposit::RingDepositIxDataRef;
use spr_interface::N_PUBLIC_SLOTS;
use spr_program::instruction::{RingAssetDeposit, RingDeposit as SppRingDeposit};
use spr_transaction::owner_utxo_hash;
use zeroize::Zeroizing;
use zolana_ring_client::{seal_deposits, CredentialOpening, CredentialReads};
use zolana_ring_member_registry::RecordPool;
use zolana_ring_policy::{EncodedRuleTable, SourceMap};
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

fn proof_paths<'a>(
    paths: impl Iterator<Item = (u64, &'a [[[u8; 32]; 3]])>,
) -> Vec<serde_json::Value> {
    paths
        .map(|(index, siblings)| {
            serde_json::json!({
                "index": index,
                "siblings": siblings
                    .iter()
                    .map(|level| level.iter().map(field).collect::<Vec<_>>())
                    .collect::<Vec<_>>(),
            })
        })
        .collect()
}

struct DepositCredentialRead<'a> {
    ring: CustomRing,
    member: [u8; 32],
    capacity: usize,
    env: &'a TestEnv,
}

struct DepositCredentials {
    read: CredentialRead,
    roots: CredentialRoots,
    trees: Vec<Address>,
    request: serde_json::Value,
}

impl DepositCredentialRead<'_> {
    fn read(self) -> Result<DepositCredentials> {
        use spr_client::rpc::{NULLIFIER_TREE_HEIGHT, STATE_TREE_HEIGHT};
        let snapshot = self.env.client.block_on(
            CredentialReads {
                ring: self.ring.program_id(),
                members: &[self.member],
            }
            .read(self.env.client.as_async(), self.env.client.as_async()),
        )?;
        let address_tree = spr_interface::pda::tree(spr_program::ADDRESS_TREE_ID);
        let mut account = fetch_account(self.env.client.rpc(), &address_tree)?;
        let checkpoint = CredentialTreeRead {
            address: &address_tree,
            owner: &account.owner,
            data: &mut account.data,
        }
        .checkpoint(snapshot.address_root.root_index)?;
        ensure!(*checkpoint.root() == snapshot.address_root.root);
        ensure!(checkpoint.sequence() == snapshot.address_root.sequence);
        let state_roots = snapshot
            .state_roots
            .iter()
            .map(|tree| CredentialStateRoot {
                tree_id: tree.tree_id,
                root: tree.root.root,
            })
            .collect::<Vec<_>>();
        let roots = CredentialRootSelection {
            ring_program: &self.ring.program_id(),
            address_checkpoint: checkpoint,
            state_roots: &state_roots,
            capacity: self.capacity,
        }
        .roots()?;
        let read = CredentialRead::new(
            snapshot.address_root.root_index,
            &snapshot
                .state_roots
                .iter()
                .map(|tree| tree.root.root_index)
                .collect::<Vec<_>>(),
        )?;
        let Some(CredentialOpening::Present(present)) = snapshot.openings.first() else {
            anyhow::bail!("deposit owner has no credential")
        };
        let tree_slot = state_roots
            .iter()
            .position(|tree| tree.tree_id == present.tree_id)
            .context("credential state tree")?;
        let [_, _, member, nullifier_pk, list_tag, aud0, aud1, eph0, eph1, ct_hash] = present
            .credential
            .elements(custom_ring_interface::domain::CREDENTIAL_STATE)?;
        let padding = serde_json::json!({
            "present": false,
            "member": field([0; 32]), "nullifierPk": field([0; 32]),
            "listTag": field([0; 32]), "aud": vec![field([0; 32]); 2],
            "eph": vec![field([0; 32]); 2], "ctHash": field([0; 32]),
            "blinding": field([0; 32]), "treeSlot": 0, "stateIndex": 0,
            "statePath": vec![field([0; 32]); STATE_TREE_HEIGHT],
            "lowValue": field([0; 32]), "lowNext": field([0; 32]), "lowIndex": 0,
            "lowPath": vec![field([0; 32]); NULLIFIER_TREE_HEIGHT],
        });
        let mut openings = vec![padding; self.capacity];
        openings[0] = serde_json::json!({
            "present": true,
            "member": field(member), "nullifierPk": field(nullifier_pk),
            "listTag": field(list_tag), "aud": [field(aud0), field(aud1)],
            "eph": [field(eph0), field(eph1)], "ctHash": field(ct_hash),
            "blinding": field(present.blinding), "treeSlot": tree_slot,
            "stateIndex": present.leaf_index,
            "statePath": present.path.iter().map(field).collect::<Vec<_>>(),
            "lowValue": field([0; 32]), "lowNext": field([0; 32]), "lowIndex": 0,
            "lowPath": vec![field([0; 32]); NULLIFIER_TREE_HEIGHT],
        });
        let request = serde_json::json!({
            "credentialOwner": field(roots.owner_hash()),
            "addressRoot": field(roots.address_root()),
            "stateRoots": roots.state_roots().iter().map(|root| serde_json::json!({
                "treeId": root.tree_id, "root": field(root.root),
            })).collect::<Vec<_>>(),
            "credentialOpenings": openings,
            "rowEntries": [], "outputEntries": vec![0; self.capacity],
        });
        let trees = std::iter::once(address_tree)
            .chain(
                state_roots
                    .iter()
                    .map(|root| spr_interface::pda::tree(root.tree_id)),
            )
            .collect();
        Ok(DepositCredentials {
            read,
            roots,
            trees,
            request,
        })
    }
}

/// A pool no gate reads.
fn unopened_pool(name: &str, width: usize) -> Result<serde_json::Map<String, serde_json::Value>> {
    let pool = RecordPool::unopened(width)?;
    let records = pool
        .records
        .iter()
        .map(|record| {
            serde_json::json!({
                "member": field(record.member),
                "next": field(record.next),
                "lists": record.lists,
                "mintPolicy": field(record.mint_policy.field()),
                "withdrawalThreshold": field(right_align(&record.mint_policy.withdrawal_threshold.to_be_bytes())),
                "assetLimits": record.mint_policy.limits.fields().iter().map(field).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    let mut out = serde_json::Map::new();
    out.insert(format!("{name}Records"), records.into());
    out.insert(
        format!("{name}Proof"),
        serde_json::json!({
            "canopy": pool.proof.canopy.iter().map(field).collect::<Vec<_>>(),
            "paths": proof_paths(
                pool.proof.paths.iter().map(|path| (path.index, path.siblings.as_slice())),
            ),
        }),
    );
    out.insert(
        format!("{name}Subjects"),
        vec![serde_json::json!({"member": field([0; 32]), "recordIndex": 0}); width].into(),
    );
    Ok(out)
}

const AMOUNT: u64 = 10_000_000;

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
    enroll_actors(&env, ring)?;
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
                Ok(OpeningRecord {
                    record: AuditRecord {
                        kind: RecordKind::Ring,
                        amount: AMOUNT,
                        owner_key,
                        mint: SOL_MINT.to_bytes(),
                        nullifier_pk: address.nullifier_pubkey,
                    },
                    secret: deposit_blinding(secret)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let encryption = seal_deposits(&openings, &auditor.pubkey())?;
        let deposits = openings
            .iter()
            .enumerate()
            .map(|(slot, opening)| {
                let mut encrypted = RingDepositPlaintext {
                    blinding: opening.secret,
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
                    owner_utxo_hash: owner_utxo_hash(&owner_hash, &opening.secret)?,
                    amount: AMOUNT,
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
        let credentials = DepositCredentialRead {
            ring,
            member: owner_identity,
            capacity,
            env: &env,
        }
        .read()?;
        let statement = DepositPublicInput {
            context_hash: &context,
            owner_utxo_hashes: &commitments,
            ciphertexts: &encryption.ciphertexts,
            assets: &assets,
            auditor_pk: auditor.pubkey().as_bytes(),
            eph_pk: encryption.ephemeral_pk.as_bytes(),
            ring_id: &ring.ring_id()?,
            credentials: &credentials.roots,
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
        let width = DepositSubjects::pool_width(count);
        let sources = SourceMap::default();
        let rules = EncodedRuleTable::default();
        let mut body = serde_json::json!({
            "circuitType": key.name,
            "publicInputHash": field(statement),
            "contextHash": field(context),
            "count": count,
            "ownerPkHashes": vec![field(owner_identity); capacity],
            "ownerKeys": vec![field(owner_key); capacity],
            "nullifierPks": vec![field(address.nullifier_pubkey); capacity],
            "blindingSecrets": secrets.iter().map(|secret| field(secret.as_slice())).collect::<Vec<_>>(),
            "ephSk": field(encryption.ephemeral_sk.as_slice()),
            "auditorPk": field(auditor.pubkey().u()),
            "assets": assets.iter().map(|asset| field(asset.asset)).collect::<Vec<_>>(),
            "amounts": assets.iter().map(|asset| field(right_align(&asset.amount.to_be_bytes()))).collect::<Vec<_>>(),
            "mintChunks": vec![pack_be::<32, 2>(&SOL_MINT.to_bytes()).map(field); capacity],
            "withdrawalCount": 0,
            "withdrawalHash": field([0; 32]),
            "withdrawals": [],
            "policyHash": field([0; 32]),
            "ringId": field(ring.ring_id()?),
            "ownRoot": field([0; 32]),
            "curatorRoot": field([0; 32]),
            "publicAssets": vec![field([0; 32]); N_PUBLIC_SLOTS],
            "publicAmounts": vec![field([0; 32]); N_PUBLIC_SLOTS],
            "publicGross": vec![field([0; 32]); N_PUBLIC_SLOTS],
            "sources": sources.slots().iter().map(|slot| serde_json::json!({
                "listId": slot.list_id,
                "registry": field(slot.registry),
            })).collect::<Vec<_>>(),
            "salted": sources.salted().bits(),
            "policyLen": rules.rule_count,
            "rules": rules.rules.iter().map(field).collect::<Vec<_>>(),
            "senderEntries": [],
            "ownerEntries": vec![serde_json::json!({
                "own": 0,
                "curator": [0],
                "credential": 0,
                "listSalt": field([0; 32]),
                "ownSalted": 0,
                "curatorSalted": [0],
            }); capacity],
            "assetEntries": vec![serde_json::json!({"own": 0, "curator": [0]}); capacity],
            "publicAssetEntries": [],
        });
        let fields = body.as_object_mut().context("a request object")?;
        for section in [
            credentials
                .request
                .clone()
                .as_object()
                .cloned()
                .context("a request section")?,
            unopened_pool("own", width)?,
            unopened_pool("curator", width)?,
        ] {
            fields.extend(section);
        }
        let request = BatchRequest {
            key: ExpectedProvingKey { name: file, sha256 },
            body,
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
            key_capacity: count,
            proof: custom_ring_interface::CustomRingProof {
                groth16: custom_ring_interface::PlainGroth16Proof {
                    proof_a: compressed.a,
                    proof_b: compressed.compressed_b()?,
                    proof_c: compressed.c,
                },
                commitment: commitment.commitment,
                commitment_pok: commitment.commitment_pok,
            },
            credential_read: credentials.read,
            own_revision: Default::default(),
            curator_revision: Default::default(),
        };
        let prefix_bytes = prefix.encode()?;
        let wrap = |mut instruction: Instruction| {
            instruction.data = [prefix_bytes.as_slice(), &instruction.data].concat();
            instruction.accounts.splice(
                0..0,
                std::iter::once(AccountMeta::new_readonly(ring.policy_pda(), false)).chain(
                    credentials
                        .trees
                        .iter()
                        .map(|tree| AccountMeta::new_readonly(*tree, false)),
                ),
            );
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

#[test]
fn an_sdk_batch_settles_at_keys_four_and_eight() -> Result<()> {
    let env = setup()?;
    let ring = CustomRing::new(custom_ring_program_id()?);
    RegisterRing {
        ring,
        payer: &env.payer,
        auditor_pubkey: X25519Keypair::new().pubkey(),
        tier: Tier::AuditOnly,
    }
    .send(&env.client)?;
    enroll_actors(&env, ring)?;
    let recipients = [
        env.sender.keypair.shielded_address()?,
        env.recipient.keypair.shielded_address()?,
    ];
    let client = env.client.ring_client();
    for (notes, key) in [(3_usize, 4_u8), (5, 8)] {
        let batch = custom_ring_sdk::RingDepositBatch {
            ring,
            payer: &env.payer,
            tree: env.tree,
            outputs: (0..notes)
                .map(|slot| custom_ring_sdk::DepositOutput {
                    recipient: DepositRecipient::Confidential(recipients[slot % 2]),
                    asset: DepositAsset::Sol,
                    amount: AMOUNT,
                    list_salt: None,
                })
                .collect(),
            cosigner: None,
        };
        let prepared = env.run(batch.prepare(client.zolana()))?;
        let instruction = env.run(prepared.prove(client))?;
        let prefix = DepositPrefix::parse(&instruction.data[..DepositPrefix::SIZE])?;
        ensure!(
            prefix.key_capacity == key,
            "{notes} notes took key {}",
            prefix.key_capacity
        );
        let tree_before = fetch_account(env.client.rpc(), &env.tree)?;
        send(env.client.rpc(), &env.payer, &[instruction])?;
        ensure!(
            fetch_account(env.client.rpc(), &env.tree)?.data != tree_before.data,
            "the key {key} batch did not change the tree"
        );
    }
    Ok(())
}
