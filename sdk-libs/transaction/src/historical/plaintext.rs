//! Scheme 1 recipient and scheme 2 sender bundle plaintexts.

use solana_address::Address;
use spr_keypair::{constants::PUBLIC_KEY_LEN, x25519::X25519_PUBKEY_LEN, PublicKey, X25519Pubkey};
use spr_transaction::{utxo::derive_transact_output_blinding, Data, Mint, TransactionError, Utxo};
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnonymousTransferRecipientPlaintext {
    pub committed: CommittedRecipientPlaintext,
    pub uncommitted: UncommittedRecipientPlaintext,
}

/// Unchecked until `AnonymousOutput::rebuilds` matches the output hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedRecipientPlaintext {
    pub owner_pubkey: PublicKey,
    pub mint: Address,
    pub amount: u64,
    pub blinding: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UncommittedRecipientPlaintext {
    /// Unauthenticated, the recipient pairs with whichever key the sender writes.
    pub sender_pubkey: X25519Pubkey,
    pub data: Data,
}

/// Published as a message, its change outputs carry no ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnonymousTransferSenderPlaintext {
    pub committed: CommittedSenderPlaintext,
    pub uncommitted: UncommittedSenderPlaintext,
}

/// Unchecked until `AnonymousOutput::rebuilds` matches each change hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedSenderPlaintext {
    pub owner_pubkey: PublicKey,
    pub spl_mint: Address,
    pub spl_amount: u64,
    pub sol_amount: u64,
    pub blinding_seed: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UncommittedSenderPlaintext {
    /// One per recipient output, in output order.
    pub recipient_viewing_pks: Vec<X25519Pubkey>,
    pub spl_data: Data,
    pub sol_data: Data,
}

impl AnonymousTransferRecipientPlaintext {
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        let Self {
            committed,
            uncommitted,
        } = self;
        uncommitted.data.validate()?;
        Ok(wincode::serialize(&RecipientWire {
            owner_pubkey: *committed.owner_pubkey.as_bytes(),
            mint: committed.mint,
            amount: committed.amount,
            sender_pubkey: *uncommitted.sender_pubkey.as_bytes(),
            blinding: committed.blinding,
            data: uncommitted.data.clone(),
        })?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        let wire: RecipientWire = wincode::deserialize_exact(bytes)?;
        wire.data.validate()?;
        Ok(Self {
            committed: CommittedRecipientPlaintext {
                owner_pubkey: PublicKey::from_bytes(wire.owner_pubkey)?,
                mint: wire.mint,
                amount: wire.amount,
                blinding: wire.blinding,
            },
            uncommitted: UncommittedRecipientPlaintext {
                sender_pubkey: X25519Pubkey::from_bytes(wire.sender_pubkey)?,
                data: wire.data,
            },
        })
    }

    /// A memo is the only record a recipient output carries, `asset` names `committed.mint`.
    pub fn into_utxo(self, asset: Mint) -> Result<Utxo, TransactionError> {
        let Self {
            committed,
            uncommitted,
        } = self;
        if uncommitted.data.ring_data().is_some() || uncommitted.data.utxo_data().is_some() {
            return Err(TransactionError::UnsupportedOutputData);
        }
        Ok(Utxo {
            owner: committed.owner_pubkey,
            asset,
            amount: committed.amount,
            blinding: committed.blinding,
            ring_program_id: None,
            data: uncommitted.data,
        })
    }
}

impl AnonymousTransferSenderPlaintext {
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        let Self {
            committed,
            uncommitted,
        } = self;
        uncommitted.spl_data.validate()?;
        uncommitted.sol_data.validate()?;
        Ok(wincode::serialize(&SenderWire {
            owner_pubkey: *committed.owner_pubkey.as_bytes(),
            spl_mint: committed.spl_mint,
            spl_amount: committed.spl_amount,
            sol_amount: committed.sol_amount,
            recipient_viewing_pks: uncommitted
                .recipient_viewing_pks
                .iter()
                .map(|key| *key.as_bytes())
                .collect(),
            blinding_seed: committed.blinding_seed,
            spl_data: uncommitted.spl_data.clone(),
            sol_data: uncommitted.sol_data.clone(),
        })?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        let wire: SenderWire = wincode::deserialize_exact(bytes)?;
        wire.spl_data.validate()?;
        wire.sol_data.validate()?;
        Ok(Self {
            committed: CommittedSenderPlaintext {
                owner_pubkey: PublicKey::from_bytes(wire.owner_pubkey)?,
                spl_mint: wire.spl_mint,
                spl_amount: wire.spl_amount,
                sol_amount: wire.sol_amount,
                blinding_seed: wire.blinding_seed,
            },
            uncommitted: UncommittedSenderPlaintext {
                recipient_viewing_pks: wire
                    .recipient_viewing_pks
                    .into_iter()
                    .map(X25519Pubkey::from_bytes)
                    .collect::<Result<_, _>>()?,
                spl_data: wire.spl_data,
                sol_data: wire.sol_data,
            },
        })
    }

    /// A zero amount marks a change output absent, the SOL change at slot 1 only after an SPL change.
    pub fn into_utxos(
        self,
        first_nullifier: &[u8; 32],
        spl_asset: Mint,
    ) -> Result<Vec<Utxo>, TransactionError> {
        let Self {
            committed,
            uncommitted,
        } = self;
        if (committed.spl_amount == 0 && !uncommitted.spl_data.is_empty())
            || (committed.sol_amount == 0 && !uncommitted.sol_data.is_empty())
        {
            return Err(TransactionError::DataWithoutOutput);
        }
        let spl = (committed.spl_amount > 0).then_some((
            spl_asset,
            committed.spl_amount,
            uncommitted.spl_data,
        ));
        let sol = (committed.sol_amount > 0).then_some((
            Mint::SOL,
            committed.sol_amount,
            uncommitted.sol_data,
        ));
        let mut utxos = Vec::new();
        for (slot, (asset, amount, data)) in (0u32..).zip(spl.into_iter().chain(sol)) {
            if data.ring_data().is_some() {
                return Err(TransactionError::MissingRingProgramId);
            }
            utxos.push(Utxo {
                owner: committed.owner_pubkey,
                asset,
                amount,
                blinding: derive_transact_output_blinding(
                    first_nullifier,
                    &committed.blinding_seed,
                    slot,
                )?,
                ring_program_id: None,
                data,
            });
        }
        Ok(utxos)
    }
}

#[derive(SchemaWrite, SchemaRead)]
struct RecipientWire {
    owner_pubkey: [u8; PUBLIC_KEY_LEN],
    mint: Address,
    amount: u64,
    sender_pubkey: [u8; X25519_PUBKEY_LEN],
    blinding: [u8; 32],
    data: Data,
}

#[derive(SchemaWrite, SchemaRead)]
struct SenderWire {
    owner_pubkey: [u8; PUBLIC_KEY_LEN],
    spl_mint: Address,
    spl_amount: u64,
    sol_amount: u64,
    #[wincode(with = "containers::Vec<[u8; X25519_PUBKEY_LEN], FixIntLen<u8>>")]
    recipient_viewing_pks: Vec<[u8; X25519_PUBKEY_LEN]>,
    blinding_seed: [u8; 32],
    spl_data: Data,
    sol_data: Data,
}
