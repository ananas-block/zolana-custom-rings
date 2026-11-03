//! One document holds a wallet's scan progress and everything it covers, one write stores both.

use std::{
    collections::{BTreeSet, HashSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use solana_address::Address;
use spr_keypair::{x25519::X25519_PUBKEY_LEN, X25519Pubkey};
use spr_transaction::{DecryptionResult, Mint, WalletUtxo};
use zolana_ring_transaction::RingAssets;

use crate::{AnonymousError, AnonymousScan, ViewingHistory, VIEWING_HISTORY_VERSION};

pub const ANONYMOUS_WALLET_VERSION: u32 = 1;

/// Notes stay listed once spent, their nullifiers mark them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnonymousWallet {
    history: ViewingHistory,
    notes: Vec<WalletUtxo>,
    spent_nullifiers: BTreeSet<[u8; 32]>,
    pending: Vec<PendingNote>,
    claims: Vec<PendingClaim>,
}

/// Rebuilt under a mint the registry does not name, only [`AnonymousWallet::resolve_pending`] makes it spendable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PendingNote(WalletUtxo);

impl PendingNote {
    pub(crate) const fn new(note: WalletUtxo) -> Self {
        Self(note)
    }

    pub fn mint(&self) -> Address {
        self.0.utxo.asset.asset
    }

    pub fn amount(&self) -> u64 {
        self.0.utxo.amount
    }

    pub fn utxo_hash(&self) -> [u8; 32] {
        self.0.utxo_hash
    }

    fn into_registered(self, asset: Mint) -> WalletUtxo {
        let mut note = self.0;
        note.utxo.asset = asset;
        note
    }
}

/// A reply read from a note, what a sender wrote about itself and nothing the proof binds.
#[derive(Clone, PartialEq, Eq)]
pub struct PendingClaim {
    pub utxo_hash: [u8; 32],
    pub claimed_viewing_key: X25519Pubkey,
    pub claimed_owner_key: [u8; 32],
    pub claimed_nullifier_pk: [u8; 32],
}

impl fmt::Debug for PendingClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingClaim")
            .field("utxo_hash", &self.utxo_hash)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WalletJson {
    wallet_version: u32,
    history: Value,
    notes: Vec<WalletUtxo>,
    spent_nullifiers: Vec<String>,
    pending_notes: Vec<PendingNote>,
    claims: Vec<ClaimJson>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ClaimJson {
    utxo_hash: String,
    claimed_viewing_key: String,
    claimed_owner_key: String,
    claimed_nullifier_pk: String,
}

impl AnonymousWallet {
    pub fn new(history: ViewingHistory) -> Self {
        Self {
            history,
            notes: Vec::new(),
            spent_nullifiers: BTreeSet::new(),
            pending: Vec::new(),
            claims: Vec::new(),
        }
    }

    pub fn history(&self) -> &ViewingHistory {
        &self.history
    }

    pub fn notes(&self) -> &[WalletUtxo] {
        &self.notes
    }

    /// Verified notes under a mint with no registration, never among [`Self::notes`].
    pub fn pending_notes(&self) -> &[PendingNote] {
        &self.pending
    }

    /// Admits every pending note `assets` now names, nothing is read from history.
    pub fn resolve_pending(&mut self, assets: &RingAssets) {
        let (registered, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending)
            .into_iter()
            .map(|note| (assets.by_mint(&note.mint()), note))
            .partition(|(asset, _)| asset.is_some());
        self.pending = waiting.into_iter().map(|(_, note)| note).collect();
        self.notes.extend(
            registered
                .into_iter()
                .filter_map(|(asset, note)| asset.map(|asset| note.into_registered(asset))),
        );
    }

    /// Replies the wallet has not confirmed, none reads as a verified sender.
    pub fn pending_claims(&self) -> &[PendingClaim] {
        &self.claims
    }

    /// The wallet's own decision to trust a claimed sender, nothing else confirms one.
    pub fn confirm_claim(&mut self, claimed: X25519Pubkey) -> Result<(), AnonymousError> {
        if !self
            .claims
            .iter()
            .any(|claim| claim.claimed_viewing_key == claimed)
        {
            return Err(AnonymousError::UnknownSenderClaim);
        }
        self.history.confirm_sender(claimed)?;
        self.claims
            .retain(|claim| claim.claimed_viewing_key != claimed);
        Ok(())
    }

    /// Takes a scan's notes, pending notes, spends, claims and progress together, a repeated scan adds nothing.
    pub fn absorb(&mut self, scan: AnonymousScan) {
        let (history, decrypted, pending, claims) = scan.into_stored();
        let mut held: HashSet<[u8; 32]> = self.notes.iter().map(|note| note.utxo_hash).collect();
        self.notes.extend(
            decrypted
                .utxos
                .into_iter()
                .filter(|note| held.insert(note.utxo_hash)),
        );
        self.pending
            .retain(|note| !held.contains(&note.utxo_hash()));
        held.extend(self.pending.iter().map(PendingNote::utxo_hash));
        self.pending.extend(
            pending
                .into_iter()
                .filter(|note| held.insert(note.utxo_hash())),
        );
        self.spent_nullifiers.extend(decrypted.spent_nullifiers);
        let mut claimed: HashSet<[u8; 32]> =
            self.claims.iter().map(|claim| claim.utxo_hash).collect();
        self.claims.extend(
            claims
                .iter()
                .filter(|claim| claimed.insert(claim.utxo_hash))
                .map(|claim| {
                    let reply = claim.claim.claimed();
                    PendingClaim {
                        utxo_hash: claim.utxo_hash,
                        claimed_viewing_key: reply.viewing_key,
                        claimed_owner_key: reply.owner_key,
                        claimed_nullifier_pk: reply.nullifier_pk,
                    }
                }),
        );
        self.history = history;
    }

    /// A tag counter or an added key, a stored position or watermark never moves here.
    pub fn update_history(&mut self, updated: ViewingHistory) -> Result<(), AnonymousError> {
        if !updated.progress_matches(&self.history) {
            return Err(AnonymousError::ScanProgressMoved);
        }
        self.history = updated;
        Ok(())
    }

    /// The held notes and spends as a scan reports them.
    pub fn decrypted(&self) -> DecryptionResult {
        DecryptionResult {
            utxos: self.notes.clone(),
            spent_nullifiers: self.spent_nullifiers.iter().copied().collect(),
            ..DecryptionResult::default()
        }
    }

    /// Its notes open the wallet's funds, store it as key material under one atomic replace.
    pub fn to_json(&self) -> String {
        let wallet = WalletJson {
            wallet_version: ANONYMOUS_WALLET_VERSION,
            history: self.history.to_json_value(),
            notes: self.notes.clone(),
            spent_nullifiers: self.spent_nullifiers.iter().map(hex::encode).collect(),
            pending_notes: self.pending.clone(),
            claims: self
                .claims
                .iter()
                .map(|claim| ClaimJson {
                    utxo_hash: hex::encode(claim.utxo_hash),
                    claimed_viewing_key: hex::encode(claim.claimed_viewing_key.as_bytes()),
                    claimed_owner_key: hex::encode(claim.claimed_owner_key),
                    claimed_nullifier_pk: hex::encode(claim.claimed_nullifier_pk),
                })
                .collect(),
        };
        serde_json::to_string(&wallet)
            .expect("a struct of strings, integers and vectors serializes")
    }

    /// A bare version 7 history migrates with no notes and no progress, a bare later one holds progress its notes are missing from.
    pub fn from_json(text: &str) -> Result<Self, AnonymousError> {
        let value: Value = serde_json::from_str(text).map_err(unparsed)?;
        if value.get("walletVersion").is_none() {
            if value.get("version").and_then(Value::as_u64) == Some(VIEWING_HISTORY_VERSION.into())
            {
                return Err(AnonymousError::WalletDocument(
                    "a history holds scan progress with no notes".into(),
                ));
            }
            return ViewingHistory::from_json_value(value).map(Self::new);
        }
        let wallet: WalletJson = serde_json::from_value(value).map_err(unparsed)?;
        if wallet.wallet_version != ANONYMOUS_WALLET_VERSION {
            return Err(AnonymousError::WalletDocument(format!(
                "version {} is unknown",
                wallet.wallet_version
            )));
        }
        let spent_nullifiers = wallet
            .spent_nullifiers
            .iter()
            .map(|text| field(text))
            .collect::<Result<_, _>>()?;
        let claims = wallet
            .claims
            .iter()
            .map(|claim| {
                let key = <[u8; X25519_PUBKEY_LEN]>::try_from(
                    hex::decode(&claim.claimed_viewing_key).unwrap_or_default(),
                )
                .map_err(|_| invalid("a claimed viewing key has the wrong length"))?;
                Ok(PendingClaim {
                    utxo_hash: field(&claim.utxo_hash)?,
                    claimed_viewing_key: X25519Pubkey::from_bytes(key)
                        .map_err(|_| invalid("a claimed viewing key is not tagged"))?,
                    claimed_owner_key: field(&claim.claimed_owner_key)?,
                    claimed_nullifier_pk: field(&claim.claimed_nullifier_pk)?,
                })
            })
            .collect::<Result<_, AnonymousError>>()?;
        Ok(Self {
            history: ViewingHistory::from_json_value(wallet.history)?,
            notes: wallet.notes,
            spent_nullifiers,
            pending: wallet.pending_notes,
            claims,
        })
    }
}

fn field(text: &str) -> Result<[u8; 32], AnonymousError> {
    hex::decode(text)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| invalid("a stored value is not 32 hex bytes"))
}

fn invalid(reason: &str) -> AnonymousError {
    AnonymousError::WalletDocument(reason.to_owned())
}

/// A serde message can quote the value it refused, the position alone names the fault.
fn unparsed(error: serde_json::Error) -> AnonymousError {
    AnonymousError::WalletDocument(format!(
        "{:?} at line {} column {}",
        error.classify(),
        error.line(),
        error.column()
    ))
}
