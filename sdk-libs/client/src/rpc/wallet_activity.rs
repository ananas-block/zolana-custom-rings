use serde::{Deserialize, Serialize};
use solana_address::Address;
use spr_indexer_api::{Base64String, Context, SerializablePubkey, SerializableSignature};

use super::{
    DecryptedInput, DecryptedOutput, DecryptedTransaction, DecryptedWithdrawal, PagedRead,
    ReadRequest, ReadTarget,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GetWalletActivityResponse {
    pub context: Context,
    pub value: WalletActivityPage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WalletActivityPage {
    pub items: Vec<WalletActivity>,
    pub cursor: Option<Base64String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WalletActivity {
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    pub event_index: u16,
    pub view: WalletView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "role",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum WalletView {
    /// The anonymous sender or a named spender, its own notes alone beside the public legs.
    Sender {
        inputs: Vec<DecryptedInput>,
        outputs: Vec<DecryptedOutput>,
        withdrawals: Vec<DecryptedWithdrawal>,
    },
    Recipient {
        outputs: Vec<DecryptedOutput>,
        withdrawals: Vec<DecryptedWithdrawal>,
    },
}

impl WalletActivity {
    pub fn read(target: ReadTarget, wallet: Address) -> ReadRequest {
        PagedRead::WalletActivity
            .request(target)
            .with_wallet(wallet)
    }

    /// `own_input` names the wallet's spent notes, a public co-owner never reads a hidden sender's.
    pub fn of(
        wallet: Address,
        transaction: DecryptedTransaction,
        own_input: impl Fn(&DecryptedInput) -> bool,
    ) -> Option<Self> {
        let DecryptedTransaction {
            slot,
            tx_signature,
            event_index,
            outputs,
            sender,
            inputs,
            spenders,
            withdrawals,
            ..
        } = transaction;
        let names = |key: SerializablePubkey| key.0 == wallet;
        let anonymous = sender.is_some_and(|sender| names(sender.owner_key));
        let outputs: Vec<_> = outputs
            .into_iter()
            .filter(|output| output.owner_key().is_some_and(names))
            .collect();
        let view = match anonymous || spenders.into_iter().any(names) {
            true => WalletView::Sender {
                inputs: inputs
                    .into_iter()
                    .filter(|input| !input.unseen && own_input(input))
                    .collect(),
                outputs,
                withdrawals,
            },
            false => {
                if outputs.is_empty() {
                    return None;
                }
                WalletView::Recipient {
                    outputs,
                    withdrawals: withdrawals
                        .into_iter()
                        .filter(|leg| names(leg.recipient) || leg.screened_owner.is_some_and(names))
                        .collect(),
                }
            }
        };
        Some(Self {
            slot,
            tx_signature,
            event_index,
            view,
        })
    }
}
