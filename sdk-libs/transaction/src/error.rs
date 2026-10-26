use custom_ring_interface::stream::StreamError;
use thiserror::Error;
use zolana_hasher::HasherError;
use zolana_keypair::KeypairError;
use zolana_ring_keys::RingKeyError;
use zolana_transaction::TransactionError;

#[derive(Debug, Error)]
pub enum RingRailError {
    #[error(transparent)]
    Transaction(#[from] TransactionError),
    #[error(transparent)]
    Keypair(#[from] KeypairError),
    #[error(transparent)]
    Keys(#[from] RingKeyError),
    #[error(transparent)]
    Stream(#[from] StreamError),
    #[error(transparent)]
    Hasher(#[from] HasherError),
    #[error("output {slot_index} carries data, a ring rail slot has a fixed body")]
    DeliveredOutputData { slot_index: usize },
    #[error("output {slot_index} is compact padding, a ring rail publishes every slot")]
    DeliveredCompactPadding { slot_index: usize },
    #[error("output {slot_index} does not frame as its ring rail publishes it")]
    RingOutputFraming { slot_index: usize },
    #[error("anonymous payment slot {slot_index} is taken, holds no ring output to its key, or repeats a tag or the pair stream")]
    RingPaymentSlot { slot_index: usize },
    #[error("anonymous ring output {slot_index} pays another owner without a stream slot")]
    UnplannedRingOutput { slot_index: usize },
    #[error(
        "exit {slot_index} names a ring address viewing key, its scheme 3 body would publish it"
    )]
    RingAddressExit { slot_index: usize },
    #[error("exit {slot_index} pays the hidden sender, its owner tag would publish the sender")]
    RingSenderExit { slot_index: usize },
}
