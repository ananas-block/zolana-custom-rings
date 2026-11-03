//! Each sender's net debit per asset, mirror `prover/circuits/policy/outflow.go`.

/// A live input, keyed by owner identity so one owner's notes aggregate across nullifier keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DebitInput {
    pub owner: [u8; 32],
    pub asset: [u8; 32],
    pub amount: u64,
}

/// A live output, an exit leaves the ring even when it pays its own owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DebitOutput {
    pub ring: bool,
    pub owner: [u8; 32],
    pub asset: [u8; 32],
    pub amount: u64,
}

/// `debit` holds a sum of inputs, past a u64.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerDebit {
    pub owner: [u8; 32],
    pub asset: [u8; 32],
    pub debit: u128,
}

/// One transfer's parties, the assets are its output and public assets.
#[derive(Clone, Copy, Debug)]
pub struct DebitTransfer<'a> {
    pub senders: &'a [[u8; 32]],
    pub assets: &'a [[u8; 32]],
    pub inputs: &'a [DebitInput],
    pub outputs: &'a [DebitOutput],
}

/// Nonzero rows in senders then assets order, a credit never moves between owners.
#[must_use]
pub fn owner_debits(transfer: &DebitTransfer<'_>) -> Vec<OwnerDebit> {
    let mut rows = Vec::new();
    for (position, owner) in transfer.senders.iter().enumerate() {
        if transfer.senders[..position].contains(owner) {
            continue;
        }
        for (position, asset) in transfer.assets.iter().enumerate() {
            if transfer.assets[..position].contains(asset) {
                continue;
            }
            let owned: u128 = transfer
                .inputs
                .iter()
                .filter(|input| input.owner == *owner && input.asset == *asset)
                .map(|input| u128::from(input.amount))
                .sum();
            let returned: u128 = transfer
                .outputs
                .iter()
                .filter(|output| output.ring && output.owner == *owner && output.asset == *asset)
                .map(|output| u128::from(output.amount))
                .sum();
            let debit = owned.saturating_sub(returned);
            if debit != 0 {
                rows.push(OwnerDebit {
                    owner: *owner,
                    asset: *asset,
                    debit,
                });
            }
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: [u8; 32] = [1; 32];
    const BOB: [u8; 32] = [2; 32];
    const CAROL: [u8; 32] = [3; 32];
    const SOL: [u8; 32] = [4; 32];
    const USDC: [u8; 32] = [5; 32];

    fn input(owner: [u8; 32], asset: [u8; 32], amount: u64) -> DebitInput {
        DebitInput {
            owner,
            asset,
            amount,
        }
    }

    fn ring(owner: [u8; 32], asset: [u8; 32], amount: u64) -> DebitOutput {
        DebitOutput {
            ring: true,
            owner,
            asset,
            amount,
        }
    }

    fn debits(
        senders: &[[u8; 32]],
        inputs: &[DebitInput],
        outputs: &[DebitOutput],
    ) -> Vec<OwnerDebit> {
        owner_debits(&DebitTransfer {
            senders,
            assets: &[SOL, USDC],
            inputs,
            outputs,
        })
    }

    fn row(owner: [u8; 32], asset: [u8; 32], debit: u128) -> OwnerDebit {
        OwnerDebit {
            owner,
            asset,
            debit,
        }
    }

    #[test]
    fn change_returns_to_its_owner_and_the_rest_is_the_debit() {
        assert_eq!(
            debits(
                &[ALICE],
                &[input(ALICE, SOL, 100), input(ALICE, SOL, 50)],
                &[ring(ALICE, SOL, 30), ring(BOB, SOL, 120)],
            ),
            [row(ALICE, SOL, 120)]
        );
    }

    #[test]
    fn an_exit_to_the_same_owner_counts_as_leaving() {
        let exit = DebitOutput {
            ring: false,
            ..ring(ALICE, SOL, 40)
        };
        assert_eq!(
            debits(
                &[ALICE],
                &[input(ALICE, SOL, 100)],
                &[exit, ring(ALICE, SOL, 60)]
            ),
            [row(ALICE, SOL, 40)]
        );
    }

    #[test]
    fn a_credit_never_moves_between_owners_or_assets() {
        assert_eq!(
            debits(
                &[ALICE, BOB],
                &[input(ALICE, SOL, 100), input(BOB, USDC, 70)],
                &[ring(BOB, SOL, 100), ring(ALICE, USDC, 70)],
            ),
            [row(ALICE, SOL, 100), row(BOB, USDC, 70)]
        );
        assert_eq!(
            debits(
                &[ALICE],
                &[input(ALICE, SOL, 100)],
                &[ring(ALICE, USDC, 100)]
            ),
            [row(ALICE, SOL, 100)]
        );
    }

    #[test]
    fn a_single_owner_deposit_offsets_its_debit_and_clamps_at_zero() {
        assert_eq!(
            debits(
                &[ALICE],
                &[input(ALICE, SOL, 100)],
                &[ring(ALICE, SOL, 80), ring(BOB, SOL, 70)],
            ),
            [row(ALICE, SOL, 20)]
        );
        assert_eq!(
            debits(
                &[ALICE],
                &[input(ALICE, SOL, 100)],
                &[ring(ALICE, SOL, 150)]
            ),
            []
        );
    }

    #[test]
    fn a_repeated_sender_or_asset_takes_one_row_and_a_stranger_none() {
        assert_eq!(
            owner_debits(&DebitTransfer {
                senders: &[ALICE, ALICE],
                assets: &[SOL, SOL],
                inputs: &[input(ALICE, SOL, 9), input(CAROL, SOL, 5)],
                outputs: &[],
            }),
            [row(ALICE, SOL, 9)]
        );
    }

    #[test]
    fn the_sum_passes_a_u64() {
        assert_eq!(
            debits(
                &[ALICE],
                &[input(ALICE, SOL, u64::MAX), input(ALICE, SOL, u64::MAX)],
                &[],
            ),
            [row(ALICE, SOL, 2 * u128::from(u64::MAX))]
        );
    }
}
