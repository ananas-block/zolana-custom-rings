# Fresh local ring controls test

Run from `sdk-libs/ts` after `npm ci` at the repository root and local builds. Use a dedicated local stack
with current SPP and user-registry programs, the generated localnet snapshots
(protocol config, tree and SPL asset counter), Photon behind the ring indexer,
and the ring prover with the SPP keys and the custom-ring keys `prover/ring/proving-keys.lock` pins,
including the deposit disclosure circuit. V1
transactions are required. Surfpool needs the explicitly opt-in local fixture
builds of Photon and the ring indexer.

```sh
ZOLANA_PROCESS_SCOPE_DIR=<scope directory of the dedicated local stack> \
ZOLANA_LOCALNET_RPC_PORT=8899 \
ZOLANA_LOCALNET_URL=http://127.0.0.1:8899 \
ZOLANA_INDEXER_URL=http://127.0.0.1:8784 \
ZOLANA_PROVER_URL=http://127.0.0.1:3001 \
ZOLANA_TREE=<tree address from the localnet snapshot> \
npm run test:ring-controls:live
```

A clone with `ZOLANA_PORT_OFFSET` set adds the offset to each port.

The fixture sets the delegate before any note exists, which turns key escrow on.
The sender and the recipient register their nullifier keys first. A deposit or
transfer to an allow-listed owner without a registered key is refused before
proving, and so is a deposit under the zero nullifier key. Deposit auditing stays off at initialization, and escrow alone forces
the audited deposit. SOL, SPL and Token-2022 deposits must land, decrypt for the
recipient and recover through the auditor before any notes are spent. Co-signing initially covers withdrawals only. A
below-threshold private transfer lands without the co-signer, and an
above-threshold transfer requires it. Transfer-scoped approval is enabled later
for the delegate checks.

A transfer above an outflow cap is refused before proving, and the delegate
move passes the cap untouched.

The runner uses `zolana/target/debug/zolana` and `target/deploy/custom_ring_program.so`
from the repository root, `just test-ts-ring-controls` builds both and starts the stack.
Override with `ZOLANA_CLI_BIN` and `RING_PROGRAM_SO` when needed. It creates a
temporary CLI config and wallet, then calls the existing CLI to create, fund and
register fresh SPL and Token-2022 mints. It passes their returned mint/ATA addresses
to the test. Optional `ZOLANA_TEST_AUTHORITY_WALLET` selects an existing local
CLI wallet.

All endpoints must be loopback. The runner itself does not start, reset, or stop services.
Stop the stack through its own `ZOLANA_PROCESS_SCOPE_DIR` after the test. Temporary
wallet/config artifacts are retained at the printed path for debugging.
