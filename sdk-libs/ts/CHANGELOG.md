# Changelog

## 0.1.0-alpha — unreleased

The custom ring surface of `@heliuslabs/zolana` moves into
`@heliuslabs/zolana-custom-rings`, built on `@heliuslabs/zolana` 0.5.0-alpha as
a pinned peer. `CustomRingClient` adds the ring proofs and the ring indexer
reads to a `ZolanaClient`, and ring projection failures are `RingError` codes.

Breaking

- `@heliuslabs/zolana/ring` and the custom ring, auditor and key registry
  exports of the `@heliuslabs/zolana` entry points move here → import them from
  `@heliuslabs/zolana-custom-rings` or its `client` and `keypair` entry points.
- `ZolanaClient`'s `proveCustomRing*`, `proveIndexedRingPolicy`,
  `proveIndexedRingDeposit`, `getRingSpendRecord`, `getRingKeyRegistryEntry`
  and `getRingKeyRegistryRegisterProof` move to `CustomRingClient` → create the
  client with `createCustomRingClient(config)`.
- The client errors `CLIENT_KEY_REGISTRY_OUT_OF_SYNC`,
  `CLIENT_KEY_REGISTRY_ROOT_CHANGED`, `CLIENT_KEY_REGISTRY_MEMBER_UNREGISTERED`,
  `CLIENT_KEY_REGISTRY_MEMBER_ALREADY_REGISTERED` and
  `CLIENT_SPEND_RECORD_OUT_OF_SYNC` are the `RingError` codes with the `RING_`
  prefix → match `RingError` codes instead.
- `CompressedProof.toCustomRingProof()` is gone → call `customRingProof(proof)`
  with the prover's proof.
- `syncWallet` opens an audited ring deposit only through the ring capsule
  decoder → pass `depositPayloadDecoder: customRingDepositPayload` in its
  config.
- `RingRpc` now posts each JSON-RPC method beneath its base URL and accepts
  `RingRpcOptions.apiKey` or the URL's `api-key`, while `RingRpc.url` omits the key;
  service clients reject malformed or conflicting credentials during construction
  and preserve unrelated URL queries → forward method paths unchanged and supply
  the API key in one place.
- `openRingDepositOpening` requires a `ConfirmedDeposit` → obtain it from the confirmed audited transaction or `RpcTransactionOrigin.confirmedDeposits`, and supply `depositSource` when recovery uses a custom confirmation provider.
- Custom-ring auditor envelopes use X25519 keys → create a new auditor configuration with `X25519Keypair`/`X25519PublicKey` before using this version.
- Ring deposit audit capsules carry a `RING_DEPOSIT_OPENING_LENGTH` (96) byte opening that also discloses the Ed25519 owner key of an anonymous ring deposit, `RingDepositOpening` takes it as `ownerKey` and `openRingDepositOpening` returns it → re-prove audited deposits with this version, a capsule sealed by an earlier version no longer decodes.
- `setRingPolicyRulesInstruction` and `buildRingSetPolicyRulesTransaction` now pass the ring config as the second account and the program refuses a windowed velocity table on an anonymous ring → rebuild the instruction with this version and keep anonymous rings on per-transfer caps.
- `RingEntryTransitionInput` and `RingEntryTransitionProofInputs` no longer
  take `payer` → drop it.

Added

- `CustomRingClient.checkRingProvingKeys()` compares the prover's ring keys
  with `RING_PROVING_KEY_SHA256S`, the keys the package pins, and refuses a
  differing digest with `CLIENT_PROVER_PROVING_KEYS_MISMATCH`.
- `RingRpc.getDecryptedTransactions` returns hidden senders, inputs and recipients in `anonymous` for authorized anonymous-ring audit readers.

Fixed

- `auditRingTransaction`, `auditRing` and `recoverRingMemberNotes` rejected the auditor message of an anonymous ring, and `decodeRingProgramConfig` threw on one; they now take `mode: "anonymous"`, report hidden senders, inputs and recipients in `anonymous` like `RingRpc.getDecryptedTransactions`, and the config decodes with `mode` while transaction builders keep refusing an anonymous ring.
