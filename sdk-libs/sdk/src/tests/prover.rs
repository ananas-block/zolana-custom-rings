use super::*;

#[test]
fn a_request_body_takes_exactly_its_length() {
    let inputs = serde_json::json!({ "nullifierSecret": format!("0x{}", "ab".repeat(32)) });
    let request = RingRequest::new(RingCircuit::RegisterKey, &inputs).unwrap();
    let body = request.body().unwrap();
    assert_eq!(body.capacity(), body.len());
    let sent: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(sent["nullifierSecret"], inputs["nullifierSecret"]);
    assert!(sent["circuitType"].is_string());
}

/// Exercise the same verifier and committed keys the SDK/program use, with real Go proofs.
#[test]
fn every_catalog_proof_verifies_under_the_committed_solana_key() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/ring-proofs.json");
    let vectors: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(vectors.len(), RING_KEYS.len());
    for key in RING_KEYS {
        let vector = &vectors[key.name];
        let proof = Proof::from_gnark_json(&vector["proof"].to_string()).unwrap();
        let encoded = vector["statement"]
            .as_str()
            .unwrap()
            .strip_prefix("0x")
            .unwrap();
        let statement: [u8; 32] = hex::decode(encoded).unwrap().try_into().unwrap();
        let vk = verifying_key(key.circuit).unwrap();
        verify_proof_statement(&proof, statement, vk)
            .unwrap_or_else(|e| panic!("{}: {e}", key.name));
        assert!(
            verify_proof_statement(&proof, [0; 32], vk).is_err(),
            "{} accepted another statement",
            key.name
        );
    }
}
