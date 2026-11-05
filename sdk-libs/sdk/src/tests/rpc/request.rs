use super::*;
use crate::tests::support::redacts;

#[test]
fn an_opening_prints_no_blinding() {
    let opening = Opening {
        blinding: [0xab; 32],
        ..Opening::default()
    };
    let printed = format!("{opening:?}");
    assert!(redacts(&printed, &["blinding"]));
    assert!(!printed.contains("171, 171"));
}

/// The json tags of Go struct `name` in `prover/ring/params.go`, `-` and embedded fields left out.
fn go_tags(name: &str) -> Vec<String> {
    let source = include_str!("../../../../../prover/ring/params.go");
    let start = source
        .find(&format!("type {name} struct {{"))
        .unwrap_or_else(|| panic!("params.go declares {name}"));
    let body = &source[start..start + source[start..].find("\n}").unwrap()];
    let mut tags: Vec<String> = body
        .split("json:\"")
        .skip(1)
        .map(|tail| tail[..tail.find('"').unwrap()].to_owned())
        .filter(|tag| tag != "-")
        .collect();
    tags.sort();
    tags
}

fn keys(value: &serde_json::Value) -> Vec<String> {
    let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    keys
}

#[test]
fn a_credential_write_names_every_go_field() {
    let write = CredentialWriteRequest {
        member: [1; 32],
        list_salt: [2; 32],
        leaf: CredentialLeafRequest::default(),
        address_next: [3; 32],
        address_index: 4,
        address_path: vec![[5; 32]],
    };
    let json = serde_json::to_value(&write).unwrap();
    assert_eq!(keys(&json), go_tags("CredentialWriteParams"));
    assert_eq!(keys(&json["leaf"]), go_tags("CredentialLeafParams"));
}
