use super::*;
use crate::tests::support::redacts;

#[test]
fn an_opening_prints_no_blinding() {
    let opening = Opening {
        blinding: [0xab; 32],
        ..Opening::default()
    };
    for printed in [format!("{opening:?}")] {
        assert!(redacts(&printed, &["blinding"]));
        assert!(!printed.contains("171, 171"));
    }
}
