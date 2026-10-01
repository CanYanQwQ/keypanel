use cardkey_api_client_example::{canonical_request, decrypt_card_key, derive_transport_key, sign_request, EncryptedCardKey};

#[test]
fn signature_v1_synthetic_vector() {
    let body = br#"{"card_key":"ABCD-EFGH-JKMN-PQRS","device_id":"device-001"}"#;
    assert_eq!(canonical_request("POST", "/api/v1/verify", "1700000000", "00112233445566778899aabbccddeeff", body), "POST\n/api/v1/verify\n1700000000\n00112233445566778899aabbccddeeff\nd4c470b7b50e407cd4b6bed475392c8da2b45fd470d238fab0b6f4ae4c9861bb");
    assert_eq!(sign_request("sk_test_secret_for_vectors_do_not_use", "POST", "/api/v1/verify", "1700000000", "00112233445566778899aabbccddeeff", body), "cdce8f8c1999966d94530a5d7c6c7fe5d4c6e84c8b89388386473f0dfeb3a60e");
}

#[test]
fn transport_v1_synthetic_vector() {
    let app_id = "ak_test_0000000000000000";
    let secret = "sk_test_secret_for_vectors_do_not_use";
    assert_eq!(to_hex(&derive_transport_key(secret, app_id).unwrap()), "bff2fbbc96525ad71f7e1492b39e1eb22fc76915f55a452dae9c7bd8e8ce8a2a");
    assert_eq!(decrypt_card_key(&EncryptedCardKey { iv: "AAECAwQFBgcICQoL".into(), data: "Dpzc19OrLLuiUzBnVjZ58nx01g==".into(), tag: "OgQTxDEviBNBjrGdUcPfPw==".into() }, secret, app_id).unwrap(), "ABCD-EFGH-JKMN-PQRS");
}

fn to_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
