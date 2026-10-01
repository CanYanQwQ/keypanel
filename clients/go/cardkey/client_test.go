package cardkey

import (
	"testing"
)

func TestSignatureV1SyntheticVector(t *testing.T) {
	body := []byte(`{"card_key":"ABCD-EFGH-JKMN-PQRS","device_id":"device-001"}`)
	canonical := "POST\n/api/v1/verify\n1700000000\n00112233445566778899aabbccddeeff\nd4c470b7b50e407cd4b6bed475392c8da2b45fd470d238fab0b6f4ae4c9861bb"
	if got := CanonicalRequest("POST", "/api/v1/verify", "1700000000", "00112233445566778899aabbccddeeff", body); got != canonical {
		t.Fatalf("canonical mismatch: %s", got)
	}
	want := "cdce8f8c1999966d94530a5d7c6c7fe5d4c6e84c8b89388386473f0dfeb3a60e"
	if got := SignRequest("sk_test_secret_for_vectors_do_not_use", "POST", "/api/v1/verify", "1700000000", "00112233445566778899aabbccddeeff", body); got != want {
		t.Fatalf("signature mismatch: %s", got)
	}
}

func TestTransportV1SyntheticVector(t *testing.T) {
	appID := "ak_test_0000000000000000"
	secret := "sk_test_secret_for_vectors_do_not_use"
	key, err := DeriveTransportKey(secret, appID)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmtHex(key); got != "bff2fbbc96525ad71f7e1492b39e1eb22fc76915f55a452dae9c7bd8e8ce8a2a" {
		t.Fatalf("key mismatch: %s", got)
	}
	plain, err := DecryptCardKey(EncryptedCardKey{IV: "AAECAwQFBgcICQoL", Data: "Dpzc19OrLLuiUzBnVjZ58nx01g==", Tag: "OgQTxDEviBNBjrGdUcPfPw=="}, secret, appID)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "ABCD-EFGH-JKMN-PQRS" {
		t.Fatalf("plaintext mismatch: %s", plain)
	}
}

func fmtHex(value []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(value)*2)
	for i, b := range value {
		out[i*2], out[i*2+1] = hex[b>>4], hex[b&15]
	}
	return string(out)
}
