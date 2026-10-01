import unittest

from cardkey_client.signer import canonical_request, sign_request
from cardkey_client.transport_crypto import decrypt_card_key, derive_transport_key


class ConformanceTests(unittest.TestCase):
    def test_signature_v1_synthetic_vector(self) -> None:
        body = '{"card_key":"ABCD-EFGH-JKMN-PQRS","device_id":"device-001"}'
        self.assertEqual(canonical_request("POST", "/api/v1/verify", "1700000000", "00112233445566778899aabbccddeeff", body), "POST\n/api/v1/verify\n1700000000\n00112233445566778899aabbccddeeff\nd4c470b7b50e407cd4b6bed475392c8da2b45fd470d238fab0b6f4ae4c9861bb")
        self.assertEqual(sign_request("sk_test_secret_for_vectors_do_not_use", "POST", "/api/v1/verify", "1700000000", "00112233445566778899aabbccddeeff", body), "cdce8f8c1999966d94530a5d7c6c7fe5d4c6e84c8b89388386473f0dfeb3a60e")

    def test_transport_v1_synthetic_vector(self) -> None:
        app_id = "ak_test_0000000000000000"
        secret = "sk_test_secret_for_vectors_do_not_use"
        self.assertEqual(derive_transport_key(secret, app_id).hex(), "bff2fbbc96525ad71f7e1492b39e1eb22fc76915f55a452dae9c7bd8e8ce8a2a")
        self.assertEqual(decrypt_card_key({"iv": "AAECAwQFBgcICQoL", "data": "Dpzc19OrLLuiUzBnVjZ58nx01g==", "tag": "OgQTxDEviBNBjrGdUcPfPw=="}, secret, app_id), "ABCD-EFGH-JKMN-PQRS")


if __name__ == "__main__":
    unittest.main()
