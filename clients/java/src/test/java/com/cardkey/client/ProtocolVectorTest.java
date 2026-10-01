package com.cardkey.client;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class ProtocolVectorTest {
    private static final String SECRET = "sk_test_secret_for_vectors_do_not_use";
    private static final String APP_ID = "ak_test_0000000000000000";
    private static final String NONCE = "00112233445566778899aabbccddeeff";

    @Test
    void requestSignatureMatchesSharedVector() {
        byte[] body = "{\"card_key\":\"ABCD-EFGH-JKMN-PQRS\",\"device_id\":\"device-001\"}".getBytes(StandardCharsets.UTF_8);
        assertEquals("d4c470b7b50e407cd4b6bed475392c8da2b45fd470d238fab0b6f4ae4c9861bb", Signer.sha256Hex(body));
        assertEquals("cdce8f8c1999966d94530a5d7c6c7fe5d4c6e84c8b89388386473f0dfeb3a60e", Signer.signRequest(SECRET, "POST", "/api/v1/verify", "1700000000", NONCE, body));
    }

    @Test
    void transportVectorDecryptsAndDerivesExpectedKey() {
        assertEquals("bff2fbbc96525ad71f7e1492b39e1eb22fc76915f55a452dae9c7bd8e8ce8a2a", java.util.HexFormat.of().formatHex(TransportCrypto.deriveKey(SECRET, APP_ID)));
        assertEquals("ABCD-EFGH-JKMN-PQRS", TransportCrypto.decrypt(new TransportPayload("AAECAwQFBgcICQoL", "Dpzc19OrLLuiUzBnVjZ58nx01g==", "OgQTxDEviBNBjrGdUcPfPw=="), SECRET, APP_ID));
    }

    @Test
    void responseSignatureUsesRawResponseAndRequestNonce() {
        byte[] body = "{\"code\":0,\"message\":\"ok\"}".getBytes(StandardCharsets.UTF_8);
        String signature = Signer.sign(SECRET, Signer.responseCanonical("1700000001", NONCE, body));
        assertTrue(Signer.verifyResponse(SECRET, body, "1700000001", NONCE, signature));
        assertFalse(Signer.verifyResponse(SECRET, "{\"code\":0}".getBytes(StandardCharsets.UTF_8), "1700000001", NONCE, signature));
    }
}
