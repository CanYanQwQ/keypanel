package com.cardkey.client

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ProtocolVectorTest {
    private val secret = "sk_test_secret_for_vectors_do_not_use"
    private val appId = "ak_test_0000000000000000"
    private val body = "{\"card_key\":\"ABCD-EFGH-JKMN-PQRS\",\"device_id\":\"device-001\"}".toByteArray()

    @Test
    fun requestSignatureMatchesSharedVector() {
        assertEquals(
            "d4c470b7b50e407cd4b6bed475392c8da2b45fd470d238fab0b6f4ae4c9861bb",
            Signer.sha256Hex(body),
        )
        assertEquals(
            "cdce8f8c1999966d94530a5d7c6c7fe5d4c6e84c8b89388386473f0dfeb3a60e",
            Signer.signRequest(secret, "POST", "/api/v1/verify", "1700000000", "00112233445566778899aabbccddeeff", body),
        )
    }

    @Test
    fun transportVectorDecryptsAndDerivesExpectedKey() {
        assertEquals(
            "bff2fbbc96525ad71f7e1492b39e1eb22fc76915f55a452dae9c7bd8e8ce8a2a",
            TransportCrypto.deriveKey(secret, appId).joinToString("") { "%02x".format(it) },
        )
        val payload = TransportPayload("AAECAwQFBgcICQoL", "Dpzc19OrLLuiUzBnVjZ58nx01g==", "OgQTxDEviBNBjrGdUcPfPw==")
        assertEquals("ABCD-EFGH-JKMN-PQRS", TransportCrypto.decrypt(payload, secret, appId))
    }

    @Test
    fun responseSignatureUsesRawResponseAndRequestNonce() {
        val response = "{\"code\":0,\"message\":\"ok\"}".toByteArray()
        val signature = Signer.sign(secret, Signer.responseCanonical("1700000001", "00112233445566778899aabbccddeeff", response))
        assertTrue(Signer.verifyResponse(secret, response, "1700000001", "00112233445566778899aabbccddeeff", signature))
        assertTrue(!Signer.verifyResponse(secret, "{\"code\":0}".toByteArray(), "1700000001", "00112233445566778899aabbccddeeff", signature))
    }
}
