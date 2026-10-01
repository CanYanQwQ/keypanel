import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalRequest, signRequest } from '../src/signer.mjs';
import { decryptCardKey, deriveTransportKey } from '../src/transport-crypto.mjs';
const appId = 'ak_test_0000000000000000';
const secret = 'sk_test_secret_for_vectors_do_not_use';
test('signature-v1 synthetic vector', () => {
  const body = '{"card_key":"ABCD-EFGH-JKMN-PQRS","device_id":"device-001"}';
  assert.equal(canonicalRequest('POST', '/api/v1/verify', '1700000000', '00112233445566778899aabbccddeeff', body), 'POST\n/api/v1/verify\n1700000000\n00112233445566778899aabbccddeeff\nd4c470b7b50e407cd4b6bed475392c8da2b45fd470d238fab0b6f4ae4c9861bb');
  assert.equal(signRequest(secret, 'POST', '/api/v1/verify', '1700000000', '00112233445566778899aabbccddeeff', body), 'cdce8f8c1999966d94530a5d7c6c7fe5d4c6e84c8b89388386473f0dfeb3a60e');
});
test('transport-v1 synthetic vector', () => {
  assert.equal(deriveTransportKey(secret, appId).toString('hex'), 'bff2fbbc96525ad71f7e1492b39e1eb22fc76915f55a452dae9c7bd8e8ce8a2a');
  assert.equal(decryptCardKey({ iv: 'AAECAwQFBgcICQoL', data: 'Dpzc19OrLLuiUzBnVjZ58nx01g==', tag: 'OgQTxDEviBNBjrGdUcPfPw==' }, secret, appId), 'ABCD-EFGH-JKMN-PQRS');
});
