import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';

import '../lib/models.dart';
import '../lib/signer.dart';
import '../lib/transport_crypto.dart';

void main() {
  const secret = 'sk_test_secret_for_vectors_do_not_use';
  const appId = 'ak_test_0000000000000000';
  const nonce = '00112233445566778899aabbccddeeff';

  test('request signature matches shared vector', () {
    final body = Uint8List.fromList(utf8.encode('{"card_key":"ABCD-EFGH-JKMN-PQRS","device_id":"device-001"}'));
    expect(Signer.sha256Hex(body), 'd4c470b7b50e407cd4b6bed475392c8da2b45fd470d238fab0b6f4ae4c9861bb');
    expect(Signer.signRequest(secret, 'POST', '/api/v1/verify', '1700000000', nonce, body), 'cdce8f8c1999966d94530a5d7c6c7fe5d4c6e84c8b89388386473f0dfeb3a60e');
  });

  test('transport vector derives expected key and decrypts', () async {
    expect(base64.encode(TransportCrypto.deriveKey(secret, appId)), 'v/L7vJZSWtcffhSSs54esi/HaRX1WkUtrpx72OjOiio=');
    const payload = TransportPayload(iv: 'AAECAwQFBgcICQoL', data: 'Dpzc19OrLLuiUzBnVjZ58nx01g==', tag: 'OgQTxDEviBNBjrGdUcPfPw==');
    expect(await TransportCrypto.decrypt(payload, secret, appId), 'ABCD-EFGH-JKMN-PQRS');
  });

  test('response signature uses raw response and request nonce', () {
    final body = Uint8List.fromList(utf8.encode('{"code":0,"message":"ok"}'));
    final signature = Signer.sign(secret, Signer.responseCanonical('1700000001', nonce, body));
    expect(Signer.verifyResponse(secret, body, '1700000001', nonce, signature), isTrue);
    expect(Signer.verifyResponse(secret, Uint8List.fromList(utf8.encode('{"code":0}')), '1700000001', nonce, signature), isFalse);
  });
}
