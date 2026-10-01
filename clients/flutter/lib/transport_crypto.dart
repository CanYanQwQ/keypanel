import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:crypto/crypto.dart' as legacy_crypto;

import 'models.dart';

/// HKDF-SHA256 plus AES-256-GCM transport encryption.
class TransportCrypto {
  static const info = 'cardkey-enc-v1';
  static const ivLength = 12;
  static const tagLength = 16;
  static const keyLength = 32;

  static Uint8List deriveKey(String appSecret, String appId) {
    final prk = legacy_crypto.Hmac(legacy_crypto.sha256, utf8.encode(appId)).convert(utf8.encode(appSecret)).bytes;
    final infoBytes = utf8.encode(info);
    return Uint8List.fromList(legacy_crypto.Hmac(legacy_crypto.sha256, prk).convert([...infoBytes, 1]).bytes.sublist(0, keyLength));
  }

  static Future<TransportPayload> encrypt(String plaintext, String appSecret, String appId) async {
    final algorithm = AesGcm.with256bits();
    final nonce = secureRandomBytes(ivLength);
    final secretKey = SecretKey(deriveKey(appSecret, appId));
    final box = await algorithm.encrypt(
      utf8.encode(plaintext),
      secretKey: secretKey,
      nonce: nonce,
      aad: utf8.encode(appId),
    );
    return TransportPayload(
      iv: base64.encode(nonce),
      data: base64.encode(box.cipherText),
      tag: base64.encode(box.mac.bytes),
    );
  }

  static Future<String> decrypt(TransportPayload payload, String appSecret, String appId) async {
    final nonce = decodeBase64(payload.iv, expectedLength: ivLength);
    final data = decodeBase64(payload.data);
    final tag = decodeBase64(payload.tag, expectedLength: tagLength);
    try {
      final clear = await AesGcm.with256bits().decrypt(
        SecretBox(data, nonce: nonce, mac: Mac(tag)),
        secretKey: SecretKey(deriveKey(appSecret, appId)),
        aad: utf8.encode(appId),
      );
      return utf8.decode(clear);
    } on SecretBoxAuthenticationError catch (error) {
      throw CardKeyApiException('卡密解密失败：认证标签校验不通过: $error');
    }
  }

  static Uint8List decodeBase64(String value, {int? expectedLength}) {
    final bytes = Uint8List.fromList(base64.decode(value));
    if (expectedLength != null && bytes.length != expectedLength) {
      throw FormatException('Invalid transport field length');
    }
    return bytes;
  }
}

Uint8List secureRandomBytes(int length) =>
    Uint8List.fromList(List<int>.generate(length, (_) => Random.secure().nextInt(256)));
