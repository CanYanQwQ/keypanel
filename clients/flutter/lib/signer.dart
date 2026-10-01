import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

class Signer {
  static const version = 'v1';
  static const headerAppId = 'X-App-Id';
  static const headerTimestamp = 'X-Timestamp';
  static const headerNonce = 'X-Nonce';
  static const headerSignature = 'X-Signature';
  static const headerVersion = 'X-Signature-Version';
  static const headerResponseSignature = 'X-Response-Signature';
  static const headerResponseTimestamp = 'X-Response-Timestamp';

  static String normalizePath(String path) {
    var value = path.split(RegExp(r'[?#]')).first;
    if (value.isEmpty) return '/';
    value = value.replaceAll(RegExp(r'/{2,}'), '/');
    if (value.length > 1) value = value.replaceFirst(RegExp(r'/+$'), '');
    return value;
  }

  static String sha256Hex(Uint8List raw) => sha256.convert(raw).toString();

  static String canonicalString(String method, String path, String timestamp, String nonce, Uint8List rawBody) =>
      [method.toUpperCase(), normalizePath(path), timestamp, nonce, sha256Hex(rawBody)].join('\n');

  static String sign(String appSecret, String canonical) =>
      Hmac(sha256, utf8.encode(appSecret)).convert(utf8.encode(canonical)).toString();

  static String signRequest(String appSecret, String method, String path, String timestamp, String nonce, Uint8List rawBody) =>
      sign(appSecret, canonicalString(method, path, timestamp, nonce, rawBody));

  static String responseCanonical(String responseTimestamp, String requestNonce, Uint8List rawResponse) =>
      [responseTimestamp, requestNonce, sha256Hex(rawResponse)].join('\n');

  static bool verifyResponse(String appSecret, Uint8List rawResponse, String responseTimestamp, String requestNonce, String signature) =>
      _constantTimeEquals(sign(appSecret, responseCanonical(responseTimestamp, requestNonce, rawResponse)), signature.trim().toLowerCase());

  static String generateNonce([int bytes = 16]) {
    final random = Random.secure();
    return List<int>.generate(bytes, (_) => random.nextInt(256))
        .map((value) => value.toRadixString(16).padLeft(2, '0')).join();
  }

  static bool _constantTimeEquals(String left, String right) {
    final a = utf8.encode(left);
    final b = utf8.encode(right);
    var difference = a.length ^ b.length;
    for (var i = 0; i < (a.length < b.length ? a.length : b.length); i++) {
      difference |= a[i] ^ b[i];
    }
    return difference == 0;
  }

}
