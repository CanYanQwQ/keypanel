import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import 'models.dart';
import 'signer.dart';

class CardKeyClient {
  CardKeyClient(this.config, {http.Client? httpClient, DateTime Function()? clock, String Function()? nonceFactory})
      : _http = httpClient ?? http.Client(),
        _clock = clock ?? (() => DateTime.now()),
        _nonceFactory = nonceFactory ?? Signer.generateNonce;

  final ClientConfig config;
  final http.Client _http;
  final DateTime Function() _clock;
  final String Function() _nonceFactory;

  Future<ApiResponse> verify(CardKeyValue cardKey, {String? deviceId}) => _post('verify', _cardInput(cardKey, deviceId));
  Future<ApiResponse> activate(CardKeyValue cardKey, {String? deviceId}) => _post('activate', _cardInput(cardKey, deviceId));
  /// There is no server-side idempotency key; never blindly retry consume.
  Future<ApiResponse> consume(CardKeyValue cardKey, {String? deviceId, int count = 1}) {
    if (count < 1 || count > 1000) throw ArgumentError.value(count, 'count');
    return _post('consume', {..._cardInput(cardKey, deviceId), 'count': count});
  }
  Future<ApiResponse> query(CardKeyValue cardKey, {String? deviceId}) => _post('query', _cardInput(cardKey, deviceId));
  Future<ApiResponse> unbind(CardKeyValue cardKey, {String? deviceId, bool force = false}) => _post('unbind', {..._cardInput(cardKey, deviceId), if (force) 'force': true});

  Future<ApiResponse> _post(String method, Map<String, Object?> body) async {
    final path = '/api/v1/$method';
    // Serialize once; these exact UTF-8 bytes are signed and sent.
    final rawBody = Uint8List.fromList(utf8.encode(jsonEncode(body)));
    final timestamp = (_clock().millisecondsSinceEpoch ~/ 1000).toString();
    final nonce = _nonceFactory();
    final response = await _http.post(
      config.baseUrl.resolve(path),
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        Signer.headerAppId: config.appId,
        Signer.headerTimestamp: timestamp,
        Signer.headerNonce: nonce,
        Signer.headerVersion: Signer.version,
        Signer.headerSignature: Signer.signRequest(config.appSecret, 'POST', path, timestamp, nonce, rawBody),
      },
      body: rawBody,
    ).timeout(config.timeout);
    final rawResponse = Uint8List.fromList(response.bodyBytes);
    final responseTimestamp = response.headers[Signer.headerResponseTimestamp.toLowerCase()];
    final responseSignature = response.headers[Signer.headerResponseSignature.toLowerCase()];
    if (config.requireResponseSignature && response.statusCode >= 200 && response.statusCode < 300 &&
        (responseTimestamp == null || responseSignature == null)) {
      throw const ResponseSignatureException('Missing response signature headers');
    }
    if (responseTimestamp != null && responseSignature != null &&
        !Signer.verifyResponse(config.appSecret, rawResponse, responseTimestamp, nonce, responseSignature)) {
      throw const ResponseSignatureException('Response signature verification failed');
    }
    final decoded = jsonDecode(utf8.decode(rawResponse));
    if (decoded is! Map<String, dynamic>) throw const CardKeyApiException('The API response must be a JSON object');
    final result = ApiResponse.fromJson(decoded, response.statusCode);
    if (response.statusCode < 200 || response.statusCode > 299 || result.code != 0 || !result.success) {
      // The structured result is returned for caller-side error handling.
    }
    return result;
  }

  static Map<String, Object?> _cardInput(CardKeyValue cardKey, String? deviceId) => {
    'card_key': cardKey.toJson(),
    if (deviceId != null) 'device_id': deviceId,
  };
}
