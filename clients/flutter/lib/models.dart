import 'dart:convert';
import 'dart:typed_data';

class TransportPayload {
  const TransportPayload({required this.iv, required this.data, required this.tag});
  final String iv;
  final String data;
  final String tag;

  Map<String, String> toJson() => {'iv': iv, 'data': data, 'tag': tag};
}

class ClientConfig {
  const ClientConfig({required this.baseUrl, required this.appId, required this.appSecret, this.timeout = const Duration(seconds: 15), this.requireResponseSignature = true});
  final Uri baseUrl;
  final String appId;
  final String appSecret;
  final Duration timeout;
  final bool requireResponseSignature;
}

class ApiResponse {
  const ApiResponse({required this.code, required this.message, required this.success, required this.serverTime, required this.httpStatus, this.data});
  final int code;
  final String message;
  final bool success;
  final int serverTime;
  final int httpStatus;
  final Object? data;

  ApiErrorCode get error => ApiErrorCode.fromCode(code);
  bool get isBusinessSuccess => code == 0 && success;

  factory ApiResponse.fromJson(Map<String, dynamic> json, int httpStatus) => ApiResponse(
    code: json['code'] as int? ?? -1,
    message: json['message'] as String? ?? '未知错误',
    success: json['success'] as bool? ?? false,
    serverTime: json['server_time'] as int? ?? 0,
    httpStatus: httpStatus,
    data: json['data'],
  );
}

class CardKeyValue {
  const CardKeyValue.plain(this.plain) : encrypted = null;
  const CardKeyValue.encrypted(this.encrypted) : plain = null;
  final String? plain;
  final TransportPayload? encrypted;

  Object toJson() => plain ?? encrypted!.toJson();
}

class CardKeyApiException implements Exception {
  const CardKeyApiException(this.message);
  final String message;
  @override
  String toString() => message;
}

class ResponseSignatureException extends CardKeyApiException {
  const ResponseSignatureException(super.message);
}

enum ApiErrorCode {
  success(0), invalidParams(1001), appNotFound(1002), appDisabled(1003), signatureInvalid(1004), timestampExpired(1005), nonceReused(1006), ipNotAllowed(1007), rateLimited(1008), dailyQuotaExceeded(1009), missingCredentials(1010), decryptFailed(1011), cardNotFound(2001), cardDisabled(2002), cardExpired(2003), cardNotActivated(2004), cardDepleted(2005), cardAlreadyActivated(2006), deviceMismatch(2007), deviceNotBound(2008), cardNotBoundToApp(2009), cardTypeUnsupported(2010), cardAlreadyDisabled(2011), notFound(4004), methodNotAllowed(4005), payloadTooLarge(4013), serverError(5000), maintenance(5003), unknown(-1);
  const ApiErrorCode(this.code);
  final int code;
  static ApiErrorCode fromCode(int code) => values.firstWhere((item) => item.code == code, orElse: () => ApiErrorCode.unknown);
}

Uint8List utf8Bytes(String value) => Uint8List.fromList(utf8.encode(value));
