#include "cardkey/client.h"
#include "cardkey/signer.h"

#include <QDateTime>
#include <QJsonDocument>
#include <QNetworkRequest>
#include <stdexcept>
#include <utility>

namespace cardkey {

ApiErrorCode ApiResponse::error() const {
    switch (code) {
    case 0: return ApiErrorCode::Success;
    case 1001: return ApiErrorCode::InvalidParams; case 1002: return ApiErrorCode::AppNotFound; case 1003: return ApiErrorCode::AppDisabled;
    case 1004: return ApiErrorCode::SignatureInvalid; case 1005: return ApiErrorCode::TimestampExpired; case 1006: return ApiErrorCode::NonceReused;
    case 1007: return ApiErrorCode::IpNotAllowed; case 1008: return ApiErrorCode::RateLimited; case 1009: return ApiErrorCode::DailyQuotaExceeded;
    case 1010: return ApiErrorCode::MissingCredentials; case 1011: return ApiErrorCode::DecryptFailed; case 2001: return ApiErrorCode::CardNotFound;
    case 2002: return ApiErrorCode::CardDisabled; case 2003: return ApiErrorCode::CardExpired; case 2004: return ApiErrorCode::CardNotActivated;
    case 2005: return ApiErrorCode::CardDepleted; case 2006: return ApiErrorCode::CardAlreadyActivated; case 2007: return ApiErrorCode::DeviceMismatch;
    case 2008: return ApiErrorCode::DeviceNotBound; case 2009: return ApiErrorCode::CardNotBoundToApp; case 2010: return ApiErrorCode::CardTypeUnsupported;
    case 2011: return ApiErrorCode::CardAlreadyDisabled; case 4004: return ApiErrorCode::NotFound; case 4005: return ApiErrorCode::MethodNotAllowed;
    case 4013: return ApiErrorCode::PayloadTooLarge; case 5000: return ApiErrorCode::ServerError; case 5003: return ApiErrorCode::Maintenance; default: return ApiErrorCode::Unknown;
    }
}

CardKeyClient::CardKeyClient(ClientConfig config, QObject *parent) : QObject(parent), config_(std::move(config)) {
    if (config_.baseUrl.scheme() != QStringLiteral("https") && config_.baseUrl.host() != QStringLiteral("localhost") && config_.baseUrl.host() != QStringLiteral("127.0.0.1")) throw std::invalid_argument("Use HTTPS in production; HTTP only for localhost examples");
}

QNetworkReply *CardKeyClient::verify(const QJsonValue &cardKey, const QString &deviceId) { QJsonObject body{{"card_key", cardKey}}; if (!deviceId.isEmpty()) body["device_id"] = deviceId; return post("verify", body); }
QNetworkReply *CardKeyClient::activate(const QJsonValue &cardKey, const QString &deviceId) { QJsonObject body{{"card_key", cardKey}}; if (!deviceId.isEmpty()) body["device_id"] = deviceId; return post("activate", body); }
QNetworkReply *CardKeyClient::consume(const QJsonValue &cardKey, const QString &deviceId, int count) { if (count < 1 || count > 1000) throw std::invalid_argument("count must be between 1 and 1000"); QJsonObject body{{"card_key", cardKey}, {"count", count}}; if (!deviceId.isEmpty()) body["device_id"] = deviceId; return post("consume", body); }
QNetworkReply *CardKeyClient::query(const QJsonValue &cardKey, const QString &deviceId) { QJsonObject body{{"card_key", cardKey}}; if (!deviceId.isEmpty()) body["device_id"] = deviceId; return post("query", body); }
QNetworkReply *CardKeyClient::unbind(const QJsonValue &cardKey, const QString &deviceId, bool force) { QJsonObject body{{"card_key", cardKey}}; if (!deviceId.isEmpty()) body["device_id"] = deviceId; if (force) body["force"] = true; return post("unbind", body); }

QNetworkReply *CardKeyClient::post(const QString &method, const QJsonObject &body) {
    const QString path = "/api/v1/" + method;
    // Compact JSON is serialized once; these exact bytes are signed and sent.
    const QByteArray rawBody = QJsonDocument(body).toJson(QJsonDocument::Compact);
    const QString timestamp = QString::number(QDateTime::currentSecsSinceEpoch());
    const QString nonce = Signer::generateNonce();
    QNetworkRequest request(config_.baseUrl.resolved(QUrl(path)));
    request.setTransferTimeout(config_.timeoutMs);
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    request.setRawHeader("Accept", "application/json"); request.setRawHeader("X-App-Id", config_.appId.toUtf8());
    request.setRawHeader("X-Timestamp", timestamp.toUtf8()); request.setRawHeader("X-Nonce", nonce.toUtf8());
    request.setRawHeader("X-Signature-Version", "v1"); request.setRawHeader("X-Signature", Signer::signRequest(config_.appSecret, "POST", path, timestamp, nonce, rawBody).toUtf8());
    // No automatic retry: consume has no idempotency key. The caller can create a new request explicitly.
    return manager_.post(request, rawBody);
}

ApiResponse CardKeyClient::parseResponse(QNetworkReply *reply) const {
    const QByteArray rawResponse = reply->readAll();
    const QString responseTimestamp = QString::fromUtf8(reply->rawHeader("X-Response-Timestamp"));
    const QString responseSignature = QString::fromUtf8(reply->rawHeader("X-Response-Signature"));
    const QString requestNonce = QString::fromUtf8(reply->request().rawHeader("X-Nonce"));
    if (config_.requireResponseSignature && reply->error() == QNetworkReply::NoError &&
        (responseTimestamp.isEmpty() || responseSignature.isEmpty())) {
        throw std::runtime_error("响应签名缺失");
    }
    if (!responseTimestamp.isEmpty() && !responseSignature.isEmpty() &&
        !Signer::verifyResponse(config_.appSecret, rawResponse, responseTimestamp, requestNonce, responseSignature)) {
        throw std::runtime_error("响应签名校验失败");
    }
    const QJsonDocument document = QJsonDocument::fromJson(rawResponse);
    if (!document.isObject()) throw std::runtime_error("响应不是合法 JSON 对象");
    const QJsonObject object = document.object();
    ApiResponse result;
    result.code = object.value("code").toInt(-1);
    result.message = object.value("message").toString();
    result.success = object.value("success").toBool(false);
    result.serverTime = object.value("server_time").toVariant().toLongLong();
    result.data = object.value("data");
    result.httpStatus = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    result.responseSignature = responseSignature;
    result.responseTimestamp = responseTimestamp;
    return result;
}

} // namespace cardkey
