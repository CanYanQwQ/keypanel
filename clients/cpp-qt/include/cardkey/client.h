#pragma once

#include <QObject>
#include <QJsonObject>
#include <QJsonValue>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QUrl>
#include <QString>
#include "transport_crypto.h"

namespace cardkey {

enum class ApiErrorCode : int {
    Success = 0, InvalidParams = 1001, AppNotFound = 1002, AppDisabled = 1003, SignatureInvalid = 1004,
    TimestampExpired = 1005, NonceReused = 1006, IpNotAllowed = 1007, RateLimited = 1008,
    DailyQuotaExceeded = 1009, MissingCredentials = 1010, DecryptFailed = 1011, CardNotFound = 2001,
    CardDisabled = 2002, CardExpired = 2003, CardNotActivated = 2004, CardDepleted = 2005,
    CardAlreadyActivated = 2006, DeviceMismatch = 2007, DeviceNotBound = 2008, CardNotBoundToApp = 2009,
    CardTypeUnsupported = 2010, CardAlreadyDisabled = 2011, NotFound = 4004, MethodNotAllowed = 4005,
    PayloadTooLarge = 4013, ServerError = 5000, Maintenance = 5003, Unknown = -1
};

struct ApiResponse {
    int code = -1;
    QString message;
    bool success = false;
    qint64 serverTime = 0;
    QJsonValue data;
    int httpStatus = 0;
    QString responseSignature;
    QString responseTimestamp;
    ApiErrorCode error() const;
    bool isBusinessSuccess() const { return success && code == 0; }
};

struct ClientConfig {
    QUrl baseUrl;
    QString appId;
    QString appSecret;
    int timeoutMs = 15000;
    bool requireResponseSignature = true;
};

class CardKeyClient : public QObject {
public:
    explicit CardKeyClient(ClientConfig config, QObject *parent = nullptr);
    QNetworkReply *verify(const QJsonValue &cardKey, const QString &deviceId = {});
    QNetworkReply *activate(const QJsonValue &cardKey, const QString &deviceId = {});
    QNetworkReply *consume(const QJsonValue &cardKey, const QString &deviceId = {}, int count = 1);
    QNetworkReply *query(const QJsonValue &cardKey, const QString &deviceId = {});
    QNetworkReply *unbind(const QJsonValue &cardKey, const QString &deviceId = {}, bool force = false);
    ApiResponse parseResponse(QNetworkReply *reply) const;
private:
    QNetworkReply *post(const QString &method, const QJsonObject &body);
    ClientConfig config_;
    QNetworkAccessManager manager_;
};

} // namespace cardkey
