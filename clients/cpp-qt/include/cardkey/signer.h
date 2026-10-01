#pragma once

#include <QByteArray>
#include <QRegularExpression>
#include <QString>

namespace cardkey {

class Signer {
public:
    static QString normalizePath(const QString &path);
    static QByteArray sha256(const QByteArray &raw);
    static QString sha256Hex(const QByteArray &raw);
    static QString canonicalString(const QString &method, const QString &path, const QString &timestamp,
                                   const QString &nonce, const QByteArray &rawBody);
    static QString sign(const QString &appSecret, const QString &canonical);
    static QString signRequest(const QString &appSecret, const QString &method, const QString &path,
                               const QString &timestamp, const QString &nonce, const QByteArray &rawBody);
    static QString responseCanonical(const QString &timestamp, const QString &requestNonce, const QByteArray &rawResponse);
    static bool verifyResponse(const QString &appSecret, const QByteArray &rawResponse,
                               const QString &responseTimestamp, const QString &requestNonce,
                               const QString &signature);
    static QString generateNonce(int bytes = 16);
};

} // namespace cardkey
