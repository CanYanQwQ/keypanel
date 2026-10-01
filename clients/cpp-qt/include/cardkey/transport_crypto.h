#pragma once

#include <QByteArray>
#include <QString>

namespace cardkey {

struct TransportPayload {
    QString iv;
    QString data;
    QString tag;
};

class TransportCrypto {
public:
    static constexpr int IvLength = 12;
    static constexpr int TagLength = 16;
    static constexpr int KeyLength = 32;
    static QByteArray deriveKey(const QString &appSecret, const QString &appId);
    static TransportPayload encrypt(const QString &plaintext, const QString &appSecret, const QString &appId);
    static QString decrypt(const TransportPayload &payload, const QString &appSecret, const QString &appId);
};

} // namespace cardkey
