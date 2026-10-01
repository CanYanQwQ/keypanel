#include "cardkey/signer.h"

#include <QCryptographicHash>
#include <QRandomGenerator>
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace cardkey {

QString Signer::normalizePath(const QString &path) {
    QString value = path.section(QRegularExpression("[?#]"), 0, 0);
    if (value.isEmpty()) return "/";
    value.replace(QRegularExpression("/{2,}"), "/");
    if (value.size() > 1) value.remove(QRegularExpression("/+$"));
    return value.isEmpty() ? "/" : value;
}

QByteArray Signer::sha256(const QByteArray &raw) {
    return QCryptographicHash::hash(raw, QCryptographicHash::Sha256);
}

QString Signer::sha256Hex(const QByteArray &raw) {
    return QString::fromLatin1(sha256(raw).toHex());
}

QString Signer::canonicalString(const QString &method, const QString &path, const QString &timestamp,
                                const QString &nonce, const QByteArray &rawBody) {
    return QStringList{method.toUpper(), normalizePath(path), timestamp, nonce, sha256Hex(rawBody)}.join('\n');
}

QString Signer::sign(const QString &appSecret, const QString &canonical) {
    const QByteArray key = appSecret.toUtf8();
    const QByteArray data = canonical.toUtf8();
    unsigned int length = 0;
    unsigned char output[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha256(), key.constData(), key.size(), reinterpret_cast<const unsigned char *>(data.constData()), data.size(), output, &length);
    return QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(output), static_cast<int>(length)).toHex());
}

QString Signer::signRequest(const QString &appSecret, const QString &method, const QString &path,
                            const QString &timestamp, const QString &nonce, const QByteArray &rawBody) {
    return sign(appSecret, canonicalString(method, path, timestamp, nonce, rawBody));
}

QString Signer::responseCanonical(const QString &timestamp, const QString &requestNonce, const QByteArray &rawResponse) {
    return QStringList{timestamp, requestNonce, sha256Hex(rawResponse)}.join('\n');
}

bool Signer::verifyResponse(const QString &appSecret, const QByteArray &rawResponse,
                            const QString &responseTimestamp, const QString &requestNonce,
                            const QString &signature) {
    return sign(appSecret, responseCanonical(responseTimestamp, requestNonce, rawResponse)).compare(signature.trimmed(), Qt::CaseInsensitive) == 0;
}

QString Signer::generateNonce(int bytes) {
    if (bytes <= 0) return {};
    QByteArray value(bytes, Qt::Uninitialized);
    for (int i = 0; i < bytes; ++i) value[i] = static_cast<char>(QRandomGenerator::system()->generate() & 0xff);
    return QString::fromLatin1(value.toHex());
}

} // namespace cardkey
