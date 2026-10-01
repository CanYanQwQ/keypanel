#include "cardkey/transport_crypto.h"

#include <cstring>
#include <stdexcept>
#include <string>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

namespace {
QByteArray decodeBase64Strict(const QString &value, const char *field) {
    const QByteArray encoded = value.toLatin1();
    const QByteArray decoded = QByteArray::fromBase64(encoded, QByteArray::AbortOnBase64DecodingErrors);
    if (decoded.isNull()) throw std::runtime_error((std::string("Invalid Base64: ") + field).c_str());
    return decoded;
}
}

namespace cardkey {

QByteArray TransportCrypto::deriveKey(const QString &appSecret, const QString &appId) {
    QByteArray output(KeyLength, Qt::Uninitialized);
    const QByteArray salt = appId.toUtf8();
    const QByteArray ikm = appSecret.toUtf8();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx, reinterpret_cast<const unsigned char *>(salt.constData()), salt.size()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx, reinterpret_cast<const unsigned char *>(ikm.constData()), ikm.size()) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx, reinterpret_cast<const unsigned char *>(INFO), static_cast<int>(strlen(INFO))) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("HKDF setup failed");
    }
    size_t length = KeyLength;
    if (EVP_PKEY_derive(ctx, reinterpret_cast<unsigned char *>(output.data()), &length) <= 0 || length != KeyLength) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("HKDF derivation failed");
    }
    EVP_PKEY_CTX_free(ctx);
    return output;
}

TransportPayload TransportCrypto::encrypt(const QString &plaintext, const QString &appSecret, const QString &appId) {
    QByteArray iv(IvLength, Qt::Uninitialized);
    if (RAND_bytes(reinterpret_cast<unsigned char *>(iv.data()), IvLength) != 1) throw std::runtime_error("IV generation failed");
    const QByteArray key = deriveKey(appSecret, appId);
    const QByteArray input = plaintext.toUtf8();
    const QByteArray aad = appId.toUtf8();
    QByteArray ciphertext(input.size(), Qt::Uninitialized);
    QByteArray tag(TagLength, Qt::Uninitialized);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int length = 0, total = 0;
    if (!ctx || EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IvLength, nullptr) <= 0 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, reinterpret_cast<const unsigned char *>(key.constData()), reinterpret_cast<const unsigned char *>(iv.constData())) <= 0 ||
        EVP_EncryptUpdate(ctx, nullptr, &length, reinterpret_cast<const unsigned char *>(aad.constData()), aad.size()) <= 0 ||
        EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char *>(ciphertext.data()), &length, reinterpret_cast<const unsigned char *>(input.constData()), input.size()) <= 0) {
        if (ctx) EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM encryption failed");
    }
    total = length;
    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(ciphertext.data()) + total, &length) <= 0) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("AES-GCM final failed"); }
    total += length;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TagLength, tag.data()) <= 0) { EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("AES-GCM tag failed"); }
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(total);
    return {iv.toBase64(), ciphertext.toBase64(), tag.toBase64()};
}

QString TransportCrypto::decrypt(const TransportPayload &payload, const QString &appSecret, const QString &appId) {
    const QByteArray iv = decodeBase64Strict(payload.iv, "iv");
    const QByteArray ciphertext = decodeBase64Strict(payload.data, "data");
    const QByteArray tag = decodeBase64Strict(payload.tag, "tag");
    if (iv.size() != IvLength || tag.size() != TagLength) throw std::runtime_error("Invalid transport payload lengths");
    const QByteArray key = deriveKey(appSecret, appId);
    const QByteArray aad = appId.toUtf8();
    QByteArray plaintext(ciphertext.size(), Qt::Uninitialized);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int length = 0, total = 0;
    if (!ctx || EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) <= 0 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IvLength, nullptr) <= 0 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, reinterpret_cast<const unsigned char *>(key.constData()), reinterpret_cast<const unsigned char *>(iv.constData())) <= 0 ||
        EVP_DecryptUpdate(ctx, nullptr, &length, reinterpret_cast<const unsigned char *>(aad.constData()), aad.size()) <= 0 ||
        EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char *>(plaintext.data()), &length, reinterpret_cast<const unsigned char *>(ciphertext.constData()), ciphertext.size()) <= 0) {
        if (ctx) EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES-GCM setup failed");
    }
    total = length;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TagLength, const_cast<char *>(tag.constData())) <= 0 ||
        EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(plaintext.data()) + total, &length) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("卡密解密失败：认证标签校验不通过");
    }
    total += length;
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(total);
    return QString::fromUtf8(plaintext);
}

} // namespace cardkey
