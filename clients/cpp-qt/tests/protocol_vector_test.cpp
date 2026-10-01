#include <QtTest>
#include "cardkey/signer.h"
#include "cardkey/transport_crypto.h"

class ProtocolVectorTest : public QObject {
    Q_OBJECT
private slots:
    void requestSignatureMatchesSharedVector() {
        const QString secret = QStringLiteral("sk_test_secret_for_vectors_do_not_use");
        const QByteArray body = QByteArrayLiteral("{\"card_key\":\"ABCD-EFGH-JKMN-PQRS\",\"device_id\":\"device-001\"}");
        QCOMPARE(cardkey::Signer::sha256Hex(body), QStringLiteral("d4c470b7b50e407cd4b6bed475392c8da2b45fd470d238fab0b6f4ae4c9861bb"));
        QCOMPARE(cardkey::Signer::signRequest(secret, "POST", "/api/v1/verify", "1700000000", "00112233445566778899aabbccddeeff", body), QStringLiteral("cdce8f8c1999966d94530a5d7c6c7fe5d4c6e84c8b89388386473f0dfeb3a60e"));
    }

    void transportVectorDecryptsAndDerivesExpectedKey() {
        const QString secret = QStringLiteral("sk_test_secret_for_vectors_do_not_use");
        const QString appId = QStringLiteral("ak_test_0000000000000000");
        QCOMPARE(QString::fromLatin1(cardkey::TransportCrypto::deriveKey(secret, appId).toHex()), QStringLiteral("bff2fbbc96525ad71f7e1492b39e1eb22fc76915f55a452dae9c7bd8e8ce8a2a"));
        const cardkey::TransportPayload payload{QStringLiteral("AAECAwQFBgcICQoL"), QStringLiteral("Dpzc19OrLLuiUzBnVjZ58nx01g=="), QStringLiteral("OgQTxDEviBNBjrGdUcPfPw==")};
        QCOMPARE(cardkey::TransportCrypto::decrypt(payload, secret, appId), QStringLiteral("ABCD-EFGH-JKMN-PQRS"));
    }

    void responseSignatureUsesRawResponseAndRequestNonce() {
        const QString secret = QStringLiteral("sk_test_secret_for_vectors_do_not_use");
        const QByteArray response = QByteArrayLiteral("{\"code\":0,\"message\":\"ok\"}");
        const QString signature = cardkey::Signer::sign(secret, cardkey::Signer::responseCanonical("1700000001", "00112233445566778899aabbccddeeff", response));
        QVERIFY(cardkey::Signer::verifyResponse(secret, response, "1700000001", "00112233445566778899aabbccddeeff", signature));
        QVERIFY(!cardkey::Signer::verifyResponse(secret, QByteArrayLiteral("{\"code\":0}"), "1700000001", "00112233445566778899aabbccddeeff", signature));
    }
};

QTEST_MAIN(ProtocolVectorTest)
#include "protocol_vector_test.moc"
