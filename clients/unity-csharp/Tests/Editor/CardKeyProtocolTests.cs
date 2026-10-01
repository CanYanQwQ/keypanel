using System;
using System.Security.Cryptography;
using System.Text;
using NUnit.Framework;

namespace CardKey.Unity.Tests;

public sealed class CardKeyProtocolTests
{
    [Test]
    public void RequestSignatureMatchesServerVector()
    {
        const string body = "{\"card_key\":\"CARD-EXAMPLE\",\"device_id\":\"device-001\"}";
        const string expected = "42b8ab8d1c81c41609a206fefa6bffcc384fb5480e4f312f18e2401e6f0ca652";
        var signature = ApiSigner.SignRequest("secret-example", "post", "/api//v1/verify?ignored=yes", "1700000000", "00112233445566778899aabbccddeeff", Encoding.UTF8.GetBytes(body));
        Assert.That(signature, Is.EqualTo(expected));
    }

    [Test]
    public void ResponseSignatureUsesRawBodyAndOriginalNonce()
    {
        const string body = "{\"code\":0,\"message\":\"操作成功\",\"success\":true,\"server_time\":1700000000,\"data\":{\"status\":\"unused\"}}";
        const string nonce = "00112233445566778899aabbccddeeff";
        const string expected = "e404631865daf3502a1adc751ca7168ad7b0f4f2fad022798f5664bf05a47874";
        var raw = Encoding.UTF8.GetBytes(body);
        var signature = ApiSigner.SignResponse("secret-example", raw, "1700000001", nonce);

        Assert.That(signature, Is.EqualTo(expected));
        Assert.That(ApiSigner.VerifyResponse("secret-example", raw, "1700000001", nonce, signature.ToUpperInvariant()), Is.True);
        Assert.That(ApiSigner.VerifyResponse("secret-example", raw, "1700000001", nonce + "x", signature), Is.False);
    }

    [Test]
    public void Rfc5869HkdfMatchesKnownVector()
    {
        var ikm = HexCodec.Decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        var salt = HexCodec.Decode("000102030405060708090a0b0c");
        var info = HexCodec.Decode("f0f1f2f3f4f5f6f7f8f9");
        const string expectedHex = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
        var actual = HkdfSha256.Derive(ikm, salt, info, 42);
        Assert.That(HexCodec.EncodeLower(actual), Is.EqualTo(expectedHex));
    }

    [Test]
    public void CardTransportMatchesFixedAesGcmVector()
    {
        var iv = HexCodec.Decode("00112233445566778899aabb");
        var payload = CardTransportCrypto.EncryptWithIvForTesting("CARD-EXAMPLE", "app-secret-vector", "ak_vector", iv);
        Assert.That(payload.iv, Is.EqualTo("ABEiM0RVZneImaq7"));
        Assert.That(payload.data, Is.EqualTo("4RQoywLAvA9x6XJC"));
        Assert.That(payload.tag, Is.EqualTo("2QHtTZb5PG+8QNIAF/zU4Q=="));
        Assert.That(CardTransportCrypto.DecryptCardKey(payload, "app-secret-vector", "ak_vector"), Is.EqualTo("CARD-EXAMPLE"));
    }

    [Test]
    public void CardTransportRejectsChangedAuthenticationData()
    {
        var payload = new EncryptedCardKey("ABEiM0RVZneImaq7", "4RQoywLAvA9x6XJC", "2QHtTZb5PG+8QNIAF/zU4Q==");
        payload.tag = "2QHtTZb5PG+8QNIAF/zU4A==";
        Assert.Throws<CryptographicException>(() => CardTransportCrypto.DecryptCardKey(payload, "app-secret-vector", "ak_vector"));
    }

    [Test]
    public void RequestJsonKeepsProtocolKeyOrderAndRawBytes()
    {
        var request = new VerifyRequest
        {
            CardKey = CardKeyInput.FromPlaintext("CARD-EXAMPLE"),
            DeviceId = "device-001",
        };
        var body = request.ToJsonBytes();
        Assert.That(Encoding.UTF8.GetString(body), Is.EqualTo("{\"card_key\":\"CARD-EXAMPLE\",\"device_id\":\"device-001\"}"));
    }
}
