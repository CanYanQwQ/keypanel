using System;
using System.Text;

namespace CardKey.Client.Tests;

internal static class ProtocolVectorTests
{
    public static void RunAll()
    {
        RequestSignatureVector();
        ResponseSignatureVector();
        Rfc5869HkdfVector();
        CardTransportEncryptionVector();
        ModelSerializationVector();
        Console.WriteLine("Protocol vectors: PASS");
    }

    private static void RequestSignatureVector()
    {
        const string body = "{\"card_key\":\"CARD-EXAMPLE\",\"device_id\":\"device-001\"}";
        const string expectedBodyHash = "76144fef3685250dc577c169a0911814c55331344eb0eb0ec1a009705fba98da";
        const string expectedSignature = "42b8ab8d1c81c41609a206fefa6bffcc384fb5480e4f312f18e2401e6f0ca652";

        var canonical = ApiSigner.CanonicalRequest(
            "post",
            "/api//v1/verify?ignored=yes",
            "1700000000",
            "00112233445566778899aabbccddeeff",
            Encoding.UTF8.GetBytes(body));

        Assert(canonical.EndsWith(expectedBodyHash, StringComparison.Ordinal), "request body hash");
        Assert(ApiSigner.Sign("secret-example", canonical) == expectedSignature, "request signature");
    }

    private static void ResponseSignatureVector()
    {
        const string response = "{\"code\":0,\"message\":\"操作成功\",\"success\":true,\"server_time\":1700000000,\"data\":{\"status\":\"unused\"}}";
        const string expected = "e404631865daf3502a1adc751ca7168ad7b0f4f2fad022798f5664bf05a47874";

        var signature = ApiSigner.SignResponse(
            "secret-example",
            Encoding.UTF8.GetBytes(response),
            "1700000001",
            "00112233445566778899aabbccddeeff");

        Assert(signature == expected, "response signature");
        Assert(ApiSigner.VerifyResponse(
            "secret-example",
            Encoding.UTF8.GetBytes(response),
            "1700000001",
            "00112233445566778899aabbccddeeff",
            signature.ToUpperInvariant()), "response signature verification");
    }

    private static void Rfc5869HkdfVector()
    {
        var ikm = Convert.FromHexString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        var salt = Convert.FromHexString("000102030405060708090a0b0c");
        var info = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9");
        const string expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

        Assert(Convert.ToHexString(CardTransportCrypto.DeriveHkdfForTesting(ikm, salt, info, 42)).ToLowerInvariant() == expected, "RFC5869 HKDF");
    }

    private static void CardTransportEncryptionVector()
    {
        const string appId = "ak_vector";
        const string appSecret = "app-secret-vector";
        var iv = Convert.FromHexString("00112233445566778899aabb");
        var encrypted = CardTransportCrypto.EncryptWithIvForTesting("CARD-EXAMPLE", appSecret, appId, iv);

        Assert(encrypted.Iv == "ABEiM0RVZneImaq7", "transport IV");
        Assert(encrypted.Data == "4RQoywLAvA9x6XJC", "transport ciphertext");
        Assert(encrypted.Tag == "2QHtTZb5PG+8QNIAF/zU4Q==", "transport tag");
        Assert(CardTransportCrypto.DecryptCardKey(encrypted, appSecret, appId) == "CARD-EXAMPLE", "transport round-trip");
    }

    private static void ModelSerializationVector()
    {
        var request = new VerifyRequest { CardKey = "CARD-EXAMPLE", DeviceId = "device-001" };
        var body = ApiJson.SerializeToUtf8Bytes(request);
        var expected = "{\"card_key\":\"CARD-EXAMPLE\",\"device_id\":\"device-001\"}";
        Assert(Encoding.UTF8.GetString(body) == expected, "request JSON bytes");
    }

    private static void Assert(bool condition, string name)
    {
        if (!condition)
        {
            throw new InvalidOperationException($"Vector failed: {name}");
        }
    }
}
