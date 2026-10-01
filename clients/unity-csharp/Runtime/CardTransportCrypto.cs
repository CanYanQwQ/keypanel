using System;
using System.Security.Cryptography;
using System.Text;

namespace CardKey.Unity;

[Serializable]
public sealed class EncryptedCardKey
{
    public string iv = string.Empty;
    public string data = string.Empty;
    public string tag = string.Empty;

    public EncryptedCardKey() { }

    public EncryptedCardKey(string iv, string data, string tag)
    {
        this.iv = iv;
        this.data = data;
        this.tag = tag;
    }
}

public static class CardTransportCrypto
{
    public const string Info = "cardkey-enc-v1";
    public const int IvLength = 12;
    public const int TagLength = 16;
    public const int KeyLength = 32;

    public static byte[] DeriveKey(string appSecret, string appId)
    {
        if (string.IsNullOrEmpty(appSecret)) throw new ArgumentException("AppSecret is required.", nameof(appSecret));
        if (string.IsNullOrEmpty(appId)) throw new ArgumentException("AppId is required.", nameof(appId));
        return HkdfSha256.Derive(Encoding.UTF8.GetBytes(appSecret), Encoding.UTF8.GetBytes(appId), Encoding.UTF8.GetBytes(Info), KeyLength);
    }

    public static EncryptedCardKey EncryptCardKey(string plaintext, string appSecret, string appId)
    {
        var iv = new byte[IvLength];
        using (var random = RandomNumberGenerator.Create()) random.GetBytes(iv);
        return EncryptWithIv(plaintext, appSecret, appId, iv);
    }

    public static string DecryptCardKey(EncryptedCardKey payload, string appSecret, string appId)
    {
        if (payload == null) throw new ArgumentNullException(nameof(payload));
        var iv = Decode(payload.iv, "iv");
        var data = Decode(payload.data, "data");
        var tag = Decode(payload.tag, "tag");
        if (iv.Length != IvLength) throw new CryptographicException("Invalid IV length.");
        if (tag.Length != TagLength) throw new CryptographicException("Invalid GCM tag length.");

        var plaintext = new byte[data.Length];
        try
        {
            using (var aes = new AesGcm(DeriveKey(appSecret, appId), TagLength))
            {
                aes.Decrypt(iv, data, tag, plaintext, Encoding.UTF8.GetBytes(appId));
            }
        }
        catch (CryptographicException)
        {
            throw new CryptographicException("Card-key transport authentication failed.");
        }
        return Encoding.UTF8.GetString(plaintext);
    }

    internal static EncryptedCardKey EncryptWithIv(string plaintext, string appSecret, string appId, byte[] iv)
    {
        if (iv.Length != IvLength) throw new ArgumentException("IV must contain 12 bytes.", nameof(iv));
        var plain = Encoding.UTF8.GetBytes(plaintext);
        var data = new byte[plain.Length];
        var tag = new byte[TagLength];
        using (var aes = new AesGcm(DeriveKey(appSecret, appId), TagLength))
        {
            aes.Encrypt(iv, plain, data, tag, Encoding.UTF8.GetBytes(appId));
        }
        return new EncryptedCardKey(Convert.ToBase64String(iv), Convert.ToBase64String(data), Convert.ToBase64String(tag));
    }

    internal static EncryptedCardKey EncryptWithIvForTesting(string plaintext, string appSecret, string appId, byte[] iv)
        => EncryptWithIv(plaintext, appSecret, appId, iv);

    private static byte[] Decode(string value, string field)
    {
        try { return Convert.FromBase64String(value); }
        catch (FormatException e) { throw new CryptographicException("Encrypted card-key field is invalid: " + field, e); }
    }
}
