using System;
using System.Security.Cryptography;
using System.Text;

namespace CardKey.Client;

public sealed record EncryptedCardKey(string Iv, string Data, string Tag);

public static class CardTransportCrypto
{
    public const string Info = "cardkey-enc-v1";
    public const int IvLength = 12;
    public const int TagLength = 16;
    public const int KeyLength = 32;

    public static byte[] DeriveKey(string appSecret, string appId)
    {
        ArgumentException.ThrowIfNullOrEmpty(appSecret);
        ArgumentException.ThrowIfNullOrEmpty(appId);

        var output = new byte[KeyLength];
        HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            Encoding.UTF8.GetBytes(appSecret),
            output,
            Encoding.UTF8.GetBytes(appId),
            Encoding.UTF8.GetBytes(Info));
        return output;
    }

    public static EncryptedCardKey EncryptCardKey(string plaintext, string appSecret, string appId)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        var iv = RandomNumberGenerator.GetBytes(IvLength);
        return EncryptWithRawIv(plaintext, appSecret, appId, iv);
    }

    public static string DecryptCardKey(EncryptedCardKey payload, string appSecret, string appId)
    {
        ArgumentNullException.ThrowIfNull(payload);
        var iv = DecodeBase64(payload.Iv, "iv");
        var ciphertext = DecodeBase64(payload.Data, "data");
        var tag = DecodeBase64(payload.Tag, "tag");

        if (iv.Length != IvLength)
        {
            throw new CryptographicException($"Invalid IV length; expected {IvLength} bytes.");
        }

        if (tag.Length != TagLength)
        {
            throw new CryptographicException($"Invalid GCM tag length; expected {TagLength} bytes.");
        }

        var plaintext = new byte[ciphertext.Length];
        try
        {
            using var aes = new AesGcm(DeriveKey(appSecret, appId), TagLength);
            aes.Decrypt(iv, ciphertext, tag, plaintext, Encoding.UTF8.GetBytes(appId));
        }
        catch (CryptographicException)
        {
            throw new CryptographicException("Card-key transport authentication failed.");
        }

        return Encoding.UTF8.GetString(plaintext);
    }

    internal static byte[] DeriveHkdfForTesting(byte[] ikm, byte[] salt, byte[] info, int length)
    {
        var output = new byte[length];
        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, output, salt, info);
        return output;
    }

    internal static EncryptedCardKey EncryptWithIvForTesting(string plaintext, string appSecret, string appId, byte[] iv)
        => EncryptWithRawIv(plaintext, appSecret, appId, iv);

    private static EncryptedCardKey EncryptWithRawIv(string plaintext, string appSecret, string appId, byte[] iv)
    {
        if (iv.Length != IvLength)
        {
            throw new ArgumentException($"IV must contain exactly {IvLength} bytes.", nameof(iv));
        }

        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[TagLength];
        using var aes = new AesGcm(DeriveKey(appSecret, appId), TagLength);
        aes.Encrypt(iv, plaintextBytes, ciphertext, tag, Encoding.UTF8.GetBytes(appId));

        return new EncryptedCardKey(
            Convert.ToBase64String(iv),
            Convert.ToBase64String(ciphertext),
            Convert.ToBase64String(tag));
    }

    private static byte[] DecodeBase64(string value, string field)
    {
        try
        {
            return Convert.FromBase64String(value);
        }
        catch (FormatException exception)
        {
            throw new CryptographicException($"Encrypted card-key field '{field}' is not valid Base64.", exception);
        }
    }
}
