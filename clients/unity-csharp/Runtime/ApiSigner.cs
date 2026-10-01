using System;
using System.Security.Cryptography;
using System.Text;

namespace CardKey.Unity;

public static class ApiSigner
{
    public const string Version = "v1";
    public const string AppIdHeader = "X-App-Id";
    public const string TimestampHeader = "X-Timestamp";
    public const string NonceHeader = "X-Nonce";
    public const string SignatureHeader = "X-Signature";
    public const string VersionHeader = "X-Signature-Version";
    public const string ResponseTimestampHeader = "X-Response-Timestamp";
    public const string ResponseSignatureHeader = "X-Response-Signature";

    public static string CreateNonce(int bytes = 16)
    {
        if (bytes < 16) throw new ArgumentOutOfRangeException(nameof(bytes));
        var value = new byte[bytes];
        using (var random = RandomNumberGenerator.Create()) random.GetBytes(value);
        return HexCodec.EncodeLower(value);
    }

    public static string SignRequest(string appSecret, string method, string path, string timestamp, string nonce, byte[] rawBody)
    {
        var canonical = string.Join("\n", method.ToUpperInvariant(), NormalizePath(path), timestamp, nonce, Sha256Hex(rawBody));
        return Sign(appSecret, canonical);
    }

    public static string SignResponse(string appSecret, byte[] rawResponseBody, string responseTimestamp, string requestNonce)
        => Sign(appSecret, string.Join("\n", responseTimestamp, requestNonce, Sha256Hex(rawResponseBody)));

    public static bool VerifyResponse(string appSecret, byte[] rawResponseBody, string responseTimestamp, string requestNonce, string signature)
    {
        try
        {
            var actual = HexCodec.Decode(signature.Trim());
            var expected = HexCodec.Decode(SignResponse(appSecret, rawResponseBody, responseTimestamp, requestNonce));
            return actual.Length == expected.Length && CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static string Sign(string appSecret, string canonical)
        => HexCodec.EncodeLower(HmacSha256(Encoding.UTF8.GetBytes(appSecret), Encoding.UTF8.GetBytes(canonical)));

    public static string NormalizePath(string path)
    {
        var end = path.IndexOfAny(new[] { '?', '#' });
        if (end >= 0) path = path.Substring(0, end);
        if (string.IsNullOrEmpty(path)) return "/";

        var builder = new StringBuilder(path.Length);
        var previousSlash = false;
        foreach (var c in path)
        {
            if (c == '/')
            {
                if (previousSlash) continue;
                previousSlash = true;
            }
            else previousSlash = false;
            builder.Append(c);
        }

        var normalized = builder.ToString();
        return normalized.Length > 1 ? normalized.TrimEnd('/') : normalized;
    }

    private static string Sha256Hex(byte[] bytes)
    {
        using (var sha = SHA256.Create()) return HexCodec.EncodeLower(sha.ComputeHash(bytes));
    }

    private static byte[] HmacSha256(byte[] key, byte[] data)
    {
        using (var hmac = new HMACSHA256(key)) return hmac.ComputeHash(data);
    }
}
