using System;
using System.Security.Cryptography;
using System.Text;

namespace CardKey.Client;

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
        if (bytes < 16)
        {
            throw new ArgumentOutOfRangeException(nameof(bytes), "Nonce must contain at least 16 random bytes.");
        }

        return Convert.ToHexString(RandomNumberGenerator.GetBytes(bytes)).ToLowerInvariant();
    }

    public static string CanonicalRequest(string method, string path, string timestamp, string nonce, ReadOnlySpan<byte> rawBody)
    {
        return string.Join('\n',
            method.ToUpperInvariant(),
            NormalizePath(path),
            timestamp,
            nonce,
            Sha256Hex(rawBody));
    }

    public static string SignRequest(string appSecret, string method, string path, string timestamp, string nonce, ReadOnlySpan<byte> rawBody)
    {
        return Sign(appSecret, CanonicalRequest(method, path, timestamp, nonce, rawBody));
    }

    public static string SignResponse(string appSecret, ReadOnlySpan<byte> rawBody, string responseTimestamp, string requestNonce)
    {
        var canonical = string.Join('\n', responseTimestamp, requestNonce, Sha256Hex(rawBody));
        return Sign(appSecret, canonical);
    }

    public static bool VerifyResponse(string appSecret, ReadOnlySpan<byte> rawBody, string responseTimestamp, string requestNonce, string signature)
    {
        if (!TryDecodeHex(signature, out var actual) || actual.Length != 32)
        {
            return false;
        }

        var expected = Convert.FromHexString(SignResponse(appSecret, rawBody, responseTimestamp, requestNonce));
        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    public static string Sign(string appSecret, string canonical)
    {
        var key = Encoding.UTF8.GetBytes(appSecret);
        var data = Encoding.UTF8.GetBytes(canonical);
        return Convert.ToHexString(HMACSHA256.HashData(key, data)).ToLowerInvariant();
    }

    public static string NormalizePath(string path)
    {
        var end = path.IndexOfAny(['?', '#']);
        if (end >= 0)
        {
            path = path[..end];
        }

        if (string.IsNullOrEmpty(path))
        {
            return "/";
        }

        var builder = new StringBuilder(path.Length);
        var previousSlash = false;
        foreach (var character in path)
        {
            if (character == '/')
            {
                if (previousSlash)
                {
                    continue;
                }

                previousSlash = true;
            }
            else
            {
                previousSlash = false;
            }

            builder.Append(character);
        }

        var normalized = builder.ToString();
        return normalized.Length > 1 ? normalized.TrimEnd('/') : normalized;
    }

    private static string Sha256Hex(ReadOnlySpan<byte> bytes)
        => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static bool TryDecodeHex(string text, out byte[] bytes)
    {
        try
        {
            bytes = Convert.FromHexString(text.Trim());
            return true;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }
}
