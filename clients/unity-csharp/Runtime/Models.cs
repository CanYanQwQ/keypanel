using System;
using System.Text;
using UnityEngine;

namespace CardKey.Unity;

[Serializable]
public sealed class CardKeyClientOptions
{
    public string BaseUrl = "https://example.invalid";
    public string AppId = "REPLACE_WITH_APP_ID";
    public string AppSecret = "REPLACE_WITH_APP_SECRET";
    public bool RequireSignedResponses = true;
    public int TimeoutSeconds = 15;

    public void Validate()
    {
        Uri uri;
        if (!Uri.TryCreate(BaseUrl, UriKind.Absolute, out uri)) throw new ArgumentException("BaseUrl is invalid.");
        if (uri.Scheme != Uri.UriSchemeHttps && uri.Host != "localhost" && uri.Host != "127.0.0.1" && uri.Host != "::1")
            throw new ArgumentException("BaseUrl must use HTTPS outside local development.");
        if (string.IsNullOrWhiteSpace(AppId)) throw new ArgumentException("AppId is required.");
        if (string.IsNullOrWhiteSpace(AppSecret)) throw new ArgumentException("AppSecret is required.");
        if (TimeoutSeconds <= 0) throw new ArgumentException("TimeoutSeconds must be positive.");
    }
}

[Serializable]
public sealed class CardKeyInput
{
    [NonSerialized] public string Plaintext;
    [NonSerialized] public EncryptedCardKey Encrypted;

    public static CardKeyInput FromPlaintext(string value)
    {
        if (string.IsNullOrEmpty(value)) throw new ArgumentException("Card key is required.", nameof(value));
        return new CardKeyInput { Plaintext = value };
    }

    public static CardKeyInput FromEncrypted(EncryptedCardKey value)
    {
        if (value == null) throw new ArgumentNullException(nameof(value));
        return new CardKeyInput { Encrypted = value };
    }

    internal string ToJsonFragment()
    {
        if (Plaintext != null) return JsonCodec.Quote(Plaintext);
        if (Encrypted != null) return JsonCodec.EncryptedCardKey(Encrypted);
        throw new InvalidOperationException("Card key input is empty.");
    }
}

[Serializable]
public sealed class VerifyRequest
{
    [NonSerialized] public CardKeyInput CardKey;
    [NonSerialized] public string DeviceId;

    public byte[] ToJsonBytes() => JsonCodec.SerializeCardRequest(CardKey, DeviceId, null, null);
}

[Serializable]
public sealed class ActivateRequest
{
    [NonSerialized] public CardKeyInput CardKey;
    [NonSerialized] public string DeviceId;

    public byte[] ToJsonBytes() => JsonCodec.SerializeCardRequest(CardKey, DeviceId, null, null);
}

[Serializable]
public sealed class ConsumeRequest
{
    [NonSerialized] public CardKeyInput CardKey;
    [NonSerialized] public string DeviceId;
    [NonSerialized] public int? Count;

    public byte[] ToJsonBytes() => JsonCodec.SerializeCardRequest(CardKey, DeviceId, Count, null);
}

[Serializable]
public sealed class QueryRequest
{
    [NonSerialized] public CardKeyInput CardKey;
    [NonSerialized] public string DeviceId;

    public byte[] ToJsonBytes() => JsonCodec.SerializeCardRequest(CardKey, DeviceId, null, null);
}

[Serializable]
public sealed class UnbindRequest
{
    [NonSerialized] public CardKeyInput CardKey;
    [NonSerialized] public string DeviceId;
    [NonSerialized] public bool? Force;

    public byte[] ToJsonBytes() => JsonCodec.SerializeCardRequest(CardKey, DeviceId, null, Force);
}

[Serializable]
public sealed class ApiResponse
{
    public int code;
    public string message;
    public bool success;
    public long server_time;
    public CardData data;
}

[Serializable]
public sealed class CardData
{
    public long card_id;
    public string status;
    public string type;
    public string activated_at;
    public string expires_at;
    public long remaining_seconds;
    public int remaining_uses;
    public bool device_bound;
    public bool activated;
    public int consumed;
    public int remaining;
    public bool unbound;
}

public sealed class ApiException : Exception
{
    public long HttpStatus { get; private set; }
    public int ApiCode { get; private set; }
    public string ApiMessage { get; private set; }

    public ApiException(long httpStatus, int apiCode, string apiMessage)
        : base(string.Format("CardKey API request failed (HTTP {0}, code {1}).", httpStatus, apiCode))
    {
        HttpStatus = httpStatus;
        ApiCode = apiCode;
        ApiMessage = apiMessage;
    }
}

public sealed class ResponseSignatureException : Exception
{
    public ResponseSignatureException(string message) : base(message) { }
}

public sealed class ApiCallResult
{
    public long HttpStatus { get; private set; }
    public ApiResponse Response { get; private set; }
    public bool IsResponseSigned { get; private set; }
    public string RequestNonce { get; private set; }

    public ApiCallResult(long httpStatus, ApiResponse response, bool isResponseSigned, string requestNonce)
    {
        HttpStatus = httpStatus;
        Response = response;
        IsResponseSigned = isResponseSigned;
        RequestNonce = requestNonce;
    }
}

internal static class JsonCodec
{
    public static byte[] SerializeCardRequest(CardKeyInput cardKey, string deviceId, int? count, bool? force)
    {
        if (cardKey == null) throw new ArgumentNullException(nameof(cardKey));
        var builder = new StringBuilder(128);
        builder.Append("{\"card_key\":").Append(cardKey.ToJsonFragment());
        if (deviceId != null) builder.Append(",\"device_id\":").Append(Quote(deviceId));
        if (count.HasValue) builder.Append(",\"count\":").Append(count.Value);
        if (force.HasValue) builder.Append(",\"force\":").Append(force.Value ? "true" : "false");
        builder.Append('}');
        return Encoding.UTF8.GetBytes(builder.ToString());
    }

    public static string Quote(string value)
    {
        if (value == null) return "null";
        var builder = new StringBuilder(value.Length + 2);
        builder.Append('"');
        foreach (var character in value)
        {
            switch (character)
            {
                case '"': builder.Append("\\\""); break;
                case '\\': builder.Append("\\\\"); break;
                case '\b': builder.Append("\\b"); break;
                case '\f': builder.Append("\\f"); break;
                case '\n': builder.Append("\\n"); break;
                case '\r': builder.Append("\\r"); break;
                case '\t': builder.Append("\\t"); break;
                default:
                    if (character < 0x20) builder.AppendFormat("\\u{0:x4}", (int)character);
                    else builder.Append(character);
                    break;
            }
        }
        builder.Append('"');
        return builder.ToString();
    }

    public static string EncryptedCardKey(EncryptedCardKey value)
    {
        if (string.IsNullOrEmpty(value.iv) || string.IsNullOrEmpty(value.data) || string.IsNullOrEmpty(value.tag))
            throw new ArgumentException("Encrypted card-key payload is incomplete.", nameof(value));
        return string.Concat("{\"iv\":", Quote(value.iv), ",\"data\":", Quote(value.data), ",\"tag\":", Quote(value.tag), "}");
    }

    public static ApiResponse DeserializeResponse(byte[] rawBody)
    {
        var response = JsonUtility.FromJson<ApiResponse>(Encoding.UTF8.GetString(rawBody));
        if (response == null) throw new InvalidOperationException("The API returned an empty JSON response.");
        return response;
    }
}
