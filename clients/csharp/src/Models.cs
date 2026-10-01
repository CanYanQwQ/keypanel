using System;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CardKey.Client;

public static class ApiJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DictionaryKeyPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false,
    };

    public static byte[] SerializeToUtf8Bytes<T>(T value)
        => JsonSerializer.SerializeToUtf8Bytes(value, Options);

    public static ApiResponse<T> DeserializeResponse<T>(ReadOnlySpan<byte> body)
        => JsonSerializer.Deserialize<ApiResponse<T>>(body, Options)
           ?? throw new JsonException("The API returned an empty JSON response.");

    public static ApiResponse<JsonElement> DeserializeUntypedResponse(ReadOnlySpan<byte> body)
        => JsonSerializer.Deserialize<ApiResponse<JsonElement>>(body, Options)
           ?? throw new JsonException("The API returned an empty JSON response.");
}

public sealed class ApiResponse<T>
{
    public int Code { get; init; }
    public string? Message { get; init; }
    public bool Success { get; init; }
    public long ServerTime { get; init; }
    public T? Data { get; init; }
}

public sealed class VerifyRequest
{
    [JsonPropertyName("card_key")]
    public object? CardKey { get; init; }

    [JsonPropertyName("device_id")]
    public string? DeviceId { get; init; }
}

public sealed class ActivateRequest
{
    [JsonPropertyName("card_key")]
    public object? CardKey { get; init; }

    [JsonPropertyName("device_id")]
    public string? DeviceId { get; init; }
}

public sealed class ConsumeRequest
{
    [JsonPropertyName("card_key")]
    public object? CardKey { get; init; }

    [JsonPropertyName("device_id")]
    public string? DeviceId { get; init; }

    public int? Count { get; init; }
}

public sealed class QueryRequest
{
    [JsonPropertyName("card_key")]
    public object? CardKey { get; init; }

    [JsonPropertyName("device_id")]
    public string? DeviceId { get; init; }
}

public sealed class UnbindRequest
{
    [JsonPropertyName("card_key")]
    public object? CardKey { get; init; }

    [JsonPropertyName("device_id")]
    public string? DeviceId { get; init; }

    public bool? Force { get; init; }
}

public sealed class CardData
{
    [JsonPropertyName("card_id")]
    public long? CardId { get; init; }

    public string? Status { get; init; }
    public string? Type { get; init; }

    [JsonPropertyName("activated_at")]
    public DateTimeOffset? ActivatedAt { get; init; }

    [JsonPropertyName("expires_at")]
    public DateTimeOffset? ExpiresAt { get; init; }

    [JsonPropertyName("remaining_seconds")]
    public long? RemainingSeconds { get; init; }

    [JsonPropertyName("remaining_uses")]
    public int? RemainingUses { get; init; }

    [JsonPropertyName("device_bound")]
    public bool DeviceBound { get; init; }

    public bool? Activated { get; init; }
    public int? Consumed { get; init; }
    public int? Remaining { get; init; }
    public bool? Unbound { get; init; }
}

public sealed class ApiException : Exception
{
    public HttpStatusCode HttpStatus { get; }
    public int ApiCode { get; }
    public string? ApiMessage { get; }

    public ApiException(HttpStatusCode httpStatus, int apiCode, string? apiMessage)
        : base($"CardKey API request failed (HTTP {(int)httpStatus}, code {apiCode}).")
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

public sealed record ApiCallResult<T>(
    HttpStatusCode HttpStatus,
    ApiResponse<T> Response,
    bool IsResponseSigned,
    string RequestNonce);
