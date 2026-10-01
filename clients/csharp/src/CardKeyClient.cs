using System;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace CardKey.Client;

public sealed class CardKeyClient : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly CardKeyClientOptions _options;
    private readonly bool _ownsHttpClient;

    public CardKeyClient(CardKeyClientOptions options, HttpClient? httpClient = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _options = options;
        _httpClient = httpClient ?? new HttpClient();
        _ownsHttpClient = httpClient is null;
        _httpClient.BaseAddress = options.BaseAddress;
        _httpClient.Timeout = options.Timeout;
    }

    public Task<ApiCallResult<CardData>> VerifyAsync(VerifyRequest request, CancellationToken cancellationToken = default)
        => SendAsync<VerifyRequest, CardData>("/api/v1/verify", request, cancellationToken);

    public Task<ApiCallResult<CardData>> ActivateAsync(ActivateRequest request, CancellationToken cancellationToken = default)
        => SendAsync<ActivateRequest, CardData>("/api/v1/activate", request, cancellationToken);

    public Task<ApiCallResult<CardData>> ConsumeAsync(ConsumeRequest request, CancellationToken cancellationToken = default)
        => SendAsync<ConsumeRequest, CardData>("/api/v1/consume", request, cancellationToken);

    public Task<ApiCallResult<CardData>> QueryAsync(QueryRequest request, CancellationToken cancellationToken = default)
        => SendAsync<QueryRequest, CardData>("/api/v1/query", request, cancellationToken);

    public Task<ApiCallResult<CardData>> UnbindAsync(UnbindRequest request, CancellationToken cancellationToken = default)
        => SendAsync<UnbindRequest, CardData>("/api/v1/unbind", request, cancellationToken);

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }
    }

    private async Task<ApiCallResult<TResponse>> SendAsync<TRequest, TResponse>(string path, TRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var rawBody = ApiJson.SerializeToUtf8Bytes(request);
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        var nonce = ApiSigner.CreateNonce();
        var signature = ApiSigner.SignRequest(_options.AppSecret, "POST", path, timestamp, nonce, rawBody);

        using var content = new ByteArrayContent(rawBody);
        content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
        using var message = new HttpRequestMessage(HttpMethod.Post, path) { Content = content };
        message.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        message.Headers.TryAddWithoutValidation(ApiSigner.AppIdHeader, _options.AppId);
        message.Headers.TryAddWithoutValidation(ApiSigner.TimestampHeader, timestamp);
        message.Headers.TryAddWithoutValidation(ApiSigner.NonceHeader, nonce);
        message.Headers.TryAddWithoutValidation(ApiSigner.SignatureHeader, signature);
        message.Headers.TryAddWithoutValidation(ApiSigner.VersionHeader, ApiSigner.Version);

        using var response = await _httpClient.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        var rawResponseBody = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        var signed = VerifyResponseSignature(response, rawResponseBody, nonce);
        var parsed = ApiJson.DeserializeResponse<TResponse>(rawResponseBody);

        if (!response.IsSuccessStatusCode || !parsed.Success || parsed.Code != 0)
        {
            throw new ApiException(response.StatusCode, parsed.Code, parsed.Message);
        }

        return new ApiCallResult<TResponse>(response.StatusCode, parsed, signed, nonce);
    }

    private bool VerifyResponseSignature(HttpResponseMessage response, byte[] rawBody, string requestNonce)
    {
        var responseTimestamp = response.Headers.TryGetValues(ApiSigner.ResponseTimestampHeader, out var timestamps)
            ? timestamps is null ? null : System.Linq.Enumerable.SingleOrDefault(timestamps)
            : null;
        var responseSignature = response.Headers.TryGetValues(ApiSigner.ResponseSignatureHeader, out var signatures)
            ? signatures is null ? null : System.Linq.Enumerable.SingleOrDefault(signatures)
            : null;

        if (string.IsNullOrWhiteSpace(responseTimestamp) && string.IsNullOrWhiteSpace(responseSignature))
        {
            if (_options.RequireSignedResponses)
            {
                throw new ResponseSignatureException("The API response did not contain a response signature.");
            }

            return false;
        }

        if (string.IsNullOrWhiteSpace(responseTimestamp) || string.IsNullOrWhiteSpace(responseSignature))
        {
            throw new ResponseSignatureException("The API response contained incomplete signature headers.");
        }

        if (!ApiSigner.VerifyResponse(_options.AppSecret, rawBody, responseTimestamp, requestNonce, responseSignature))
        {
            throw new ResponseSignatureException("The API response signature was invalid.");
        }

        return true;
    }
}
