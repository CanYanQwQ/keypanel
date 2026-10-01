using System;
using System.Net.Http;

namespace CardKey.Client;

public sealed class CardKeyClientOptions
{
    public required Uri BaseAddress { get; init; }
    public required string AppId { get; init; }
    public required string AppSecret { get; init; }
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(15);
    public bool RequireSignedResponses { get; init; } = true;

    internal void Validate()
    {
        if (!BaseAddress.IsAbsoluteUri || (BaseAddress.Scheme != Uri.UriSchemeHttps && BaseAddress.Host is not ("localhost" or "127.0.0.1" or "::1")))
        {
            throw new ArgumentException("BaseAddress must use HTTPS outside a local development host.", nameof(BaseAddress));
        }

        if (string.IsNullOrWhiteSpace(AppId))
        {
            throw new ArgumentException("AppId is required.", nameof(AppId));
        }

        if (string.IsNullOrWhiteSpace(AppSecret))
        {
            throw new ArgumentException("AppSecret is required.", nameof(AppSecret));
        }
    }
}
