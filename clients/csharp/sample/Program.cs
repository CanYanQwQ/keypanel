using System;
using System.IO;
using System.Text.Json;
using CardKey.Client;
using CardKey.Client.Tests;

if (args.Length > 0 && string.Equals(args[0], "vectors", StringComparison.OrdinalIgnoreCase))
{
    ProtocolVectorTests.RunAll();
    return;
}

if (args.Length == 0 || !string.Equals(args[0], "sample", StringComparison.OrdinalIgnoreCase))
{
    Console.WriteLine("Usage: dotnet run --project CardKey.Client.csproj -- vectors|sample");
    return;
}

var configPath = args.Length > 1 ? args[1] : Path.Combine(AppContext.BaseDirectory, "appsettings.json");
if (!File.Exists(configPath))
{
    Console.Error.WriteLine("No appsettings.json was found. Copy sample/appsettings.example.json to a protected location and pass its path.");
    return;
}

var config = JsonSerializer.Deserialize<SampleConfig>(await File.ReadAllTextAsync(configPath), ApiJson.Options)
             ?? throw new InvalidOperationException("Configuration file is empty.");

if (config.BaseUrl.Contains("example.invalid", StringComparison.OrdinalIgnoreCase)
    || config.AppId.Contains("REPLACE", StringComparison.OrdinalIgnoreCase)
    || config.AppSecret.Contains("REPLACE", StringComparison.OrdinalIgnoreCase))
{
    Console.Error.WriteLine("The sample configuration still contains placeholders; no network request was made.");
    return;
}

using var client = new CardKeyClient(new CardKeyClientOptions
{
    BaseAddress = new Uri(config.BaseUrl, UriKind.Absolute),
    AppId = config.AppId,
    AppSecret = config.AppSecret,
    RequireSignedResponses = config.RequireSignedResponses,
});

Console.WriteLine("This sample intentionally does not print credentials or card keys.");
Console.WriteLine("Available calls are exposed by CardKeyClient.VerifyAsync, ActivateAsync, ConsumeAsync, QueryAsync and UnbindAsync.");
Console.WriteLine("Add a protected integration harness for your environment instead of putting secrets in source or logs.");

sealed class SampleConfig
{
    public string BaseUrl { get; init; } = "https://example.invalid";
    public string AppId { get; init; } = "REPLACE_WITH_APP_ID";
    public string AppSecret { get; init; } = "REPLACE_WITH_APP_SECRET";
    public bool RequireSignedResponses { get; init; } = true;
}
