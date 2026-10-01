using System;
using UnityEngine;

namespace CardKey.Unity.Samples;

public sealed class CardKeySampleConfig : MonoBehaviour
{
    [Header("Placeholders only. Do not ship real credentials in a Unity asset.")]
    public string BaseUrl = "https://example.invalid";
    public string AppId = "REPLACE_WITH_APP_ID";
    public string AppSecret = "REPLACE_WITH_APP_SECRET";
    public bool RequireSignedResponses = true;

    public CardKeyClient CreateClient()
    {
        var options = new CardKeyClientOptions
        {
            BaseUrl = BaseUrl,
            AppId = AppId,
            AppSecret = AppSecret,
            RequireSignedResponses = RequireSignedResponses,
        };
        return new CardKeyClient(options);
    }

    public void VerifyPlaceholderCard()
    {
        if (BaseUrl.Contains("example.invalid", StringComparison.OrdinalIgnoreCase)
            || AppId.Contains("REPLACE", StringComparison.OrdinalIgnoreCase)
            || AppSecret.Contains("REPLACE", StringComparison.OrdinalIgnoreCase))
        {
            Debug.LogWarning("CardKey sample still uses placeholders; no network request was sent.");
            return;
        }

        var client = CreateClient();
        var request = new VerifyRequest
        {
            CardKey = CardKeyInput.FromPlaintext("CARD-EXAMPLE"),
            DeviceId = "device-001",
        };
        StartCoroutine(client.Verify(request,
            result => Debug.Log(string.Format("CardKey response received. HTTP {0}, code {1}, signed={2}.", result.HttpStatus, result.Response.code, result.IsResponseSigned)),
            error => Debug.LogError("CardKey request failed without sensitive details: " + error.GetType().Name)));
    }
}
