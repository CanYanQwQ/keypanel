using System;
using System.Collections;
using System.Text;
using UnityEngine;
using UnityEngine.Networking;

namespace CardKey.Unity;

public sealed class CardKeyClient
{
    private readonly CardKeyClientOptions options;

    public CardKeyClient(CardKeyClientOptions options)
    {
        if (options == null) throw new ArgumentNullException(nameof(options));
        options.Validate();
        this.options = options;
    }

    public IEnumerator Verify(VerifyRequest request, Action<ApiCallResult> onSuccess, Action<Exception> onError)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));
        return Send("/api/v1/verify", request.ToJsonBytes(), onSuccess, onError);
    }

    public IEnumerator Activate(ActivateRequest request, Action<ApiCallResult> onSuccess, Action<Exception> onError)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));
        return Send("/api/v1/activate", request.ToJsonBytes(), onSuccess, onError);
    }

    public IEnumerator Consume(ConsumeRequest request, Action<ApiCallResult> onSuccess, Action<Exception> onError)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));
        return Send("/api/v1/consume", request.ToJsonBytes(), onSuccess, onError);
    }

    public IEnumerator Query(QueryRequest request, Action<ApiCallResult> onSuccess, Action<Exception> onError)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));
        return Send("/api/v1/query", request.ToJsonBytes(), onSuccess, onError);
    }

    public IEnumerator Unbind(UnbindRequest request, Action<ApiCallResult> onSuccess, Action<Exception> onError)
    {
        if (request == null) throw new ArgumentNullException(nameof(request));
        return Send("/api/v1/unbind", request.ToJsonBytes(), onSuccess, onError);
    }

    private IEnumerator Send(string path, byte[] rawBody, Action<ApiCallResult> onSuccess, Action<Exception> onError)
    {
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture);
        var nonce = ApiSigner.CreateNonce();
        var signature = ApiSigner.SignRequest(options.AppSecret, "POST", path, timestamp, nonce, rawBody);
        var url = options.BaseUrl.TrimEnd('/') + path;

        using (var request = new UnityWebRequest(url, UnityWebRequest.kHttpVerbPOST))
        {
            request.uploadHandler = new UploadHandlerRaw(rawBody);
            request.downloadHandler = new DownloadHandlerBuffer();
            request.timeout = options.TimeoutSeconds;
            request.SetRequestHeader("Content-Type", "application/json; charset=utf-8");
            request.SetRequestHeader("Accept", "application/json");
            request.SetRequestHeader(ApiSigner.AppIdHeader, options.AppId);
            request.SetRequestHeader(ApiSigner.TimestampHeader, timestamp);
            request.SetRequestHeader(ApiSigner.NonceHeader, nonce);
            request.SetRequestHeader(ApiSigner.SignatureHeader, signature);
            request.SetRequestHeader(ApiSigner.VersionHeader, ApiSigner.Version);

            yield return request.SendWebRequest();

            var body = request.downloadHandler != null ? request.downloadHandler.data : Array.Empty<byte>();
            try
            {
                var signed = VerifyResponse(request, body, nonce);
                var response = JsonCodec.DeserializeResponse(body);
                if (request.responseCode < 200 || request.responseCode >= 300 || !response.success || response.code != 0)
                    throw new ApiException(request.responseCode, response.code, response.message);
                onSuccess?.Invoke(new ApiCallResult(request.responseCode, response, signed, nonce));
            }
            catch (Exception exception)
            {
                onError?.Invoke(exception);
            }
        }
    }

    private bool VerifyResponse(UnityWebRequest request, byte[] body, string nonce)
    {
        var responseTimestamp = request.GetResponseHeader(ApiSigner.ResponseTimestampHeader);
        var responseSignature = request.GetResponseHeader(ApiSigner.ResponseSignatureHeader);
        if (string.IsNullOrEmpty(responseTimestamp) && string.IsNullOrEmpty(responseSignature))
        {
            if (options.RequireSignedResponses) throw new ResponseSignatureException("The API response did not contain a response signature.");
            return false;
        }
        if (string.IsNullOrEmpty(responseTimestamp) || string.IsNullOrEmpty(responseSignature))
            throw new ResponseSignatureException("The API response contained incomplete signature headers.");
        if (!ApiSigner.VerifyResponse(options.AppSecret, body, responseTimestamp, nonce, responseSignature))
            throw new ResponseSignatureException("The API response signature was invalid.");
        return true;
    }
}
