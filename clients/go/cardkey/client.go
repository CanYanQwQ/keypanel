package cardkey

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	SignatureVersion = "v1"
	TransportInfo    = "cardkey-enc-v1"
	IVLength         = 12
	TagLength        = 16
)

func NormalizePath(path string) string {
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if path == "" {
		return "/"
	}
	parts := make([]string, 0)
	for _, part := range strings.Split(path, "/") {
		if part != "" {
			parts = append(parts, part)
		}
	}
	result := "/" + strings.Join(parts, "/")
	if result == "" {
		return "/"
	}
	return result
}
func CanonicalRequest(method, path, timestamp, nonce string, rawBody []byte) string {
	sum := sha256.Sum256(rawBody)
	return strings.Join([]string{strings.ToUpper(method), NormalizePath(path), timestamp, nonce, hex.EncodeToString(sum[:])}, "\n")
}
func SignRequest(secret, method, path, timestamp, nonce string, rawBody []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(CanonicalRequest(method, path, timestamp, nonce, rawBody)))
	return hex.EncodeToString(mac.Sum(nil))
}
func CanonicalResponse(timestamp, nonce string, rawBody []byte) string {
	sum := sha256.Sum256(rawBody)
	return strings.Join([]string{timestamp, nonce, hex.EncodeToString(sum[:])}, "\n")
}
func SignResponse(secret, timestamp, nonce string, rawBody []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(CanonicalResponse(timestamp, nonce, rawBody)))
	return hex.EncodeToString(mac.Sum(nil))
}
func GenerateNonce() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func DeriveTransportKey(secret, appID string) ([]byte, error) {
	reader, err := hkdf.Key(sha256.New, []byte(secret), []byte(appID), TransportInfo, 32)
	if err != nil {
		return nil, err
	}
	return reader, nil
}
func EncryptCardKey(plaintext, secret, appID string) (EncryptedCardKey, error) {
	key, err := DeriveTransportKey(secret, appID)
	if err != nil {
		return EncryptedCardKey{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return EncryptedCardKey{}, err
	}
	gcm, err := cipher.NewGCMWithTagSize(block, TagLength)
	if err != nil {
		return EncryptedCardKey{}, err
	}
	iv := make([]byte, IVLength)
	if _, err = rand.Read(iv); err != nil {
		return EncryptedCardKey{}, err
	}
	sealed := gcm.Seal(nil, iv, []byte(plaintext), []byte(appID))
	data, tag := sealed[:len(sealed)-TagLength], sealed[len(sealed)-TagLength:]
	return EncryptedCardKey{base64.StdEncoding.EncodeToString(iv), base64.StdEncoding.EncodeToString(data), base64.StdEncoding.EncodeToString(tag)}, nil
}
func DecryptCardKey(payload EncryptedCardKey, secret, appID string) (string, error) {
	key, err := DeriveTransportKey(secret, appID)
	if err != nil {
		return "", err
	}
	iv, err := base64.StdEncoding.DecodeString(payload.IV)
	if err != nil {
		return "", err
	}
	data, err := base64.StdEncoding.DecodeString(payload.Data)
	if err != nil {
		return "", err
	}
	tag, err := base64.StdEncoding.DecodeString(payload.Tag)
	if err != nil {
		return "", err
	}
	if len(iv) != IVLength || len(tag) != TagLength {
		return "", errors.New("invalid CardKey transport payload length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCMWithTagSize(block, TagLength)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, iv, append(data, tag...), []byte(appID))
	if err != nil {
		return "", errors.New("CardKey GCM authentication failed")
	}
	return string(plain), nil
}

type Client struct {
	BaseURL, AppID, AppSecret string
	HTTPClient                *http.Client
	RequireResponseSignature  bool
}

func NewClient(baseURL, appID, appSecret string) (*Client, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1")) {
		return nil, errors.New("use HTTPS in production; HTTP is allowed only for localhost examples")
	}
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), AppID: appID, AppSecret: appSecret, HTTPClient: &http.Client{Timeout: 15 * time.Second}, RequireResponseSignature: true}, nil
}
func (c *Client) Verify(input map[string]any) (APIResponse, error) { return c.post("verify", input) }
func (c *Client) Activate(input map[string]any) (APIResponse, error) {
	return c.post("activate", input)
}
func (c *Client) Consume(input map[string]any) (APIResponse, error) { return c.post("consume", input) }
func (c *Client) Query(input map[string]any) (APIResponse, error)   { return c.post("query", input) }
func (c *Client) Unbind(input map[string]any) (APIResponse, error)  { return c.post("unbind", input) }
func (c *Client) post(method string, input map[string]any) (APIResponse, error) {
	path := "/api/v1/" + method
	// Marshal once. These exact bytes are hashed, signed, and sent; never re-marshal after signing.
	rawBody, err := json.Marshal(input)
	if err != nil {
		return APIResponse{}, err
	}
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	nonce, err := GenerateNonce()
	if err != nil {
		return APIResponse{}, err
	}
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+path, bytes.NewReader(rawBody))
	if err != nil {
		return APIResponse{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-App-Id", c.AppID)
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature-Version", SignatureVersion)
	req.Header.Set("X-Signature", SignRequest(c.AppSecret, "POST", path, timestamp, nonce, rawBody))
	response, err := c.HTTPClient.Do(req)
	if err != nil {
		return APIResponse{}, err
	}
	defer response.Body.Close()
	rawResponseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return APIResponse{}, err
	}
	if err := c.verifyResponse(response, rawResponseBody, nonce); err != nil {
		return APIResponse{}, err
	}
	var result APIResponse
	result, err = parseAPIResponse(rawResponseBody)
	if err != nil {
		return APIResponse{}, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || result.Code != 0 || !result.Success {
		return APIResponse{}, &APIError{result.Code, result.Message, response.StatusCode, result}
	}
	return result, nil
}
func (c *Client) verifyResponse(response *http.Response, body []byte, nonce string) error {
	signature, timestamp := response.Header.Get("X-Response-Signature"), response.Header.Get("X-Response-Timestamp")
	if signature == "" || timestamp == "" {
		if c.RequireResponseSignature && response.StatusCode >= 200 && response.StatusCode < 300 {
			return &ResponseSignatureError{"missing response signature headers"}
		}
		return nil
	}
	if !hmac.Equal([]byte(SignResponse(c.AppSecret, timestamp, nonce, body)), []byte(strings.ToLower(strings.TrimSpace(signature)))) {
		return &ResponseSignatureError{"response signature verification failed"}
	}
	return nil
}
