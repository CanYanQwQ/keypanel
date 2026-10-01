import { ApiError, ProtocolError, ResponseSignatureError } from './errors.mjs';
import { parseApiResponse } from './models.mjs';
import { generateNonce, signRequest, signResponse } from './signer.mjs';

export class CardKeyClient {
  constructor({ baseUrl, appId, appSecret, timeoutMs = 15000, requireResponseSignature = true, fetchImpl = globalThis.fetch }) {
    this.baseUrl = baseUrl; this.appId = appId; this.appSecret = appSecret;
    this.timeoutMs = timeoutMs; this.requireResponseSignature = requireResponseSignature; this.fetchImpl = fetchImpl;
    if (!fetchImpl) throw new Error('A global fetch implementation is required');
    if (!/^https:\/\//i.test(baseUrl) && !/^http:\/\/localhost(?::\d+)?(?:\/|$)/i.test(baseUrl)) throw new Error('Use HTTPS in production; HTTP is allowed only for localhost examples');
  }
  verify(input) { return this.#post('verify', input); }
  activate(input) { return this.#post('activate', input); }
  consume(input) { return this.#post('consume', input); }
  query(input) { return this.#post('query', input); }
  unbind(input) { return this.#post('unbind', input); }
  async #post(method, input) {
    const path = `/api/v1/${method}`;
    // Serialize once; hash, sign, and send these exact raw UTF-8 bytes.
    const rawBody = Buffer.from(JSON.stringify(input), 'utf8');
    const timestamp = String(Math.floor(Date.now() / 1000));
    const nonce = generateNonce();
    const signature = signRequest(this.appSecret, 'POST', path, timestamp, nonce, rawBody);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response;
    let rawResponseBody;
    try {
      response = await this.fetchImpl(new URL(path, this.baseUrl).toString(), { method: 'POST', headers: {
        Accept: 'application/json', 'Content-Type': 'application/json', 'X-App-Id': this.appId,
        'X-Timestamp': timestamp, 'X-Nonce': nonce, 'X-Signature-Version': 'v1', 'X-Signature': signature
      }, body: rawBody, signal: controller.signal });
      rawResponseBody = new Uint8Array(await response.arrayBuffer());
    } finally { clearTimeout(timer); }
    const responseSignature = response.headers.get('X-Response-Signature');
    const responseTimestamp = response.headers.get('X-Response-Timestamp');
    if (!responseSignature || !responseTimestamp) {
      if (this.requireResponseSignature && response.ok) throw new ResponseSignatureError('Missing response signature headers');
    } else if (signResponse(this.appSecret, responseTimestamp, nonce, rawResponseBody) !== responseSignature.trim().toLowerCase()) {
      throw new ResponseSignatureError('Response signature verification failed');
    }
    let parsed;
    try { parsed = parseApiResponse(JSON.parse(Buffer.from(rawResponseBody).toString('utf8'))); }
    catch (error) { throw new ProtocolError(error instanceof SyntaxError ? 'The API response is not valid JSON' : error.message, { cause: error }); }
    if (!response.ok || parsed.code !== 0 || !parsed.success) throw new ApiError(parsed.code, parsed.message, response.status, parsed);
    return parsed;
  }
}
