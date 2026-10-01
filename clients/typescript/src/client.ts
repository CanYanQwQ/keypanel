import {
  ResponseSignatureError,
  ApiError,
  ProtocolError,
} from './errors.ts';
import type {
  ApiResponse,
  CardKeyClientOptions,
  CardKeyValue,
} from './models.ts';
import {
  generateNonce,
  signRequest,
  signResponse,
} from './signer.ts';

export interface CardActionInput {
  card_key: CardKeyValue;
  device_id?: string;
}

export interface ConsumeInput extends CardActionInput {
  count?: number;
}

export interface UnbindInput extends CardActionInput {
  force?: boolean;
}

export type ApiMethod = 'verify' | 'activate' | 'consume' | 'query' | 'unbind';

export class CardKeyClient {
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly timeoutMs: number;
  private readonly requireResponseSignature: boolean;

  constructor(private readonly options: CardKeyClientOptions) {
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
    this.timeoutMs = options.timeoutMs ?? 15_000;
    this.requireResponseSignature = options.requireResponseSignature ?? true;
    if (!this.fetchImpl) throw new Error('A global fetch implementation is required');
    if (!/^https:\/\//i.test(options.baseUrl) && !/^http:\/\/localhost(?::\d+)?(?:\/|$)/i.test(options.baseUrl)) {
      throw new Error('Use HTTPS in production; HTTP is allowed only for localhost examples');
    }
  }

  verify(input: CardActionInput): Promise<ApiResponse> {
    return this.post('verify', input);
  }

  activate(input: CardActionInput): Promise<ApiResponse> {
    return this.post('activate', input);
  }

  consume(input: ConsumeInput): Promise<ApiResponse> {
    return this.post('consume', input);
  }

  query(input: CardActionInput): Promise<ApiResponse> {
    return this.post('query', input);
  }

  unbind(input: UnbindInput): Promise<ApiResponse> {
    return this.post('unbind', input);
  }

  private async post(method: ApiMethod, input: CardActionInput | ConsumeInput | UnbindInput): Promise<ApiResponse> {
    const path = `/api/v1/${method}`;
    // Serialize once and sign/send these exact UTF-8 bytes. Never re-stringify after signing.
    const rawBody = Buffer.from(JSON.stringify(input), 'utf8');
    const timestamp = String(Math.floor(Date.now() / 1000));
    const nonce = generateNonce();
    const signature = signRequest(this.options.appSecret, 'POST', path, timestamp, nonce, rawBody);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    let rawResponseBody: Uint8Array;
    try {
      response = await this.fetchImpl(new URL(path, this.options.baseUrl).toString(), {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json',
          'X-App-Id': this.options.appId,
          'X-Timestamp': timestamp,
          'X-Nonce': nonce,
          'X-Signature-Version': 'v1',
          'X-Signature': signature,
        },
        body: rawBody,
        signal: controller.signal,
      });
      rawResponseBody = new Uint8Array(await response.arrayBuffer());
    } finally {
      clearTimeout(timer);
    }

    this.verifyResponseSignature(response, rawResponseBody, nonce);
    let parsed: ApiResponse;
    try {
      parsed = JSON.parse(Buffer.from(rawResponseBody).toString('utf8')) as ApiResponse;
    } catch (error) {
      throw new ProtocolError('The API response is not valid JSON', { cause: error });
    }
    if (typeof parsed.code !== 'number' || typeof parsed.success !== 'boolean' || typeof parsed.message !== 'string' || typeof parsed.server_time !== 'number') {
      throw new ProtocolError('The API response is missing required fields');
    }
    if (!response.ok || parsed.code !== 0 || !parsed.success) {
      throw new ApiError(parsed.code, parsed.message, response.status, parsed);
    }
    return parsed;
  }

  private verifyResponseSignature(response: Response, rawBody: Uint8Array, requestNonce: string): void {
    const signature = response.headers.get('X-Response-Signature');
    const timestamp = response.headers.get('X-Response-Timestamp');
    if (!signature || !timestamp) {
      if (this.requireResponseSignature && response.ok) {
        throw new ResponseSignatureError('Missing response signature headers');
      }
      return;
    }
    const expected = signResponse(this.options.appSecret, timestamp, requestNonce, rawBody);
    if (expected !== signature.trim().toLowerCase()) {
      throw new ResponseSignatureError('Response signature verification failed');
    }
  }
}
