import type {
  ActivateInput,
  CardKeyApiResponse,
  CardKeyFetch,
  CardKeyOperation,
  CardKeyProxyClientOptions,
  ConsumeInput,
  OperationDataMap,
  OperationInputMap,
  OperationResponse,
  QueryInput,
  UnbindInput,
  VerifyInput,
} from './types.js';

export const DEFAULT_PROXY_PATH = '/api/cardkey-proxy';

function assertProxyPath(proxyPath: string): void {
  if (
    !proxyPath.startsWith('/') ||
    proxyPath.startsWith('//') ||
    proxyPath.includes('://') ||
    /[?#\r\n]/.test(proxyPath)
  ) {
    throw new Error('proxyPath must be a same-origin path without query strings or fragments');
  }
}

function assertInput(operation: CardKeyOperation, input: OperationInputMap[CardKeyOperation]): void {
  if (!input || typeof input !== 'object') {
    throw new TypeError('proxy input must be an object');
  }

  if (typeof input.card_key !== 'string' || input.card_key.trim() === '') {
    throw new TypeError('card_key must be a non-empty string');
  }

  if (input.device_id !== undefined && typeof input.device_id !== 'string') {
    throw new TypeError('device_id must be a string when provided');
  }

  if (operation === 'consume') {
    const count = (input as ConsumeInput).count;
    if (count !== undefined && (!Number.isInteger(count) || count < 1 || count > 1000)) {
      throw new TypeError('count must be an integer between 1 and 1000');
    }
  }

  if (operation !== 'consume' && 'count' in input) {
    throw new TypeError('count is only valid for consume');
  }

  if (operation === 'unbind') {
    const force = (input as UnbindInput).force;
    if (force !== undefined && typeof force !== 'boolean') {
      throw new TypeError('force must be a boolean when provided');
    }
  }

  if (operation !== 'unbind' && 'force' in input) {
    throw new TypeError('force is only valid for unbind');
  }
}

function toProxyRequest<TOperation extends CardKeyOperation>(
  operation: TOperation,
  input: OperationInputMap[TOperation],
) {
  assertInput(operation, input);

  const request = {
    operation,
    card_key: input.card_key,
    ...(input.device_id === undefined ? {} : { device_id: input.device_id }),
  } as CardKeyProxyRequestFor<TOperation>;

  if (operation === 'consume' && (input as ConsumeInput).count !== undefined) {
    request.count = (input as ConsumeInput).count;
  }

  if (operation === 'unbind' && (input as UnbindInput).force !== undefined) {
    request.force = (input as UnbindInput).force;
  }

  return request;
}

type CardKeyProxyRequestFor<TOperation extends CardKeyOperation> = {
  operation: TOperation;
  card_key: string;
  device_id?: string;
  count?: number;
  force?: boolean;
};

function isApiResponse(value: unknown): value is CardKeyApiResponse {
  if (!value || typeof value !== 'object') {
    return false;
  }

  const response = value as Record<string, unknown>;
  return (
    Number.isInteger(response.code) &&
    typeof response.message === 'string' &&
    typeof response.success === 'boolean' &&
    typeof response.server_time === 'number'
  );
}

export class CardKeyTransportError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'CardKeyTransportError';
  }
}

export class CardKeyProtocolError extends Error {
  readonly rawBody: string;

  constructor(message: string, rawBody: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'CardKeyProtocolError';
    this.rawBody = rawBody;
  }
}

export class CardKeyHttpError extends Error {
  readonly status: number;
  readonly response: CardKeyApiResponse;

  constructor(status: number, response: CardKeyApiResponse) {
    super(`CardKey proxy returned HTTP ${status}: ${response.message}`);
    this.name = 'CardKeyHttpError';
    this.status = status;
    this.response = response;
  }
}

export class CardKeyProxyClient {
  private readonly proxyPath: string;
  private readonly fetchImpl: CardKeyFetch;
  private readonly credentials: RequestCredentials;
  private readonly csrfToken?: string;
  private readonly csrfHeader: string;

  constructor(options: CardKeyProxyClientOptions = {}) {
    this.proxyPath = options.proxyPath ?? DEFAULT_PROXY_PATH;
    assertProxyPath(this.proxyPath);

    const fetchImpl = options.fetch ?? globalThis.fetch?.bind(globalThis);
    if (!fetchImpl) {
      throw new Error('A fetch implementation is required in this environment');
    }

    this.fetchImpl = fetchImpl;
    this.credentials = options.credentials ?? 'same-origin';
    this.csrfToken = options.csrfToken;
    this.csrfHeader = options.csrfHeader ?? 'X-CSRF-TOKEN';
  }

  async request<TOperation extends CardKeyOperation>(
    operation: TOperation,
    input: OperationInputMap[TOperation],
  ): Promise<OperationResponse<TOperation>> {
    const payload = toProxyRequest(operation, input);
    // This exact string is sent to the protected proxy. The browser never signs it.
    const rawBody = JSON.stringify(payload);
    const headers: Record<string, string> = {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    };

    if (this.csrfToken) {
      headers[this.csrfHeader] = this.csrfToken;
    }

    let response: Response;
    try {
      response = await this.fetchImpl(this.proxyPath, {
        method: 'POST',
        credentials: this.credentials,
        headers,
        body: rawBody,
      });
    } catch (cause) {
      throw new CardKeyTransportError('CardKey proxy request failed', { cause });
    }

    let rawResponseBody: string;
    try {
      rawResponseBody = await response.text();
    } catch (cause) {
      throw new CardKeyTransportError('CardKey proxy response could not be read', { cause });
    }

    let decoded: unknown;
    try {
      decoded = JSON.parse(rawResponseBody);
    } catch (cause) {
      throw new CardKeyProtocolError(
        'CardKey proxy returned invalid JSON',
        rawResponseBody,
        { cause },
      );
    }

    if (!isApiResponse(decoded)) {
      throw new CardKeyProtocolError(
        'CardKey proxy returned an invalid API envelope',
        rawResponseBody,
      );
    }

    if (!response.ok) {
      throw new CardKeyHttpError(response.status, decoded);
    }

    // A HTTP 200 response can still have success=false. Callers must inspect both.
    return decoded as OperationResponse<TOperation>;
  }

  verify(input: VerifyInput) {
    return this.request('verify', input);
  }

  activate(input: ActivateInput) {
    return this.request('activate', input);
  }

  consume(input: ConsumeInput) {
    // Deliberately no automatic retry: consume may decrement card uses.
    return this.request('consume', input);
  }

  query(input: QueryInput) {
    return this.request('query', input);
  }

  unbind(input: UnbindInput) {
    return this.request('unbind', input);
  }
}

export function createCardKeyProxyClient(options: CardKeyProxyClientOptions = {}) {
  return new CardKeyProxyClient(options);
}

export function isSuccessfulResponse(response: CardKeyApiResponse): boolean {
  return response.success && response.code === 0;
}

export type CardKeyDataFor<TOperation extends CardKeyOperation> = OperationDataMap[TOperation];
