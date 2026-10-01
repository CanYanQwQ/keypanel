export const CARD_KEY_OPERATIONS = [
  'verify',
  'activate',
  'consume',
  'query',
  'unbind',
] as const;

export type CardKeyOperation = (typeof CARD_KEY_OPERATIONS)[number];

export interface VerifyInput {
  card_key: string;
  device_id?: string;
}

export interface ActivateInput {
  card_key: string;
  device_id?: string;
}

export interface ConsumeInput {
  card_key: string;
  device_id?: string;
  count?: number;
}

export interface QueryInput {
  card_key: string;
  device_id?: string;
}

export interface UnbindInput {
  card_key: string;
  device_id?: string;
  force?: boolean;
}

export interface OperationInputMap {
  verify: VerifyInput;
  activate: ActivateInput;
  consume: ConsumeInput;
  query: QueryInput;
  unbind: UnbindInput;
}

export interface CardKeyProxyRequest {
  operation: CardKeyOperation;
  card_key: string;
  device_id?: string;
  count?: number;
  force?: boolean;
}

export interface CardKeyApiResponse<TData = unknown> {
  code: number;
  message: string;
  success: boolean;
  server_time: number;
  data?: TData;
}

export interface CardData {
  card_id: number;
  status: string;
  type: string;
  activated_at: string | null;
  expires_at: string | null;
  remaining_seconds: number | null;
  remaining_uses: number | null;
  device_bound: boolean;
}

export interface ConsumeData {
  consumed: number;
  remaining: number | null;
}

export type OperationDataMap = {
  verify: CardData;
  activate: CardData & { activated?: boolean };
  consume: ConsumeData;
  query: CardData;
  unbind: { unbound: boolean; message?: string };
};

export type OperationResponse<TOperation extends CardKeyOperation> = CardKeyApiResponse<
  OperationDataMap[TOperation]
>;

export type CardKeyFetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

export interface CardKeyProxyClientOptions {
  /** Same-origin protected proxy path; absolute URLs are rejected. */
  proxyPath?: string;
  /** Inject a fetch implementation for SSR or tests. */
  fetch?: CardKeyFetch;
  /** Browser credentials are sent by default for same-origin session auth. */
  credentials?: RequestCredentials;
  /** Optional CSRF token issued by the host application. */
  csrfToken?: string;
  /** Host-specific CSRF header name; defaults to X-CSRF-TOKEN. */
  csrfHeader?: string;
}
