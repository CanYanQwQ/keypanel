export interface EncryptedCardKey {
  iv: string;
  data: string;
  tag: string;
}

export type CardKeyValue = string | EncryptedCardKey;

export interface ApiResponse<T = unknown> {
  code: number;
  message: string;
  success: boolean;
  server_time: number;
  data?: T;
}

export interface CardKeyClientOptions {
  baseUrl: string;
  appId: string;
  appSecret: string;
  timeoutMs?: number;
  requireResponseSignature?: boolean;
  fetchImpl?: typeof globalThis.fetch;
}
