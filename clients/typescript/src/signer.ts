import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export const SIGNATURE_VERSION = 'v1';

export function normalizePath(path: string): string {
  const withoutQuery = path.split(/[?#]/, 1)[0] ?? '';
  if (withoutQuery === '') return '/';
  const collapsed = withoutQuery.replace(/\/{2,}/g, '/');
  return collapsed.length > 1 ? collapsed.replace(/\/+$/, '') : collapsed;
}

export function canonicalRequest(
  method: string,
  path: string,
  timestamp: string,
  nonce: string,
  rawBody: Uint8Array | string = '',
): string {
  const body = typeof rawBody === 'string' ? Buffer.from(rawBody, 'utf8') : Buffer.from(rawBody);
  return [
    method.toUpperCase(),
    normalizePath(path),
    String(timestamp),
    String(nonce),
    createHash('sha256').update(body).digest('hex'),
  ].join('\n');
}

export function signRequest(
  appSecret: string,
  method: string,
  path: string,
  timestamp: string,
  nonce: string,
  rawBody: Uint8Array | string = '',
): string {
  return createHmac('sha256', Buffer.from(appSecret, 'utf8'))
    .update(canonicalRequest(method, path, timestamp, nonce, rawBody), 'utf8')
    .digest('hex');
}

export function canonicalResponse(
  responseTimestamp: string,
  requestNonce: string,
  rawResponseBody: Uint8Array,
): string {
  return [
    String(responseTimestamp),
    String(requestNonce),
    createHash('sha256').update(Buffer.from(rawResponseBody)).digest('hex'),
  ].join('\n');
}

export function signResponse(
  appSecret: string,
  responseTimestamp: string,
  requestNonce: string,
  rawResponseBody: Uint8Array,
): string {
  return createHmac('sha256', Buffer.from(appSecret, 'utf8'))
    .update(canonicalResponse(responseTimestamp, requestNonce, rawResponseBody), 'utf8')
    .digest('hex');
}

export function verifySignature(expectedSecret: string, canonical: string, supplied: string): boolean {
  const normalized = supplied.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) return false;
  const expected = createHmac('sha256', Buffer.from(expectedSecret, 'utf8'))
    .update(canonical, 'utf8')
    .digest();
  const actual = Buffer.from(normalized, 'hex');
  return timingSafeEqual(expected, actual);
}

export function generateNonce(bytes = 16): string {
  return randomBytes(bytes).toString('hex');
}
