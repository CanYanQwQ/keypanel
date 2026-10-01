import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export const SIGNATURE_VERSION = 'v1';
export function normalizePath(path) {
  const withoutQuery = path.split(/[?#]/, 1)[0] ?? '';
  if (!withoutQuery) return '/';
  const collapsed = withoutQuery.replace(/\/{2,}/g, '/');
  return collapsed.length > 1 ? collapsed.replace(/\/+$/, '') : collapsed;
}
export function canonicalRequest(method, path, timestamp, nonce, rawBody = '') {
  const bytes = typeof rawBody === 'string' ? Buffer.from(rawBody, 'utf8') : Buffer.from(rawBody);
  return [method.toUpperCase(), normalizePath(path), String(timestamp), String(nonce), createHash('sha256').update(bytes).digest('hex')].join('\n');
}
export function signRequest(appSecret, method, path, timestamp, nonce, rawBody = '') {
  return createHmac('sha256', Buffer.from(appSecret, 'utf8')).update(canonicalRequest(method, path, timestamp, nonce, rawBody), 'utf8').digest('hex');
}
export function canonicalResponse(responseTimestamp, requestNonce, rawResponseBody) {
  return [String(responseTimestamp), String(requestNonce), createHash('sha256').update(Buffer.from(rawResponseBody)).digest('hex')].join('\n');
}
export function signResponse(appSecret, responseTimestamp, requestNonce, rawResponseBody) {
  return createHmac('sha256', Buffer.from(appSecret, 'utf8')).update(canonicalResponse(responseTimestamp, requestNonce, rawResponseBody), 'utf8').digest('hex');
}
export function verifySignature(appSecret, canonical, supplied) {
  const value = supplied.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(value)) return false;
  return timingSafeEqual(createHmac('sha256', Buffer.from(appSecret, 'utf8')).update(canonical).digest(), Buffer.from(value, 'hex'));
}
export function generateNonce(bytes = 16) { return randomBytes(bytes).toString('hex'); }
