import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';
export const TRANSPORT_INFO = 'cardkey-enc-v1';
export const IV_LENGTH = 12;
export const TAG_LENGTH = 16;
export function deriveTransportKey(appSecret, appId) {
  return Buffer.from(hkdfSync('sha256', Buffer.from(appSecret, 'utf8'), Buffer.from(appId, 'utf8'), Buffer.from(TRANSPORT_INFO, 'utf8'), 32));
}
export function encryptCardKey(plaintext, appSecret, appId) {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv('aes-256-gcm', deriveTransportKey(appSecret, appId), iv, { authTagLength: TAG_LENGTH });
  cipher.setAAD(Buffer.from(appId, 'utf8'));
  const data = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  return { iv: iv.toString('base64'), data: data.toString('base64'), tag: cipher.getAuthTag().toString('base64') };
}
export function decryptCardKey(payload, appSecret, appId) {
  const iv = Buffer.from(payload.iv, 'base64');
  const data = Buffer.from(payload.data, 'base64');
  const tag = Buffer.from(payload.tag, 'base64');
  if (iv.length !== IV_LENGTH || tag.length !== TAG_LENGTH) throw new Error('Invalid CardKey transport payload length');
  const decipher = createDecipheriv('aes-256-gcm', deriveTransportKey(appSecret, appId), iv, { authTagLength: TAG_LENGTH });
  decipher.setAAD(Buffer.from(appId, 'utf8')); decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
}
