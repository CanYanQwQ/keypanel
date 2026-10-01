export function parseApiResponse(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new TypeError('The API response must be a JSON object');
  }
  for (const field of ['code', 'message', 'success', 'server_time']) {
    if (!(field in payload)) throw new TypeError(`The API response is missing ${field}`);
  }
  if (!Number.isInteger(payload.code) || typeof payload.message !== 'string' || typeof payload.success !== 'boolean' || !Number.isInteger(payload.server_time)) {
    throw new TypeError('The API response has invalid field types');
  }
  return payload;
}

export function isEncryptedCardKey(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value)
    && typeof value.iv === 'string' && typeof value.data === 'string' && typeof value.tag === 'string');
}
