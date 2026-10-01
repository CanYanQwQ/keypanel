import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CardKeyHttpError,
  CardKeyProtocolError,
  CardKeyTransportError,
  createCardKeyProxyClient,
} from '../dist/index.js';

function response(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

test('sends only the allowlisted proxy payload and never upstream signature headers', async () => {
  let request;
  const client = createCardKeyProxyClient({
    fetch: async (input, init) => {
      request = { input, init };
      return response(200, {
        code: 0,
        message: '操作成功',
        success: true,
        server_time: 1700000000,
        data: { card_id: 1 },
      });
    },
  });

  await client.verify({ card_key: 'ABCD-EFGH-JKMN-PQRS', device_id: 'browser-1' });

  assert.equal(request.input, '/api/cardkey-proxy');
  assert.equal(request.init.method, 'POST');
  assert.equal(request.init.credentials, 'same-origin');
  assert.deepEqual(JSON.parse(request.init.body), {
    operation: 'verify',
    card_key: 'ABCD-EFGH-JKMN-PQRS',
    device_id: 'browser-1',
  });
  assert.equal(request.init.headers['X-App-Id'], undefined);
  assert.equal(request.init.headers['X-Signature'], undefined);
});

test('does not retry consume after a transport failure', async () => {
  let calls = 0;
  const client = createCardKeyProxyClient({
    fetch: async () => {
      calls += 1;
      throw new Error('timeout');
    },
  });

  await assert.rejects(
    client.consume({ card_key: 'ABCD-EFGH-JKMN-PQRS', count: 1 }),
    CardKeyTransportError,
  );
  assert.equal(calls, 1);
});

test('preserves business failure responses returned with HTTP 200', async () => {
  const client = createCardKeyProxyClient({
    fetch: async () => response(200, {
      code: 2007,
      message: '设备不匹配，该卡密已绑定其他设备',
      success: false,
      server_time: 1700000000,
    }),
  });

  const result = await client.verify({ card_key: 'ABCD-EFGH-JKMN-PQRS' });
  assert.equal(result.success, false);
  assert.equal(result.code, 2007);
});

test('distinguishes non-2xx and invalid JSON responses', async () => {
  const httpClient = createCardKeyProxyClient({
    fetch: async () => response(401, {
      code: 1010,
      message: '缺少必要的认证头',
      success: false,
      server_time: 1700000000,
    }),
  });
  await assert.rejects(
    httpClient.query({ card_key: 'ABCD-EFGH-JKMN-PQRS' }),
    (error) => error instanceof CardKeyHttpError && error.status === 401,
  );

  const protocolClient = createCardKeyProxyClient({
    fetch: async () => new Response('not-json', { status: 502 }),
  });
  await assert.rejects(
    protocolClient.query({ card_key: 'ABCD-EFGH-JKMN-PQRS' }),
    CardKeyProtocolError,
  );
});
