import { useState } from 'react';
import { isSuccessfulResponse } from './client.js';
import { useCardKeyProxy } from './useCardKeyProxy.js';

/**
 * Minimal browser form example. It only calls the protected same-origin proxy.
 * No AppSecret, upstream AppID, or VITE_* secret is read by this component.
 */
export function CardKeyVerifyExample() {
  const [cardKey, setCardKey] = useState('');
  const [deviceId, setDeviceId] = useState('');
  const proxy = useCardKeyProxy();

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const result = await proxy.verify({
      card_key: cardKey,
      ...(deviceId ? { device_id: deviceId } : {}),
    });

    if (isSuccessfulResponse(result)) {
      // Render the returned business data in the host UI.
      console.info('Card verification succeeded', result.data);
    }
  }

  return (
    <form onSubmit={submit}>
      <label>
        Card key
        <input value={cardKey} onChange={(event) => setCardKey(event.target.value)} />
      </label>
      <label>
        Device ID
        <input value={deviceId} onChange={(event) => setDeviceId(event.target.value)} />
      </label>
      <button type="submit" disabled={proxy.loading}>
        {proxy.loading ? 'Checking…' : 'Verify'}
      </button>
      {proxy.error ? <p role="alert">Request failed. Try again later.</p> : null}
      {proxy.response && !proxy.response.success ? (
        <p role="status">{proxy.response.message}</p>
      ) : null}
    </form>
  );
}
