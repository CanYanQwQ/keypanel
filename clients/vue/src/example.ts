import { ref } from 'vue';
import { useCardKeyProxy } from './useCardKeyProxy.js';

/**
 * Minimal browser form example. The card key is user input; no AppSecret or
 * VITE_* secret is read here. All authentication and encryption stay in the
 * protected server-side proxy.
 */
export function useVerifyCardKeyExample() {
  const cardKey = ref('');
  const deviceId = ref('');
  const proxy = useCardKeyProxy();

  async function submit() {
    return proxy.verify({
      card_key: cardKey.value,
      ...(deviceId.value ? { device_id: deviceId.value } : {}),
    });
  }

  return {
    ...proxy,
    cardKey,
    deviceId,
    submit,
  };
}
