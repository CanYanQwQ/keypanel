import { ref, shallowRef, type Ref, type ShallowRef } from 'vue';
import {
  createCardKeyProxyClient,
  type CardKeyProxyClient,
} from './client.js';
import type {
  ActivateInput,
  CardKeyApiResponse,
  CardKeyOperation,
  CardKeyProxyClientOptions,
  ConsumeInput,
  OperationInputMap,
  OperationResponse,
  QueryInput,
  UnbindInput,
  VerifyInput,
} from './types.js';

export interface UseCardKeyProxyReturn {
  loading: Readonly<Ref<boolean>>;
  response: Readonly<ShallowRef<CardKeyApiResponse | null>>;
  error: Readonly<ShallowRef<unknown>>;
  clearError(): void;
  verify(input: VerifyInput): Promise<OperationResponse<'verify'>>;
  activate(input: ActivateInput): Promise<OperationResponse<'activate'>>;
  consume(input: ConsumeInput): Promise<OperationResponse<'consume'>>;
  query(input: QueryInput): Promise<OperationResponse<'query'>>;
  unbind(input: UnbindInput): Promise<OperationResponse<'unbind'>>;
}

export function useCardKeyProxy(
  options: CardKeyProxyClientOptions = {},
  existingClient?: CardKeyProxyClient,
): UseCardKeyProxyReturn {
  const client = existingClient ?? createCardKeyProxyClient(options);
  const loading = ref(false);
  const response = shallowRef<CardKeyApiResponse | null>(null);
  const error = shallowRef<unknown>(null);

  async function run<TOperation extends CardKeyOperation>(
    operation: TOperation,
    input: OperationInputMap[TOperation],
  ): Promise<OperationResponse<TOperation>> {
    loading.value = true;
    error.value = null;

    try {
      const result = await client.request(operation, input);
      response.value = result;
      return result;
    } catch (cause) {
      error.value = cause;
      response.value = null;
      throw cause;
    } finally {
      loading.value = false;
    }
  }

  return {
    loading,
    response,
    error,
    clearError: () => {
      error.value = null;
    },
    verify: (input) => run('verify', input),
    activate: (input) => run('activate', input),
    consume: (input) => run('consume', input),
    query: (input) => run('query', input),
    unbind: (input) => run('unbind', input),
  };
}
