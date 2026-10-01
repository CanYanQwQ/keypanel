import { useCallback, useMemo, useState } from 'react';
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
  loading: boolean;
  response: CardKeyApiResponse | null;
  error: unknown;
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
  const client = useMemo(
    () => existingClient ?? createCardKeyProxyClient(options),
    [existingClient, options.proxyPath, options.fetch, options.credentials, options.csrfToken, options.csrfHeader],
  );
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState<CardKeyApiResponse | null>(null);
  const [error, setError] = useState<unknown>(null);

  const run = useCallback(
    async <TOperation extends CardKeyOperation>(
      operation: TOperation,
      input: OperationInputMap[TOperation],
    ): Promise<OperationResponse<TOperation>> => {
      setLoading(true);
      setError(null);

      try {
        const result = await client.request(operation, input);
        setResponse(result);
        return result;
      } catch (cause) {
        setError(cause);
        setResponse(null);
        throw cause;
      } finally {
        setLoading(false);
      }
    },
    [client],
  );

  return {
    loading,
    response,
    error,
    clearError: () => setError(null),
    verify: (input) => run('verify', input),
    activate: (input) => run('activate', input),
    consume: (input) => run('consume', input),
    query: (input) => run('query', input),
    unbind: (input) => run('unbind', input),
  };
}
