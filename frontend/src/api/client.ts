// ==========================================================================
// Unified API Client
// All backend communication flows through this module.
// Page components MUST use hooks; hooks call api modules; api modules use this client.
// ==========================================================================

import type { ApiError } from '@/types'

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? '/api'

class ApiClientError extends Error {
  public readonly code?: string
  public readonly details?: unknown

  constructor(err: ApiError) {
    super(err.message)
    this.name = 'ApiClientError'
    this.code = err.code
    this.details = err.details
  }
}

async function request<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const url = `${BASE_URL}${path}`
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(init.headers as Record<string, string> | undefined ?? {}),
  }

  let response: Response
  try {
    response = await fetch(url, { ...init, headers })
  } catch (networkError) {
    throw new ApiClientError({
      message: 'Backend unavailable — check that the server is running.',
      code: 'NETWORK_ERROR',
    })
  }

  if (!response.ok) {
    let errBody: ApiError = { message: `HTTP ${response.status}` }
    try { errBody = await response.json() } catch { /* not json */ }
    throw new ApiClientError(errBody)
  }

  // 204 No Content
  if (response.status === 204) return undefined as T

  return response.json() as Promise<T>
}

export const apiClient = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, {
      method: 'POST',
      body: body !== undefined ? JSON.stringify(body) : undefined,
    }),
  patch: <T>(path: string, body?: unknown) =>
    request<T>(path, {
      method: 'PATCH',
      body: body !== undefined ? JSON.stringify(body) : undefined,
    }),
  delete: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
}
