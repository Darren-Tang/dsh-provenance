/**
 * Bounded HTTP client.
 *
 * Every request is size-capped, time-capped and allowlist-checked. Redirects
 * are resolved manually so each hop is re-validated (a permissive redirect is
 * a classic allowlist bypass).
 */

import { assertAllowedUrl } from './guard.js'

export interface FetchOptions {
  /** Hard cap on response bytes. The stream is aborted once exceeded. */
  maxBytes: number
  timeoutMs?: number
  headers?: Record<string, string>
  maxRedirects?: number
  /**
   * Caller-owned cancellation, e.g. a tool's `exec.signal`.
   *
   * Combined with the internal timeout rather than replacing it, so a caller
   * cannot accidentally remove the timeout and neither can outlive the other.
   */
  signal?: AbortSignal
}

export interface FetchResult {
  status: number
  url: string
  body: Uint8Array
  headers: Headers
}

export class HttpError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.name = 'HttpError'
    this.status = status
  }
}

const DEFAULT_TIMEOUT_MS = 20_000

/** Merge the internal timeout with any caller-supplied cancellation. */
function combineSignals(timeoutMs: number, external: AbortSignal | undefined): AbortSignal {
  const timeout = AbortSignal.timeout(timeoutMs)
  return external ? AbortSignal.any([timeout, external]) : timeout
}

/** Fetch bytes with allowlist, timeout and size ceiling enforced. */
export async function fetchBytes(
  rawUrl: string,
  options: FetchOptions,
): Promise<FetchResult> {
  const maxRedirects = options.maxRedirects ?? 3
  let target = assertAllowedUrl(rawUrl)

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const response = await fetch(target, {
      redirect: 'manual',
      signal: combineSignals(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, options.signal),
      headers: {
        'user-agent': 'dsh-provenance (+https://github.com/topics/dsh-plugin)',
        ...options.headers,
      },
    })

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location')
      if (!location) {
        throw new HttpError(response.status, `redirect without location from ${target.href}`)
      }
      // Re-validate every hop against the same allowlist.
      target = assertAllowedUrl(new URL(location, target).href)
      continue
    }

    if (!response.ok) {
      throw new HttpError(response.status, `HTTP ${response.status} for ${target.href}`)
    }

    const declared = Number(response.headers.get('content-length') ?? '0')
    if (declared > options.maxBytes) {
      throw new HttpError(
        response.status,
        `response too large: content-length ${declared} > limit ${options.maxBytes}`,
      )
    }

    const body = await readCapped(response, options.maxBytes)
    return { status: response.status, url: target.href, body, headers: response.headers }
  }

  throw new HttpError(310, `too many redirects for ${rawUrl}`)
}

/**
 * Drain a response body, aborting as soon as the cap is exceeded.
 *
 * We deliberately do not trust `content-length`: a hostile endpoint can lie or
 * omit it, so the running total is what actually enforces the ceiling.
 */
async function readCapped(response: Response, maxBytes: number): Promise<Uint8Array> {
  if (!response.body) return new Uint8Array(0)

  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0

  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      if (!value) continue
      total += value.byteLength
      if (total > maxBytes) {
        throw new HttpError(413, `response exceeded ${maxBytes} bytes`)
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }

  const out = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.byteLength
  }
  return out
}

/** Fetch and parse JSON under the same limits. */
export async function fetchJson<T>(rawUrl: string, options: FetchOptions): Promise<T> {
  const result = await fetchBytes(rawUrl, options)
  const text = new TextDecoder().decode(result.body)
  return JSON.parse(text) as T
}

/**
 * Optional GitHub token, read from the environment only.
 *
 * Used purely to raise the anonymous rate limit. Never logged, never persisted,
 * never sent anywhere except api.github.com.
 */
export function githubAuthHeaders(): Record<string, string> {
  const token = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN
  return token ? { authorization: `Bearer ${token}` } : {}
}
