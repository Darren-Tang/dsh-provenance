/**
 * Network egress guard.
 *
 * THREAT MODEL — read before changing anything here.
 *
 * This tool fetches URLs that are partly derived from ATTACKER-CONTROLLED data:
 * a malicious package can put anything in `repository.url`, and an attestation
 * payload can assert any repo. Without a guard, a "security scanner" becomes an
 * SSRF pivot that probes the operator's internal network.
 *
 * Defence, in order:
 *   1. Scheme must be https.
 *   2. Host must be on a small, fixed, public allowlist. Attacker input can
 *      only ever contribute PATH segments, never the host.
 *   3. No embedded credentials, no non-default port.
 *   4. Literal IP hosts are rejected outright (covers private ranges and the
 *      decimal/hex encodings people use to smuggle them past naive checks).
 *   5. Path segments built from untrusted input are validated separately by
 *      `assertSafePathSegment` so nobody can traverse to another API endpoint.
 *
 * Redirects are followed manually and re-validated against the same allowlist.
 */

/** Fixed public allowlist. Nothing here resolves to private space. */
export const ALLOWED_HOSTS: readonly string[] = [
  'registry.npmjs.org',
  'codeload.github.com',
  'api.github.com',
]

export class EgressError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'EgressError'
  }
}

/** Matches IPv4 dotted quads, bare integers, hex, and bracketed IPv6. */
function looksLikeIpLiteral(host: string): boolean {
  if (host.startsWith('[')) return true
  if (/^\d+$/.test(host)) return true
  if (/^0[xX][0-9a-fA-F]+$/.test(host)) return true
  if (/^[0-9.]+$/.test(host)) return true
  return false
}

/**
 * Validate a fully-formed URL before any request.
 *
 * @throws EgressError when the target is not an allowlisted public endpoint.
 */
export function assertAllowedUrl(raw: string): URL {
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    throw new EgressError(`not a valid absolute URL: ${raw}`)
  }

  if (url.protocol !== 'https:') {
    throw new EgressError(`only https is allowed, got ${url.protocol} (${raw})`)
  }
  if (url.username || url.password) {
    throw new EgressError('URLs with embedded credentials are rejected')
  }
  if (url.port && url.port !== '443') {
    throw new EgressError(`non-default port is rejected: ${url.port}`)
  }

  const host = url.hostname.toLowerCase()
  if (looksLikeIpLiteral(host)) {
    throw new EgressError(`literal IP hosts are rejected: ${host}`)
  }
  if (!ALLOWED_HOSTS.includes(host)) {
    throw new EgressError(
      `host not on allowlist: ${host} (allowed: ${ALLOWED_HOSTS.join(', ')})`,
    )
  }
  return url
}

/**
 * Validate one path segment derived from untrusted input.
 *
 * Blocks traversal (`..`), separators, and encoded separators so a crafted
 * `repository.url` cannot redirect us to a different API endpoint on an
 * otherwise allowlisted host.
 */
export function assertSafePathSegment(value: string, label: string): string {
  if (!value) throw new EgressError(`${label} is empty`)
  if (value.length > 128) throw new EgressError(`${label} is too long`)
  if (!/^[A-Za-z0-9._-]+$/.test(value)) {
    throw new EgressError(`${label} contains unsupported characters: ${value}`)
  }
  if (value === '.' || value === '..') {
    throw new EgressError(`${label} must not be a traversal segment`)
  }
  return value
}

/**
 * Validate a git ref used as a path segment.
 *
 * Refs legitimately contain `/` (e.g. `release/1.2`), so slashes are allowed
 * while traversal and leading dashes are not.
 */
export function assertSafeGitRef(value: string): string {
  if (!value) throw new EgressError('git ref is empty')
  if (value.length > 200) throw new EgressError('git ref is too long')
  if (value.includes('..')) throw new EgressError(`git ref must not contain '..': ${value}`)
  if (value.startsWith('-') || value.startsWith('/') || value.endsWith('/')) {
    throw new EgressError(`malformed git ref: ${value}`)
  }
  if (!/^[A-Za-z0-9._/-]+$/.test(value)) {
    throw new EgressError(`git ref contains unsupported characters: ${value}`)
  }
  return value
}
