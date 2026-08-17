/**
 * npm registry access.
 *
 * Everything is read-only metadata plus the tarball bytes. We never invoke npm
 * or pnpm, so no lifecycle script can run as a side effect of auditing.
 */

import { fetchBytes, fetchJson } from '../net/fetch.js'
import { assertSafePathSegment } from '../net/guard.js'

const REGISTRY = 'https://registry.npmjs.org'
const METADATA_LIMIT = 8 * 1024 * 1024
const TARBALL_LIMIT = 32 * 1024 * 1024

export interface RegistryDist {
  tarball: string
  shasum?: string
  integrity?: string
  fileCount?: number
  unpackedSize?: number
  attestations?: {
    url?: string
    provenance?: { predicateType?: string }
  }
}

export interface RegistryVersion {
  name: string
  version: string
  dist: RegistryDist
  scripts?: Record<string, string>
  repository?: string | { url?: string; type?: string; directory?: string }
  deprecated?: string
}

export interface Packument {
  name: string
  'dist-tags'?: Record<string, string>
  versions?: Record<string, RegistryVersion>
  time?: Record<string, string>
  maintainers?: Array<{ name?: string; email?: string }>
}

/**
 * Build a registry URL from an untrusted package name.
 *
 * Scoped names contain a `/`, which is legal in the path but must not allow
 * traversal, so each segment is validated independently.
 */
function packumentUrl(name: string): string {
  if (name.startsWith('@')) {
    const [scope = '', pkg = ''] = [name.slice(1, name.indexOf('/')), name.slice(name.indexOf('/') + 1)]
    assertSafePathSegment(scope, 'package scope')
    assertSafePathSegment(pkg, 'package name')
    return `${REGISTRY}/@${scope}%2f${pkg}`
  }
  assertSafePathSegment(name, 'package name')
  return `${REGISTRY}/${name}`
}

export async function fetchPackument(name: string, signal?: AbortSignal): Promise<Packument> {
  return fetchJson<Packument>(packumentUrl(name), {
    maxBytes: METADATA_LIMIT,
    headers: { accept: 'application/json' },
    ...(signal ? { signal } : {}),
  })
}

/**
 * Resolve a range or dist-tag to a concrete version.
 *
 * Deliberately conservative: exact versions and dist-tags are honoured, but we
 * do not reimplement semver range arithmetic. An unresolvable range falls back
 * to `latest` and the caller records a warning, because silently picking the
 * wrong version would make the whole report misleading.
 */
export function resolveVersion(
  packument: Packument,
  range: string | undefined,
): { version: string; exact: boolean; note?: string } {
  const versions = Object.keys(packument.versions ?? {})
  const tags = packument['dist-tags'] ?? {}

  if (!range || range === 'latest' || range === '*') {
    const latest = tags['latest'] ?? versions[versions.length - 1]
    if (!latest) throw new Error(`no versions published for ${packument.name}`)
    return { version: latest, exact: false }
  }

  if (versions.includes(range)) return { version: range, exact: true }
  const tagged = tags[range]
  if (tagged) return { version: tagged, exact: false }

  const bare = range.replace(/^[\^~>=<\s]+/, '')
  if (versions.includes(bare)) {
    return {
      version: bare,
      exact: false,
      note: `range "${range}" was audited against ${bare}; the installer may resolve a different version`,
    }
  }

  const latest = tags['latest'] ?? versions[versions.length - 1]
  if (!latest) throw new Error(`cannot resolve "${range}" for ${packument.name}`)
  return {
    version: latest,
    exact: false,
    note: `range "${range}" could not be resolved precisely; audited "latest" (${latest}) instead`,
  }
}

export async function fetchTarball(url: string, signal?: AbortSignal): Promise<Uint8Array> {
  const result = await fetchBytes(url, {
    maxBytes: TARBALL_LIMIT,
    ...(signal ? { signal } : {}),
  })
  return result.body
}

/** Normalise the several shapes a `repository` field can take. */
export function repositoryUrlOf(version: RegistryVersion): string | undefined {
  const repository = version.repository
  if (!repository) return undefined
  if (typeof repository === 'string') return repository
  return repository.url
}

/**
 * Subdirectory within the repository that this package is published from.
 *
 * Essential for monorepos: the tarball's paths are relative to the package
 * root, while a repository tarball is relative to the repo root. Without this
 * offset almost every file fails to line up and the comparison degrades into
 * "unverifiable", which looks like a clean result but verifies nothing.
 */
export function repositoryDirectoryOf(version: RegistryVersion): string | undefined {
  const repository = version.repository
  if (!repository || typeof repository === 'string') return undefined
  const directory = repository.directory?.trim()
  if (!directory) return undefined
  return directory.replace(/^\.?\//, '').replace(/\/$/, '')
}
