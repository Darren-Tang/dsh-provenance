/**
 * GitHub source access.
 *
 * Only two endpoints are used, both on the allowlist:
 *   - api.github.com      repo metadata and ref resolution
 *   - codeload.github.com source tarballs
 *
 * Owner, repo and ref all originate from untrusted manifests, so every value is
 * validated as a path segment before it reaches a URL.
 */

import { fetchBytes, fetchJson, githubAuthHeaders } from '../net/fetch.js'
import { assertSafeGitRef, assertSafePathSegment } from '../net/guard.js'

const API = 'https://api.github.com'
const CODELOAD = 'https://codeload.github.com'
const METADATA_LIMIT = 2 * 1024 * 1024
const TARBALL_LIMIT = 32 * 1024 * 1024

export interface RepoMetadata {
  full_name?: string
  stargazers_count?: number
  created_at?: string
  pushed_at?: string
  archived?: boolean
  fork?: boolean
  default_branch?: string
  message?: string
}

export async function fetchRepoMetadata(
  owner: string,
  repo: string,
  signal?: AbortSignal,
): Promise<RepoMetadata> {
  assertSafePathSegment(owner, 'repo owner')
  assertSafePathSegment(repo, 'repo name')
  return fetchJson<RepoMetadata>(`${API}/repos/${owner}/${repo}`, {
    maxBytes: METADATA_LIMIT,
    headers: { accept: 'application/vnd.github+json', ...githubAuthHeaders() },
    ...(signal ? { signal } : {}),
  })
}

/** Download a source tarball for a ref. Returns raw gzip bytes. */
export async function fetchSourceTarball(
  owner: string,
  repo: string,
  ref: string,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  assertSafePathSegment(owner, 'repo owner')
  assertSafePathSegment(repo, 'repo name')
  assertSafeGitRef(ref)
  const result = await fetchBytes(`${CODELOAD}/${owner}/${repo}/tar.gz/${ref}`, {
    maxBytes: TARBALL_LIMIT,
    ...(signal ? { signal } : {}),
  })
  return result.body
}

export interface ChooseRefOptions {
  provenanceCommit?: string
  version?: string
  explicitRef?: string
  signal?: AbortSignal
}

export type RefOrigin = 'provenance' | 'version-tag' | 'explicit' | 'default-branch'

export interface SourceResolution {
  tarball: Uint8Array
  ref: string
  origin: RefOrigin
}

/**
 * Download repository source for a release, trying candidate refs in order of
 * anchor strength.
 *
 * Deliberately does NOT consult api.github.com to discover which refs exist.
 * The anonymous API allows 60 requests per hour, so a rate limit there would
 * disable the single most valuable check in this tool. codeload has no such
 * limit and answers the only question that matters — "can this ref be
 * downloaded?" — by simply returning 404 when it cannot.
 *
 * Candidate order:
 *   1. explicit ref, when the operator forced one
 *   2. provenance commit — asserted by the build, exact
 *   3. `v<version>` then `<version>` — the conventional release tags
 *   4. HEAD — weakest, moves independently of the release
 */
export async function fetchSourceForRelease(
  owner: string,
  repo: string,
  options: ChooseRefOptions,
): Promise<SourceResolution> {
  const candidates: Array<{ ref: string; origin: RefOrigin }> = []

  if (options.explicitRef) {
    candidates.push({ ref: options.explicitRef, origin: 'explicit' })
  } else {
    if (options.provenanceCommit) {
      candidates.push({ ref: options.provenanceCommit, origin: 'provenance' })
    }
    if (options.version) {
      candidates.push({ ref: `v${options.version}`, origin: 'version-tag' })
      candidates.push({ ref: options.version, origin: 'version-tag' })
    }
    candidates.push({ ref: 'HEAD', origin: 'default-branch' })
  }

  const failures: string[] = []
  for (const candidate of candidates) {
    try {
      const tarball = await fetchSourceTarball(owner, repo, candidate.ref, options.signal)
      return { tarball, ref: candidate.ref, origin: candidate.origin }
    } catch (error) {
      failures.push(`${candidate.ref}: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  throw new Error(`no downloadable ref for ${owner}/${repo} (tried ${failures.join('; ')})`)
}
