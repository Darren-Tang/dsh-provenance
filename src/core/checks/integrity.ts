/**
 * Tarball integrity verification.
 *
 * The registry publishes an SRI digest for every release. Recomputing it over
 * the bytes we actually downloaded detects tampering between the registry and
 * us (proxy, mirror, cache poisoning, MITM).
 *
 * Note the scope honestly: a matching digest proves the bytes match what the
 * registry serves. It says nothing about whether the publisher was honest.
 * Publisher honesty is what provenance and the source diff are for.
 */

import { createHash } from 'node:crypto'
import type { IntegrityResult } from '../types.js'

/** Compute an SRI-style digest over raw tarball bytes. */
export function computeSri(data: Uint8Array, algorithm: 'sha512' | 'sha1'): string {
  const digest = createHash(algorithm).update(data).digest('base64')
  return `${algorithm}-${digest}`
}

/**
 * Compare declared and computed digests.
 *
 * The digest is taken over the compressed `.tgz` bytes, matching npm semantics.
 */
export function verifyIntegrity(
  tarball: Uint8Array,
  declaredIntegrity: string | undefined,
  shasum: string | undefined,
): IntegrityResult {
  if (declaredIntegrity) {
    const algorithm = declaredIntegrity.startsWith('sha512-') ? 'sha512' : undefined
    if (algorithm) {
      const computed = computeSri(tarball, 'sha512')
      return {
        status: computed === declaredIntegrity ? 'match' : 'mismatch',
        algorithm,
        declared: declaredIntegrity,
        computed,
      }
    }
  }

  // Older releases only carry a hex sha1 shasum.
  if (shasum) {
    const computed = createHash('sha1').update(tarball).digest('hex')
    return {
      status: computed === shasum ? 'match' : 'mismatch',
      algorithm: 'sha1',
      declared: shasum,
      computed,
    }
  }

  return { status: 'undeclared' }
}
