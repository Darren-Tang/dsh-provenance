/**
 * npm provenance attestation.
 *
 * Provenance is the only cryptographic bridge from "a package on the registry"
 * back to "a commit in a repository". When present it tells us the package was
 * built by a known CI workflow from a specific commit, which turns the source
 * diff from guesswork into an exact comparison.
 *
 * HONEST SCOPE — do not let this drift.
 *
 * This version PARSES the attestation payload. It does NOT verify the sigstore
 * signature chain, so a hostile registry response could assert anything. The
 * report therefore always carries `signatureVerified: false`, and the renderer
 * tells the operator to run `npm audit signatures` for the cryptographic check.
 *
 * The reason for spelling this out so loudly: a comparable tool in this
 * ecosystem shipped a runtime sentinel that never fired for two releases,
 * because its tests mirrored the same wrong assumption as its implementation.
 * Overstating what a check proves is the failure mode of security tooling, so
 * unverified assertions stay labelled as unverified.
 */

import { fetchJson } from '../net/fetch.js'
import { assertAllowedUrl } from '../net/guard.js'
import type { AttestationKind, ProvenanceResult } from '../types.js'
import type { RegistryDist } from '../sources/registry.js'

const ATTESTATION_LIMIT = 4 * 1024 * 1024

interface AttestationBundle {
  attestations?: Array<{
    predicateType?: string
    bundle?: {
      dsseEnvelope?: { payload?: string; payloadType?: string }
    }
  }>
}

interface SlsaPredicate {
  buildDefinition?: {
    externalParameters?: {
      workflow?: { repository?: string; path?: string; ref?: string }
    }
    resolvedDependencies?: Array<{
      uri?: string
      digest?: { gitCommit?: string }
    }>
  }
  runDetails?: {
    builder?: { id?: string }
  }
}

interface InTotoStatement {
  predicateType?: string
  predicate?: SlsaPredicate
}

/**
 * Resolve provenance for a release.
 *
 * Returns `absent` when the publisher did not attest, which is the common case
 * and is a `notice`, not a failure.
 */
export async function checkProvenance(
  dist: RegistryDist,
  signal?: AbortSignal,
): Promise<ProvenanceResult> {
  const url = dist.attestations?.url
  if (!url) {
    return { status: 'absent', signatureVerified: false }
  }

  try {
    // The URL comes from registry metadata, so it is still guard-checked.
    assertAllowedUrl(url)
    const bundle = await fetchJson<AttestationBundle>(url, {
      maxBytes: ATTESTATION_LIMIT,
      headers: { accept: 'application/json' },
      ...(signal ? { signal } : {}),
    })

    const statements: InTotoStatement[] = []

    for (const attestation of bundle.attestations ?? []) {
      const payload = attestation.bundle?.dsseEnvelope?.payload
      if (!payload) continue
      const statement = decodeStatement(payload)
      if (statement?.predicate) statements.push(statement)
    }

    if (statements.length === 0) {
      return {
        status: 'lookup-failed',
        signatureVerified: false,
        error: 'attestation bundle contained no parsable statement',
      }
    }

    // Pick the SLSA provenance statement, not merely the first one present.
    //
    // npm attaches both a publish attestation and (when the publisher opted in)
    // a SLSA provenance attestation. Only the latter carries buildDefinition and
    // the git commit. Taking whichever came first in the array silently
    // discarded the commit for every package that has both — observed against
    // the real registry, where the publish attestation is returned first.
    const chosen =
      statements.find((statement) => classify(statement) === 'slsa-provenance') ?? statements[0]!

    const predicate = chosen.predicate
    const workflow = predicate?.buildDefinition?.externalParameters?.workflow
    const commit = predicate ? findGitCommit(predicate) : undefined

    return {
      status: 'present-unverified',
      signatureVerified: false,
      attestationKind: classify(chosen),
      ...(chosen.predicateType ? { predicateType: chosen.predicateType } : {}),
      ...(workflow?.repository ? { sourceRepository: workflow.repository } : {}),
      ...(workflow?.path ? { workflow: workflow.path } : {}),
      ...(commit ? { sourceCommit: commit } : {}),
      ...(predicate?.runDetails?.builder?.id ? { builderId: predicate.runDetails.builder.id } : {}),
    }
  } catch (error) {
    return {
      status: 'lookup-failed',
      signatureVerified: false,
      error: error instanceof Error ? error.message : String(error),
    }
  }
}

/** Distinguish a source-anchoring attestation from a mere publish record. */
function classify(statement: InTotoStatement): AttestationKind {
  const type = statement.predicateType ?? ''
  if (/slsa\.dev\/provenance/i.test(type)) return 'slsa-provenance'
  if (statement.predicate?.buildDefinition) return 'slsa-provenance'
  if (/npm\/attestation/i.test(type)) return 'npm-publish'
  return 'other'
}

function decodeStatement(payloadBase64: string): InTotoStatement | undefined {
  try {
    const json = Buffer.from(payloadBase64, 'base64').toString('utf8')
    const parsed: unknown = JSON.parse(json)
    return typeof parsed === 'object' && parsed !== null ? (parsed as InTotoStatement) : undefined
  } catch {
    return undefined
  }
}

function findGitCommit(predicate: SlsaPredicate): string | undefined {
  for (const dependency of predicate.buildDefinition?.resolvedDependencies ?? []) {
    const commit = dependency.digest?.gitCommit
    if (commit && /^[0-9a-f]{40}$/i.test(commit)) return commit
  }
  return undefined
}

/** Extract `owner/repo` from a provenance repository URI. */
export function repoFromProvenance(
  provenance: ProvenanceResult,
): { owner: string; repo: string } | undefined {
  const raw = provenance.sourceRepository
  if (!raw) return undefined
  const match = /github\.com\/([A-Za-z0-9._-]+)\/([A-Za-z0-9._-]+)/.exec(raw)
  if (!match) return undefined
  const [, owner, repo] = match
  if (!owner || !repo) return undefined
  return { owner, repo }
}
