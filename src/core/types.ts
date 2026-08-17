/**
 * Shared report vocabulary.
 *
 * Design rule: every field here must be derivable from evidence we actually
 * collected. When we cannot verify something we say `unverifiable`, never `ok`.
 */

/** Ordered by escalation. `report.verdict` is the max severity of all findings. */
export type Severity = 'ok' | 'notice' | 'review' | 'block'

export const SEVERITY_ORDER: readonly Severity[] = ['ok', 'notice', 'review', 'block']

export function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER.indexOf(a) >= SEVERITY_ORDER.indexOf(b) ? a : b
}

export interface Finding {
  /** Stable rule id, e.g. `integrity.mismatch`. Safe to allowlist in CI. */
  id: string
  severity: Severity
  title: string
  detail: string
  /** Concrete evidence: paths, hashes, urls. Never secrets in cleartext. */
  evidence?: string[]
}

/* ------------------------------------------------------------------ *
 * Install source
 * ------------------------------------------------------------------ */

export type SourceKind = 'npm' | 'github' | 'tarball' | 'local' | 'unknown'

export interface SourceSpec {
  /** Exactly what the user typed. */
  raw: string
  kind: SourceKind
  /** npm package name, when resolvable. */
  name?: string
  /** npm semver range / dist-tag as written. */
  range?: string
  owner?: string
  repo?: string
  /** git ref as written (branch, tag or sha). */
  ref?: string
  /**
   * True when the reference identifies immutable content.
   *
   * - npm exact version -> pinned (published versions are immutable)
   * - npm range/dist-tag -> not pinned (resolves to something else tomorrow)
   * - github + 40-hex sha -> pinned
   * - github + branch/tag -> NOT pinned (the repo owner can move it)
   */
  pinned: boolean
  /** Why `pinned` is false. */
  pinReason?: string
}

/* ------------------------------------------------------------------ *
 * Checks
 * ------------------------------------------------------------------ */

export interface ResolvedRelease {
  name: string
  version: string
  tarballUrl: string
  /** SRI string from the registry, e.g. `sha512-...`. */
  declaredIntegrity?: string
  shasum?: string
  publishedAt?: string
  /** `repository.url` as declared by the package manifest. */
  repositoryUrl?: string
  /** Number of files in the published tarball. */
  fileCount?: number
  unpackedBytes?: number
}

export type IntegrityStatus = 'match' | 'mismatch' | 'undeclared'

export interface IntegrityResult {
  status: IntegrityStatus
  algorithm?: string
  declared?: string
  computed?: string
}

export interface LifecycleScriptResult {
  /** Scripts that a package manager may run at install time. */
  present: Array<{ hook: string; command: string }>
  /**
   * pnpm >= 10 blocks dependency lifecycle scripts unless allowlisted via
   * `onlyBuiltDependencies`, but `prepare` still runs for git-sourced deps.
   * We report presence and let the reader apply their own pnpm semantics.
   */
  note: string
}

export type ProvenanceStatus =
  | 'absent'
  | 'present-unverified'
  | 'present-verified'
  | 'lookup-failed'

/**
 * npm publishes up to two different attestations per release, and they prove
 * very different things:
 *
 *   slsa-provenance  which commit and CI workflow built the artifact. This is
 *                    the only one that anchors the package to source code.
 *   npm-publish      who pushed the release. Says nothing about the source.
 *
 * Conflating them would let a package that merely proves "npm published this"
 * appear as if its source were verified, so the kind is always recorded.
 */
export type AttestationKind = 'slsa-provenance' | 'npm-publish' | 'other'

export interface ProvenanceResult {
  status: ProvenanceStatus
  attestationKind?: AttestationKind
  /** Repo asserted by the attestation, e.g. `github.com/owner/repo`. */
  sourceRepository?: string
  /** Commit asserted by the attestation. This is our strongest anchor. */
  sourceCommit?: string
  workflow?: string
  builderId?: string
  predicateType?: string
  /**
   * We parse the attestation payload but do NOT verify the sigstore signature
   * chain in this version. Always reported honestly.
   */
  signatureVerified: false
  error?: string
}

export type FileVerdict = 'match' | 'mismatch' | 'npm-only' | 'unverifiable'

export interface FileComparison {
  path: string
  verdict: FileVerdict
  npmSha256?: string
  gitSha256?: string
  /** Why a file could not be verified (e.g. build output). */
  reason?: string
}

export interface DiffResult {
  compared: boolean
  /** Git ref the comparison ran against. */
  ref?: string
  refOrigin?: 'provenance' | 'version-tag' | 'explicit' | 'default-branch'
  counts: Record<FileVerdict, number>
  /** Truncated for readability; full list lives in `files`. */
  files: FileComparison[]
  skippedReason?: string
}

/* ------------------------------------------------------------------ *
 * Report
 * ------------------------------------------------------------------ */

/**
 * Invariants this tool holds itself to. Mirrors the report so a reader can
 * check our claims instead of trusting us.
 */
export interface Guarantees {
  /** We never run the audited package's code, scripts or install hooks. */
  executedAuditedCode: false
  /** We never write the audited package to disk; everything stays in memory. */
  wroteAuditedPackageToDisk: false
  /** Honest: signature chain verification is not implemented yet. */
  signatureCryptographicallyVerified: boolean
  /** Hosts we were allowed to contact. */
  networkAllowlist: readonly string[]
}

export interface PreflightReport {
  schemaVersion: 1
  tool: { name: string; version: string }
  generatedAt: string
  source: SourceSpec
  resolved?: ResolvedRelease
  integrity?: IntegrityResult
  scripts?: LifecycleScriptResult
  provenance?: ProvenanceResult
  diff?: DiffResult
  findings: Finding[]
  verdict: Severity
  guarantees: Guarantees
  /** Non-fatal problems during collection (network, rate limit, ...). */
  warnings: string[]
}

export interface InstalledPluginRecord {
  name: string
  version?: string
  /** Resolution string from the lockfile, when found. */
  resolution?: string
  declaredSpec?: string
  integrity?: string
  path: string
}

export interface VerifyReport {
  schemaVersion: 1
  tool: { name: string; version: string }
  generatedAt: string
  profileDir: string
  plugins: InstalledPluginRecord[]
  findings: Finding[]
  verdict: Severity
  warnings: string[]
}
