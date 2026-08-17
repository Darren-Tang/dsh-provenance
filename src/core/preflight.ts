/**
 * Pre-install supply-chain preflight.
 *
 * Answers one question: if I install this source right now, what am I actually
 * getting, and does it match the source I was shown?
 *
 * Non-negotiable invariants, asserted in the report's `guarantees` block:
 *   - the audited package's code is never executed
 *   - no package manager is ever invoked (so no install hook can fire)
 *   - nothing from the audited package is written to disk
 *   - egress is restricted to a fixed public allowlist
 */

import { findManifest, indexFiles, readTarGz, stripRoot, type TarEntry } from './archive/tar.js'
import { compareTrees, isExecutableExtra } from './checks/diff.js'
import { verifyIntegrity } from './checks/integrity.js'
import { checkProvenance, repoFromProvenance } from './checks/provenance.js'
import { detectLifecycleScripts, isHighRiskCommand } from './checks/scripts.js'
import { TOOL } from './meta.js'
import { ALLOWED_HOSTS } from './net/guard.js'
import { fetchRepoMetadata, fetchSourceForRelease, fetchSourceTarball } from './sources/github.js'
import {
  fetchPackument,
  fetchTarball,
  repositoryDirectoryOf,
  repositoryUrlOf,
  resolveVersion,
  type RegistryVersion,
} from './sources/registry.js'
import { parseRepositoryUrl, parseSource } from './sources/spec.js'
import {
  maxSeverity,
  type DiffResult,
  type Finding,
  type PreflightReport,
  type ProvenanceResult,
  type Severity,
  type SourceSpec,
} from './types.js'

export interface PreflightOptions {
  /** Skip the repository comparison (faster, fewer requests). */
  skipDiff?: boolean
  /** Force a specific git ref for the comparison. */
  ref?: string
  maxListedFiles?: number
  /**
   * Caller cancellation. When invoked as a dsh tool this is `exec.signal`,
   * which the tool contract requires us to honour.
   */
  signal?: AbortSignal
}

export async function preflight(
  rawSource: string,
  options: PreflightOptions = {},
): Promise<PreflightReport> {
  const source = parseSource(rawSource)
  const findings: Finding[] = []
  const warnings: string[] = []

  const report: PreflightReport = {
    schemaVersion: 1,
    tool: { name: TOOL.name, version: TOOL.version },
    generatedAt: new Date().toISOString(),
    source,
    findings,
    verdict: 'ok',
    warnings,
    guarantees: {
      executedAuditedCode: false,
      wroteAuditedPackageToDisk: false,
      signatureCryptographicallyVerified: false,
      networkAllowlist: ALLOWED_HOSTS,
    },
  }

  addPinFindings(source, findings)

  try {
    if (source.kind === 'npm' && source.name) {
      await auditNpmSource(source, report, findings, warnings, options)
    } else if (source.kind === 'github' && source.owner && source.repo) {
      await auditGithubSource(source, report, findings, warnings, options)
    } else {
      findings.push({
        id: 'source.unsupported',
        severity: 'review',
        title: `Cannot verify a ${source.kind} source remotely`,
        detail:
          source.kind === 'local'
            ? 'Local paths have no registry or repository to compare against. Review the directory contents directly.'
            : 'This source type cannot be resolved to an immutable artifact plus an upstream repository, so provenance cannot be established.',
        evidence: [source.raw],
      })
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    findings.push({
      id: 'audit.failed',
      severity: 'review',
      title: 'Preflight could not complete',
      detail: `Collection failed, so absence of findings below means nothing: ${message}`,
      evidence: [message],
    })
  }

  report.verdict = findings.reduce<Severity>((acc, f) => maxSeverity(acc, f.severity), 'ok')
  return report
}

/* ------------------------------------------------------------------ *
 * npm path
 * ------------------------------------------------------------------ */

async function auditNpmSource(
  source: SourceSpec,
  report: PreflightReport,
  findings: Finding[],
  warnings: string[],
  options: PreflightOptions,
): Promise<void> {
  const name = source.name!
  const packument = await fetchPackument(name, options.signal)
  const resolution = resolveVersion(packument, source.range)
  if (resolution.note) warnings.push(resolution.note)

  const release: RegistryVersion | undefined = packument.versions?.[resolution.version]
  if (!release) throw new Error(`registry has no metadata for ${name}@${resolution.version}`)

  const publishedAt = packument.time?.[resolution.version]
  const repositoryUrl = repositoryUrlOf(release)

  report.resolved = {
    name: release.name ?? name,
    version: resolution.version,
    tarballUrl: release.dist.tarball,
    ...(release.dist.integrity ? { declaredIntegrity: release.dist.integrity } : {}),
    ...(release.dist.shasum ? { shasum: release.dist.shasum } : {}),
    ...(publishedAt ? { publishedAt } : {}),
    ...(repositoryUrl ? { repositoryUrl } : {}),
    ...(release.dist.fileCount !== undefined ? { fileCount: release.dist.fileCount } : {}),
    ...(release.dist.unpackedSize !== undefined ? { unpackedBytes: release.dist.unpackedSize } : {}),
  }

  if (release.deprecated) {
    findings.push({
      id: 'registry.deprecated',
      severity: 'notice',
      title: 'Package version is deprecated',
      detail: release.deprecated,
    })
  }

  // --- integrity -------------------------------------------------------
  const tarball = await fetchTarball(release.dist.tarball, options.signal)
  const integrity = verifyIntegrity(tarball, release.dist.integrity, release.dist.shasum)
  report.integrity = integrity

  if (integrity.status === 'mismatch') {
    findings.push({
      id: 'integrity.mismatch',
      severity: 'block',
      title: 'Downloaded tarball does not match the registry digest',
      detail:
        'The bytes served to us differ from the digest the registry publishes. Treat this as tampering ' +
        'somewhere between the registry and this machine (proxy, mirror, or cache) until proven otherwise.',
      evidence: [`declared ${integrity.declared}`, `computed ${integrity.computed}`],
    })
  } else if (integrity.status === 'undeclared') {
    findings.push({
      id: 'integrity.undeclared',
      severity: 'notice',
      title: 'Registry published no integrity digest',
      detail: 'Without a declared digest there is nothing to verify the downloaded bytes against.',
    })
  }

  // --- manifest and install hooks --------------------------------------
  const npmEntries = readTarGz(tarball)
  const npmFiles = indexFiles(stripRoot(npmEntries))
  const manifest = findManifest(npmFiles)
  addScriptFindings(manifest, findings, report)

  // --- provenance ------------------------------------------------------
  const provenance = await checkProvenance(release.dist, options.signal)
  report.provenance = provenance
  addProvenanceFindings(provenance, findings)

  // --- source comparison ------------------------------------------------
  if (options.skipDiff) return

  const repo = repoFromProvenance(provenance) ?? parseRepositoryUrl(repositoryUrl)
  if (!repo) {
    findings.push({
      id: 'repository.missing',
      severity: 'review',
      title: 'No upstream repository to compare against',
      detail:
        'The package declares no usable GitHub repository and carries no provenance, so there is no way ' +
        'to check whether the published files match any reviewable source.',
    })
    return
  }

  try {
    await addDiff(
      repo,
      resolution.version,
      provenance,
      npmEntries,
      report,
      findings,
      options,
      repositoryDirectoryOf(release),
    )
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    warnings.push(`source comparison skipped: ${message}`)
    report.diff = { compared: false, counts: emptyCounts(), files: [], skippedReason: message }
    findings.push({
      id: 'diff.unavailable',
      severity: 'notice',
      title: 'Source comparison could not run',
      detail: `The published files were not compared against the repository: ${message}`,
    })
  }
}

async function addDiff(
  repo: { owner: string; repo: string },
  version: string,
  provenance: ProvenanceResult,
  npmEntries: TarEntry[],
  report: PreflightReport,
  findings: Finding[],
  options: PreflightOptions,
  gitSubdirectory: string | undefined,
): Promise<void> {
  const resolved = await fetchSourceForRelease(repo.owner, repo.repo, {
    ...(provenance.sourceCommit ? { provenanceCommit: provenance.sourceCommit } : {}),
    ...(options.ref ? { explicitRef: options.ref } : {}),
    ...(options.signal ? { signal: options.signal } : {}),
    version,
  })

  const gitEntries = readTarGz(resolved.tarball)

  const diff = compareTrees(npmEntries, gitEntries, {
    ref: resolved.ref,
    refOrigin: resolved.origin,
    ...(gitSubdirectory ? { gitSubdirectory } : {}),
    ...(options.maxListedFiles !== undefined ? { maxListedFiles: options.maxListedFiles } : {}),
  })
  report.diff = diff
  addDiffFindings(diff, findings)
}

/* ------------------------------------------------------------------ *
 * github path
 * ------------------------------------------------------------------ */

async function auditGithubSource(
  source: SourceSpec,
  report: PreflightReport,
  findings: Finding[],
  warnings: string[],
  options: PreflightOptions,
): Promise<void> {
  const owner = source.owner!
  const repo = source.repo!

  try {
    const metadata = await fetchRepoMetadata(owner, repo, options.signal)
    if (metadata.archived) {
      findings.push({
        id: 'repository.archived',
        severity: 'notice',
        title: 'Repository is archived',
        detail: 'An archived repository receives no security fixes.',
      })
    }
    if ((metadata.stargazers_count ?? 0) === 0) {
      findings.push({
        id: 'repository.unreviewed',
        severity: 'notice',
        title: 'Repository has no stars',
        detail:
          'No community signal at all. Not evidence of malice, but nobody else has reviewed this code either.',
      })
    }
  } catch (error) {
    warnings.push(
      `repository metadata unavailable: ${error instanceof Error ? error.message : String(error)}`,
    )
  }

  const ref = source.ref ?? 'HEAD'
  const gitTarball = await fetchSourceTarball(owner, repo, ref, options.signal)
  const entries = readTarGz(gitTarball)
  const manifest = findManifest(indexFiles(stripRoot(entries)))
  addScriptFindings(manifest, findings, report)

  findings.push({
    id: 'source.git-no-registry-anchor',
    severity: 'notice',
    title: 'Git source has no registry artifact to cross-check',
    detail:
      'Installing straight from git means there is no published tarball and no provenance attestation, ' +
      'so the only thing to review is the repository contents at this ref.',
    evidence: [`github:${owner}/${repo}#${ref}`],
  })
}

/* ------------------------------------------------------------------ *
 * findings
 * ------------------------------------------------------------------ */

function addPinFindings(source: SourceSpec, findings: Finding[]): void {
  if (source.pinned) return

  // A moving git ref is strictly worse than a moving npm range: the npm version
  // you audited stays byte-identical forever, whereas a branch can be rewritten
  // under the same name, so review and install can disagree silently.
  const severity: Severity = source.kind === 'github' ? 'review' : 'notice'
  findings.push({
    id: source.kind === 'github' ? 'source.floating-git-ref' : 'source.unpinned-range',
    severity,
    title:
      source.kind === 'github'
        ? 'Install source is a moving git reference'
        : 'Install source is not pinned to an exact version',
    detail:
      source.pinReason ??
      'The source does not identify immutable content, so what you review is not guaranteed to be what you install.',
    evidence: [source.raw],
  })
}

function addScriptFindings(
  manifest: Record<string, unknown> | undefined,
  findings: Finding[],
  report: PreflightReport,
): void {
  const scripts = detectLifecycleScripts(manifest)
  report.scripts = scripts
  if (scripts.present.length === 0) return

  const risky = scripts.present.filter((entry) => isHighRiskCommand(entry.command))

  if (risky.length > 0) {
    findings.push({
      id: 'scripts.high-risk-install-hook',
      severity: 'block',
      title: 'Install hook fetches or executes external content',
      detail:
        'This command runs during `dsh plugin add`, before any post-install scanner can inspect anything. ' +
        'A hook that reaches the network or pipes into a shell is the standard install-time dropper pattern.',
      evidence: risky.map((entry) => `${entry.hook}: ${entry.command}`),
    })
    return
  }

  findings.push({
    id: 'scripts.install-hook-present',
    severity: 'review',
    title: 'Package declares install-time lifecycle scripts',
    detail: `These run during installation, not after it. ${scripts.note}`,
    evidence: scripts.present.map((entry) => `${entry.hook}: ${entry.command}`),
  })
}

function addProvenanceFindings(provenance: ProvenanceResult, findings: Finding[]): void {
  switch (provenance.status) {
    case 'absent':
      findings.push({
        id: 'provenance.absent',
        severity: 'notice',
        title: 'No provenance attestation',
        detail:
          'The publisher did not attest which commit and workflow produced this package, so the link from ' +
          'artifact to source code rests on convention rather than evidence.',
      })
      break
    case 'present-unverified':
      // Only SLSA provenance anchors the artifact to a commit. A publish
      // attestation proves who released it and nothing about the source, so
      // reporting both as equally good would overstate the guarantee.
      if (provenance.attestationKind === 'slsa-provenance' && provenance.sourceCommit) {
        findings.push({
          id: 'provenance.build-attested',
          severity: 'ok',
          title: 'Build provenance found, pinning the artifact to a commit',
          detail:
            'The attestation asserts which commit and workflow built this package, so the source comparison ' +
            'below runs against exact content. This tool parses that claim but does not verify the sigstore ' +
            'signature chain; run `npm audit signatures` for the cryptographic check.',
          evidence: [
            provenance.sourceRepository ? `repository ${provenance.sourceRepository}` : 'repository unknown',
            `commit ${provenance.sourceCommit}`,
            ...(provenance.workflow ? [`workflow ${provenance.workflow}`] : []),
          ],
        })
      } else {
        findings.push({
          id: 'provenance.publish-only',
          severity: 'notice',
          title: 'Only a publish attestation is present, with no build provenance',
          detail:
            'The registry can attest who published this release, but not which commit it was built from. ' +
            'The artifact therefore still cannot be tied to reviewable source, and the comparison below falls ' +
            'back to an inferred tag or branch.',
          evidence: [
            `attestation type ${provenance.predicateType ?? 'unknown'}`,
            ...(provenance.sourceRepository ? [`repository ${provenance.sourceRepository}`] : []),
          ],
        })
      }
      break
    case 'lookup-failed':
      findings.push({
        id: 'provenance.lookup-failed',
        severity: 'notice',
        title: 'Provenance attestation could not be read',
        detail: provenance.error ?? 'unknown error',
      })
      break
  }
}

function addDiffFindings(diff: DiffResult, findings: Finding[]): void {
  // An exact commit from provenance leaves no room for benign explanation: any
  // difference means the published artifact is not that commit. A guessed tag
  // can legitimately be off by a release, so it only warrants review.
  const exactAnchor = diff.refOrigin === 'provenance' || diff.refOrigin === 'explicit'

  if (diff.counts.mismatch > 0) {
    findings.push({
      id: 'diff.content-mismatch',
      severity: exactAnchor ? 'block' : 'review',
      title: `${diff.counts.mismatch} published file(s) differ from the repository`,
      detail: exactAnchor
        ? `Compared against ${diff.ref} (${diff.refOrigin}), which identifies exact content. Files that differ ` +
          'were not built from the source you can read.'
        : `Compared against ${diff.ref} (${diff.refOrigin}). Some difference is expected when the tag is inferred, ` +
          'but each differing file should be explained before installing.',
      evidence: diff.files
        .filter((file) => file.verdict === 'mismatch')
        .slice(0, 10)
        .map((file) => file.path),
    })
  }

  const extras = diff.files.filter(isExecutableExtra)
  if (extras.length > 0) {
    findings.push({
      id: 'diff.executable-npm-only',
      severity: exactAnchor ? 'block' : 'review',
      title: `${extras.length} executable file(s) shipped but absent upstream`,
      detail:
        'These files exist in the published package but not in the repository. Adding code at publish time is ' +
        'how a package with clean, well-reviewed source ships something else to installers.',
      evidence: extras.slice(0, 10).map((file) => file.path),
    })
  }

  // A comparison that matched nothing is the most dangerous state this tool can
  // produce: the table shows "0 mismatch, 0 npm-only" and reads like a clean
  // bill of health, while in fact not one file was checked. Packages that ship
  // only build output land here, and so would an attacker who arranged for it.
  // Saying so explicitly is the whole point of the unverifiable bucket.
  if (diff.counts.match === 0 && diff.counts.mismatch === 0 && extras.length === 0) {
    findings.push({
      id: 'diff.nothing-verified',
      severity: 'review',
      title: 'The source comparison verified nothing',
      detail:
        `Not a single file in the published package could be matched against ${diff.ref}. Typically the ` +
        'package ships only build output, or it is published from a subdirectory that its manifest does not ' +
        'declare via repository.directory. Either way the "0 mismatch" result above carries no assurance: ' +
        'read the published files directly, or reproduce the build.',
      evidence: [
        `unverifiable ${diff.counts.unverifiable}`,
        `compared against ${diff.ref} (${diff.refOrigin})`,
      ],
    })
    return
  }

  if (
    diff.counts.mismatch === 0 &&
    extras.length === 0 &&
    diff.counts.match > 0 &&
    diff.counts.unverifiable > 0
  ) {
    const total = diff.counts.match + diff.counts.unverifiable
    findings.push({
      id: 'diff.partially-verifiable',
      severity: 'notice',
      title: `Verified ${diff.counts.match} of ${total} published file(s)`,
      detail:
        `${diff.counts.match} file(s) matched the repository byte for byte and ${diff.counts.unverifiable} ` +
        'could not be checked, being build output or rewritten on publish. The ratio is stated plainly rather ' +
        'than summarised as a pass: a low one means most of what you install was never compared to anything.',
      evidence: [
        `verified ${diff.counts.match}`,
        `unverifiable ${diff.counts.unverifiable}`,
        `compared against ${diff.ref} (${diff.refOrigin})`,
      ],
    })
  }
}

function emptyCounts(): DiffResult['counts'] {
  return { match: 0, mismatch: 0, 'npm-only': 0, unverifiable: 0 }
}
