/**
 * Report rendering.
 *
 * Two rules govern this file:
 *
 * 1. Lead with the verdict and what it means, then show evidence. An operator
 *    deciding whether to run `dsh plugin add` needs the answer first.
 * 2. Never render a clean report as proof of safety. Every output repeats the
 *    scope of what was and was not verified, because "no findings" from a
 *    partial check is exactly how false assurance gets manufactured.
 */

import type { PreflightReport, Severity, VerifyReport } from './types.js'

const VERDICT_LABEL: Record<Severity, string> = {
  ok: 'OK',
  notice: 'NOTICE',
  review: 'REVIEW',
  block: 'BLOCK',
}

const VERDICT_MEANING: Record<Severity, string> = {
  ok: 'Checks passed within the scope stated below. This is not a guarantee of safety.',
  notice: 'Nothing alarming, but some properties could not be established. Skim the notices.',
  review: 'Read the source before installing. At least one property that should hold does not.',
  block: 'Do not install without a specific explanation for each blocking finding.',
}

export function renderPreflight(report: PreflightReport): string {
  const lines: string[] = []
  const { source, resolved } = report

  lines.push(`# ${VERDICT_LABEL[report.verdict]} — ${source.raw}`)
  lines.push('')
  lines.push(VERDICT_MEANING[report.verdict])
  lines.push('')

  lines.push('## Resolved')
  lines.push(`- source kind: ${source.kind}`)
  lines.push(`- pinned to immutable content: ${source.pinned ? 'yes' : `no (${source.pinReason ?? 'unknown'})`}`)
  if (resolved) {
    lines.push(`- package: ${resolved.name}@${resolved.version}`)
    if (resolved.publishedAt) lines.push(`- published: ${resolved.publishedAt}`)
    if (resolved.repositoryUrl) lines.push(`- declared repository: ${resolved.repositoryUrl}`)
  }
  if (report.integrity) {
    lines.push(
      `- tarball integrity: ${report.integrity.status}${
        report.integrity.algorithm ? ` (${report.integrity.algorithm})` : ''
      }`,
    )
  }
  if (report.provenance) {
    lines.push(`- provenance: ${report.provenance.status}`)
    if (report.provenance.sourceCommit) {
      lines.push(`- attested commit: ${report.provenance.sourceCommit}`)
    }
  }
  lines.push('')

  if (report.diff?.compared) {
    const { counts, ref, refOrigin } = report.diff
    lines.push('## Published artifact vs repository')
    lines.push(`Compared against \`${ref}\` (${refOrigin}).`)
    lines.push('')
    lines.push('| verdict | files | meaning |')
    lines.push('| --- | --- | --- |')
    lines.push(`| match | ${counts.match} | identical bytes upstream |`)
    lines.push(`| mismatch | ${counts.mismatch} | same path, different content |`)
    lines.push(`| npm-only | ${counts['npm-only']} | shipped but absent upstream |`)
    lines.push(`| unverifiable | ${counts.unverifiable} | build output or publish-rewritten |`)
    lines.push('')

    const notable = report.diff.files.filter(
      (file) => file.verdict === 'mismatch' || file.verdict === 'npm-only',
    )
    if (notable.length > 0) {
      lines.push('Files needing explanation:')
      for (const file of notable.slice(0, 25)) {
        lines.push(`- \`${file.path}\` — ${file.verdict}${file.reason ? ` (${file.reason})` : ''}`)
      }
      lines.push('')
    }
  }

  lines.push('## Findings')
  if (report.findings.length === 0) {
    lines.push('No findings.')
  } else {
    for (const finding of report.findings) {
      lines.push(`### [${VERDICT_LABEL[finding.severity]}] ${finding.title}`)
      lines.push(`\`${finding.id}\``)
      lines.push('')
      lines.push(finding.detail)
      if (finding.evidence?.length) {
        lines.push('')
        for (const item of finding.evidence) lines.push(`- ${item}`)
      }
      lines.push('')
    }
  }

  if (report.warnings.length > 0) {
    lines.push('## Warnings')
    for (const warning of report.warnings) lines.push(`- ${warning}`)
    lines.push('')
  }

  lines.push('## Scope of this check')
  lines.push('- The audited package was never executed and never written to disk.')
  lines.push('- No package manager was invoked, so no install hook could fire.')
  lines.push(`- Network egress was restricted to: ${report.guarantees.networkAllowlist.join(', ')}.`)
  lines.push(
    `- Sigstore signature chain verified: ${
      report.guarantees.signatureCryptographicallyVerified ? 'yes' : 'no — run `npm audit signatures` for that'
    }.`,
  )
  lines.push('- Build output cannot be verified without reproducing the build.')
  lines.push('- A clean report means these rules found nothing, not that the package is safe.')

  return lines.join('\n')
}

export function renderVerify(report: VerifyReport): string {
  const lines: string[] = []

  lines.push(`# ${VERDICT_LABEL[report.verdict]} — installed plugins`)
  lines.push('')
  lines.push(VERDICT_MEANING[report.verdict])
  lines.push('')
  lines.push(`Profile: \`${report.profileDir}\``)
  lines.push('')

  if (report.plugins.length > 0) {
    lines.push('## Installed third-party plugins')
    lines.push('')
    lines.push('| plugin | declared | installed |')
    lines.push('| --- | --- | --- |')
    for (const plugin of report.plugins) {
      lines.push(
        `| ${plugin.name} | \`${plugin.declaredSpec ?? '?'}\` | ${plugin.version ?? 'not installed'} |`,
      )
    }
    lines.push('')
  }

  lines.push('## Findings')
  if (report.findings.length === 0) {
    lines.push('No findings.')
  } else {
    for (const finding of report.findings) {
      lines.push(`### [${VERDICT_LABEL[finding.severity]}] ${finding.title}`)
      lines.push(`\`${finding.id}\``)
      lines.push('')
      lines.push(finding.detail)
      if (finding.evidence?.length) {
        lines.push('')
        for (const item of finding.evidence) lines.push(`- ${item}`)
      }
      lines.push('')
    }
  }

  if (report.warnings.length > 0) {
    lines.push('## Warnings')
    for (const warning of report.warnings) lines.push(`- ${warning}`)
    lines.push('')
  }

  lines.push('## Scope of this check')
  lines.push('- Fully local: no plugin code was executed and no network request was made.')
  lines.push('- Install hooks listed here may already have run when the plugin was installed.')
  lines.push('- Run `preflight` before installing to catch those in time.')

  return lines.join('\n')
}

/** Process exit code for CI: only `block` fails the build by default. */
export function exitCodeFor(verdict: Severity, strict: boolean): number {
  if (verdict === 'block') return 2
  if (strict && verdict === 'review') return 1
  return 0
}
