/**
 * Install-intent detection for the tool guard.
 *
 * WHY A GUARD AT ALL
 *
 * A dsh agent can run shell commands. That means the agent itself can be talked
 * into installing a plugin — via a poisoned README, a web page it fetched, or a
 * crafted issue comment. Auditing only what a human types misses the case where
 * the agent does the installing.
 *
 * So install attempts are intercepted and refused unless that exact source has
 * already passed a preflight in this session. The result is a closed loop:
 * the agent tries to install, gets refused with instructions, runs the
 * preflight, then proceeds if the verdict allows.
 *
 * This module is pure string analysis with no framework dependency, so the
 * matching rules are unit-testable without booting a harness.
 */

/** Package managers whose install verbs bring third-party code into a profile. */
const INSTALL_PATTERNS: Array<{ manager: string; pattern: RegExp }> = [
  // `dsh plugin --profile web add <spec>` forwards to pnpm.
  { manager: 'dsh', pattern: /\bdsh\s+plugin\b[^\n]*?\badd\b/ },
  { manager: 'pnpm', pattern: /\bpnpm\s+(?:--\S+\s+)*add\b/ },
  { manager: 'npm', pattern: /\bnpm\s+(?:i|install|add)\b/ },
  { manager: 'yarn', pattern: /\byarn\s+add\b/ },
]

/** Flags and subcommands that are never package specifiers. */
const NON_SPEC = new Set([
  'add',
  'install',
  'i',
  'plugin',
  'dsh',
  'pnpm',
  'npm',
  'yarn',
  '--profile',
  '-P',
  '-D',
  '--save-dev',
  '--save',
  '--global',
  '-g',
])

export interface InstallIntent {
  manager: string
  /** Package specifiers as written on the command line. */
  specs: string[]
  command: string
}

/**
 * Detect an install attempt and extract its specifiers.
 *
 * Returns `undefined` when the command is not an install, so the guard stays
 * out of the way of ordinary work.
 */
export function detectInstallIntent(command: string): InstallIntent | undefined {
  const normalised = command.replace(/\s+/g, ' ').trim()
  if (!normalised) return undefined

  const matched = INSTALL_PATTERNS.find((entry) => entry.pattern.test(normalised))
  if (!matched) return undefined

  const specs: string[] = []
  const tokens = normalised.split(' ')
  let sawInstallVerb = false

  for (const token of tokens) {
    if (!sawInstallVerb) {
      if (/^(?:add|install|i)$/.test(token)) sawInstallVerb = true
      continue
    }
    if (token.startsWith('-')) continue
    if (NON_SPEC.has(token)) continue
    specs.push(token)
  }

  return { manager: matched.manager, specs, command: normalised }
}

/**
 * Collect every string in a tool's arguments.
 *
 * Argument NAMES are deliberately not assumed. Different shell-ish tools use
 * `command`, `script`, `cmd` or an argv array, and guessing wrong is exactly
 * how a guard ends up silently never firing. Scanning all string values costs
 * nothing and cannot miss the payload.
 */
export function collectStrings(value: unknown, depth = 0): string[] {
  if (depth > 6) return []
  if (typeof value === 'string') return [value]
  if (Array.isArray(value)) return value.flatMap((item) => collectStrings(item, depth + 1))
  if (value && typeof value === 'object') {
    return Object.values(value as Record<string, unknown>).flatMap((item) =>
      collectStrings(item, depth + 1),
    )
  }
  return []
}

/**
 * Normalise a specifier for allowlist comparison.
 *
 * `github:owner/repo` and `github:owner/repo#sha` are distinct entries on
 * purpose: approving a pinned commit must not approve the moving branch.
 */
export function normaliseSpec(spec: string): string {
  return spec.trim().replace(/^github:/, 'github:').toLowerCase()
}

/**
 * Session-scoped record of sources that passed preflight.
 *
 * In memory only, and never persisted: an approval decision should not silently
 * survive a restart, an upgrade, or a change in the underlying package.
 */
export class ApprovalLedger {
  private readonly approved = new Map<string, { verdict: string; at: string }>()

  approve(spec: string, verdict: string): void {
    this.approved.set(normaliseSpec(spec), { verdict, at: new Date().toISOString() })
  }

  isApproved(spec: string): boolean {
    return this.approved.has(normaliseSpec(spec))
  }

  /** Specifiers in an install attempt that have not cleared preflight. */
  unapproved(specs: string[]): string[] {
    return specs.filter((spec) => !this.isApproved(spec))
  }

  size(): number {
    return this.approved.size
  }
}
