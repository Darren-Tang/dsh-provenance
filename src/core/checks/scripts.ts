/**
 * Lifecycle script detection.
 *
 * THIS IS THE TIME-CRITICAL CHECK.
 *
 * `dsh plugin --profile web add <pkg>` forwards to pnpm. Install-time hooks run
 * DURING that command, before any post-install scanner gets a chance to look at
 * the code. By then arbitrary code has already executed with the operator's
 * privileges. Any audit that only runs after installation structurally cannot
 * catch this, which is precisely the gap this tool exists to close.
 *
 * pnpm semantics matter and are reported rather than assumed:
 *   - pnpm >= 10 does not run dependency lifecycle scripts unless the package
 *     is allowlisted through `onlyBuiltDependencies`.
 *   - `prepare` still runs for git-sourced dependencies, because the package
 *     has to be built from source.
 *   - Older pnpm, npm and yarn run these hooks by default.
 *
 * So presence is reported as a fact, and the operator applies their own
 * package-manager semantics. We do not claim to know their configuration.
 */

import type { LifecycleScriptResult } from '../types.js'

/** Hooks a package manager may execute at install time. */
const INSTALL_HOOKS = [
  'preinstall',
  'install',
  'postinstall',
  'prepare',
  'prepublish',
  'preprepare',
  'postprepare',
] as const

const PNPM_NOTE =
  'pnpm >= 10 blocks dependency lifecycle scripts unless allowlisted via onlyBuiltDependencies, ' +
  'but `prepare` still runs for git-sourced dependencies. npm, yarn and older pnpm run these by default. ' +
  'Presence is reported as fact; apply your own package-manager configuration.'

export function detectLifecycleScripts(
  manifest: Record<string, unknown> | undefined,
): LifecycleScriptResult {
  const present: Array<{ hook: string; command: string }> = []
  const scripts = manifest?.['scripts']

  if (scripts && typeof scripts === 'object') {
    const table = scripts as Record<string, unknown>
    for (const hook of INSTALL_HOOKS) {
      const command = table[hook]
      if (typeof command === 'string' && command.trim()) {
        present.push({ hook, command: command.trim() })
      }
    }
  }

  return { present, note: PNPM_NOTE }
}

/**
 * Flag install commands that reach the network or spawn a shell pipeline.
 *
 * A hook that merely runs `tsc` is ordinary. A hook that curls a URL into a
 * shell is the textbook install-time dropper, so the two are separated instead
 * of alarming on every build step.
 */
export function isHighRiskCommand(command: string): boolean {
  const patterns = [
    /\bcurl\b/i,
    /\bwget\b/i,
    /\bnc\b/i,
    /\bnode\s+-e\b/i,
    /\beval\b/i,
    /\bbase64\s+-d\b/i,
    /\|\s*(?:ba)?sh\b/i,
    /\bchmod\s+\+x\b/i,
    /https?:\/\//i,
  ]
  return patterns.some((pattern) => pattern.test(command))
}
