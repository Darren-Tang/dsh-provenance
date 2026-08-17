/**
 * dsh plugin entry point.
 *
 * Kept deliberately thin. All logic lives under `src/core`, which has no
 * framework dependency, because dsh v0.1 is a developer preview that states
 * outright that breaking changes are coming. When an interface moves, only this
 * file should need rewriting.
 *
 * Registered surface:
 *   provenance_preflight  audit an install source BEFORE installing
 *   provenance_verify     inspect what is already installed in a profile
 *   a tool guard          refuse agent-driven installs that skipped preflight
 */

import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { ApprovalLedger, collectStrings, detectInstallIntent } from './core/intercept.js'
import { preflight } from './core/preflight.js'
import { renderPreflight, renderVerify } from './core/report.js'
import { defaultDshHome, profileDir, verifyProfile } from './core/verify.js'

export const name = 'dsh-provenance'
export const inject = ['tools']

export interface Config {
  /**
   * Refuse agent-initiated plugin installs whose source has not passed a
   * preflight in this session. Default true: an agent that can be steered into
   * installing code is the threat this plugin exists to address.
   */
  guardInstalls?: boolean
  /** Skip the repository comparison by default (fewer network requests). */
  skipDiffByDefault?: boolean
}

/**
 * Minimal shape of the pipeline's execution view.
 *
 * Per `packages/core/tools/README.md`, pipeline views expose `arguments`, while
 * only a tool's own body receives a parameter named `args`. Reading `args` here
 * would produce a guard that never fires — a mistake already shipped once in
 * this ecosystem, so the field name is documented rather than assumed.
 */
interface GuardExecution {
  name: string
  arguments: unknown
}

export function apply(ctx: Context, config: Config = {}): void {
  const ledger = new ApprovalLedger()
  const guardInstalls = config.guardInstalls ?? true
  const skipDiffDefault = config.skipDiffByDefault ?? false

  ctx.tools.register(
    defineTool({
      name: 'provenance_preflight',
      description:
        'Check a dsh plugin install source BEFORE installing it. Verifies the registry digest, reads any ' +
        'npm provenance attestation, detects install-time lifecycle scripts, and compares the published ' +
        'files against the upstream repository to detect code that was added at publish time. Never ' +
        'executes the audited package. Run this before `dsh plugin add`.',
      parameters: {
        source: {
          type: 'string',
          required: true,
          description:
            'Install source, e.g. "some-plugin", "some-plugin@1.2.3", "github:owner/repo" or "github:owner/repo#<sha>".',
        },
        skip_diff: {
          type: 'boolean',
          description: 'Skip the repository comparison. Faster, but publish-time injection goes undetected.',
        },
        ref: {
          type: 'string',
          description: 'Force a git ref to compare against instead of inferring one.',
        },
      },
      output: {
        schema: { type: 'string' },
        render: (_args, value) => [{ type: 'text', text: value }],
      },
      async execute(args, exec) {
        const report = await preflight(args.source, {
          skipDiff: args.skip_diff ?? skipDiffDefault,
          ...(args.ref ? { ref: args.ref } : {}),
          signal: exec.signal,
        })

        // Anything short of a blocking verdict clears the source for install.
        // A blocking verdict must not be recorded, or the guard would wave
        // through precisely the case it exists to stop.
        if (report.verdict !== 'block') {
          ledger.approve(args.source, report.verdict)
        }

        return renderPreflight(report)
      },
    }),
  )

  ctx.tools.register(
    defineTool({
      name: 'provenance_verify',
      description:
        'Inspect plugins already installed in a dsh profile: which are pinned to immutable sources, which ' +
        'can still be traced upstream, and which shipped install-time hooks that already ran. Fully local, ' +
        'no network access, never executes plugin code.',
      parameters: {
        profile: {
          type: 'string',
          description: 'Profile name to inspect, e.g. "web" or "headless". Defaults to "web".',
        },
        dir: {
          type: 'string',
          description: 'Explicit profile directory, overriding the profile name.',
        },
      },
      output: {
        schema: { type: 'string' },
        render: (_args, value) => [{ type: 'text', text: value }],
      },
      async execute(args) {
        const dir = args.dir ?? profileDir(args.profile ?? 'web', defaultDshHome())
        const report = await verifyProfile(dir)
        return renderVerify(report)
      },
    }),
  )

  if (!guardInstalls) return

  /**
   * Monotonic install guard.
   *
   * `guard` is used rather than the `tools/pre-execute` waterfall for two
   * reasons: its signature is documented exactly (`(execution) => string |
   * undefined`, synchronous), and its denial is monotonic, so no later plugin
   * can turn this refusal back into permission.
   *
   * Being synchronous, it cannot perform the network audit itself; it consults
   * the ledger that `provenance_preflight` writes. That is the correct split —
   * the decision is cheap and local, the investigation is explicit.
   */
  ctx.tools.guard((execution: GuardExecution) => {
    for (const candidate of collectStrings(execution.arguments)) {
      const intent = detectInstallIntent(candidate)
      if (!intent) continue

      const pending = ledger.unapproved(intent.specs)
      if (intent.specs.length === 0 || pending.length === 0) continue

      return (
        `dsh-provenance: refusing to install ${pending.join(', ')} without a supply-chain preflight. ` +
        'Installing runs the package\'s install hooks immediately, so this cannot be checked afterwards. ' +
        `Call provenance_preflight with source="${pending[0]}" first, then retry.`
      )
    }
    return undefined
  })
}
