#!/usr/bin/env node
/**
 * Standalone CLI.
 *
 * Deliberately usable without dsh installed, for two reasons: the checks are
 * valuable in CI before anything reaches a developer machine, and decoupling
 * the engine from the harness means a breaking dsh interface change cannot take
 * the security tooling down with it.
 */

import { parseArgs } from 'node:util'
import { TOOL } from './core/meta.js'
import { preflight } from './core/preflight.js'
import { exitCodeFor, renderPreflight, renderVerify } from './core/report.js'
import { defaultDshHome, listProfiles, profileDir, verifyProfile } from './core/verify.js'

const USAGE = `${TOOL.name} v${TOOL.version}

Verify that the plugin you install matches the source you reviewed.

Usage:
  dsh-provenance preflight <source> [options]   Check BEFORE installing
  dsh-provenance verify [options]               Check what is already installed
  dsh-provenance profiles                       List discovered dsh profiles

Sources:
  pkg-name                 latest from npm
  pkg-name@1.2.3           exact npm version
  github:owner/repo        moving git reference (flagged)
  github:owner/repo#<sha>  pinned git reference

Options:
  --json               machine-readable output
  --no-diff            skip the repository comparison (fewer requests)
  --ref <ref>          force a git ref for the comparison
  --profile <name>     profile to verify (default: web)
  --dir <path>         verify an explicit profile directory
  --strict             exit non-zero on REVIEW as well as BLOCK
  --help

Exit codes: 0 ok/notice, 1 review (--strict only), 2 block.

This tool never executes the audited package and never writes it to disk.
`

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      json: { type: 'boolean', default: false },
      diff: { type: 'boolean', default: true },
      ref: { type: 'string' },
      profile: { type: 'string', default: 'web' },
      dir: { type: 'string' },
      strict: { type: 'boolean', default: false },
      help: { type: 'boolean', default: false },
    },
  })

  const command = positionals[0]

  if (values.help || !command) {
    process.stdout.write(USAGE)
    return 0
  }

  switch (command) {
    case 'preflight': {
      const source = positionals[1]
      if (!source) {
        process.stderr.write('error: preflight requires a source\n\n' + USAGE)
        return 64
      }
      const report = await preflight(source, {
        skipDiff: !values.diff,
        ...(values.ref ? { ref: values.ref } : {}),
      })
      process.stdout.write(
        values.json ? `${JSON.stringify(report, null, 2)}\n` : `${renderPreflight(report)}\n`,
      )
      return exitCodeFor(report.verdict, values.strict)
    }

    case 'verify': {
      const dir = values.dir ?? profileDir(values.profile)
      const report = await verifyProfile(dir)
      process.stdout.write(
        values.json ? `${JSON.stringify(report, null, 2)}\n` : `${renderVerify(report)}\n`,
      )
      return exitCodeFor(report.verdict, values.strict)
    }

    case 'profiles': {
      const home = defaultDshHome()
      const profiles = await listProfiles(home)
      if (profiles.length === 0) {
        process.stdout.write(`No profiles found under ${home}. Set DSH_HOME if it lives elsewhere.\n`)
        return 0
      }
      process.stdout.write(`Profiles under ${home}:\n`)
      for (const profile of profiles) process.stdout.write(`  ${profile}\n`)
      return 0
    }

    default:
      process.stderr.write(`error: unknown command "${command}"\n\n${USAGE}`)
      return 64
  }
}

main()
  .then((code) => process.exit(code))
  .catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`)
    process.exit(70)
  })
