/**
 * Installed-plugin verification.
 *
 * Complements `preflight`, which runs before installation. This side answers:
 * what is actually installed in this profile, and can each of those plugins
 * still be traced back to an immutable source?
 *
 * Entirely local and offline: it reads the profile manifest, the lockfile and
 * `node_modules` manifests. It never executes plugin code and never phones home.
 *
 * Profile layout, per the dsh CLI reference:
 *   $DSH_HOME/profiles/<name>/package.json      out-of-tree plugin deps
 *   $DSH_HOME/profiles/<name>/pnpm-lock.yaml    resolutions and integrity
 *   $DSH_HOME/profiles/<name>/node_modules/     what pnpm actually installed
 */

import { readFile, readdir, stat } from 'node:fs/promises'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { detectLifecycleScripts, isHighRiskCommand } from './checks/scripts.js'
import { TOOL } from './meta.js'
import { parseSource } from './sources/spec.js'
import {
  maxSeverity,
  type Finding,
  type InstalledPluginRecord,
  type Severity,
  type VerifyReport,
} from './types.js'

/** Bundles shipped with dsh itself; not third-party supply chain. */
const BUILT_IN_PREFIXES = ['@deepseek-ai/dsh-']

export function defaultDshHome(): string {
  return process.env['DSH_HOME'] ?? join(homedir(), '.dsh')
}

export function profileDir(profile: string, dshHome = defaultDshHome()): string {
  return join(dshHome, 'profiles', profile)
}

export async function verifyProfile(dir: string): Promise<VerifyReport> {
  const findings: Finding[] = []
  const warnings: string[] = []
  const plugins: InstalledPluginRecord[] = []

  const report: VerifyReport = {
    schemaVersion: 1,
    tool: { name: TOOL.name, version: TOOL.version },
    generatedAt: new Date().toISOString(),
    profileDir: dir,
    plugins,
    findings,
    verdict: 'ok',
    warnings,
  }

  const manifest = await readJsonFile(join(dir, 'package.json'))
  if (!manifest) {
    findings.push({
      id: 'profile.not-found',
      severity: 'review',
      title: 'Profile manifest not found',
      detail:
        `No package.json under ${dir}. Pass the correct profile name, or set DSH_HOME if the harness ` +
        'home is not in the default location.',
      evidence: [dir],
    })
    report.verdict = 'review'
    return report
  }

  const declared = collectDependencies(manifest)
  const integrityBySpec = await readLockIntegrity(join(dir, 'pnpm-lock.yaml'), warnings)

  for (const [name, spec] of declared) {
    if (BUILT_IN_PREFIXES.some((prefix) => name.startsWith(prefix))) continue

    const installedDir = join(dir, 'node_modules', name)
    const installed = await readJsonFile(join(installedDir, 'package.json'))
    const version = typeof installed?.['version'] === 'string' ? installed['version'] : undefined

    const record: InstalledPluginRecord = {
      name,
      declaredSpec: spec,
      path: installedDir,
      ...(version ? { version } : {}),
      ...(integrityBySpec.get(`${name}@${version}`)
        ? { integrity: integrityBySpec.get(`${name}@${version}`)! }
        : {}),
    }
    plugins.push(record)

    // The single most useful local signal: is this dependency traceable to
    // immutable content at all?
    const source = parseSource(spec.startsWith('github:') || spec.includes('/') ? spec : `${name}@${spec}`)
    if (!source.pinned) {
      findings.push({
        id: source.kind === 'github' ? 'installed.floating-git-ref' : 'installed.unpinned-range',
        severity: source.kind === 'github' ? 'review' : 'notice',
        title: `${name} is not pinned to immutable content`,
        detail:
          source.pinReason ??
          'The declared specifier can resolve to different content on a future install.',
        evidence: [`${name}: ${spec}`],
      })
    }

    if (!installed) {
      findings.push({
        id: 'installed.missing',
        severity: 'notice',
        title: `${name} is declared but not installed`,
        detail: 'The profile manifest lists this plugin but node_modules has no manifest for it.',
        evidence: [installedDir],
      })
      continue
    }

    // Hooks found here already ran at install time. Reported so the operator
    // knows which packages had the opportunity to execute code.
    const scripts = detectLifecycleScripts(installed)
    if (scripts.present.length > 0) {
      const risky = scripts.present.filter((entry) => isHighRiskCommand(entry.command))
      findings.push({
        id: risky.length > 0 ? 'installed.high-risk-hook' : 'installed.hook-present',
        severity: risky.length > 0 ? 'review' : 'notice',
        title: `${name} ships install-time lifecycle scripts`,
        detail:
          'These hooks may already have executed when the plugin was installed. Verifying them now is ' +
          'after the fact; run preflight before installing to catch this earlier.',
        evidence: scripts.present.map((entry) => `${entry.hook}: ${entry.command}`),
      })
    }
  }

  if (plugins.length === 0) {
    findings.push({
      id: 'profile.no-third-party-plugins',
      severity: 'ok',
      title: 'No third-party plugins installed in this profile',
      detail: 'Only built-in dsh bundles were found, so there is no external supply chain here.',
    })
  }

  report.verdict = findings.reduce<Severity>((acc, f) => maxSeverity(acc, f.severity), 'ok')
  return report
}

/** Enumerate profiles under a harness home. */
export async function listProfiles(dshHome = defaultDshHome()): Promise<string[]> {
  try {
    const entries = await readdir(join(dshHome, 'profiles'), { withFileTypes: true })
    return entries.filter((entry) => entry.isDirectory()).map((entry) => entry.name)
  } catch {
    return []
  }
}

export async function pathExists(target: string): Promise<boolean> {
  try {
    await stat(target)
    return true
  } catch {
    return false
  }
}

function collectDependencies(manifest: Record<string, unknown>): Map<string, string> {
  const out = new Map<string, string>()
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    const table = manifest[field]
    if (!table || typeof table !== 'object') continue
    for (const [name, spec] of Object.entries(table as Record<string, unknown>)) {
      if (typeof spec === 'string') out.set(name, spec)
    }
  }
  return out
}

async function readJsonFile(path: string): Promise<Record<string, unknown> | undefined> {
  try {
    const text = await readFile(path, 'utf8')
    const parsed: unknown = JSON.parse(text)
    return typeof parsed === 'object' && parsed !== null
      ? (parsed as Record<string, unknown>)
      : undefined
  } catch {
    return undefined
  }
}

/**
 * Best-effort integrity extraction from pnpm-lock.yaml.
 *
 * Deliberately a narrow line scan rather than a full YAML parse: pulling in a
 * YAML dependency would undercut the zero-dependency posture of a security
 * tool, and the only fields needed are package keys and their integrity values.
 * Because it is best-effort, a miss produces no finding — it never claims a
 * mismatch it cannot substantiate.
 */
async function readLockIntegrity(
  lockPath: string,
  warnings: string[],
): Promise<Map<string, string>> {
  const out = new Map<string, string>()
  let text: string
  try {
    text = await readFile(lockPath, 'utf8')
  } catch {
    warnings.push(
      'pnpm-lock.yaml not found; installed integrity values were not read (declared specifiers were still checked)',
    )
    return out
  }

  const lines = text.split(/\r?\n/)
  let currentKey: string | undefined

  for (const line of lines) {
    // Package keys look like `  /foo@1.0.0:` (v6) or `  foo@1.0.0:` (v9).
    const keyMatch = /^ {2}\/?((?:@[^/\s]+\/)?[^@\s/][^@\s]*@[^:\s]+):\s*$/.exec(line)
    if (keyMatch?.[1]) {
      currentKey = keyMatch[1]
      continue
    }
    if (!currentKey) continue

    const inline = /integrity:\s*(sha\d+-[A-Za-z0-9+/=]+)/.exec(line)
    if (inline?.[1]) {
      out.set(currentKey, inline[1])
      currentKey = undefined
    }
  }

  return out
}
