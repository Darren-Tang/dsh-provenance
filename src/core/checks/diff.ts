/**
 * Published-artifact vs source-repository comparison.
 *
 * THE GAP THIS CLOSES
 *
 * Every existing scanner in this ecosystem reads the files already on disk and
 * asks "does this code do something bad?". None of them ask the prior question:
 * "is this code the code the author showed me?" An npm tarball is whatever the
 * publisher uploaded. It is not built from the repository by the registry, and
 * nothing forces the two to agree. A publisher can push clean source to GitHub,
 * collect stars and reviews, then publish a tarball with one extra file in it.
 *
 * Naive byte-for-byte diffing produces noise, because published packages
 * legitimately differ from repositories: build output is present, sources and
 * tests are absent. So findings are sorted into four honest buckets:
 *
 *   match        same path, identical bytes
 *   mismatch     same path, DIFFERENT bytes  -> the strongest signal available
 *   npm-only     shipped but absent upstream -> the classic injection shape
 *   unverifiable build output; cannot be checked without reproducing the build
 *
 * `unverifiable` is never reported as `match`. A tool that rounds "I could not
 * check this" up to "this is fine" is worse than no tool, because it converts
 * absence of evidence into false assurance.
 */

import { indexFiles, sha256Hex, stripRoot, type TarEntry } from '../archive/tar.js'
import type { DiffResult, FileComparison, FileVerdict } from '../types.js'

/** Paths that are build output rather than authored source. */
const BUILD_OUTPUT = [
  /^lib\//,
  /^dist\//,
  /^build\//,
  /^out\//,
  /^es\//,
  /^esm\//,
  /^cjs\//,
  /\.min\.js$/,
  /\.map$/,
  /\.d\.ts$/,
]

/** Files npm generates or rewrites on publish; differences are expected. */
const PUBLISH_NORMALISED = [/^package\.json$/, /^README(\.md)?$/i, /^LICEN[SC]E/i, /^\.npmignore$/]

/** Executable source extensions: an unexplained extra one of these is serious. */
const EXECUTABLE_SOURCE = /\.(?:m?js|cjs|ts|mts|cts|jsx|tsx|node|wasm|sh|bash|py)$/i

function isBuildOutput(path: string): boolean {
  return BUILD_OUTPUT.some((pattern) => pattern.test(path))
}

function isPublishNormalised(path: string): boolean {
  return PUBLISH_NORMALISED.some((pattern) => pattern.test(path))
}

export interface DiffOptions {
  ref: string
  refOrigin: DiffResult['refOrigin']
  /** Cap on files listed in the report; counts always reflect everything. */
  maxListedFiles?: number
  /**
   * Path within the repository that the package is published from.
   *
   * Required for monorepos, where npm paths are relative to the package root
   * but repository paths are relative to the repo root.
   */
  gitSubdirectory?: string
}

/** Re-root repository entries onto the published package's path space. */
function rebaseGitFiles(
  gitFiles: Map<string, TarEntry>,
  subdirectory: string | undefined,
): Map<string, TarEntry> {
  if (!subdirectory) return gitFiles
  const prefix = `${subdirectory.replace(/\/$/, '')}/`
  const rebased = new Map<string, TarEntry>()
  for (const [path, entry] of gitFiles) {
    if (path.startsWith(prefix)) {
      rebased.set(path.slice(prefix.length), entry)
    }
  }
  // A declared directory that matches nothing is more likely a stale manifest
  // than an empty package, so fall back rather than report everything missing.
  return rebased.size > 0 ? rebased : gitFiles
}

/**
 * Compare a published tarball against a repository tarball.
 *
 * Both inputs are already-parsed entry lists, so this function performs no I/O
 * and is fully unit-testable.
 */
export function compareTrees(
  npmEntries: TarEntry[],
  gitEntries: TarEntry[],
  options: DiffOptions,
): DiffResult {
  const npmFiles = indexFiles(stripRoot(npmEntries))
  const gitFiles = rebaseGitFiles(indexFiles(stripRoot(gitEntries)), options.gitSubdirectory)

  const files: FileComparison[] = []
  const counts: Record<FileVerdict, number> = {
    match: 0,
    mismatch: 0,
    'npm-only': 0,
    unverifiable: 0,
  }

  for (const [path, npmEntry] of npmFiles) {
    if (!npmEntry.data) continue

    const gitEntry = gitFiles.get(path)

    if (isBuildOutput(path)) {
      counts.unverifiable++
      files.push({
        path,
        verdict: 'unverifiable',
        reason: 'build output; verifying it requires reproducing the build',
      })
      continue
    }

    if (!gitEntry) {
      // Publish-normalised metadata is expected to differ; a shipped source
      // file with no upstream counterpart is the injection shape we care about.
      if (isPublishNormalised(path)) {
        counts.unverifiable++
        files.push({
          path,
          verdict: 'unverifiable',
          reason: 'rewritten by the registry on publish',
        })
        continue
      }
      counts['npm-only']++
      files.push({
        path,
        verdict: 'npm-only',
        npmSha256: sha256Hex(npmEntry.data),
        reason: EXECUTABLE_SOURCE.test(path)
          ? 'executable file shipped in the package but absent from the repository'
          : 'shipped in the package but absent from the repository',
      })
      continue
    }

    if (!gitEntry.data) {
      counts.unverifiable++
      files.push({ path, verdict: 'unverifiable', reason: 'upstream entry has no content' })
      continue
    }

    const npmHash = sha256Hex(npmEntry.data)
    const gitHash = sha256Hex(gitEntry.data)

    if (npmHash === gitHash) {
      counts.match++
      files.push({ path, verdict: 'match' })
      continue
    }

    if (isPublishNormalised(path)) {
      counts.unverifiable++
      files.push({
        path,
        verdict: 'unverifiable',
        reason: 'rewritten by the registry on publish',
        npmSha256: npmHash,
        gitSha256: gitHash,
      })
      continue
    }

    counts.mismatch++
    files.push({ path, verdict: 'mismatch', npmSha256: npmHash, gitSha256: gitHash })
  }

  // Severity first, then path, so the report leads with what matters.
  const rank: Record<FileVerdict, number> = {
    mismatch: 0,
    'npm-only': 1,
    unverifiable: 2,
    match: 3,
  }
  files.sort((a, b) => rank[a.verdict] - rank[b.verdict] || a.path.localeCompare(b.path))

  const limit = options.maxListedFiles ?? 100
  return {
    compared: true,
    ref: options.ref,
    refOrigin: options.refOrigin,
    counts,
    files: files.slice(0, limit),
  }
}

/** Files that carry real weight in the verdict. */
export function significantFindings(diff: DiffResult): FileComparison[] {
  return diff.files.filter(
    (file) => file.verdict === 'mismatch' || file.verdict === 'npm-only',
  )
}

/** True when an npm-only file is executable code rather than an asset. */
export function isExecutableExtra(file: FileComparison): boolean {
  return file.verdict === 'npm-only' && EXECUTABLE_SOURCE.test(file.path)
}
