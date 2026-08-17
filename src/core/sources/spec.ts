/**
 * Install-source parsing.
 *
 * `dsh plugin --profile <name> <pnpm args>` forwards straight to pnpm, so the
 * accepted sources are pnpm's. What matters for supply-chain review is not the
 * syntax but whether the reference identifies IMMUTABLE content:
 *
 *   npm exact version   -> immutable. A published version cannot change.
 *   npm range/dist-tag  -> mutable resolution. Audit today, install something
 *                          else tomorrow. Risk is at the next install.
 *   github + 40-hex sha -> immutable.
 *   github + branch/tag -> MUTABLE CONTENT under the same name. The repo owner
 *                          can rewrite what that ref points at, so the code you
 *                          reviewed is not necessarily the code you install.
 *                          This is strictly worse than a mutable npm range and
 *                          is the case nobody currently checks.
 */

import type { SourceSpec } from '../types.js'

const EXACT_SEMVER = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/
const FULL_SHA = /^[0-9a-f]{40}$/i

/** Parse a user-supplied install source into a normalised spec. */
export function parseSource(raw: string): SourceSpec {
  const input = raw.trim()

  if (!input) {
    return { raw, kind: 'unknown', pinned: false, pinReason: 'empty source' }
  }

  if (input.startsWith('file:') || input.startsWith('link:') || input.startsWith('.')) {
    return {
      raw,
      kind: 'local',
      pinned: false,
      pinReason: 'local path; contents are whatever is on disk at install time',
    }
  }

  if (input.startsWith('http://') || input.startsWith('https://')) {
    const githubArchive = /^https:\/\/(?:www\.)?github\.com\/([^/]+)\/([^/]+)/.exec(input)
    if (githubArchive) {
      return parseGithubShorthand(`github:${githubArchive[1]}/${githubArchive[2]}`, raw)
    }
    return {
      raw,
      kind: 'tarball',
      pinned: false,
      pinReason: 'remote tarball URL; the bytes behind a URL can be replaced',
    }
  }

  if (input.startsWith('github:') || /^[^@/]+\/[^@/]+(?:#.*)?$/.test(input)) {
    return parseGithubShorthand(input, raw)
  }

  if (input.startsWith('git+') || input.startsWith('git@') || input.startsWith('git:')) {
    const ref = input.includes('#') ? input.slice(input.lastIndexOf('#') + 1) : undefined
    const pinned = !!ref && FULL_SHA.test(ref)
    return {
      raw,
      kind: 'github',
      ...(ref ? { ref } : {}),
      pinned,
      ...(pinned ? {} : { pinReason: 'git source without a full commit sha' }),
    }
  }

  return parseNpmSpec(input, raw)
}

function parseGithubShorthand(input: string, raw: string): SourceSpec {
  const withoutScheme = input.startsWith('github:') ? input.slice('github:'.length) : input
  const [locator = '', ref] = splitOnce(withoutScheme, '#')
  const [owner = '', repoRaw = ''] = splitOnce(locator, '/')
  const repo = repoRaw.replace(/\.git$/, '')

  const pinned = !!ref && FULL_SHA.test(ref)
  return {
    raw,
    kind: 'github',
    ...(owner ? { owner } : {}),
    ...(repo ? { repo } : {}),
    ...(ref ? { ref } : {}),
    pinned,
    ...(pinned
      ? {}
      : {
          pinReason: ref
            ? `ref "${ref}" is a branch or tag, not a commit sha; the repo owner can move it`
            : 'no ref given; resolves to the default branch, whose contents can change at any time',
        }),
  }
}

function parseNpmSpec(input: string, raw: string): SourceSpec {
  let name = input
  let range: string | undefined

  // Scoped: @scope/name@range. Unscoped: name@range.
  const at = input.startsWith('@') ? input.indexOf('@', 1) : input.indexOf('@')
  if (at > 0) {
    name = input.slice(0, at)
    range = input.slice(at + 1)
  }

  if (!range) {
    return {
      raw,
      kind: 'npm',
      name,
      range: 'latest',
      pinned: false,
      pinReason: 'no version given; resolves to the "latest" dist-tag',
    }
  }

  const pinned = EXACT_SEMVER.test(range)
  return {
    raw,
    kind: 'npm',
    name,
    range,
    pinned,
    ...(pinned
      ? {}
      : { pinReason: `"${range}" is a range or dist-tag, so the next install may resolve elsewhere` }),
  }
}

function splitOnce(value: string, separator: string): [string, string?] {
  const index = value.indexOf(separator)
  if (index < 0) return [value]
  return [value.slice(0, index), value.slice(index + separator.length)]
}

/** Extract `owner/repo` from a package manifest `repository` field. */
export function parseRepositoryUrl(
  url: string | undefined,
): { owner: string; repo: string } | undefined {
  if (!url) return undefined
  const match = /github\.com[/:]([A-Za-z0-9._-]+)\/([A-Za-z0-9._-]+?)(?:\.git)?(?:[/#?].*)?$/.exec(
    url,
  )
  if (!match) return undefined
  const [, owner, repo] = match
  if (!owner || !repo) return undefined
  return { owner, repo }
}
