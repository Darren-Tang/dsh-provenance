/**
 * In-memory tar.gz reader.
 *
 * WHY WE PARSE TAR OURSELVES
 *
 * The whole point of this tool is to inspect untrusted archives without ever
 * letting them touch the filesystem. Delegating to a generic extractor means
 * files land on disk, which reintroduces zip-slip, symlink escape and disk
 * exhaustion. Parsing in memory removes those classes entirely:
 *
 *   - no path is ever joined against a real directory -> no zip-slip
 *   - no symlink is ever created -> no link escape
 *   - hard ceilings on entry count / entry size / total size -> no tar bomb
 *   - `maxOutputLength` on gunzip -> no decompression bomb
 *   - no install hook can run, because we never invoke a package manager
 *
 * Cost: ~150 lines of header parsing. Worth it for a security tool that also
 * wants zero runtime dependencies.
 */

import { createHash } from 'node:crypto'
import { gunzipSync } from 'node:zlib'

const BLOCK_SIZE = 512

export interface TarEntry {
  /** Normalised path with the archive's root directory stripped. */
  path: string
  size: number
  mode: number
  type: 'file' | 'directory' | 'symlink' | 'hardlink' | 'other'
  linkTarget?: string
  /** Present for regular files only. */
  data?: Uint8Array
}

export interface ArchiveLimits {
  maxEntries: number
  maxEntrySize: number
  maxTotalSize: number
  /** Ceiling for gunzip output, guarding against compression bombs. */
  maxInflatedSize: number
}

export const DEFAULT_LIMITS: ArchiveLimits = {
  maxEntries: 5_000,
  maxEntrySize: 8 * 1024 * 1024,
  maxTotalSize: 64 * 1024 * 1024,
  maxInflatedSize: 128 * 1024 * 1024,
}

export class ArchiveError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ArchiveError'
  }
}

/** Read an octal numeric header field, tolerating NUL/space padding. */
function readOctal(block: Uint8Array, offset: number, length: number): number {
  // GNU base-256 encoding for large values sets the high bit of the first byte.
  const first = block[offset] ?? 0
  if ((first & 0x80) !== 0) {
    let value = first & 0x7f
    for (let i = 1; i < length; i++) {
      value = value * 256 + (block[offset + i] ?? 0)
    }
    return value
  }

  let text = ''
  for (let i = 0; i < length; i++) {
    const byte = block[offset + i] ?? 0
    if (byte === 0 || byte === 0x20) {
      if (text) break
      continue
    }
    text += String.fromCharCode(byte)
  }
  if (!text) return 0
  const parsed = Number.parseInt(text, 8)
  return Number.isFinite(parsed) ? parsed : 0
}

function readString(block: Uint8Array, offset: number, length: number): string {
  let end = offset
  const limit = offset + length
  while (end < limit && (block[end] ?? 0) !== 0) end++
  return new TextDecoder().decode(block.subarray(offset, end))
}

function mapTypeFlag(flag: string): TarEntry['type'] {
  switch (flag) {
    case '0':
    case '\0':
    case '7':
      return 'file'
    case '1':
      return 'hardlink'
    case '2':
      return 'symlink'
    case '5':
      return 'directory'
    default:
      return 'other'
  }
}

/** Parse a PAX extended header payload (`"<len> key=value\n"` records). */
function parsePaxRecords(data: Uint8Array): Map<string, string> {
  const out = new Map<string, string>()
  const text = new TextDecoder().decode(data)
  let cursor = 0
  while (cursor < text.length) {
    const space = text.indexOf(' ', cursor)
    if (space < 0) break
    const declaredLength = Number.parseInt(text.slice(cursor, space), 10)
    if (!Number.isFinite(declaredLength) || declaredLength <= 0) break
    const record = text.slice(space + 1, cursor + declaredLength).replace(/\n$/, '')
    const eq = record.indexOf('=')
    if (eq > 0) out.set(record.slice(0, eq), record.slice(eq + 1))
    cursor += declaredLength
  }
  return out
}

/**
 * Reject anything that could escape a directory if a caller ever did write it.
 *
 * We do not write files, but paths flow into reports and diff keys, so they are
 * normalised at the boundary rather than at each use site.
 */
function normalisePath(raw: string): string {
  const unified = raw.replace(/\\/g, '/')
  if (unified.startsWith('/') || /^[A-Za-z]:/.test(unified)) {
    throw new ArchiveError(`absolute path in archive: ${raw}`)
  }
  const segments = unified.split('/').filter((s) => s !== '' && s !== '.')
  if (segments.includes('..')) {
    throw new ArchiveError(`path traversal in archive: ${raw}`)
  }
  return segments.join('/')
}

/**
 * Decompress and walk a tar.gz entirely in memory.
 *
 * @param gz raw gzip bytes
 * @param limits hard ceilings; exceeding any of them throws
 */
export function readTarGz(gz: Uint8Array, limits: ArchiveLimits = DEFAULT_LIMITS): TarEntry[] {
  let tar: Buffer
  try {
    tar = gunzipSync(gz, { maxOutputLength: limits.maxInflatedSize })
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    throw new ArchiveError(`gunzip failed (possible bomb or corrupt archive): ${message}`)
  }

  const entries: TarEntry[] = []
  let offset = 0
  let totalBytes = 0
  let pendingLongName: string | undefined
  let pendingPax: Map<string, string> | undefined

  while (offset + BLOCK_SIZE <= tar.length) {
    const header = tar.subarray(offset, offset + BLOCK_SIZE)

    // Two consecutive zero blocks terminate the archive.
    if (header.every((byte) => byte === 0)) break

    const rawName = readString(header, 0, 100)
    const mode = readOctal(header, 100, 8)
    const size = readOctal(header, 124, 12)
    const typeFlag = String.fromCharCode(header[156] ?? 0)
    const linkName = readString(header, 157, 100)
    const prefix = readString(header, 345, 155)

    offset += BLOCK_SIZE

    if (size < 0 || size > limits.maxEntrySize) {
      throw new ArchiveError(`entry exceeds size limit (${size} > ${limits.maxEntrySize})`)
    }
    const dataEnd = offset + size
    if (dataEnd > tar.length) {
      throw new ArchiveError('truncated archive: entry data past end of stream')
    }
    const payload = tar.subarray(offset, dataEnd)
    // Entry bodies are padded to a 512-byte boundary.
    offset += Math.ceil(size / BLOCK_SIZE) * BLOCK_SIZE

    // GNU long name: the payload holds the next entry's path.
    if (typeFlag === 'L') {
      pendingLongName = new TextDecoder().decode(payload).replace(/\0+$/, '')
      continue
    }
    // PAX extended header: applies to the following entry.
    if (typeFlag === 'x') {
      pendingPax = parsePaxRecords(payload)
      continue
    }
    // PAX global header: not entry-scoped, ignore.
    if (typeFlag === 'g' || typeFlag === 'K') {
      continue
    }

    let name = pendingLongName ?? (prefix ? `${prefix}/${rawName}` : rawName)
    const paxPath = pendingPax?.get('path')
    if (paxPath) name = paxPath
    pendingLongName = undefined
    pendingPax = undefined

    if (!name) continue

    const type = mapTypeFlag(typeFlag)
    const normalised = normalisePath(name)
    if (!normalised) continue

    if (entries.length >= limits.maxEntries) {
      throw new ArchiveError(`archive has more than ${limits.maxEntries} entries`)
    }

    if (type === 'file') {
      totalBytes += size
      if (totalBytes > limits.maxTotalSize) {
        throw new ArchiveError(`archive exceeds total size limit ${limits.maxTotalSize}`)
      }
      entries.push({
        path: normalised,
        size,
        mode,
        type,
        data: Uint8Array.prototype.slice.call(payload),
      })
    } else {
      entries.push({
        path: normalised,
        size,
        mode,
        type,
        ...(linkName ? { linkTarget: linkName } : {}),
      })
    }
  }

  return entries
}

/**
 * Strip the archive's single root directory.
 *
 * npm tarballs nest everything under `package/`; GitHub codeload tarballs use
 * `<repo>-<ref>/`. Comparing the two requires a common root.
 */
export function stripRoot(entries: TarEntry[]): TarEntry[] {
  const roots = new Set<string>()
  for (const entry of entries) {
    const slash = entry.path.indexOf('/')
    roots.add(slash < 0 ? entry.path : entry.path.slice(0, slash))
  }
  if (roots.size !== 1) return entries

  const [root] = [...roots]
  const prefix = `${root}/`
  const out: TarEntry[] = []
  for (const entry of entries) {
    if (entry.path === root) continue
    if (!entry.path.startsWith(prefix)) return entries
    out.push({ ...entry, path: entry.path.slice(prefix.length) })
  }
  return out
}

export function sha256Hex(data: Uint8Array): string {
  return createHash('sha256').update(data).digest('hex')
}

/** Index regular files by path for O(1) comparison. */
export function indexFiles(entries: TarEntry[]): Map<string, TarEntry> {
  const map = new Map<string, TarEntry>()
  for (const entry of entries) {
    if (entry.type === 'file') map.set(entry.path, entry)
  }
  return map
}

export function findManifest(files: Map<string, TarEntry>): Record<string, unknown> | undefined {
  const entry = files.get('package.json')
  if (!entry?.data) return undefined
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(entry.data))
    return typeof parsed === 'object' && parsed !== null
      ? (parsed as Record<string, unknown>)
      : undefined
  } catch {
    return undefined
  }
}
