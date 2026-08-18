# dsh-provenance

[English](README.md) | [中文](README.zh.md)

[![npm version](https://img.shields.io/npm/v/dsh-provenance)](https://www.npmjs.com/package/dsh-provenance)
[![npm downloads](https://img.shields.io/npm/dm/dsh-provenance)](https://www.npmjs.com/package/dsh-provenance)
[![license](https://img.shields.io/npm/l/dsh-provenance)](https://github.com/Darren-Tang/dsh-provenance/blob/main/LICENSE)
[![dsh-plugin](https://img.shields.io/badge/dsh-plugin-DeepSeek%20Harness-4f46e5)](https://github.com/deepseek-ai/deepseek-harness)

**The source you read on GitHub is not necessarily the package you install.**

A supply-chain preflight for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) plugins.
It answers a question no other scanner in this ecosystem asks.

![dsh-provenance demo](assets/demo.gif)

Existing plugin scanners read the files already on your disk and ask *"does this code do
something bad?"*. That is a useful question, but it comes second. The first question is:

> **Is this code the code the author showed me?**

An npm tarball is whatever the publisher uploaded. The registry does not build it from the
repository, and nothing forces the two to agree. A publisher can push clean source to GitHub,
collect stars and reviews, then publish a tarball with one extra file in it. Every scanner that
runs *after* `dsh plugin add` will happily scan the injected file as if it belonged there — and by
then the package's install hooks have already executed.

`dsh-provenance` runs **before** installation and compares three independent sources of truth:
the npm registry, the upstream repository, and the bytes actually on the wire.

---

## What it checks

| Check | Question answered |
| --- | --- |
| **Source pinning** | Does this specifier identify *immutable* content, or can it change under the same name? |
| **Registry integrity** | Do the bytes we received match the digest the registry publishes? |
| **Install hooks** | Will code execute during `dsh plugin add`, before any post-install scan can look? |
| **Build provenance** | Does a SLSA attestation tie this artifact to a specific commit and CI workflow? |
| **Artifact vs source** | Do the published files actually match that commit — and was anything added at publish time? |

### Why pinning matters more than it looks

```
some-plugin@1.2.3          pinned      a published npm version is immutable
some-plugin@^1.2.3         NOT pinned  the next install may resolve elsewhere
github:owner/repo          NOT pinned  the default branch can be rewritten under the same name
github:owner/repo#v1.0.0   NOT pinned  a tag can be moved by the repo owner
github:owner/repo#<sha>    pinned      a commit sha cannot be forged
```

A moving git reference is strictly worse than a floating npm range. With npm, the version you
audited stays byte-identical forever. With a branch, **the code you reviewed and the code you
install can differ silently**, and the plugin directories are full of `github:owner/repo` install
instructions.

---

## Install

As a dsh plugin:

```sh
dsh plugin --profile web add dsh-provenance
```

As a standalone CLI (no dsh required, useful in CI):

```sh
npm install -g dsh-provenance
```

Requires Node.js 22.19+. **Zero runtime dependencies** — a tool that inspects untrusted packages
should not drag in a supply chain of its own.

---

## Use

### Before installing anything

```sh
dsh-provenance preflight some-plugin@1.2.3
dsh-provenance preflight github:owner/repo
dsh-provenance preflight some-plugin --json      # for CI
```

### Inside dsh

Two tools are registered, so the agent can run the checks itself:

- `provenance_preflight` — audit an install source before installing
- `provenance_verify` — inspect what is already installed in a profile

### Auditing what you already installed

```sh
dsh-provenance verify --profile web
```

Fully local: no network, no plugin code executed. It reports which installed plugins are pinned,
which can still be traced upstream, and which shipped install hooks that already ran.

### CI

```sh
dsh-provenance preflight some-plugin@1.2.3 --strict
```

Exit codes: `0` ok/notice, `1` review (with `--strict`), `2` block.

---

## The install guard

A dsh agent can run shell commands, which means **the agent itself can be talked into installing a
plugin** — through a poisoned README, a fetched web page, or a crafted issue comment. Auditing only
what a human types misses that path entirely.

So install attempts are intercepted and refused unless that source has already passed a preflight
in this session:

```
dsh-provenance: refusing to install evil-plugin without a supply-chain preflight.
Installing runs the package's install hooks immediately, so this cannot be checked
afterwards. Call provenance_preflight with source="evil-plugin" first, then retry.
```

Disable with `{ guardInstalls: false }` if it gets in your way.

Implementation note: this uses `ctx.tools.guard()` rather than the `tools/pre-execute` waterfall,
because `guard`'s signature is documented exactly (`(execution) => string | undefined`, synchronous)
and its denial is *monotonic* — no later plugin can turn the refusal back into permission. The guard
reads `execution.arguments`, which is the field name the pipeline actually exposes; a comparable
tool in this ecosystem read `exec.args` and shipped a sentinel that never fired for two releases.

---

## What this tool does NOT do

Stated plainly, because overstating scope is how security tooling does harm:

- **It does not verify sigstore signatures.** Attestation payloads are parsed, not
  cryptographically verified. Run `npm audit signatures` for that. Every report says so.
- **It cannot verify build output.** `lib/`, `dist/` and minified files are reported as
  `unverifiable`, never as `match`. Verifying them requires reproducing the build.
- **A clean report is not proof of safety.** It means these rules found nothing.
- **It is not a code scanner.** It checks *where code came from*, not what it does. Pair it with a
  behavioural scanner; the two answer different questions.
- **It is not a runtime ledger.** It does not observe or record what a plugin does after install.
  That is provenance in the audit-log sense, not provenance in the supply-chain sense. This tool
  runs *before* install and refuses; it does not run after and record.

### The failure mode it refuses to have

If not a single published file can be matched against the repository, the report does **not** show a
reassuring `0 mismatch`. It raises `diff.nothing-verified` and says the comparison verified nothing.
A tool that rounds *"I could not check this"* up to *"this is fine"* is worse than no tool, because
it manufactures false assurance out of missing evidence.

---

## Safety properties

Auditing hostile packages is itself dangerous. Every report carries a `guarantees` block asserting:

- **The audited package is never executed.** No package manager is invoked, so no install hook can
  fire as a side effect of auditing.
- **Nothing is written to disk.** Archives are parsed entirely in memory, which structurally
  eliminates zip-slip, symlink escape and disk exhaustion rather than defending against them.
- **Egress is allowlisted** to `registry.npmjs.org`, `codeload.github.com` and `api.github.com`.
  This matters: a malicious package controls its own `repository.url`, so without a fixed host
  allowlist a scanner becomes an SSRF pivot into the operator's internal network. Literal IPs,
  embedded credentials, non-default ports and redirects off the allowlist are all rejected.
- **Bounded everywhere.** Response size, gzip output, entry count and per-entry size all have hard
  ceilings, so an archive cannot exhaust memory.
- **Credentials from the environment only.** `GITHUB_TOKEN` is optional, used solely to raise the
  anonymous rate limit, and never logged or persisted.

---

## Architecture

```
src/core/     zero framework dependencies — the engine, fully unit-tested
src/index.ts  thin dsh adapter
src/cli.ts    standalone CLI
```

dsh v0.1 is a developer preview that states outright that breaking changes are coming. The
supply-chain logic is therefore deliberately isolated from the harness interface: when dsh moves,
only the thin adapter should need rewriting, and the CLI keeps working regardless.

## Development

```sh
npm install
npm test              # builds core, then runs the suite
npm run typecheck     # core only, no peer deps needed
npm run build         # full build, needs the dsh peer packages
```

Tests exercise real gzip bytes, real tar headers and the real documented field names, rather than
mocks that could mirror the same wrong assumption as the implementation.

Local development against a dsh source checkout:

```sh
npm run build
# set the absolute path inside cordis.yml first
pnpm dsh web --patch /absolute/path/to/dsh-provenance/cordis.yml
```

## License

MIT
