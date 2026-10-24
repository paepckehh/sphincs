# AGENTS.md

## Project

`paepcke.de/sphincs` is a small, dependency-light Go library implementing a
stateless hash-based (SPHINCS-256-style, "hypertree") post-quantum signature
scheme built from BLAKE3 and a ChaCha-based permutation. It is derived from
`github.com/yawning/sphincs256` and is explicitly experimental.

Because this is cryptographic code, treat every change as security-sensitive:
avoid altering parameter relationships, byte layout, endianness, or the
hash/permutation construction unless the change is intentional and verified.

## Commands

```sh
make            # default target: prints the project name only (does not build)
make build      # go build -v
make check      # gofmt -w -s . followed by staticcheck
make deps       # DESTRUCTIVE: deletes go.mod/go.sum and re-initializes the module

go build ./...
go vet ./...
gofmt -l .
staticcheck ./...
go test ./...   # no test files currently exist in this repo
```

- `make check` rewrites files in place (`gofmt -w`), so run it before reviewing a diff.
- `make deps` derives the module path from the current directory name
  (`paepcke.de/$(basename $(CURDIR))`). Running it outside a directory named
  `sphincs` silently changes the module path; do not run it casually.
- The repo has no tests, no testdata, and no lint config file. Do not assume a
  test harness exists; validate changes with `go build`, `go vet`, `staticcheck`,
  and a temporary round-trip program (GenerateKey -> Sign -> Verify) if needed.

## Layout

| File | Responsibility |
| --- | --- |
| `api.go` | Public API: exported sizes, `GenerateKey`, `Sign`, `Verify` |
| `core.go` | Hypertree constants, `leafaddr`, seed derivation, tree hashing, auth-path computation/validation |
| `wots.go` | WOTS+ chain/seed expansion, key generation, `wotsSign`, `wotsVerify` |
| `horst.go` | HORST few-time signature (`horstSign`, `horstVerify`) and its tree |
| `hash.go` | `hashVarlen` (BLAKE3-256), `hashH2nn`, `hashHnn` and masked variants |
| `chacha.go` | 12-round ChaCha permutation, PRG/keystream helpers (`chachaPrg`, `keystreamBytes`) |
| `permute.go` | Portable `chachaPermute` for uncommon architectures |
| `permute_unaligned.go` | `unsafe` reinterpretation of `[64]byte` as `[16]uint32` |

Constants are split by concern, not centralized: hypertree params in `core.go`,
WOTS params in `wots.go`, HORST params in `horst.go`, hash sizes in `hash.go`,
and exported sizes/formulas in `api.go`.

## Architecture and data flow

- **Key generation** (`GenerateKey`): takes a fixed 96-byte seed token
  (`SeedTokenSize == PrivateKeySize`, seed + random seed + root), hashes the
  top subtree, and returns fixed-size arrays. No error return.
- **Signing** (`Sign`): deterministically derives the leaf index and `R` from
  BLAKE3(secret-random-seed || message), recomputes the public key root,
  derives the message hash, then emits HORST signature, then per-level WOTS
  signature + authentication path. The signature layout is
  `R || leaf index || HORST sig || nLevels * (WOTS sig || auth path)`.
- **Verification** (`Verify`): recomputes the message hash, verifies HORST,
  walks WOTS levels upward, and compares the final root with the public key
  using `crypto/subtle.ConstantTimeCompare`.
- The private key is written through `HORST`/`WOTS` seed expansion, never used
  directly as signing material.
- Signing is deterministic for a given key and message (no per-signature
  randomness). Changing the seed changes every derived one-time key.

### Parameter relationships (do not break)

- `totalTreeHeight = 60`, `subtreeHeight = 5`, `nLevels = totalTreeHeight / subtreeHeight = 12`.
- WOTS: `wotsLogW = 4`, `wotsW = 16`, `wotsL = 67` (must match the base-w
  encoding and checksum loops in `wots.go`).
- HORST: `horstLogT = 16`, `horstT = 1 << 16`, `horstK = 32`.
- `nMasks = 2 * horstLogT` must be at least
  `max(2*(subtreeHeight+wotsLogL), wotsW-1, 2*horstLogT)` (documented in `core.go`).
- `SignatureSize` in `api.go` is derived from these constants; changing any of
  them changes the exported ABI and all key/signature sizes.
- `generateSeed` packs address fields into 64 bits: level in bits 0-3, subtree
  shifted by 4, subleaf shifted by 59. HORST uses `level = nLevels`.

## Gotchas

- **`hashSize` (32) is not `HashSize` (64).** `HashSize`/`MessageSize` describe
  the BLAKE3-512 message digest length; the internal chain/leaf hash size is 32
  bytes (`hashSize`). The README's "blake3-512" refers to the message digest.
- `hashVarlen` uses `blake3.Sum256`, while `Sign`/`Verify` use `blake3.Sum512`;
  this is intentional, not an inconsistency to unify.
- `chachaPermute`/`doRounds` is a 12-round permutation **without** the final
  feed-forward addition. `salsa20WordToByte` adds the input back. Do not
  "correct" this into stock ChaCha20; the hash construction depends on it.
- The permutation has two build-tagged implementations. Any change must be
  made in both `permute.go` and `permute_unaligned.go`. The unsafe version is
  selected for `i386, amd64, arm64, ppc64le, s390x` and assumes little-endian.
- Fixed-size array APIs (`[PublicKeySize]byte`, etc.) copy keys and signatures
  on every call. `Sign` takes the private key by value and wipes only its local
  copy, so the caller's key is unchanged. Be careful when refactoring these
  signatures: they are the public ABI and callers rely on array sizes.
- Some intermediates are overwritten with the byte `'0'` rather than zeroed
  before return; this is best-effort wiping, not guaranteed constant-time
  erasure. Avoid introducing data-dependent branches in hash/verify paths.
- `go.mod` requires Go 1.27.2, while `.github/workflows/golang.yml` pins Go
  1.24 with `CGO_ENABLED=0`. The CI matrix may not match the local toolchain;
  do not "fix" a 1.24 CI failure by lowering language features without checking.
- CI branch filters differ: `golang.yml` and `dependabot.yml` target `main`,
  `codeql.yml` targets `master`. The default/working branch is `main`.
- Only `github.com/zeebo/blake3` is a direct dependency (`cpuid` is indirect).
  Prefer the standard library and avoid adding dependencies.

## Conventions

- Package name is `sphincs`; all files live in the repository root (no
  subpackages, no `internal/`).
- Unexported helpers use camelCase (`hashH2nnMask`, `computeAuthpathWots`);
  exported API is minimal and documented with `// Name ...` comments.
- Single-letter and short names (`n`, `l`, `mh`, `a`, `sk`) are idiomatic here
  and should be preserved when editing cryptographic routines.
- Wrap lines at a normal Go width; the code is gofmt'd with `-s`
  (simplification mode).

## Release

Repository tags follow patch bumps of `v0.1.x`. Releases in the history are
prepared by updating dependencies/`go.mod`, committing, tagging `v0.1.<N+1>`,
and pushing commits and tags to `origin`.
