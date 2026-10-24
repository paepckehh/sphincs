<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/hero-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/hero-light.svg">
  <img src="docs/hero-light.svg" alt="sphincs: stateless hash-based post-quantum signatures in pure Go" width="100%">
</picture>

# 🌲 sphincs

**Post-quantum signatures without the state.**

Stateless, hash-based, deterministic, and dependency-light. One tiny Go package
with a three-function API: `GenerateKey`, `Sign`, `Verify`.

[![Go Reference](https://pkg.go.dev/badge/paepcke.de/sphincs.svg)](https://pkg.go.dev/paepcke.de/sphincs)
[![Go Report Card](https://goreportcard.com/badge/paepcke.de/sphincs)](https://goreportcard.com/report/paepcke.de/sphincs)
[![Go Build](https://github.com/paepckehh/sphincs/actions/workflows/golang.yml/badge.svg)](https://github.com/paepckehh/sphincs/actions/workflows/golang.yml)
[![License](https://img.shields.io/github/license/paepckehh/sphincs)](https://github.com/paepckehh/sphincs/blob/main/LICENSE)
[![Release](https://img.shields.io/github/v/release/paepckehh/sphincs)](https://github.com/paepckehh/sphincs/releases/latest)
[![Go Version](https://img.shields.io/badge/go-1.27.2-00ADD8)](https://go.dev/dl/)

`go get paepcke.de/sphincs`

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/established-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/established-light.svg">
  <img src="docs/established-light.svg" alt="sphincs: established in 2022, 26+ tagged releases, continuous development" width="100%">
</picture>

</div>

---

## 💡 Why

A signature scheme should not need a session, a counter, or a database. It
should not need a new dependency tree either. `sphincs` is a small, readable
implementation of a stateless hash-based hypertree signature scheme, built on
BLAKE3 and a compact ChaCha permutation.

- 🌲 **Stateless by design**: no per-signature state, no nonce tracking, no key
  reuse bookkeeping. Lose the process, keep the key.
- 🎯 **Deterministic signatures**: the same key and message always produce the
  same signature. Great for reproducible builds, tests, and audit trails.
- ⚡ **Fast verification**: sub-millisecond on modern hardware, which is where
  post-quantum signatures usually hurt.
- 🪶 **Tiny surface**: one package, three exported functions, one direct
  dependency (`github.com/zeebo/blake3`).
- 🧱 **Fixed-size ABI**: plain byte arrays for keys, messages, and signatures.
  No reflection, no serialization, no hidden allocation in the hash core.
- 🧪 **Tested**: round-trip, tamper detection, determinism, key derivation, and
  checksum encoding are covered by `go test ./...`.

> **Status: experimental.** This is a clean, maintained implementation for
> research, tooling, and interoperability experiments. It is not audited and
> it is not wire-compatible with SPHINCS+. Do not deploy it as the only
> signature scheme protecting production secrets without an independent review.

## 🚀 Quick start

```go
package main

import (
	"crypto/rand"
	"fmt"

	"paepcke.de/sphincs"
)

func main() {
	var seed [sphincs.SeedTokenSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		panic(err)
	}

	pk, sk := sphincs.GenerateKey(seed)

	var msg [sphincs.MessageSize]byte
	copy(msg[:], "hello, post-quantum world")

	sig := sphincs.Sign(sk, msg)
	fmt.Println(sphincs.Verify(pk, msg, sig)) // true
}
```

Install it or run it straight from the module cache:

```shell
go get paepcke.de/sphincs@latest
```

## 📦 Sizes

| Item | Bytes |
| :--- | ---: |
| Public key | 1,056 |
| Private key / seed token | 1,088 |
| Signature | 41,000 |
| Message | 64 |
| Message digest | 64 |

The private key *is* the seed token. It contains the master seed, the public
masks, and the per-key signing random seed. Fill it with `crypto/rand`, store
it like a private key, and never derive it from a short password.

## 📊 Performance

Informal benchmark on an Intel i5-12400T, Go 1.27.2, linux/amd64:

| Operation | Time | Allocations |
| :--- | ---: | ---: |
| `GenerateKey` | ~3.9 ms | 34 |
| `Sign` | ~70 ms | 437 |
| `Verify` | ~0.73 ms | 1 |

```shell
go test -run '^$' -bench . -benchmem
```

Signing builds a fresh WOTS+ path for every level, so it does real work. It is
still comfortably in interactive range. Verification only walks the supplied
paths and usually lands well below one millisecond.

## 🔬 How it works

`sphincs` is a 12-level hypertree over WOTS+ leaves, with a HORST few-time
signature at the bottom:

```text
message
   │
   ▼
BLAKE3-512 ──► leaf index + R
   │
   ▼
HORST signature over the message hash
   │
   ├── subtree 0: WOTS+ signature + auth path
   ├── subtree 1: WOTS+ signature + auth path
   │   ...
   └── subtree 11: WOTS+ signature + auth path
   │
   ▼
41,000-byte signature
```

- **Message digest**: BLAKE3-512, truncated to a 64-byte fixed message.
- **Tree**: 12 subtrees of height 5, giving a 60-bit leaf space.
- **Leaves**: WOTS+ with `w = 16`, `l = 67`.
- **Few-time layer**: HORST with `t = 2^16` and `k = 32`.
- **Seed expansion**: a 12-round ChaCha permutation with the same masked hash
  construction as the original SPHINCS-256 design.
- **Verification**: constant-time comparison of the reconstructed root against
  the public key.

The construction is derived from
[yawning/sphincs256](https://github.com/yawning/sphincs256) and keeps its
byte-level layout and parameter relationships. The hash and permutation choices
are intentional: BLAKE3-512 for message digests, BLAKE3-256 for seed derivation,
and a 12-round ChaCha permutation *without* the final feed-forward for the
masked tree hash.

## 🧭 API

```go
func GenerateKey(psrnd [SeedTokenSize]byte) (pk [PublicKeySize]byte, sk [PrivateKeySize]byte)
func Sign(sk [PrivateKeySize]byte, message [MessageSize]byte) (signature [SignatureSize]byte)
func Verify(pk [PublicKeySize]byte, message [MessageSize]byte, signature [SignatureSize]byte) bool
```

| Exported constant | Value | Meaning |
| :--- | ---: | :--- |
| `PublicKeySize` | 1,056 | Public key length |
| `PrivateKeySize` | 1,088 | Private key length |
| `SeedTokenSize` | 1,088 | Seed token accepted by `GenerateKey` |
| `SignatureSize` | 41,000 | Signature length |
| `HashSize` | 64 | BLAKE3-512 digest length |
| `MessageSize` | 64 | Fixed message length |

Everything is a fixed-size array. Keys and signatures are copied on every call,
which keeps the API safe to use from multiple goroutines and makes ownership
obvious.

## 🔐 Security notes

- **Experimental, not audited.** Treat this as a serious implementation, not a
  certified one.
- **Deterministic signing.** There is no per-signature randomness. The same key
  and message always produce the same signature. As with other deterministic
  signature schemes, a faulty signing device that emits two different
  signatures for the same input can leak key material.
- **Fixed message size.** `Sign` and `Verify` accept exactly 64 bytes. Hash or
  frame longer messages before signing.
- **Fixed-size keys.** The seed token must be generated with a CSPRNG and kept
  secret. It is not stretched from a passphrase.
- **Best-effort wiping.** Local private material is cleared before return, but
  Go gives no hard guarantee against copies made by the runtime or the OS.
- **Root comparison is constant-time.** Verification uses
  `crypto/subtle.ConstantTimeCompare` for the final root check.

Report vulnerabilities to `alert.git (/AT/) paepcke.de`. See
[SECURITY.md](SECURITY.md).

## 🧩 Design decisions

- **Stateless beats stateful.** No leaf counter means no multi-process locking
  and no "signing state" to back up.
- **Hash-based beats number-theoretic.** Security rests on hash and permutation
  assumptions, not on factoring or discrete logarithms.
- **BLAKE3 is fast and boring.** The message path uses a well-tested BLAKE3
  implementation instead of a hand-rolled compression function.
- **Tiny API beats a framework.** Three functions and six constants are enough
  to sign, verify, and reason about key sizes.
- **One dependency beats ten.** `zeebo/blake3` is the only direct dependency.

## 🧪 Development

```shell
make check          # gofmt, go vet, go test
make build          # go build -v ./...
make test           # go test ./...
make vet            # go vet ./...
make fmt            # gofmt -w -s .
make lint           # staticcheck ./... (optional)
```

The package has no subpackages, no generated code, and no build tags beyond the
two architecture-specific permutation implementations.

## 📚 Docs and references

- API reference: [pkg.go.dev/paepcke.de/sphincs](https://pkg.go.dev/paepcke.de/sphincs)
- Project home: [paepcke.de/sphincs](https://paepcke.de/sphincs/)
- Hero artwork: [dark](docs/hero-dark.svg) / [light](docs/hero-light.svg)
- Established banner: [dark](docs/established-dark.svg) / [light](docs/established-light.svg)
- Original implementation: [github.com/yawning/sphincs256](https://github.com/yawning/sphincs256) (BSD-3-Clause)
- BLAKE3: [github.com/zeebo/blake3](https://github.com/zeebo/blake3) (CC0)
- SPHINCS+ paper: [cryptojedi.org/papers/spx-20190923.pdf](https://cryptojedi.org/papers/spx-20190923.pdf)
- SPHINCS+ reference code: [github.com/sphincs/sphincsplus](https://github.com/sphincs/sphincsplus)

## 👯 Sibling projects

Same author, same "small tool, sharp edges" philosophy:

- [certinfo](https://github.com/paepckehh/certinfo): decode x.509, CSRs, and SSH keys
- [tlsinfo](https://github.com/paepckehh/tlsinfo): inspect TLS endpoints and certificates

## 🤝 Contributing

Yes, please. PRs, issue reports, benchmarks, and independent review are all
welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## 🛡 License

BSD 3-Clause. See [LICENSE](LICENSE).

## 📃 Citation

```bibtex
@misc{sphincs,
  author = {Michael Paepcke},
  title = {sphincs: stateless hash-based post-quantum signatures in pure Go},
  year = {2022},
  publisher = {GitHub},
  journal = {GitHub repository},
  howpublished = {\url{https://paepcke.de/sphincs}}
}
```

Special thanks to Daniel J. Bernstein, Andreas Huelsing, Stefan Koelbl, Ruben
Niederhagen, Joost Rijneveld, and Peter Schwabe for the SPHINCS framework, and
to the authors of `yawning/sphincs256` and `zeebo/blake3`.
