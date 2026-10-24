// Package sphincs provides stateless hash-based (hypertree) post-quantum signatures.
package sphincs

import (
	"crypto/subtle"
	"encoding/binary"
	"slices"

	"github.com/zeebo/blake3"
)

const (
	// PublicKeySize is the length of a public key in bytes.
	PublicKeySize = (nMasks + 1) * hashSize
	// PrivateKeySize is the length of a private key in bytes.
	PrivateKeySize = seedBytes + PublicKeySize - hashSize + skRandSeedBytes
	// SignatureSize is the length of a signature in bytes.
	SignatureSize = messageHashSeedBytes + leafIndexBytes + horstSigBytes + nLevels*wotsSigBytes + totalTreeHeight*hashSize
	// SeedTokenSize is the exact private-key-sized seed token consumed by GenerateKey.
	SeedTokenSize = PrivateKeySize
	// HashSize is the length of the BLAKE3-512 message digest in bytes.
	HashSize = 64
	// MessageSize is the fixed message length accepted by Sign and Verify.
	MessageSize = HashSize
)

// GenerateKey derives a public/private key pair from a private-key-sized seed token.
func GenerateKey(psrnd [SeedTokenSize]byte) ([PublicKeySize]byte, [PrivateKeySize]byte) {
	var publicKey [PublicKeySize]byte
	privateKey := psrnd
	copy(publicKey[:nMasks*hashSize], privateKey[seedBytes:])
	// Initialization of top-subtree address.
	a := leafaddr{level: nLevels - 1, subtree: 0, subleaf: 0}
	// Construct top subtree.
	treehash(publicKey[nMasks*hashSize:], subtreeHeight, privateKey[:], &a, publicKey[:])
	return publicKey, privateKey
}

// Sign signs the message with privateKey and returns the signature.
func Sign(tsk [PrivateKeySize]byte, message [MessageSize]byte) [SignatureSize]byte {
	var (
		sm      [SignatureSize]byte
		leafidx uint64
		r       [messageHashSeedBytes]byte
		root    [hashSize]byte
		seed    [seedBytes]byte
		masks   [nMasks * hashSize]byte
		mh      [MessageSize]byte
	)

	// Derive the leaf index and R deterministically from the secret random seed.
	{
		scratch := sm[SignatureSize-skRandSeedBytes:]
		copy(scratch, tsk[PrivateKeySize-skRandSeedBytes:])
		rnd := blake3.Sum512(slices.Concat(scratch[:skRandSeedBytes], message[:]))
		leafidx = binary.LittleEndian.Uint64(rnd[0:]) & leafIndexMask
		copy(r[:], rnd[16:])

		// Recompute the public key and message hash.
		scratch = sm[SignatureSize-messageHashSeedBytes-PublicKeySize:]
		copy(scratch, r[:])
		a := leafaddr{level: nLevels - 1, subtree: 0, subleaf: 0}
		pk := scratch[messageHashSeedBytes:]
		copy(pk[:nMasks*hashSize], tsk[seedBytes:])
		treehash(pk[nMasks*hashSize:], subtreeHeight, tsk[:], &a, pk)
		mh = blake3.Sum512(slices.Concat(scratch[:messageHashSeedBytes+PublicKeySize], message[:]))
	}

	// Use unique value $d$ for HORST address.
	a := leafaddr{level: nLevels, subleaf: int(leafidx & ((1 << subtreeHeight) - 1)), subtree: leafidx >> subtreeHeight}
	sigp := sm[:]
	copy(sigp[0:messageHashSeedBytes], r[:])
	sigp = sigp[messageHashSeedBytes:]
	copy(masks[:], tsk[seedBytes:])
	for i := range uint64(leafIndexBytes) {
		sigp[i] = byte((leafidx >> (8 * i)) & 0xff)
	}
	sigp = sigp[leafIndexBytes:]
	generateSeed(seed[:], tsk[:], &a)
	horstSign(sigp, &root, &seed, masks[:], mh[:])
	sigp = sigp[horstSigBytes:]
	for i := range nLevels {
		a.level = i
		generateSeed(seed[:], tsk[:], &a)
		wotsSign(sigp, &root, &seed, masks[:])
		sigp = sigp[wotsSigBytes:]
		computeAuthpathWots(&root, sigp, &a, tsk[:], masks[:], subtreeHeight)
		sigp = sigp[subtreeHeight*hashSize:]
		a.subleaf = int(a.subtree & ((1 << subtreeHeight) - 1))
		a.subtree >>= subtreeHeight
	}
	clear(tsk[:])
	return sm
}

// Verify reports whether signature is valid for message under tpk.
func Verify(tpk [PublicKeySize]byte, message [MessageSize]byte, signature [SignatureSize]byte) bool {
	var (
		leafidx uint64
		wotsPk  [wotsL * hashSize]byte
		pkhash  [hashSize]byte
		root    [hashSize]byte
	)

	mh := blake3.Sum512(slices.Concat(signature[:messageHashSeedBytes], tpk[:], message[:]))
	sigp := signature[messageHashSeedBytes:]
	for i := range uint64(leafIndexBytes) {
		leafidx |= uint64(sigp[i]) << (8 * i)
	}

	horstVerify(root[:], sigp[leafIndexBytes:], tpk[:], mh[:])
	sigp = sigp[leafIndexBytes+horstSigBytes:]
	for range nLevels {
		wotsVerify(&wotsPk, sigp, &root, tpk[:])
		sigp = sigp[wotsSigBytes:]
		lTree(pkhash[:], wotsPk[:], tpk[:])
		validateAuthpath(&root, &pkhash, uint(leafidx&((1<<subtreeHeight)-1)), sigp, tpk[:], subtreeHeight)
		leafidx >>= subtreeHeight
		sigp = sigp[subtreeHeight*hashSize:]
	}
	return subtle.ConstantTimeCompare(root[:], tpk[nMasks*hashSize:]) == 1
}
