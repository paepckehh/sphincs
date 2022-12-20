// Package sphincs provides hashbased hypertree post-quantum secure signatures
package sphincs

// import
import (
	"crypto/subtle"
	"encoding/binary"

	"github.com/zeebo/blake3"
)

// const
const (
	// PublicKeySize is the length of a SPHINCS-256 public key in bytes.
	PublicKeySize = (nMasks + 1) * hashSize
	// PrivateKeySize is the length of a SPHINCS-256 private key in bytes.
	PrivateKeySize = seedBytes + PublicKeySize - hashSize + skRandSeedBytes
	// SignatureSize is the length of a SPHINCS-256 signature in bytes.
	SignatureSize = 32 + (totalTreeHeight+7)/8 + horstSigBytes + (nLevels)*wotsSigBytes + totalTreeHeight*hashSize
	// SeedTokenSize
	SeedTokenSize = PrivateKeySize
	// SignatureSize
	HashSize = 64
	// MessageSize
	MessageSize = HashSize
)

// GenerateKey generates a public/private key pair
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

	// Create leafidx deterministically.
	{
		// Shift scratch upwards for convinience.
		scratch := sm[SignatureSize-skRandSeedBytes:]
		copy(scratch[:skRandSeedBytes], tsk[PrivateKeySize-skRandSeedBytes:])
		//
		rnd := blake3.Sum512(append(scratch[:32], message[:]...))
		leafidx = binary.LittleEndian.Uint64(rnd[0:]) & 0xfffffffffffffff
		copy(r[:], rnd[16:])
		// Prepare msgHash
		scratch = sm[SignatureSize-messageHashSeedBytes-PublicKeySize:]
		// Copy R.
		copy(scratch[:], r[:])
		// Construct and copy pk.
		a := leafaddr{level: nLevels - 1, subtree: 0, subleaf: 0}
		pk := scratch[messageHashSeedBytes:]
		copy(pk[:nMasks*hashSize], tsk[seedBytes:])
		treehash(pk[nMasks*hashSize:], subtreeHeight, tsk[:], &a, pk)
		mh = blake3.Sum512(append(scratch[:messageHashSeedBytes+PublicKeySize], message[:]...))
	}

	// Use unique value $d$ for HORST address.
	a := leafaddr{level: nLevels, subleaf: int(leafidx & ((1 << subtreeHeight) - 1)), subtree: leafidx >> subtreeHeight}
	sigp := sm[:]
	copy(sigp[0:messageHashSeedBytes], r[:])
	sigp = sigp[messageHashSeedBytes:]
	copy(masks[:], tsk[seedBytes:])
	for i := uint64(0); i < (totalTreeHeight+7)/8; i++ {
		sigp[i] = byte((leafidx >> (8 * i)) & 0xff)
	}
	sigp = sigp[(totalTreeHeight+7)/8:]
	generateSeed(seed[:], tsk[:], &a)
	horstSign(sigp, &root, &seed, masks[:], mh[:])
	sigp = sigp[horstSigBytes:]
	for i := 0; i < nLevels; i++ {
		a.level = i
		generateSeed(seed[:], tsk[:], &a)
		wotsSign(sigp, &root, &seed, masks[:])
		sigp = sigp[wotsSigBytes:]
		computeAuthpathWots(&root, sigp, &a, tsk[:], masks[:], subtreeHeight)
		sigp = sigp[subtreeHeight*hashSize:]
		a.subleaf = int(a.subtree & ((1 << subtreeHeight) - 1))
		a.subtree >>= subtreeHeight
	}
	// wipe privkey
	for i := range tsk {
		tsk[i] = '0'
	}
	return sm
}

// Verify takes a public key, message and signature and returns true if the signature is valid.
func Verify(tpk [PublicKeySize]byte, message [MessageSize]byte, signature [SignatureSize]byte) bool {
	var (
		leafidx uint64
		wotsPk  [wotsL * hashSize]byte
		pkhash  [hashSize]byte
		root    [hashSize]byte
	)
	// message hash
	mh := blake3.Sum512(multiSliceAppend(signature[:messageHashSeedBytes], tpk[:], message[:]))
	// sig
	sigp := signature[:]
	sigp = sigp[messageHashSeedBytes:]
	for i := uint64(0); i < (totalTreeHeight+7)/8; i++ {
		leafidx |= uint64(sigp[i]) << (8 * i)
	}
	// verify
	horstVerify(root[:], sigp[(totalTreeHeight+7)/8:], tpk[:], mh[:])
	sigp = sigp[(totalTreeHeight+7)/8:]
	sigp = sigp[horstSigBytes:]
	for i := 0; i < nLevels; i++ {
		wotsVerify(&wotsPk, sigp, &root, tpk[:])
		sigp = sigp[wotsSigBytes:]
		lTree(pkhash[:], wotsPk[:], tpk[:])
		validateAuthpath(&root, &pkhash, uint(leafidx&0x1f), sigp, tpk[:], subtreeHeight)
		leafidx >>= 5
		sigp = sigp[subtreeHeight*hashSize:]
	}
	tpkRewt := tpk[nMasks*hashSize:]
	return subtle.ConstantTimeCompare(root[:], tpkRewt) == 1
}
